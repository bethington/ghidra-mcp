#!/usr/bin/env python3
r"""Unattended shadow-mode watcher: accumulate BATTLETESTED evidence safely.

WHY THIS EXISTS
---------------
Measured 2026-07-31: 191 shadow dispatchers deployed, 186 bound to a reimpl,
sampler PRESENT, 66 BILLION accumulated hits -- and **zero** functions promoted
to CONF_BATTLETESTED, because all 191 sat in `mode=0 (original)`.

In original mode the thunk returns before the comparison. The reimpl never
runs, nothing is compared, and `distinct_inputs` stays 0 forever. Promotion
requires >=1000 hits AND >=20 distinct inputs AND 0 divergences, so the gate
could never open no matter how long the game ran or how fast the port workers
proved new functions. Prove throughput was never the bottleneck.

WHY IT IS A WATCHER AND NOT A ONE-SHOT FLIP
-------------------------------------------
Shadow mode runs BOTH implementations on every real call. dispatch_control's
own docstring records that an all-at-once change left a
`D2Common.dll.CRASHED_114disp_*` artifact in the patch directory, and the
hottest dispatcher here takes ~20 BILLION calls. So:

  * we shadow a NARROW, explicitly-chosen set (coolest-first);
  * we watch every polling round and REVERT any dispatcher that diverges,
    immediately -- a divergence means the reimpl disagrees with the original in
    the live game, which is a correctness finding, not something to leave
    running;
  * we revert everything on exit, including Ctrl-C, so an interrupted watch
    never leaves the game in a doubled-work state.

A divergence is recorded (CONF_REFUTED is battletest_promoter's job, not
ours), not silently swallowed -- see feedback_loud_failures.

USAGE
    # dry run: show what would be shadowed, change nothing
    python fun-doc/scripts/shadow_battletest_watch.py --count 20

    # flip the 20 coolest ready dispatchers and watch until Ctrl-C
    python fun-doc/scripts/shadow_battletest_watch.py --count 20 --apply

    # bounded run (e.g. overnight), then auto-revert
    python fun-doc/scripts/shadow_battletest_watch.py --count 20 --apply --minutes 480

    # revert everything to original and exit
    python fun-doc/scripts/shadow_battletest_watch.py --revert-all
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

_FUNDOC = Path(__file__).resolve().parent.parent
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

ORACLE_URL = os.environ.get("D2DBG_MCP_URL", "http://127.0.0.1:8790").rstrip("/")
LOG = _FUNDOC / "logs" / "shadow_battletest_watch.jsonl"

# Promotion thresholds are battletest_promoter's; mirrored here only for the
# progress display. The promoter remains the single authority on promotion.
MIN_HITS, MIN_DISTINCT = 1000, 20

_shadowed: list = []          # indices we flipped; reverted on every exit path


def _get(path: str, timeout: float = 20.0):
    with urllib.request.urlopen(f"{ORACLE_URL}{path}", timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _post(path: str, body: dict, timeout: float = 20.0):
    req = urllib.request.Request(
        f"{ORACLE_URL}{path}", data=json.dumps(body).encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def dispatchers() -> list:
    return _get("/dispatchers").get("dispatchers", []) or []


def set_mode(index: int, mode: str) -> dict:
    return _post(f"/dispatcher/{index}/mode", {"mode": mode})


def log(event: str, **fields) -> None:
    rec = {"ts": datetime.now().isoformat(), "event": event, **fields}
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except OSError:
        pass
    print(f"  [{event}] " + " ".join(f"{k}={v}" for k, v in fields.items()), flush=True)


def revert(indices, reason: str) -> None:
    """Put dispatchers back in original mode. Best-effort and idempotent."""
    for i in list(indices):
        try:
            set_mode(i, "original")
        except Exception as e:  # noqa: BLE001
            print(f"  WARNING: could not revert dispatcher {i}: {e}", flush=True)
    if indices:
        log("reverted", count=len(indices), reason=reason)


def pick_candidates(ds: list, count: int, min_hits: int = MIN_HITS,
                    skip_weak: bool = False) -> list:
    """Dispatchers that can actually produce a NEW promotion, coolest first.

    Mechanical eligibility:
      * hooked            -- an unhooked dispatcher never runs at all;
      * arg_count >= 0    -- argc -1 is the coord family, which predates the
                             sampler and reports distinct_inputs=0 meaning
                             "unknown". It can never satisfy the diversity
                             gate, so shadowing it is pure cost;
      * mode == original  -- do not disturb anything already set by hand.

    And -- the part a naive "coolest ready dispatchers" pick gets wrong --
    the function must be able to GAIN something:

      * NOT already at or above CONF_BATTLETESTED. The first run of this
        script selected the 20 coolest dispatchers past the volume bar and 13
        of them were already promoted; shadowing those doubles per-call work
        in the live game and cannot produce a single promotion.

    `weak_proof` rows are INCLUDED by default, which looks wrong at first
    glance -- battletest_promoter refuses to promote them, so shadowing them
    cannot produce a promotion today. It is deliberate: shadow evidence is the
    only thing that can ever clear the flag (scripts/clear_weak_proof.py), and
    the flag's own text names it -- "re-prove against DIVERSE objects (or trust
    shadow/V2)". Excluding them, as the first version of this script did, makes
    the clearing path unreachable and strands 37 functions forever. Pass
    --skip-weak to exclude them.

    Ghidra rung lookups are one HTTP call each, so this is deliberately only
    run at selection time, not per polling round.
    """
    import battletest_promoter as btp
    import conf_ladder as cl

    try:
        rows = btp._load_registry()
        weak = {str(r.get("address", "")).lower().replace("0x", "")
                for r in rows if r.get("weak_proof")}
    except Exception:
        weak = set()

    eligible = [d for d in ds
                if d.get("hooked")
                and (d.get("arg_count") or -1) >= 0
                and d.get("modeName") == "original"
                and d.get("hits", 0) >= min_hits]
    eligible.sort(key=lambda d: d.get("hits", 0))

    picks = []
    for d in eligible:
        base = btp.IMAGE_BASES.get(d.get("module"))
        if base is None:
            continue
        a = format(base + d["offset"], "x")
        is_weak = a in weak
        if is_weak and skip_weak:
            continue
        held = btp._ghidra_rung("0x" + a, d["module"])
        # Already-promoted functions are excluded even when weak-flagged --
        # there is nothing left to gain either way.
        if cl.rung_strength("CONF_BATTLETESTED") <= cl.rung_strength(held):
            continue
        d = dict(d)
        d["_weak_proof"] = is_weak
        picks.append(d)
        if len(picks) >= count:
            break
    return picks


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--count", type=int, default=20, help="how many to shadow")
    ap.add_argument("--apply", action="store_true", help="actually change modes")
    ap.add_argument("--minutes", type=float, default=0,
                    help="stop and revert after N minutes (0 = until interrupted)")
    ap.add_argument("--interval", type=float, default=120, help="poll seconds")
    ap.add_argument("--revert-all", action="store_true",
                    help="set every dispatcher back to original and exit")
    ap.add_argument("--skip-weak", action="store_true",
                    help="exclude weak_proof rows. They cannot promote today, "
                         "but shadow evidence is the ONLY thing that can clear "
                         "the flag (scripts/clear_weak_proof.py), so they are "
                         "included by default")
    ap.add_argument("--min-hits", type=int, default=MIN_HITS,
                    help="volume floor for selection. Lower it to pre-arm "
                         "functions that gameplay has barely reached yet, so "
                         "they sample inputs as soon as they ARE called "
                         "(default: the promotion bar itself)")
    args = ap.parse_args()

    try:
        ds = dispatchers()
    except Exception as e:  # noqa: BLE001
        print(f"D2Debugger unreachable at {ORACLE_URL}: {e}", file=sys.stderr)
        return 1

    if args.revert_all:
        idx = [d["index"] for d in ds if d.get("modeName") != "original"]
        if not idx:
            print("nothing to revert -- all dispatchers already original.")
            return 0
        revert(idx, "explicit --revert-all")
        return 0

    picks = pick_candidates(ds, args.count, min_hits=args.min_hits,
                            skip_weak=args.skip_weak)
    if not picks:
        print("no eligible dispatchers (need hooked, argc>=0, original, "
              f">={args.min_hits} hits, not already BATTLETESTED, not weak_proof).")
        return 0

    n_weak = sum(1 for d in picks if d.get("_weak_proof"))
    print(f"{len(ds)} dispatchers; selecting {len(picks)} below CONF_BATTLETESTED "
          f"(>={args.min_hits} hits)"
          + (f", of which {n_weak} are weak_proof (gathering evidence to CLEAR "
             f"the flag, not to promote)" if n_weak else "")
          + ", coolest first:\n")
    for d in picks:
        tag = " [weak_proof]" if d.get("_weak_proof") else ""
        print(f"  [{d['index']:>3}] {d['hits']:>10} hits  argc={d['arg_count']}  "
              f"{d['module']:<14} {d['name']}{tag}")

    if not args.apply:
        print("\nDRY RUN -- re-run with --apply to shadow these and watch.")
        return 0

    # Revert on EVERY exit path. An interrupted watch that left dispatchers in
    # shadow would silently double per-call work in the live game.
    def _bail(signum, _frame):
        revert(_shadowed, f"signal {signum}")
        sys.exit(130)

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(s, _bail)
        except (ValueError, OSError):
            pass

    try:
        for d in picks:
            set_mode(d["index"], "shadow")
            _shadowed.append(d["index"])
        log("shadow_enabled", count=len(_shadowed),
            names=[d["name"] for d in picks])

        deadline = time.time() + args.minutes * 60 if args.minutes else None
        baseline = {d["index"]: d.get("hits", 0) for d in picks}
        round_no = 0
        while True:
            if deadline and time.time() >= deadline:
                log("window_elapsed", minutes=args.minutes)
                break
            time.sleep(args.interval)
            round_no += 1
            try:
                cur = {d["index"]: d for d in dispatchers()}
            except Exception as e:  # noqa: BLE001
                log("poll_failed", error=str(e))
                continue

            # --- SESSION BOUNDARY: re-apply shadow mode ----------------------
            # Dispatcher mode and counters both live in the patch DLL and are
            # PROCESS-STATIC: a game relaunch resets every dispatcher to
            # `original` and every counter to 0. Nothing tells us this happened
            # -- /dispatchers keeps answering, the oracle keeps reporting
            # healthy, and this loop keeps logging cheerful rounds while
            # accumulating exactly nothing.
            #
            # Measured 2026-07-31: the game was auto-recovered from a wedged
            # state at 04:21 (correctly -- that is oracle_health doing its job),
            # and the watch then ran for SIX HOURS reporting rounds against 119
            # dispatchers that had all silently reverted to original. One hour
            # of real evidence, six hours of theatre.
            #
            # So re-assert ownership every round. This is idempotent and cheap:
            # for a dispatcher already in shadow it is a no-op.
            lost = [i for i in _shadowed
                    if cur.get(i) and cur[i].get("modeName") != "shadow"]
            if lost:
                log("session_boundary", reset=len(lost),
                    note="game restarted -- modes and counters wiped; "
                         "re-applying shadow")
                for i in lost:
                    try:
                        set_mode(i, "shadow")
                    except Exception as e:  # noqa: BLE001
                        log("reapply_failed", index=i, error=str(e))
                # Counters restarted from zero, so the hit baseline must too or
                # every subsequent round reports a negative delta as 0.
                baseline = {i: 0 for i in _shadowed}
                continue

            # --- divergence -> revert THAT dispatcher immediately ------------
            for i in list(_shadowed):
                d = cur.get(i)
                if d and d.get("divergences", 0) > 0:
                    log("DIVERGENCE", index=i, name=d.get("name"),
                        divergences=d["divergences"], hits=d.get("hits"),
                        note="reimpl disagrees with the original in the live "
                             "game -- reverted; battletest_promoter owns the "
                             "CONF_REFUTED verdict")
                    revert([i], "divergence")
                    _shadowed.remove(i)

            ready = [cur[i] for i in _shadowed
                     if cur.get(i)
                     and cur[i].get("distinct_inputs", 0) >= MIN_DISTINCT
                     and cur[i].get("hits", 0) >= MIN_HITS
                     and cur[i].get("divergences", 0) == 0]
            gained = sum(max(0, cur[i].get("hits", 0) - baseline.get(i, 0))
                         for i in _shadowed if cur.get(i))
            maxd = max((cur[i].get("distinct_inputs", 0)
                        for i in _shadowed if cur.get(i)), default=0)
            log("round", n=round_no, shadowed=len(_shadowed),
                new_hits=gained, max_distinct=maxd, gate=MIN_DISTINCT,
                meeting_gate=len(ready))

            # --- promotions ---------------------------------------------------
            try:
                import battletest_promoter as btp
                res = btp.poll_and_promote()
                if res.get("promoted"):
                    log("PROMOTED", functions=res["promoted"])
                if res.get("refuted"):
                    log("REFUTED", functions=res["refuted"])
            except Exception as e:  # noqa: BLE001
                log("promoter_error", error=str(e))
    finally:
        revert(_shadowed, "watch finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

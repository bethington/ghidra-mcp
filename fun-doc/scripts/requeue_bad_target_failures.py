"""Re-queue terminal live-prove failures that were really a RELOCATED MODULE.

WHY
---
The conformance stack assumed a module loads at its Ghidra image base. D2Common
(0x6fd50000) and D2Game (0x6fc20000) do. D2Client does NOT -- the live process
maps it at 0x03600000 and leaves Ghidra's 0x6fab0000 unmapped -- so every
D2Client `/oracle` call `call`ed unmapped memory. The fault was SEH-caught and
reported as the generic "handler-exception", which `_classify_prove_failure`
files as `marshal_fault`: "wrong callconv/slot-count or a bad pointer arg".

`marshal_fault` is TERMINAL. So 104 D2Client functions were retired on an ABI
verdict while their reimpl had never executed a single time -- including
`SetVideoInitializedFlag`, a zero-arg void setter, "failing an ABI check" on one
vector. That impossibility is the tell.

The pipeline fix is module+rva resolution (gen_resolve_table.py,
provider_runtime.cpp, port_live_prove.stamp_live_identity) plus the oracle's
bad-target gate. This script repairs the DATA the bug produced.

WHAT IT DOES
------------
Finds rows with a terminal `port_status='live_prove_failed'` whose recorded
failure is a FAULT SIGNATURE, in binaries whose module is currently RELOCATED,
and returns them to the queue as `oracle_unavailable` (the same non-terminal
status every other environmental failure uses).

Deliberately NOT re-queued:
  * `mismatch`      -- both sides ran and disagreed. A real comparison.
  * build failures  -- `build_candidate` / `build_provider`: the candidate did
                       not compile. True regardless of any module base.
  * binaries at their Ghidra base -- D2Common's 32 marshal_faults are genuine
                       ABI findings and must stay terminal.

Relocation is read from the oracle's `GET /modules` (live base per module) against
Ghidra's `/get_metadata` image base. Both are required, so a wrong guess cannot
mass-unretire real failures. `--module NAME` forces a module to be treated as
relocated when the game is not running.

CURRENT RELOCATION IS NOT EVIDENCE ABOUT A PAST VERDICT
-------------------------------------------------------
Bases are assigned per launch, so "relocated right now" says nothing about where
the module sat when a verdict was recorded weeks ago. Measured 2026-07-30 across
two launches of the same build: D2Client 0x03600000 -> 0x03550000 -> 0x6F270000,
and D2Common -- at its preferred base all day -- came back at 0x6E510000.

Taking current relocation at face value would have re-queued 39 D2Common rows
whose faults are genuine ABI findings: D2Common proved 248 functions successfully
in the same period, which is only possible if its addresses were right then.

So a candidate must ALSO show that its binary was demonstrably broken AT THE TIME
of the failure: the run log is joined on (program, address) to date each failure,
and the row is kept only when that binary had NO successful live proof within
--evidence-window-hours of it. A binary that was proving fine hours either side of
a fault was addressable, and that fault is a real verdict.

USAGE
-----
    python fun-doc/scripts/requeue_bad_target_failures.py                 # dry run
    python fun-doc/scripts/requeue_bad_target_failures.py --apply
    python fun-doc/scripts/requeue_bad_target_failures.py --module D2Client.dll --apply

Run with the Prove workers STOPPED: a running worker can write a fresh terminal
verdict for a row this script just re-queued.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

_FUNDOC_DIR = Path(__file__).resolve().parent.parent
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

ORACLE_URL = os.environ.get("D2DBG_MCP_URL", "http://127.0.0.1:8790").rstrip("/")
GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")

# Recorded-failure signatures that mean "a call faulted", i.e. exactly what an
# unmapped target produces. Matched against port_last_result / port_failure_stage.
_FAULT_SIGNATURES = (
    "SEH fault inside the oracle",          # marshal_fault detail
    "game-thread call FAULTED",             # handle lane, onGameThread path
    "handler-exception",                    # raw oracle error, if it reached the row
    "bad-target",                           # post-fix gate (already environmental)
)
_FAULT_STAGES = ("marshal_fault", "bad_target")


def _get_json(url: str, timeout: int = 15):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            body = json.loads(resp.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None
    # 7.0.0 envelope: {"result": "<json string>"}
    if isinstance(body, dict) and isinstance(body.get("result"), str):
        try:
            return json.loads(body["result"])
        except ValueError:
            return None
    return body


def live_module_bases():
    """{module_name_lower: live_base} from the oracle, or {} when unavailable."""
    payload = _get_json(f"{ORACLE_URL}/modules")
    if not isinstance(payload, dict) or not payload.get("ok"):
        return {}
    out = {}
    for entry in payload.get("modules") or []:
        name, base = entry.get("name"), entry.get("base")
        if isinstance(name, str) and isinstance(base, int):
            out[name.lower()] = base
    return out


def ghidra_image_base(program: str):
    """Ghidra's image base for a program path, or None."""
    meta = _get_json(f"{GHIDRA_HTTP}/get_metadata?program="
                     + urllib.parse.quote(program, safe=""))
    if not isinstance(meta, dict):
        return None
    raw = meta.get("base_address") or meta.get("image_base")
    try:
        return int(str(raw), 16)
    except (TypeError, ValueError):
        return None


def is_fault_row(row) -> bool:
    if (row.get("port_failure_stage") or "") in _FAULT_STAGES:
        return True
    detail = row.get("port_last_result") or ""
    return any(sig in detail for sig in _FAULT_SIGNATURES)


# Live-lane outcomes that PROVE the binary was addressable at that moment: the
# oracle called the original and got a real answer back.
_LIVE_SUCCESS = {"proven_live_pending_review", "proven_pending_review", "proven_live",
                 "proven", "mismatch"}
_LIVE_MODES = {"port_live", "port_handle", "port"}


def load_run_history(runs_path):
    """(failure_time, success_times) from logs/runs.jsonl.

    failure_time: {(program, address): latest ISO ts of a fault-signature failure}
    success_times: {program: sorted [ISO ts]} of outcomes that prove the binary was
    addressable at that time.
    """
    failure_time, success_times = {}, {}
    try:
        fh = open(runs_path, encoding="utf-8")
    except OSError:
        return failure_time, success_times
    with fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("mode") not in _LIVE_MODES:
                continue
            program, ts = rec.get("program"), rec.get("timestamp")
            if not program or not ts:
                continue
            result, stage = rec.get("result"), rec.get("failure_stage")
            if result in _LIVE_SUCCESS or stage == "mismatch":
                success_times.setdefault(program, []).append(ts)
            elif stage in _FAULT_STAGES or result == "live_prove_failed":
                addr = str(rec.get("address") or "").lower().replace("0x", "")
                if addr:
                    key = (program, addr)
                    if ts > failure_time.get(key, ""):
                        failure_time[key] = ts
    for v in success_times.values():
        v.sort()
    return failure_time, success_times


def was_addressable_then(program, ts, success_times, window_hours):
    """True when `program` had a successful live proof within +/- window of `ts`.

    That is positive evidence the module's addresses were correct at the time, so a
    fault recorded then is a real verdict about the function -- not a bad target.
    """
    from datetime import datetime, timedelta

    times = success_times.get(program)
    if not times or not ts:
        return False
    try:
        t = datetime.fromisoformat(ts)
    except ValueError:
        return False
    window = timedelta(hours=window_hours)
    for other in times:
        try:
            o = datetime.fromisoformat(other)
        except ValueError:
            continue
        if abs(o - t) <= window:
            return True
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="write the re-queue (default is a dry run)")
    ap.add_argument("--module", action="append", default=[], metavar="NAME",
                    help="treat NAME (e.g. D2Client.dll) as relocated without asking "
                         "the oracle; repeatable. Use when the game is not running.")
    ap.add_argument("--evidence-window-hours", type=float, default=12.0, metavar="H",
                    help="a fault is kept as GENUINE (not re-queued) when its binary had "
                         "a successful live proof within H hours of it -- proof the module "
                         "was addressable at the time. Default 12.")
    ap.add_argument("--runs", default=str(_FUNDOC_DIR / "logs" / "runs.jsonl"),
                    help="run log used to date failures and find successes")
    args = ap.parse_args(argv)

    import fun_doc  # deferred: a dry run should not need SQLAlchemy any earlier

    forced = {m.lower() for m in args.module}
    live = live_module_bases()
    if not live and not forced:
        print(f"[requeue] FATAL: {ORACLE_URL}/modules is unavailable and no --module "
              f"was given, so relocation cannot be established. Refusing to guess -- "
              f"start the game (or pass --module D2Client.dll).", file=sys.stderr)
        return 2
    if live:
        print(f"[requeue] oracle reports {len(live)} loaded module(s)")

    failure_time, success_times = load_run_history(args.runs)
    print(f"[requeue] run history: {len(failure_time)} dated failure(s), "
          f"{sum(len(v) for v in success_times.values())} live success(es) across "
          f"{len(success_times)} binary/binaries")

    state = fun_doc.load_state()
    functions = state.get("functions") or {}
    print(f"[requeue] {len(functions)} workflow row(s) in state")

    # Cache the relocation verdict per binary: one Ghidra round-trip each.
    verdict: dict = {}

    def relocated(program: str):
        """(is_relocated, why). None for is_relocated == 'cannot tell'."""
        if program in verdict:
            return verdict[program]
        module = program.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        if module.lower() in forced:
            verdict[program] = (True, f"{module} forced via --module")
            return verdict[program]
        gb = ghidra_image_base(program)
        lb = live.get(module.lower())
        if gb is None or lb is None:
            verdict[program] = (None, f"{module}: ghidra_base={gb} live_base={lb}")
        elif lb != gb:
            verdict[program] = (True, f"{module}: live 0x{lb:08x} != ghidra 0x{gb:08x}")
        else:
            verdict[program] = (False, f"{module}: live == ghidra 0x{gb:08x}")
        return verdict[program]

    hits, skipped = [], collections.Counter()
    for key, row in functions.items():
        if (row.get("port_status") or "") != "live_prove_failed":
            continue
        if not is_fault_row(row):
            skipped["not a fault signature (real mismatch/build failure)"] += 1
            continue
        program = key.rsplit("::", 1)[0]
        is_reloc, why = relocated(program)
        if is_reloc is None:
            skipped[f"cannot establish relocation -- {why}"] += 1
            continue
        if not is_reloc:
            skipped[f"module at its Ghidra base -- {why}"] += 1
            continue
        # Current relocation alone is not evidence about a past verdict (see the
        # module docstring). Require that the binary was ALSO demonstrably broken
        # around the time this failure was recorded.
        addr = key.rsplit("::", 1)[-1].lower().replace("0x", "")
        ts = failure_time.get((program, addr))
        if ts is None:
            skipped["failure not datable from runs.jsonl -- left terminal"] += 1
            continue
        if was_addressable_then(program, ts, success_times, args.evidence_window_hours):
            skipped[f"binary was proving successfully around {ts[:10]} -- genuine "
                    f"verdict, left terminal"] += 1
            continue
        hits.append((key, row, why))

    for reason, n in skipped.most_common():
        print(f"[requeue] skipped {n:>4}: {reason}")

    by_binary = collections.Counter(k.rsplit("::", 1)[0] for k, _r, _w in hits)
    print(f"\n[requeue] {len(hits)} row(s) to re-queue:")
    for program, n in by_binary.most_common():
        print(f"    {n:>4}  {program}   ({verdict[program][1]})")

    if not hits:
        print("[requeue] nothing to do")
        return 0
    if not args.apply:
        print("\n[requeue] DRY RUN -- re-run with --apply to write. Sample:")
        for key, row, _why in hits[:10]:
            print(f"    {key}  {row.get('name') or '?'}  "
                  f"<- {(row.get('port_last_result') or '')[:60]}")
        return 0

    for key, _row, why in hits:
        fun_doc.update_function_state(key, {
            "port_status": "oracle_unavailable",
            "port_failure_stage": "bad_target",
            "port_last_result": (
                "bad_target: the original's address was not mapped in the running game "
                f"({why}) -- the reimpl was never executed, so the previous "
                "live_prove_failed was not a verdict about this function. Re-queued by "
                "scripts/requeue_bad_target_failures.py."),
        })
    print(f"[requeue] re-queued {len(hits)} row(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

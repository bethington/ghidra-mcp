"""battletest_promoter.py -- the promotion half of the continuous port loop's
"shadow to verify" step (sibling to shadow_promote.py, which STAGES a function
as a shadow dispatcher; this module watches the ALREADY-STAGED-AND-DEPLOYED
dispatchers and promotes CONF_LIVE -> CONF_BATTLETESTED once real gameplay has
produced enough zero-divergence evidence).

This automates, exactly, the manual procedure run by hand 2026-07-07 (see
conformance/D2COMMON_FULL_SHADOW_PLAN.md and proven_functions.jsonl history):
poll D2Debugger's /dispatchers, and for any dispatcher in shadow mode with
zero divergences and hits over a volume bar, flip its Ghidra CONF_ tag and
registry row from CONF_LIVE to CONF_BATTLETESTED.

Standalone (imports nothing from fun_doc). Two ways to use it:
  - CLI: `python battletest_promoter.py` (one poll+promote pass) or
         `python battletest_promoter.py --loop --interval 60` (continuous).
  - Library: `poll_and_promote()` from fun_doc's continuous port-worker loop
    (best-effort, non-fatal -- see maybe_promote's docstring).
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import time
import urllib.parse
from pathlib import Path

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
PROVEN_REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"
ORACLE_URL = os.environ.get("D2DBG_MCP_URL", "http://127.0.0.1:8790")
GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")

import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parent))
import conf_ladder  # noqa: E402

# Per-program image base. Was a single _D2COMMON_BASE constant, which silently
# made this module D2Common-only: a D2Client dispatcher's offset would resolve
# to a D2Common address that either names the wrong function or none at all.
IMAGE_BASES = {
    "D2Common.dll": 0x6FD50000,
    "D2Client.dll": 0x6FAB0000,
}
_D2COMMON_BASE = IMAGE_BASES["D2Common.dll"]  # back-compat for existing callers

BATTLE_MIN_HITS = int(os.environ.get(
    "FUNDOC_BATTLETEST_MIN_HITS",
    str(conf_ladder.PROMOTION_THRESHOLDS["CONF_BATTLETESTED"]["calls"])))
BATTLE_MIN_DISTINCT = int(os.environ.get(
    "FUNDOC_BATTLETEST_MIN_DISTINCT",
    str(conf_ladder.PROMOTION_THRESHOLDS["CONF_BATTLETESTED"]["distinct_inputs"])))
SHIP_MIN_HITS = int(os.environ.get(
    "FUNDOC_SHIP_MIN_HITS",
    str(conf_ladder.PROMOTION_THRESHOLDS["CONF_SHIPPED"]["calls"])))

# The full ladder, not a local four-item copy. The stale copy predated
# CONF_VETTED/CONF_SHIPPED/CONF_BLOCKED/CONF_REFUTED, so promoting here would
# have left any of those standing alongside CONF_BATTLETESTED -- silently
# breaking the mutual exclusivity the whole taxonomy depends on.
CONF_TAGS = conf_ladder.ALL_CONF_TAGS


def _http_get_json(base_url: str, path: str, timeout: int = 8) -> dict:
    u = urllib.parse.urlparse(base_url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    try:
        conn.request("GET", path)
        raw = conn.getresponse().read().decode("utf-8", "replace")
    finally:
        conn.close()
    return json.loads(raw)


def _ghidra_post(path: str, data: dict) -> dict:
    """POST to Ghidra, sending `program` as a QUERY param -- never in the body.

    @Param(value="program") defaults to ParamSource.QUERY, so a body-sourced
    program is silently IGNORED and the write lands on whatever program is
    ACTIVE. Found live 2026-07-29: this helper passed program in the body, so
    every promotion/refutation targeted the active program (D2Client.dll at the
    time) at a D2Common address -- which resolves to no function, fails, and
    was swallowed. The whole refutation path looked like a no-op.

    Same failure class as the hardcoded program="D2Common.dll" default fixed
    2026-07-27. Wrong-binary writes do not announce themselves; they just do
    nothing, somewhere else.
    """
    u = urllib.parse.urlparse(GHIDRA_HTTP)
    body = dict(data)
    program = body.pop("program", None)
    qs = ("?" + urllib.parse.urlencode({"program": program})) if program else ""
    conn = http.client.HTTPConnection(u.hostname, u.port or 8089, timeout=15)
    try:
        conn.request("POST", path + qs, body=json.dumps(body),
                      headers={"Content-Type": "application/json"})
        raw = conn.getresponse().read().decode("utf-8", "replace")
    except OSError as e:
        return {"error": f"ghidra unreachable: {e}"}
    finally:
        conn.close()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": raw[:200]}


def _set_rung(address_hex: str, rung: str, program: str, record: dict | None = None) -> dict:
    """Set one mutually-exclusive CONF_ rung, optionally with a Conf-map record."""
    others = ",".join(t for t in CONF_TAGS if t != rung)
    _ghidra_post("/remove_function_tag", {"function": address_hex, "tags": others, "program": program})
    resp = _ghidra_post("/add_function_tag",
                        {"function": address_hex, "tags": rung, "program": program})
    if record is not None:
        _ghidra_post("/set_property",
                     {"map": conf_ladder.CONF_PROPERTY_MAP, "address": address_hex,
                      "value": json.dumps(record, separators=(",", ":")),
                      "program": program})
    return resp


def _set_battletested(address_hex: str, program: str = "D2Common.dll") -> dict:
    return _set_rung(address_hex, "CONF_BATTLETESTED", program)


def _ghidra_rung(address_hex: str, program: str) -> str | None:
    """The CONF_ rung GHIDRA currently holds -- the source of truth.

    Not the registry's `conf` field. Found live 2026-07-29:
    ITEMS_GetItemDataByte45 diverged 2,620 times while holding CONF_LIVE in
    Ghidra, but had NO registry row (and Ghidra had since renamed it to
    ITEMS_GetItemDataInvPage). Trusting the mirror meant a falsified rung
    survived untouched.
    """
    u = urllib.parse.urlparse(GHIDRA_HTTP)
    conn = http.client.HTTPConnection(u.hostname, u.port or 8089, timeout=15)
    try:
        conn.request("GET", "/get_function_tags?" + urllib.parse.urlencode(
            {"function": address_hex, "program": program}))
        obj = json.loads(conn.getresponse().read().decode("utf-8", "replace"))
    except (OSError, json.JSONDecodeError):
        return None
    finally:
        conn.close()
    for t in (obj.get("tags") or []):
        if t.get("name") in CONF_TAGS:
            return t["name"]
    return None


# Shadow telemetry watermarks, keyed "<module>:<addr>". SEPARATE from
# proven_functions.jsonl on purpose: that file is the git-tracked mirror of the
# CONF PROOF axis, and writing per-poll counters for all ~103 dispatchers (most
# of them unproven) would bury the proofs in telemetry. Saturation needs
# DURABLE state though -- poll_and_promote is usually a one-shot invocation, so
# a process-local dict would reset every run and saturation could never be
# observed.
WATERMARKS = D2MOO_REPO / "conformance" / "shadow_watermarks.json"


def _load_watermarks() -> dict:
    try:
        return json.loads(WATERMARKS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_watermarks(w: dict) -> None:
    try:
        WATERMARKS.parent.mkdir(parents=True, exist_ok=True)
        WATERMARKS.write_text(json.dumps(w, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as e:
        print(f"  [promoter WARN] could not persist saturation watermarks: {e}")


def _load_registry() -> list:
    if not PROVEN_REGISTRY.exists():
        return []
    return [json.loads(l) for l in PROVEN_REGISTRY.read_text(encoding="utf-8").splitlines() if l.strip()]


def _save_registry(rows: list) -> None:
    PROVEN_REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    with open(PROVEN_REGISTRY, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


_WARNED_NO_DISTINCT: set = set()
_WARNED_DOMAIN: set = set()


def poll_and_promote(*, min_hits: int = BATTLE_MIN_HITS,
                     min_distinct: int = BATTLE_MIN_DISTINCT,
                     program: str = "D2Common.dll",
                     allow_ship: bool = False) -> dict:
    """One pass: read live dispatcher hit/divergence counters, refresh the
    registry's shadow counters on every dispatcher-active row, then either
    PROMOTE (zero divergence, volume AND input-diversity bars met) or REFUTE
    (any divergence -> CONF_REFUTED). Best-effort -- returns
    {"ok": False, "error": ...} on any connectivity problem rather than raising
    (this is meant to run unattended).

    `allow_ship` gates the terminal CONF_SHIPPED rung, which means "dispatched
    by default in the running game" -- that changes what the game executes, so
    it is opt-in rather than something an unattended poll does on its own.
    """
    try:
        disp = _http_get_json(ORACLE_URL, "/dispatchers")
    except OSError as e:
        return {"ok": False, "error": f"D2Debugger unreachable: {e}"}
    if not disp.get("ok"):
        return {"ok": False, "error": disp.get("error", "bad /dispatchers response")}

    rows = _load_registry()
    marks = _load_watermarks()
    # Keyed by ADDRESS ONLY. Was (name, address): a Ghidra rename desyncs the
    # mirror's name and the lookup silently misses, which is how a CONF_LIVE
    # function diverging 2,620 times went un-refuted. The taxonomy says it
    # outright: key by address, the name is not stable.
    def _akey(a):
        return str(a).lower().lstrip("0x").rjust(8, "0")
    by_key = {_akey(r["address"]): r for r in rows}
    promoted, refuted = [], []
    if IMAGE_BASES.get(program) is None:
        return {"ok": False, "error": f"no image base known for program {program!r}; "
                                      f"add it to IMAGE_BASES"}
    for d in disp.get("dispatchers", []):
        # Each dispatcher names its OWN patch module (D2Debugger multi-bridge).
        # `program` is only the fallback for an older oracle that emits a flat
        # list with no attribution -- applying one image base to a mixed list
        # would resolve D2Client offsets inside D2Common, which is the
        # wrong-binary failure class again.
        mod = d.get("module") or program
        base = IMAGE_BASES.get(mod)
        if base is None:
            if mod not in _WARNED_NO_DISTINCT:
                _WARNED_NO_DISTINCT.add(mod)
                print(f"  [promoter WARN] dispatcher module {mod!r} has no known image "
                      f"base -- skipping its dispatchers. Add it to IMAGE_BASES.")
            continue
        addr_hex = f"0x{base + d['offset']:x}"
        r = by_key.get(_akey(addr_hex))
        hits, divs = d.get("hits", 0), d.get("divergences", 0)
        if r is not None:
            r["shadow_hits"] = hits
            r["shadow_divergences"] = divs
            r["shadow_mode"] = d.get("modeName")
        # Distinct argument values the shadow thunk has actually seen.
        # SHIPPING_PROMOTION_PLAN: "1M calls with 3 inputs is not coverage".
        distinct = d.get("distinct_inputs")
        mkey = f"{mod}:{addr_hex}"
        if distinct is not None:
            # Watermark + session bookkeeping. Tracked for EVERY dispatcher --
            # a function with no registry row (one that reached its rung via the
            # static oracle) still needs saturation measured, which is exactly
            # the case that stranded GetItemQualityStringId.
            m = dict(marks.get(mkey, {}))

            # SESSION BOUNDARY: the patch DLL's counters are process-static, so
            # they restart at 0 on relaunch. A hit count that went DOWN is the
            # only reliable signal that this is a new game session.
            if hits < m.get("last_hits", 0):
                m["counted_this_session"] = False
                m["distinct"] = None          # force a fresh watermark below
            m["last_hits"] = hits

            # Record the hit count at which distinct last CHANGED; saturation is
            # measured from there. A NEW input also breaks any saturation this
            # session had already claimed.
            if m.get("distinct") != distinct:
                m["distinct"] = distinct
                m["at_hits"] = hits
                m["counted_this_session"] = False

            # Count this session ONCE, the first poll at which it saturates.
            if (conf_ladder.is_saturated(hits, m.get("at_hits"))
                    and not m.get("counted_this_session")):
                m["saturated_sessions"] = int(m.get("saturated_sessions", 0)) + 1
                m["counted_this_session"] = True

            marks[mkey] = m
            if r is not None:
                r["shadow_distinct_inputs"] = distinct
        # WINDOWED rate since the last epoch. A hot-reloaded fix (verify_shadow_fix /
        # --set-epoch) records the counters at fix time as shadow_epoch_*; we then
        # judge the DELTA, so a fixed function promotes on its own without a game
        # restart to clear the pre-fix (poisoned) cumulative divergences. Default
        # epoch 0/0 == lifetime totals (unchanged behavior for never-reset rows).
        eh = r.get("shadow_epoch_hits", 0) if r else 0
        ed = r.get("shadow_epoch_divergences", 0) if r else 0
        dhits, ddivs = hits - eh, divs - ed
        is_shadow = d.get("modeName") == "shadow"

        # --- DIVERGENCE -> CONF_REFUTED -------------------------------------
        # A divergence is the primary signal under shadow-first, and until now
        # it only incremented a counter: the disproved rung kept standing
        # forever. The rung was a claim; this falsifies it.
        if is_shadow and ddivs > 0:
            # Ghidra is the source of truth for the held rung; the registry may
            # lag, name-drift, or not exist for this function at all.
            held = _ghidra_rung(addr_hex, mod) or (r.get("conf") if r else None)
            demote, rung, record = conf_ladder.decide_refutation(
                held, "shadow_divergence",
                {"divergences": ddivs, "hits": dhits, "mode": d.get("modeName")})
            if demote:
                record["date"] = time.strftime("%Y-%m-%d")
                res = _set_rung(addr_hex, rung, mod, record)
                if res.get("status") == "success" or "already_present" in str(res):
                    refuted.append({"name": d["name"], "address": addr_hex,
                                    "from": held, "divergences": ddivs})
                    if r is not None:
                        r["conf"] = rung
                        r["refuted_date"] = record["date"]
                        r["refuted_from"] = record["refuted_from"]
            continue  # a diverging function is never a promotion candidate

        # NOTE: r may be None here. The registry MIRRORS Ghidra; a function can
        # legitimately hold a rung with no mirror row -- anything that reached
        # CONF_VECTORS via the static oracle never went through record_proof, so
        # it was never written. Blocking promotion on a missing mirror row would
        # permanently strand exactly those functions (found live 2026-07-29:
        # GetItemQualityStringId, CONF_VECTORS in Ghidra, 0 registry rows). The
        # row is CREATED on promotion below instead.

        # --- PROMOTION ------------------------------------------------------
        # Diversity is required, not optional. `distinct_inputs` absent means an
        # older D2Debugger without the sampler -- FAIL CLOSED rather than
        # promote on volume alone, which is the evidence the plan calls
        # worthless. Loud, so a missing sampler surfaces instead of silently
        # halting all promotion.
        if is_shadow and ddivs == 0 and dhits >= min_hits and not (r or {}).get("weak_proof"):  # noqa: E501
            argc = d.get("arg_count")
            # argc -1 == the coord family, which predates the sampler and has no
            # per-entry storage; distinct is reported as 0 there but means
            # "unknown", not "one input". Both that and a missing field are
            # NO DIVERSITY DATA -> fail closed.
            if distinct is None or argc is None or argc < 0:
                if d["name"] not in _WARNED_NO_DISTINCT:
                    _WARNED_NO_DISTINCT.add(d["name"])
                    print(f"  [promoter WARN] {d['name']}: {dhits} clean hits but no "
                          f"input-diversity data (distinct_inputs={distinct}, "
                          f"arg_count={argc}) -- the dispatcher predates the sampler. "
                          f"NOT promoting on volume alone.")
                continue
            target = ("CONF_SHIPPED" if (allow_ship and dhits >= SHIP_MIN_HITS)
                      else "CONF_BATTLETESTED")
            # Diversity gate via the SHARED rule in conf_ladder -- not a second
            # inline copy. (An inline copy of the CONF_ tag list in this very
            # module went stale and silently broke mutual exclusivity; the same
            # drift is what this avoids.)
            _m = marks.get(mkey, {})
            sat_sessions = int(_m.get("saturated_sessions", 0))
            saturated = (conf_ladder.is_saturated(hits, _m.get("at_hits"))
                         and conf_ladder.saturation_qualifies(sat_sessions))
            floor = conf_ladder.effective_distinct_floor(target, argc, saturated)
            if min_distinct != BATTLE_MIN_DISTINCT and not saturated:
                floor = min(floor, min_distinct)   # honor an explicit override
            # Emit BEFORE the guard below: a function that saturated but is one
            # session short would otherwise stall in complete silence -- the
            # exact failure mode this whole diagnostic exists to prevent.
            if distinct < BATTLE_MIN_DISTINCT and d["name"] not in _WARNED_DOMAIN:
                _WARNED_DOMAIN.add(d["name"])
                if saturated:
                    print(f"  [promoter] {d['name']}: input space SATURATED at "
                          f"{distinct} distinct across {sat_sessions} sessions "
                          f"-- diversity floor waived; that is 100% of reachable "
                          f"coverage, not a relaxed bar.")
                elif conf_ladder.is_saturated(hits, _m.get("at_hits")):
                    print(f"  [promoter] {d['name']}: saturated at {distinct} distinct "
                          f"but only in {sat_sessions}/"
                          f"{conf_ladder.REQUIRED_SATURATED_SESSIONS} session(s) -- "
                          f"needs another game session to rule out state-dependent "
                          f"inputs. NOT promoting.")
            if distinct < floor:
                continue  # volume without diversity proves little
            if saturated and distinct < BATTLE_MIN_DISTINCT and d["name"] not in _WARNED_DOMAIN:
                _WARNED_DOMAIN.add(d["name"])
                print(f"  [promoter] {d['name']}: input space SATURATED at {distinct} "
                      f"distinct ({hits - (r or {}).get('shadow_distinct_at_hits', 0)} "
                      f"calls with no new input) -- diversity floor waived; that is "
                      f"100% of reachable coverage, not a relaxed bar.")
            held = _ghidra_rung(addr_hex, mod) or (r or {}).get("conf")
            if conf_ladder.rung_strength(target) <= conf_ladder.rung_strength(held):
                continue
            record = {
                "conf": target, "method": "shadow", "hits": dhits,
                "distinct_inputs": distinct, "date": time.strftime("%Y-%m-%d")}
            if saturated and distinct < BATTLE_MIN_DISTINCT:
                # Make the rung's ACTUAL basis auditable: this promoted on
                # exhausted-input-space evidence, not on meeting the flat floor.
                # Saturation within one session is not saturation globally.
                record["diversity"] = (
                    f"saturated@{distinct} across {sat_sessions} sessions "
                    f"({hits - _m.get('at_hits', 0)} calls with no new input "
                    f"in the latest)")
            tag_result = _set_rung(addr_hex, target, mod, record)
            if tag_result.get("status") == "success" or "already_present" in str(tag_result):
                if r is None:
                    # Materialise the missing mirror row (append-only registry).
                    r = {"name": d["name"], "address": addr_hex, "program": mod,
                         "callconv": None, "ret": None,
                         "date": time.strftime("%Y-%m-%d"),
                         "origin": "shadow promotion; no prior record_proof row "
                                   "(reached its previous rung via the static oracle)"}
                    rows.append(r)
                    by_key[_akey(addr_hex)] = r
                r["conf"] = target
                r["battletested_date"] = time.strftime("%Y-%m-%d")
                r["shadow_distinct_inputs"] = distinct
                if eh or ed:
                    r["battletested_windowed"] = f"{dhits} clean hits since epoch (post-fix)"
                promoted.append({"name": d["name"], "hits": dhits,
                                 "distinct": distinct, "rung": target})

    _save_registry(rows)
    _save_watermarks(marks)
    return {"ok": True, "promoted": promoted, "refuted": refuted,
            "dispatchers_seen": len(disp.get("dispatchers", []))}


def set_shadow_epoch(name: str, *, program: str = "D2Common.dll") -> dict:
    """Record the CURRENT live (hits, divergences) as this function's epoch baseline
    in the registry, so poll_and_promote judges only NEW calls. Call right after a
    hot-reloaded reimpl fix -- the pre-fix cumulative divergences are poisoned; the
    epoch draws a clean line so a correct fix promotes without a game restart."""
    try:
        disp = _http_get_json(ORACLE_URL, "/dispatchers")
    except OSError as e:
        return {"ok": False, "error": f"D2Debugger unreachable: {e}"}
    cur = None
    for d in disp.get("dispatchers", []):
        if d["name"] == name:
            cur = d
            break
    if cur is None:
        return {"ok": False, "error": f"{name} is not a live dispatcher"}
    rows = _load_registry()
    marks = _load_watermarks()
    hit = False
    for r in rows:
        if r.get("name") == name:
            r["shadow_epoch_hits"] = cur.get("hits", 0)
            r["shadow_epoch_divergences"] = cur.get("divergences", 0)
            r["shadow_epoch_date"] = time.strftime("%Y-%m-%d")
            hit = True
    if not hit:
        return {"ok": False, "error": f"{name} not in registry"}
    _save_registry(rows)
    return {"ok": True, "name": name, "epoch_hits": cur.get("hits", 0),
            "epoch_divergences": cur.get("divergences", 0)}


def loop(interval: int = 60, *, stop_flag=None) -> None:
    """Continuous polling loop. `stop_flag` (optional) is anything with
    .is_set() -- lets a caller (e.g. fun-doc's WorkerManager) interrupt it the
    same way the existing functions-mode worker loop does."""
    while True:
        if stop_flag is not None and stop_flag.is_set():
            return
        result = poll_and_promote()
        if result.get("promoted"):
            print(f"[battletest_promoter] promoted: {result['promoted']}")
        elif not result.get("ok"):
            print(f"[battletest_promoter] {result.get('error')}")
        for _ in range(interval):
            if stop_flag is not None and stop_flag.is_set():
                return
            time.sleep(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="poll continuously instead of once")
    ap.add_argument("--interval", type=int, default=60, help="seconds between polls in --loop mode")
    ap.add_argument("--min-hits", type=int, default=BATTLE_MIN_HITS)
    ap.add_argument("--set-epoch", metavar="NAME",
                    help="record NAME's current shadow counters as its epoch baseline "
                         "(after a hot-reloaded fix -- promote on NEW clean calls, no restart)")
    args = ap.parse_args()
    if args.set_epoch:
        print(json.dumps(set_shadow_epoch(args.set_epoch), indent=2))
    elif args.loop:
        loop(args.interval)
    else:
        print(json.dumps(poll_and_promote(min_hits=args.min_hits), indent=2))

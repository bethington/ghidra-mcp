"""batch_picker.py -- classify-aware batch selection for prove_doc runs.

The 2026-07-12 batch test showed WHY batches under-deliver: port_targets' planner
partitions on static ABI alone ("PROVABLE NOW"), but the worker's own
classify_function has final say on routing -- anything it calls "stateful" is
skipped in ~1s with no prove attempt, and the delegate translator almost never
fires. 13/19 batch slots died that way. A batch slot is only worth burning on a
function BOTH filters accept.

This picker sweeps the unproven in-scope pool and keeps a candidate only if:
  1. name is unique in the binary            (the proof registry is keyed by name;
                                              duplicate names would collide)
  2. not library/runtime-looking             (oracle-crash risk, same rule as
                                              port_targets)
  3. currently DOC_DRAFT with NO conf rung   (the batch must demonstrate the
                                              draft -> verified transition)
  4. classify_function routes it to a LIVE prover -- the filter the planner
     was missing:
       global_leaf  -> process_global_leaf_live   (named-global resolver path)
       shadow_leaf  -> process_handle_leaf_live   (live captured-object path;
                       only when the planner saw NO abort hazard -- abort-class
                       shadow leaves are deferred by the worker itself)
     ("leaf" is deliberately NOT accepted: it routes to the STATIC OpenD2
      pipeline, which cannot earn CONF_LIVE/DOC_VERIFIED through prove_doc.
      "stateful" is skipped by the worker outright.)
  5. planner lane is provable_now            (stack-slot ABI; excludes
                                              register-explicit marshal faults
                                              and missing resolver globals).
     Exception: a GLOBAL_LEAF may instead be abort_class-only -- the
     global-leaf path clamps abort vectors in-envelope
     (abi_static.clamp_abort_vectors), so sparse-switch aborts are safe there.
     shadow_unreachable_risk never disqualifies (it only predicts no
     BATTLETEST; CONF_LIVE via the direct oracle is unaffected).

Usage (from fun-doc/, venv active; Ghidra live on :8089):
    python batch_picker.py --count 10 --out picks.json
    python batch_picker.py --count 10 --pool-limit 400 -v
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import port_pipeline as pp
import port_targets as pt

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
TRIAGE_BACKLOG = D2MOO_REPO / "conformance" / "profiler" / "triage_backlog.json"
REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"
PROGRAM_PATH = os.environ.get("FUNDOC_GHIDRA_PROGRAM", "/Mods/PD2-S12/D2Common.dll")

# game-subsystem functions -- the population the live prover handles today.
# The verb is NOT required: classify_function is the real routing gate; the
# prefix just keeps obvious non-game/library shapes out of the scan.
_GETTER_RE = re.compile(
    r"^(DATATBLS|SKILLS|MONSTER|ITEMS|UNITS|UNIT|PATH|STAT|MISSILES|INVENTORY|"
    r"OBJECTS|COLLISION|DUNGEON|COMMON|SEED|DRLG|QUESTS|WAYPOINTS)_")

# lanes that do NOT disqualify a pick. shadow_unreachable_risk only means the fn
# won't BATTLETEST (0 internal callers); CONF_LIVE via the direct oracle is
# unaffected -- DATATBLS_GetObjectDataPtr carried this lane and fully promoted.
_TOLERATED_LANES = {"shadow_unreachable_risk"}

_RUNG_TAGS = ("DOC_DRAFT", "DOC_REVIEWED", "DOC_VERIFIED",
              "CONF_LIVE", "CONF_BATTLETESTED", "CONF_REGRESSION",
              "CONF_VECTORS", "CONF_DRAFT")


def _proven_names() -> set:
    try:
        rows = [json.loads(l) for l in REGISTRY.read_text(encoding="utf-8").splitlines()
                if l.strip()]
    except OSError:
        return set()
    return {r.get("name") for r in rows}


def _tag_addr_set(tag: str) -> set:
    import urllib.request, urllib.parse
    url = (pp.GHIDRA_HTTP + "/search_functions_by_tag?" +
           urllib.parse.urlencode({"tag": tag, "program": PROGRAM_PATH}))
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except OSError:
        return set()
    return {str(f.get("address", "")).lower().removeprefix("0x")
            for f in (data.get("functions") or [])}


def candidate_pool(pool_limit: int) -> list[dict]:
    """Unproven, unique-name, getter-shaped, DOC_DRAFT-only functions, in
    triage (address) order."""
    t = json.loads(TRIAGE_BACKLOG.read_text(encoding="utf-8"))
    # entries carrying 'scope' were flagged by triage.py --scrub-backlog as library/
    # trivial leaks; they stay in the file to keep indices stable but are not targets
    in_scope = [f for f in (t.get("in_scope") or []) if not f.get("scope")]
    proven = _proven_names()

    name_counts = {}
    for f in in_scope:
        name_counts[f["name"]] = name_counts.get(f["name"], 0) + 1

    tag_sets = {tag: _tag_addr_set(tag) for tag in _RUNG_TAGS}

    pool = []
    for f in in_scope:
        name, addr = f["name"], str(f["address"]).lower()
        bare = addr.removeprefix("0x")
        if name in proven or name_counts[name] > 1:
            continue
        if not _GETTER_RE.match(name):
            continue
        if pp._looks_like_library_or_runtime(name):
            continue
        rungs = [tag for tag in _RUNG_TAGS if bare in tag_sets[tag]]
        if rungs != ["DOC_DRAFT"]:
            continue
        pool.append({"name": name, "address": addr})
        if len(pool) >= pool_limit:
            break
    return pool


def pick(count: int, pool_limit: int = 400, verbose: bool = False,
         log=print) -> list[dict]:
    """Scan the pool in order; keep candidates that pass classify + planner.
    Stops as soon as `count` picks are accumulated."""
    pool = candidate_pool(pool_limit)
    log(f"[pick] pool: {len(pool)} unproven unique-name DOC_DRAFT candidates")
    picks, scanned, why = [], 0, {}

    def _skip(name, reason, detail=""):
        why[reason] = why.get(reason, 0) + 1
        if verbose:
            log(f"  [skip] {name}: {reason}{' ' + detail if detail else ''}")

    for row in pool:
        if len(picks) >= count:
            break
        scanned += 1
        name, addr = row["name"], row["address"]
        dec = pp._ghidra_get("decompile_function",
                             params={"address": addr, "program": PROGRAM_PATH})
        try:
            cls = pp.classify_function(str(dec))
        except Exception as e:
            _skip(name, "classify_error", str(e))
            continue
        if cls not in ("global_leaf", "shadow_leaf"):
            _skip(name, f"classify={cls}")
            continue
        plan = pt.plan_targets([row], wire_globals=False)
        lanes = {lane for lane, items in plan.items()
                 if isinstance(items, list) and any(i["name"] == name for i in items)}
        blocking = lanes - _TOLERATED_LANES
        ok = (blocking == {"provable_now"}
              # global-leaf abort-class is safe: its vector path clamps in-envelope
              or (cls == "global_leaf" and blocking == {"abort_class"}))
        if not ok:
            _skip(name, f"lanes[{cls}]", str(sorted(lanes)))
            continue
        picks.append({"name": name, "address": addr, "classify": cls,
                      "lanes": sorted(lanes)})
        log(f"  [PICK {len(picks)}/{count}] {name} @ {addr}  {cls}  lanes={sorted(lanes)}")
    log(f"[pick] scanned {scanned}/{len(pool)}, picked {len(picks)}/{count}")
    if why:
        log("[pick] rejections: " + ", ".join(f"{k}={v}" for k, v in
                                              sorted(why.items(), key=lambda kv: -kv[1])))
    return picks


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--pool-limit", type=int, default=400,
                    help="max pool entries to consider (triage order)")
    ap.add_argument("--out", default=None, help="write picks JSON here")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log every rejection, not just picks")
    args = ap.parse_args()
    picks = pick(args.count, pool_limit=args.pool_limit, verbose=args.verbose)
    if args.out:
        Path(args.out).write_text(json.dumps(picks, indent=2) + "\n", encoding="utf-8")
        print(f"[pick] written to {args.out}")
    return 0 if len(picks) >= args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Populate `functions_workflow.callees` so bottom-up ordering has something to order.

WHY. `select_candidates` sorts by `_callee_readiness` -- "functions whose
callees are all documented sort ahead of functions with undocumented
dependencies" -- and that ordering was inert for most of the corpus because the
data it reads was never written.

MEASURED 2026-08-06: 10,904 of 63,401 functions (17.2%) have a callee list.
D2Client (3,679), D2Common (2,507), ProjectDiablo (15,248), glide3x (10,221)
and libcrypto (6,996) have ZERO. Until 802b2d4 every one of those returned
readiness 1.0 -- maximum, the value a trivially-ready leaf gets -- so the sort
ordered nothing. That fix made the gap HONEST (unknown now sorts between ready
and blocked); this script closes it.

EDGES COME FROM REFERENCES, not `/get_full_call_graph`. That endpoint is
measurably incomplete: `__CxxFrameHandler3` has 7 UNCONDITIONAL_CALL xrefs and
reports zero call-graph edges. `call_graph` is the single shared builder --
scope analysis and documentation ordering ask the same question and must not
have two answers.

WRITES, and only with --apply:
    functions_workflow.callees      list of callee addresses, bare lower hex
    functions_workflow.is_leaf      True only when the list is EMPTY

An empty list is written deliberately and is not the same as leaving the field
NULL: [] means "scanned, genuinely calls nothing", NULL means "nobody looked".
Collapsing those is the defect this exists to repair, so it must not be
recreated by skipping the leaves.

Report-first with a dry-run default, like every other sweep here.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Set

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import call_graph as cg                                          # noqa: E402
import fun_doc as fd                                             # noqa: E402


def _norm(addr: str) -> str:
    """Bare lowercase hex. SQL stores it that way; the xref helpers return
    0x-prefixed, and getting this wrong makes the whole thing a silent no-op --
    the same trap backfill_library_code documents and tests for."""
    return str(addr or "").lower().replace("0x", "").lstrip("0").rjust(8, "0")


def callees_for_program(program: str, addresses: List[str]) -> Dict[str, Set[str]]:
    """{address -> set of callee addresses}, both normalised.

    Addresses go DOWN 0x-prefixed. `library_scope._bulk_xrefs_to` strips the
    first two characters (`a[2:]`) rather than parsing, so a bare address is
    silently mangled -- `6fbf1000` becomes `bf1000`, every lookup misses, and
    the result is an empty graph that looks exactly like "this binary has no
    references". Measured here on D2Net.dll: 174 functions, zero edges, and the
    EmptyGraph guard was the only thing that stopped it from writing `[]` over
    the whole binary.
    """
    addresses = ["0x" + _norm(a) for a in addresses]
    referrers = cg.function_referrers(program, addresses)
    callees = cg.invert(referrers)
    known = {_norm(a) for a in addresses}
    out: Dict[str, Set[str]] = {}
    for caller, cs in callees.items():
        c = _norm(caller)
        if c in known:
            out[c] = {_norm(x) for x in cs}
    return out


def plan(program: str, state=None) -> dict:
    """What would change, without changing it."""
    state = state or fd.load_state()
    funcs = state.get("functions", {})
    rows = {k: f for k, f in funcs.items()
            if (f.get("program") or "") == program}
    if not rows:
        return {"program": program, "error": "no rows in state for this program"}

    addresses = [f["address"] for f in rows.values()]
    try:
        edges = callees_for_program(program, addresses)
    except cg.EmptyGraph as exc:
        # An empty graph is not "this binary has no calls" -- it is a failed
        # read, and writing [] everywhere from it would mark the whole binary
        # as leaves. Refuse.
        return {"program": program, "error": str(exc)}

    already = missing = leaves = 0
    updates = {}
    for key, f in rows.items():
        addr = _norm(f["address"])
        cs = sorted(edges.get(addr, set()))
        if f.get("callees") is not None:
            already += 1
            continue
        missing += 1
        if not cs:
            leaves += 1
        updates[key] = cs
    return {"program": program, "rows": len(rows), "already_populated": already,
            "would_write": missing, "of_which_leaves": leaves,
            "updates": updates}


def apply_plan(p: dict) -> int:
    state = fd.load_state()
    funcs = state.get("functions", {})
    written = 0
    for key, cs in (p.get("updates") or {}).items():
        f = funcs.get(key)
        if f is None:
            continue
        # `callees` ONLY. An empty list here means "calls nothing else IN THIS
        # PROGRAM" -- calls to imports and other DLLs are filtered out, because
        # they are not things this corpus can document first. That is the right
        # input for ordering, but it is NOT the same claim as "this function is
        # a leaf", and writing is_leaf from it would assert something stronger
        # than was measured. select_candidates derives its own is_leaf from
        # `callees` anyway, so there is nothing to gain by overreaching.
        f["callees"] = cs
        fd.update_function_state(key, f)
        written += 1
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--program", action="append", required=True,
                    help="program path, repeatable")
    ap.add_argument("--apply", action="store_true",
                    help="write; omit for a dry run")
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    state = fd.load_state()
    reports = []
    for program in args.program:
        p = plan(program, state)
        if p.get("error"):
            print(f"  !! {program}: {p['error']}")
            reports.append({k: v for k, v in p.items() if k != "updates"})
            continue
        print(f"  {program}: {p['rows']} rows | already {p['already_populated']} "
              f"| would write {p['would_write']} (of which {p['of_which_leaves']} "
              f"genuine leaves)")
        if args.apply:
            n = apply_plan(p)
            print(f"     wrote {n}")
        reports.append({k: v for k, v in p.items() if k != "updates"})

    if not args.apply:
        print("\nDRY RUN -- nothing written. Re-run with --apply.")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(reports, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

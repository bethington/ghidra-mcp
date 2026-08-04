"""Backfill the SQL `library_code` flag from Ghidra's durable LIB_* function tags.

WHY THIS EXISTS

`library_code` in `functions_workflow` is a DENORMALIZED CACHE of the LIB_*
Ghidra tag. The tag is the durable signal -- it lives on the address and
survives renaming -- and `refresh_candidate_scores` re-syncs the column from it
(see `_lib_tagged_addrs`). But that sync only touches functions the refresh
pass actually visits, so a binary tagged AFTER its last scan keeps a stale
column forever.

Measured 2026-08-04 on PD2_EXT.dll: Ghidra held 271 LIB_CRT tags while all 463
SQL rows said `library_code = 0`. The selector's `skip_library_code` reads the
COLUMN, so those 271 CRT functions stayed selectable and ~430 of the binary's
469 functions were documented as though they were mod code. The tags were
applied by the 2026-08-02/03 crt_sweep work; the binary's last scan was
2026-04-26.

This is a cache-coherence fix, not a new signal: it copies what Ghidra already
knows into the column the selector reads.

REPORT-FIRST, dry-run default -- same contract as crt_sweep.py and
audit_evicted_globals.py. `--apply` writes ONLY the `library_code` /
`library_code_at` / `library_code_reasons` columns, and only ever in the
direction Ghidra's tags support.

USAGE

    python fun-doc/scripts/backfill_library_code.py --folder /Mods/PD2-S12
    python fun-doc/scripts/backfill_library_code.py --program /Mods/PD2-S12/PD2_EXT.dll
    python fun-doc/scripts/backfill_library_code.py --folder /Mods/PD2-S12 --apply
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import conformance_dashboard as cd                              # noqa: E402
import fun_doc as fd                                            # noqa: E402

REASON = "LIB_* Ghidra tag (durable)"


def _bare(addr: str) -> str:
    """SQL stores addresses as bare lowercase hex; the tag readers return 0x-prefixed."""
    a = str(addr).lower()
    return a[2:] if a.startswith("0x") else a


def plan_for_program(conn, program: str) -> dict:
    """What would change for one binary. No writes."""
    tagged = {_bare(a) for a in fd._lib_tagged_addrs(program)}
    rows = conn.execute(
        "select address, name, library_code from functions_workflow where program_path = ?",
        (program,),
    ).fetchall()
    by_addr = {_bare(r[0]): (r[1], r[2]) for r in rows}

    to_set, to_clear, orphan_tags = [], [], []
    for addr, (name, flag) in by_addr.items():
        if addr in tagged and not flag:
            to_set.append((addr, name))
        elif addr not in tagged and flag:
            # The column claims library code with no tag backing it. Left ALONE:
            # the name-based detector also writes this column, and clearing its
            # verdict here would silently re-open functions it excluded on
            # evidence this script cannot see.
            to_clear.append((addr, name))
    orphan_tags = sorted(tagged - set(by_addr))

    return {
        "program": program,
        "sql_rows": len(rows),
        "ghidra_tags": len(tagged),
        "already_correct": sum(1 for a, (n, f) in by_addr.items() if (a in tagged) == bool(f)),
        "to_set": to_set,
        "untagged_but_flagged": to_clear,
        "tagged_not_in_sql": orphan_tags,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--program", help="single program path")
    g.add_argument("--folder", help="project folder prefix, e.g. /Mods/PD2-S12")
    ap.add_argument("--apply", action="store_true",
                    help="write library_code=1 for tagged functions. Never clears.")
    ap.add_argument("--out", help="write the JSON report here")
    args = ap.parse_args()

    import sqlite3
    db = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state.db")
    if not os.path.exists(db):
        print(f"no sqlite store at {db}; this script only supports the sqlite backend",
              file=sys.stderr)
        return 2
    conn = sqlite3.connect(db)

    if args.program:
        programs = [args.program]
    else:
        prefix = args.folder.rstrip("/") + "/"
        programs = [b["path"] for b in cd.list_binaries()["binaries"]
                    if b["path"].startswith(prefix)]
    if not programs:
        print("no programs matched", file=sys.stderr)
        return 2

    report, tot = [], Counter()
    print(f"{'binary':<26} {'sql':>6} {'tags':>6} {'to set':>7} {'ok':>7}")
    for p in programs:
        r = plan_for_program(conn, p)
        report.append(r)
        tot["sql"] += r["sql_rows"]
        tot["tags"] += r["ghidra_tags"]
        tot["set"] += len(r["to_set"])
        tot["orphan"] += len(r["tagged_not_in_sql"])
        tot["flagged_untagged"] += len(r["untagged_but_flagged"])
        print(f"{p.split('/')[-1]:<26} {r['sql_rows']:>6} {r['ghidra_tags']:>6} "
              f"{len(r['to_set']):>7} {r['already_correct']:>7}")

    print()
    print(f"TOTAL  sql_rows={tot['sql']}  ghidra_tags={tot['tags']}  "
          f"would set library_code=1 on {tot['set']}")
    if tot["orphan"]:
        print(f"  tagged in Ghidra but absent from SQL: {tot['orphan']} "
              f"(never scanned; a scan will pick them up)")
    if tot["flagged_untagged"]:
        print(f"  flagged in SQL with no tag: {tot['flagged_untagged']} "
              f"(LEFT ALONE -- the name-based detector also writes this column)")

    if args.apply:
        stamp = datetime.now().isoformat()
        n = 0
        for r in report:
            for addr, _name in r["to_set"]:
                conn.execute(
                    "update functions_workflow set library_code = 1, library_code_at = ?, "
                    "library_code_reasons = ? where program_path = ? and address = ?",
                    (stamp, json.dumps([REASON]), r["program"], addr))
                n += 1
        conn.commit()
        print(f"\nAPPLIED: library_code=1 on {n} function(s). "
              f"The selector's skip_library_code will now exclude them.")
    else:
        print("\n(dry run -- re-run with --apply to write the column)")

    out = args.out or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "library_code_backfill.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"report -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

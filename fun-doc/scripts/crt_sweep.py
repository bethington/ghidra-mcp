"""Corpus sweep: find every function that is literally VS2003/VC6 library code.

Report-first with a dry-run default, like `falsify_sweep.py` and
`cross_version_disagreement.py` before it -- read the JSON, then `--apply`.

WHAT IT WRITES (only with --apply, and only through crt_identify.sync_to_ghidra)

    always      LIB_CRT function tag + a durable "CRT Identify" bookmark
    FUN_xxx     the real library name, because nothing is lost by taking it
    documented  NOTHING, unless --rename-documented

That last bucket is the interesting one and it is deliberately manual. On
D2Common it contains functions like `DispatchExtendedPrecisionFloatOperation`
(1,183 bytes, actually `__adj_fdiv_r`) and `LOG_ReleaseCriticalSectionByIndex`
(actually `__unlock`) -- real documentation, written by a model, describing CRT
code as though it were game logic. Correcting those is valuable and is exactly
the kind of bulk rename that deserves a human reading the list first.

USAGE

    python fun-doc/scripts/crt_sweep.py --folder /Mods/PD2-S12
    python fun-doc/scripts/crt_sweep.py --program /Mods/PD2-S12/D2Common.dll
    python fun-doc/scripts/crt_sweep.py --folder /Mods/PD2-S12 --apply
    python fun-doc/scripts/crt_sweep.py --program ... --apply --rename-documented
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crt_identify as ci                                       # noqa: E402


def _get(path: str, **params) -> dict:
    url = f"{ci.GHIDRA_URL}{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=180) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def programs_under(folder: str) -> list:
    info = _get("/mcp/instance_info")
    pref = folder.rstrip("/") + "/"
    return sorted(p["path"] for p in info.get("programs", [])
                  if str(p.get("path", "")).startswith(pref))


def classify(match: ci.Match) -> str:
    """Which bucket a match falls in -- drives both the report and the writes."""
    if match.ambiguous:
        return "ambiguous"
    if match.weak:
        return "weak_evidence"
    if not match.confident_name:
        return "too_short"
    if ci._canon(match.current_name) == ci._canon(match.lib_name or ""):
        return "already_correct"
    if ci.is_default_name(match.current_name):
        return "default_named"
    return "documented_disagrees"


def sweep_program(program: str, index: ci.LibraryIndex, apply: bool,
                  rename_documented: bool) -> dict:
    try:
        matches = ci.identify_program(program, index=index)
    except Exception as exc:                                    # noqa: BLE001
        print(f"  {program}: ERROR {str(exc)[:160]}")
        return {"program": program, "error": str(exc)[:400], "matches": []}

    buckets = Counter(classify(m) for m in matches)
    rows, writes = [], Counter()
    for m in matches:
        bucket = classify(m)
        row = {"address": m.address, "current_name": m.current_name,
               "lib_name": m.lib_name, "size": m.size, "obj": m.obj,
               "lib": m.lib, "bucket": bucket,
               "candidates": m.candidates if m.ambiguous else None}
        if apply:
            res = ci.sync_to_ghidra(
                m, apply_name=True,
                rename_documented=rename_documented)
            row["write"] = res
            writes["tagged"] += int(bool(res.get("tagged")))
            writes["bookmarked"] += int(bool(res.get("bookmarked")))
            writes["renamed"] += int(bool(res.get("renamed")))
            if res.get("error"):
                # Loud, never silent -- a write-back that fails quietly is how
                # the wrong-binary CONF_ bug survived for weeks.
                print(f"    ! write failed {m.address} {m.current_name}: "
                      f"{res['error']}")
        rows.append(row)

    name = program.rsplit("/", 1)[-1]
    print(f"  {name:28} {len(matches):5} matched   "
          f"correct={buckets['already_correct']:4} "
          f"FUN_={buckets['default_named']:3} "
          f"disagree={buckets['documented_disagrees']:3} "
          f"ambig={buckets['ambiguous']:3} "
          f"weak={buckets['weak_evidence']:3}"
          + (f"   [wrote {writes['tagged']}t/{writes['bookmarked']}b/"
             f"{writes['renamed']}r]" if apply else ""))
    return {"program": program, "matched": len(matches),
            "buckets": dict(buckets), "writes": dict(writes), "matches": rows}


def coverage_report(results: list, roots: list) -> None:
    """Which binaries could we possibly have matched, and how much did we?

    A low match count means one of two completely different things, and without
    this table they are indistinguishable: either the binary really is mostly
    non-library code, or it was built by a toolchain whose runtime we do not
    hold. Measured on PD2-S12, the split is stark -- the VS2003 binaries land at
    20-48% while everything built by a modern toolchain sits at 0-2%, which is
    a statement about our library collection, not about those binaries.
    """
    print(f"\n{'='*78}\nCOVERAGE -- what could have matched, and what did\n")
    print(f"  {'binary':22}{'funcs':>7}{'lib-id':>8}{'%':>7}  toolchain (Rich header)")
    print("  " + "-" * 74)
    rows = []
    for r in results:
        name = r["program"].rsplit("/", 1)[-1]
        try:
            total = len(_get("/list_functions", program=r["program"],
                             limit=100000).get("functions", []))
        except Exception:                                       # noqa: BLE001
            total = 0
        path = next((os.path.join(root, name) for root in roots
                     if os.path.exists(os.path.join(root, name))), None)
        if path:
            rich = ci.rich_toolchain(path)
            tc = (rich or {}).get("toolchain") or "no Rich header (not MSVC-linked)"
        else:
            tc = "<file not on disk -- cannot tell>"
        rows.append((name, total, r.get("matched", 0), tc))

    tn = tm = 0
    for name, total, matched, tc in sorted(rows, key=lambda x: -x[1]):
        tn += total
        tm += matched
        pct = f"{100.0 * matched / total:.1f}" if total else "-"
        print(f"  {name:22}{total:>7}{matched:>8}{pct:>7}  {tc}")
    print("  " + "-" * 74)
    print(f"  {'TOTAL':22}{tn:>7}{tm:>8}"
          f"{(100.0 * tm / tn if tn else 0):>6.1f}%")
    print("\n  A binary with a toolchain we hold no library for CANNOT match,\n"
          "  so its low number says nothing about how much of it is game code.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--program", help="single program path")
    g.add_argument("--folder", help="all programs under this project folder")
    ap.add_argument("--apply", action="store_true",
                    help="write tags/bookmarks/names (default: dry run)")
    ap.add_argument("--rename-documented", action="store_true",
                    help="also rename functions that already carry real "
                         "documentation (review the report first)")
    ap.add_argument("--report", default=None, help="write JSON report here")
    ap.add_argument("--rich-root", action="append", default=None,
                    help="directory holding the binaries on disk; enables the "
                         "Rich-header coverage report, which says which "
                         "toolchain built each binary and therefore whether we "
                         "hold a library that COULD match it. Repeatable.")
    ap.add_argument("--libs", nargs="*", default=None,
                    help="override the static libraries to index")
    args = ap.parse_args(argv)

    if args.rename_documented and not args.apply:
        print("--rename-documented has no effect without --apply")

    index = ci.load_index(args.libs)
    print(f"index: {index.count} library functions from "
          f"{len(index.libs)} librar{'y' if len(index.libs)==1 else 'ies'} "
          f"({index.rejected} rejected: fewer than "
          f"{ci.MIN_INFORMATIVE_BYTES} bytes survive masking)")
    for lib in index.libs:
        print(f"        {lib}")
    if not index.count:
        print("EMPTY INDEX -- no libraries found. Nothing can match.")
        return 2

    targets = [args.program] if args.program else programs_under(args.folder)
    if not targets:
        print(f"no programs found under {args.folder}")
        return 2
    print(f"\n{'APPLYING' if args.apply else 'DRY RUN'} over "
          f"{len(targets)} program(s)\n")

    results = [sweep_program(p, index, args.apply, args.rename_documented)
               for p in targets]

    tot = Counter()
    for r in results:
        for k, v in (r.get("buckets") or {}).items():
            tot[k] += v
    print(f"\n{'='*70}\ntotal matched: {sum(tot.values())}")
    for k in ("already_correct", "default_named", "documented_disagrees",
              "ambiguous", "weak_evidence", "too_short"):
        print(f"  {k:22} {tot[k]:6}")

    if args.rich_root:
        coverage_report(results, args.rich_root)

    if not args.apply:
        print("\nDRY RUN -- nothing written. Re-run with --apply.")
        if tot["documented_disagrees"]:
            print(f"{tot['documented_disagrees']} function(s) carry real "
                  f"documentation that disagrees with the library name.\n"
                  f"Review those in the report before --rename-documented.")

    out = args.report or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "crt_sweep_report.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"applied": args.apply,
                   "rename_documented": args.rename_documented,
                   "index_size": index.count, "libs": index.libs,
                   "totals": dict(tot), "programs": results}, fh, indent=1)
    print(f"\nreport: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

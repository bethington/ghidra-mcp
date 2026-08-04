"""Corpus sweep: apply BSim identification verdicts, report-first.

Report-first with a dry-run default, like `crt_sweep.py`, `falsify_sweep.py` and
`cross_version_disagreement.py` before it -- read the JSON, then `--apply`.

WHAT IT WRITES (only with --apply, and only through bsim_identify.sync_to_ghidra)

    writable     a LIB_* tag + a durable "BSim Identify" bookmark
    FUN_xxx      the reference name, because nothing is lost by taking it
    documented   NOTHING, unless --rename-documented

WHAT IT REFUSES TO WRITE, and why each bucket exists

    ambiguous         the top similarity tier carried more than one distinct
                      name. This is the rule that moves precision from ~86% to
                      1.0000; without it OpenSSL's `*_it` accessors all claim
                      each other.
    unnamed_top       the closest reference function has no name to give.
    below_threshold   under sim 0.95 or significance 30 -- the calibrated
                      floors, set by negative controls (see bsim_identify).
    too_short         under 16 body bytes; degenerate bodies match anything.

None of those earn a tag. A `LIB_*` tag makes the fun-doc selector skip a
function PERMANENTLY, so an unidentified function must not get one.

This sweep does NOT query Ghidra for similarity -- it consumes the JSONL dump
produced by `scripts/bsim/Analyze_BSimIdentifyDump.java`. Produce one first:

    analyzeHeadless <proj> <name> -process D2Common.dll -noanalysis \
      -scriptPath scripts\\bsim -postScript Analyze_BSimIdentifyDump.java \
      file:/C:/bsim/refindex C:/tmp/d2common.jsonl 10 0.3 0.0 500

USAGE

    python fun-doc/scripts/bsim_sweep.py --dump C:/tmp/d2common.jsonl \
        --program /Mods/PD2-S12/D2Common.dll
    python fun-doc/scripts/bsim_sweep.py --dump ... --program ... --apply
    python fun-doc/scripts/bsim_sweep.py --dump ... --program ... \
        --apply --rename-documented
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bsim_identify as bi                                      # noqa: E402


def assert_program_resolves(program: str) -> None:
    """Refuse to --apply against a program path Ghidra cannot resolve.

    Two documented failure modes meet here and the combination is dangerous:

      * Git Bash rewrites a leading-slash argument, so `/Mods/PD2-S12/x.dll`
        arrives as `C:/Program Files/Git/Mods/PD2-S12/x.dll` (use
        MSYS_NO_PATHCONV=1);
      * a POST whose `program` does not resolve falls through to the ACTIVE
        program -- which is how a "dry run" once performed a real write on the
        wrong binary.

    So an unresolvable path must stop the run rather than silently retarget it.
    """
    try:
        info = bi._get("/mcp/instance_info")
    except Exception as exc:                                    # noqa: BLE001
        raise SystemExit(f"cannot reach Ghidra at {bi.GHIDRA_URL}: {exc}")

    known = [str(p.get("path", "")) for p in info.get("programs", [])]
    if program in known:
        return

    hint = ""
    tail = program.rsplit("/", 1)[-1]
    near = [p for p in known if p.rsplit("/", 1)[-1] == tail]
    if near:
        hint = "\n  did you mean:  " + "\n                 ".join(near[:5])
        if program.replace("\\", "/").endswith(tuple(n.lstrip("/") for n in near)):
            hint += ("\n  (looks like Git Bash path mangling -- "
                     "prefix the command with MSYS_NO_PATHCONV=1)")
    raise SystemExit(
        f"refusing to apply: program {program!r} is not open in Ghidra.{hint}\n"
        f"  {len(known)} programs are open; an unresolvable program would fall "
        f"through to the ACTIVE one.")


def parse_tags(pairs) -> dict:
    """--tag libcrypto-1_1.dll=LIB_OPENSSL  ->  {'libcrypto-1_1.dll': 'LIB_OPENSSL'}"""
    tags = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"--tag needs EXE=TAG, got {pair!r}")
        exe, tag = pair.split("=", 1)
        tags[exe.strip()] = tag.strip()
    return tags


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump", required=True, help="JSONL from Analyze_BSimIdentifyDump")
    ap.add_argument("--program", required=True, help="Ghidra program path to write to")
    ap.add_argument("--tag", action="append", default=[], metavar="EXE=TAG",
                    help=f"reference exe -> function tag (default {bi.DEFAULT_TAG})")
    ap.add_argument("--sim-floor", type=float, default=bi.SIM_FLOOR)
    ap.add_argument("--signif-floor", type=float, default=bi.SIGNIF_FLOOR)
    ap.add_argument("--apply", action="store_true", help="actually write to Ghidra")
    ap.add_argument("--rename-documented", action="store_true",
                    help="also overwrite names that are NOT Ghidra defaults")
    ap.add_argument("--json", default=None, help="write the full report here")
    ap.add_argument("--limit", type=int, default=0, help="stop after N writable matches")
    args = ap.parse_args()

    if args.sim_floor < bi.SIM_FLOOR or args.signif_floor < bi.SIGNIF_FLOOR:
        print(f"! floors BELOW the calibrated point "
              f"(sim {bi.SIM_FLOOR}, signif {bi.SIGNIF_FLOOR}). Phase 0 measured "
              f"false positives below these; re-run the negative controls before "
              f"trusting any --apply at this setting.", file=sys.stderr)

    matches = bi.identify_from_dump(args.dump, program=args.program,
                                    tags=parse_tags(args.tag),
                                    sim_floor=args.sim_floor,
                                    signif_floor=args.signif_floor)
    buckets = Counter(m.bucket for m in matches)
    writable = [m for m in matches if m.writable]
    renamable = [m for m in matches if m.bucket == "writable"]
    documented = [m for m in matches if m.bucket == "documented_preserved"]
    if args.limit:
        renamable = renamable[:args.limit]

    print(f"dump:     {args.dump}")
    print(f"program:  {args.program}")
    print(f"floors:   sim >= {args.sim_floor}  significance >= {args.signif_floor}")
    print(f"verdicts above floors: {len(matches)}")
    for bucket, count in buckets.most_common():
        print(f"  {bucket:<22} {count}")
    print(f"\ntaggable (writable):    {len(writable)}")
    print(f"renamable (FUN_* only): {len(renamable)}")
    print(f"documented, preserved:  {len(documented)}"
          f"{'  (--rename-documented would take these)' if documented else ''}")

    if documented:
        print("\n  documented names a rename WOULD overwrite (review these):")
        for m in documented[:15]:
            print(f"    {m.address}  {m.current_name!r} -> {m.match_name!r}"
                  f"  sim={m.similarity:.4f} sig={m.significance:.1f}")
        if len(documented) > 15:
            print(f"    ... {len(documented) - 15} more")

    report = {
        "dump": args.dump, "program": args.program,
        "sim_floor": args.sim_floor, "signif_floor": args.signif_floor,
        "applied": bool(args.apply),
        "buckets": dict(buckets),
        "matches": [{
            "address": m.address, "bucket": m.bucket,
            "current_name": m.current_name, "match_name": m.match_name,
            "similarity": m.similarity, "significance": m.significance,
            "body_size": m.body_size, "source_exe": m.source_exe,
            "tag": m.tag, "candidates": m.candidates,
        } for m in matches],
    }

    if args.apply:
        assert_program_resolves(args.program)
        targets = renamable + documented if args.rename_documented else renamable
        # Tag + bookmark every writable match, even the already_correct ones:
        # the bookmark is durable evidence and survives a later rename.
        to_write = {m.address: m for m in writable}
        for m in targets:
            to_write[m.address] = m
        print(f"\napplying to {len(to_write)} matches ...")
        results = []
        renamed = failed = 0
        for i, m in enumerate(to_write.values(), 1):
            res = bi.sync_to_ghidra(
                m, apply_name=(m in targets),
                rename_documented=args.rename_documented)
            results.append(res)
            if res.get("renamed"):
                renamed += 1
            if res.get("error"):
                failed += 1
                print(f"  ! {res['address']}: {res['error']}")
            if i % 250 == 0:
                print(f"  ... {i}/{len(to_write)}")
        report["results"] = results
        print(f"\nrenamed {renamed}, write errors {failed}")
    else:
        print("\nDRY RUN -- nothing written. Review, then re-run with --apply.")

    out = args.json or os.path.splitext(args.dump)[0] + "_bsim_report.json"
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print(f"report: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

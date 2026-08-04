"""Corpus sweep: identify library code and scope it out of the inventory.

Report-first with a dry-run default, like `crt_sweep.py`, `falsify_sweep.py`
and `cross_version_disagreement.py` before it -- read the JSON, then `--apply`.

WHAT IT WRITES (only with --apply, and only after the Benchmark gate passes)

    Ghidra   LIB_* function tag + a durable "Library Scope" bookmark
    Ghidra   `Scope` property map entry on every library-OWNED global
    SQL      functions_workflow.library_code = 1, with lane attribution

Nothing is deleted and no function is renamed. Every exclusion is a flag, so a
bad verdict is one flip to undo.

THE GATE

`Benchmark.dll` is the positive control: 9 functions whose source we wrote. If
any lane claims one, the sweep refuses to apply and exits non-zero. There is no
override flag, on purpose -- a control you can wave through is not a control.
Include it in the sweep (`--folder /testing/benchmark`, or just point --folder
at a parent) or pass `--no-gate` to acknowledge you are running without one.

USAGE

    python fun-doc/scripts/library_scope_sweep.py --folder /Mods/PD2-S12
    python fun-doc/scripts/library_scope_sweep.py --all
    python fun-doc/scripts/library_scope_sweep.py --program /Mods/PD2-S12/D2Common.dll
    python fun-doc/scripts/library_scope_sweep.py --all --apply
    python fun-doc/scripts/library_scope_sweep.py --all --lanes bytes,fid
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import library_scope as ls                                        # noqa: E402


def _walk_project(root: str = "/", depth: int = 0) -> list[str]:
    """Every Program path at or under `root`.

    /list_project_files is FOLDER-SCOPED, not recursive: at "/" it answers with
    `folders: [...]` and an EMPTY `files` list. Calling it once and reading
    `files` therefore selects nothing at all and the sweep exits "no programs
    selected" -- which looks like an empty project rather than a wrong call.
    """
    if depth > 8:                       # cycles are impossible, typos are not
        return []
    try:
        raw = ls._get("/list_project_files", folder=root, limit=100000)
    except Exception as e:                                        # noqa: BLE001
        print(f"! cannot list {root}: {e}", file=sys.stderr)
        return []
    if isinstance(raw, dict) and isinstance(raw.get("result"), str):
        try:
            raw = json.loads(raw["result"])
        except json.JSONDecodeError:
            return []
    out: list[str] = []
    for item in (raw.get("files") or []):
        p = item.get("path") if isinstance(item, dict) else str(item)
        ctype = item.get("content_type") if isinstance(item, dict) else "Program"
        if p and ctype == "Program":
            out.append(p)
    base = root.rstrip("/")
    for sub in (raw.get("folders") or []):
        name = sub.get("name") if isinstance(sub, dict) else str(sub)
        if name:
            out.extend(_walk_project(f"{base}/{name}", depth + 1))
    return out


def _list_programs(folder: str | None, everything: bool) -> list[str]:
    """Program paths to sweep, from Ghidra's project listing."""
    root = "/" if everything else (folder or "/")
    return sorted(set(_walk_project(root)))


def _print_table(reports: list[ls.ProgramReport]) -> None:
    print()
    print(f"{'binary':<26} {'defined':>8} {'library':>8} {'in-scope':>9} "
          f"{'globals':>8} {'lib-glob':>9}")
    print("-" * 74)
    tot = [0, 0, 0, 0]
    for r in sorted(reports, key=lambda x: -x.defined):
        print(f"{r.binary:<26} {r.defined:>8} {len(r.verdicts):>8} "
              f"{r.in_scope:>9} {r.total_globals:>8} {len(r.lib_globals):>9}")
        tot[0] += r.defined
        tot[1] += len(r.verdicts)
        tot[2] += r.total_globals
        tot[3] += len(r.lib_globals)
    print("-" * 74)
    print(f"{'TOTAL':<26} {tot[0]:>8} {tot[1]:>8} {tot[0]-tot[1]:>9} "
          f"{tot[2]:>8} {tot[3]:>9}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--program", help="single program path")
    src.add_argument("--folder", help="every .dll/.exe under this project folder")
    src.add_argument("--all", action="store_true", help="every program in the project")
    ap.add_argument("--include", action="append", default=[], metavar="PATH",
                    help="extra program to add to the sweep. Repeatable. Use it to pull "
                         "Benchmark.dll in when sweeping a folder that lacks it, so the "
                         "positive control actually runs.")
    ap.add_argument("--apply", action="store_true",
                    help="write tags, Scope entries and library_code flags")
    ap.add_argument("--lanes", default=",".join(ls.ALL_LANES),
                    help=f"comma-separated subset of {','.join(ls.ALL_LANES)}")
    ap.add_argument("--bsim-dump", help="JSONL dump for the BSim lane")
    ap.add_argument("--no-globals", action="store_true",
                    help="skip the globals exclusive-reference rule")
    ap.add_argument("--no-gate", action="store_true",
                    help="acknowledge running without the Benchmark.dll control")
    ap.add_argument("--report", help="write the JSON report here")
    ap.add_argument("--max-programs", type=int, default=40,
                    help="refuse to sweep more than this many programs (default 40). "
                         "Every program touched gets OPENED by Ghidra, and ~20 open "
                         "programs crashes it -- `--all` selects 583 in this project.")
    args = ap.parse_args()

    lanes = tuple(x.strip() for x in args.lanes.split(",") if x.strip())
    bad = [x for x in lanes if x not in ls.ALL_LANES]
    if bad:
        print(f"unknown lane(s): {', '.join(bad)}", file=sys.stderr)
        return 2

    if args.program:
        programs = [args.program]
    else:
        programs = _list_programs(args.folder, args.all)
    for extra in args.include:
        if extra not in programs:
            programs.append(extra)
    if not programs:
        print("no programs selected", file=sys.stderr)
        return 2

    # Reading a program through the plugin OPENS it, and Ghidra falls over
    # somewhere past ~20 open shared-server programs. `--all` on this project
    # selects 583 (every archived version folder), so an unguarded corpus run
    # is not a long sweep -- it is a crash. The cap is a refusal, not a
    # truncation: silently sweeping the first 40 would report corpus-wide
    # coverage it never had.
    if len(programs) > args.max_programs:
        print(f"REFUSING: {len(programs)} programs selected, cap is "
              f"{args.max_programs}.\nEvery program swept is opened by Ghidra and "
              f"~20 open programs crashes it.\nNarrow with --folder, or raise "
              f"--max-programs deliberately.", file=sys.stderr)
        for p in programs[:8]:
            print(f"    {p}", file=sys.stderr)
        print(f"    ... and {len(programs) - 8} more", file=sys.stderr)
        return 2

    print(f"sweeping {len(programs)} program(s), lanes: {', '.join(lanes)}")
    print(f"mode: {'APPLY' if args.apply else 'dry-run (report only)'}")
    print()

    # One shared index across the whole corpus. Building it per program would
    # re-read every MSVC runtime on the box 32 times.
    index = None
    if "bytes" in lanes:
        try:
            index = ls.ci.load_index()
            print(f"library index: {index.count} signatures from {len(index.libs)} "
                  f"library file(s), {index.rejected} rejected as too weak\n")
        except Exception as e:                                    # noqa: BLE001
            print(f"! byte lane unavailable ({e}) -- continuing without it\n")

    reports: list[ls.ProgramReport] = []
    for i, p in enumerate(programs, 1):
        print(f"[{i}/{len(programs)}] {p}", flush=True)
        rep = ls.sweep_program(p, lanes=lanes, index=index,
                               bsim_dump=args.bsim_dump,
                               do_globals=not args.no_globals)
        reports.append(rep)

    _print_table(reports)

    styled = [(r.binary, v) for r in reports for v in r.styled]
    review = sum(len(r.review) for r in reports)
    print()
    print(f"heuristic review queue: {review} function(s) -- tagged nothing")
    print(f"game-styled names on library code: {len(styled)} -- review these")
    for b, v in styled[:25]:
        print(f"    {b:<22} {v.current_name:<44} -> {v.lib_name or '?'}")
    if len(styled) > 25:
        print(f"    ... and {len(styled) - 25} more (see the report)")

    passed, violations = ls.benchmark_gate(reports)
    swept_benchmark = any(r.binary == ls.BENCHMARK_BINARY for r in reports)
    print()
    if violations:
        print("BENCHMARK GATE: FAILED")
        for v in violations:
            print(f"    {v}")
    elif swept_benchmark:
        print("BENCHMARK GATE: passed (0 authored functions claimed)")
    else:
        print("BENCHMARK GATE: not exercised -- Benchmark.dll was not in this sweep")

    stamp = _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    out = {
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "lanes": list(lanes),
        "applied": bool(args.apply),
        "gate": {"passed": passed, "exercised": swept_benchmark,
                 "violations": violations},
        "programs": [r.to_json() for r in reports],
    }
    path = args.report or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", f"library_scope_{stamp}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nreport: {path}")

    if not args.apply:
        print("\ndry run -- nothing written. Review the report, then re-run with --apply.")
        return 0

    if not passed:
        print("\nREFUSING TO APPLY: the Benchmark control was claimed. "
              "Fix the lane, do not override.", file=sys.stderr)
        return 1
    if not swept_benchmark and not args.no_gate:
        print("\nREFUSING TO APPLY: Benchmark.dll was not swept, so the positive "
              "control never ran.\nInclude it, or pass --no-gate to acknowledge.",
              file=sys.stderr)
        return 1

    print("\napplying...")
    totals = {"tagged": 0, "failed": 0, "globals": 0}
    for rep in reports:
        fs = ls.apply_function_verdicts(rep)
        gs = ls.apply_global_scope(rep)
        totals["tagged"] += fs["tagged"]
        totals["failed"] += fs["failed"]
        totals["globals"] += gs["marked"]
        if fs["tagged"] or gs["marked"]:
            print(f"  {rep.binary:<24} {fs['tagged']:>5} tags  "
                  f"{gs['marked']:>5} globals"
                  + (f"  ({fs['failed']} FAILED)" if fs["failed"] else ""))
    flags = ls.sync_library_code_flags(reports)
    print(f"\ntagged {totals['tagged']} function(s), "
          f"{totals['globals']} global(s), "
          f"library_code flag set on {flags.get('updated', 0)} SQL row(s)")
    if totals["failed"]:
        print(f"! {totals['failed']} write(s) FAILED -- see the log above")
    if flags.get("missing"):
        print(f"note: {flags['missing']} tagged address(es) had no SQL row "
              f"(not yet inventoried)")
    print("\nRun save_program / checkin to persist the Ghidra side.")
    return 0 if not totals["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

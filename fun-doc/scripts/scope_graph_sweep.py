"""Corpus sweep: scope functions out by REFERENCE, not by name or by bytes.

Report-first, like `library_scope_sweep.py` / `falsify_sweep.py` /
`crt_sweep.py` before it -- but with a stricter apply path, because this lane
INFERS rather than matches. See `fun-doc/scope_graph.py` for the rule.

WHAT IT WRITES (only with --apply, and only after both controls pass)

    Ghidra   SCOPE_EXCLUDED function tag + `Scope` property + a durable bookmark
    SQL      functions_workflow.scope_excluded = 1, with the referrer reason

Never a `LIB_*` tag: those mean a lane matched an artifact, and an inference must
not be able to forge one. Nothing is renamed and nothing is deleted -- every
exclusion is one flag to flip back.

--apply CONSUMES A REVIEWED REPORT, IT DOES NOT RE-DECIDE

    scope_graph_sweep.py --folder /Mods/PD2-S12          # writes a report
    ...read it...
    scope_graph_sweep.py --apply logs/scope_graph_*.json # writes THAT report

The apply pass re-sweeps and diffs against the file. On any difference it
REFUSES and names the delta. This is not ceremony: the graph is recomputed from
live Ghidra state, so a rename, a re-analysis, or another lane's tags landing in
between can move a verdict -- and re-deciding at apply time would mean the
operator approved one set while a different set got written.

THE TWO CONTROLS, NEITHER WITH AN OVERRIDE

    Benchmark.dll   0 of its 9 authored functions may be swept (ground truth:
                    we wrote their C).
    PD2_EXT.dll     its 4 authored functions must survive. That binary is where
                    the cascade was measured -- `dllmain_dispatch` is the only
                    referrer of `PD2EXT_InstallBootstrapHook`, which is the only
                    referrer of the next one, and so on, so one bad verdict at
                    the CRT boundary deletes the whole authored subtree. The
                    offline test proves the guard against a mocked graph; only
                    this proves it against a real one.

A control that never RAN is not a control that passed, so an unexercised control
also refuses; `--no-gate` acknowledges that deliberately and is the only way
past it. There is no flag that turns a FAILING control into a pass.

USAGE

    python fun-doc/scripts/scope_graph_sweep.py --program /Mods/PD2-S12/PD2_EXT.dll
    python fun-doc/scripts/scope_graph_sweep.py --folder /Mods/PD2-S12
    python fun-doc/scripts/scope_graph_sweep.py --apply fun-doc/logs/scope_graph_X.json
    python fun-doc/scripts/scope_graph_sweep.py --apply ... --no-sql   # Ghidra only
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
sys.path.insert(0, _HERE)

import scope_graph as sg                                          # noqa: E402
import library_scope as ls                                        # noqa: E402
# The project walk is IMPORTED, not re-implemented. /list_project_files is
# folder-scoped, so the recursion (and the "reading files at / returns an empty
# list and looks like an empty project" trap) has exactly one home.
from library_scope_sweep import _list_programs                    # noqa: E402


def _print_table(reports: list[sg.ScopeReport]) -> None:
    print()
    print(f"{'binary':<26} {'total':>7} {'seed-lib':>9} {'swept':>7} "
          f"{'in-scope':>9} {'protected':>10} {'no-refs':>8} {'rounds':>7}")
    print("-" * 90)
    tot = [0, 0, 0, 0]
    for r in sorted(reports, key=lambda x: -x.total):
        print(f"{r.binary:<26} {r.total:>7} {r.seed_library:>9} "
              f"{len(r.swept):>7} {len(r.in_scope):>9} {len(r.protected):>10} "
              f"{r.unreferenced:>8} {r.rounds:>7}")
        tot[0] += r.total
        tot[1] += r.seed_library
        tot[2] += len(r.swept)
        tot[3] += len(r.in_scope)
    print("-" * 90)
    print(f"{'TOTAL':<26} {tot[0]:>7} {tot[1]:>9} {tot[2]:>7} {tot[3]:>9}")


def _print_samples(reports: list[sg.ScopeReport], n: int = 20) -> None:
    """Show what would be swept. The review is the point, so this prints the
    NAMES -- a list of addresses is not something a human can check."""
    rows = [(r.binary, s) for r in reports for s in r.swept]
    if not rows:
        print("\nnothing swept.")
        return
    print(f"\nswept sample ({min(n, len(rows))} of {len(rows)}) -- "
          f"read these before --apply:")
    for b, s in rows[:n]:
        refs = ", ".join(x["name"] or x["address"] for x in s["referrers"][:3])
        print(f"    {b:<20} {s['address']}  {(s['name'] or '?'):<44} <- {refs}")
    if len(rows) > n:
        print(f"    ... and {len(rows) - n} more (all of them are in the report)")


def _sweep_all(programs: list[str]) -> list[sg.ScopeReport]:
    reports: list[sg.ScopeReport] = []
    for i, p in enumerate(programs, 1):
        print(f"[{i}/{len(programs)}] {p}", flush=True)
        try:
            reports.append(sg.sweep_program(p))
        except sg.EmptyGraph as e:
            # Loud, and NOT a report with zero edges: an empty reference set is
            # indistinguishable from "this binary references nothing", which read
            # as a finding once already (950 dropped edges parsed as "the authored
            # functions call nothing else").
            print(f"  ! {e}", flush=True)
        except Exception as e:                                    # noqa: BLE001
            print(f"  ! sweep failed for {p}: {e}", flush=True)
    return reports


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--program", help="single program path")
    src.add_argument("--folder", help="every program under this project folder")
    src.add_argument("--all", action="store_true", help="every program in the project")
    src.add_argument("--apply", metavar="REPORT_JSON",
                     help="write the verdicts in this reviewed report (re-sweeps "
                          "the same programs first and refuses on any difference)")
    ap.add_argument("--include", action="append", default=[], metavar="PATH",
                    help="extra program to add to the sweep. Repeatable -- use it to "
                         "pull Benchmark.dll or PD2_EXT.dll in so the controls run.")
    ap.add_argument("--no-gate", action="store_true",
                    help="acknowledge applying with a control that never ran. Does "
                         "NOT turn a FAILING control into a pass.")
    ap.add_argument("--no-sql", action="store_true",
                    help="write Ghidra tags only, skip the functions_workflow flag. "
                         "The selector reads the FLAG, so the exclusion is inert "
                         "until a later refresh pass re-derives it.")
    ap.add_argument("--report", help="write the JSON report here")
    ap.add_argument("--max-programs", type=int, default=40,
                    help="refuse to sweep more than this many programs (default 40). "
                         "Every program touched gets OPENED by Ghidra and ~20 open "
                         "programs crashes it -- `--all` selects 583 here.")
    args = ap.parse_args()

    saved = None
    if args.apply:
        try:
            with open(args.apply, encoding="utf-8") as fh:
                saved = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            print(f"cannot read the report to apply: {e}", file=sys.stderr)
            return 2
        programs = [p["program"] for p in (saved.get("programs") or [])
                    if p.get("program")]
        if not programs:
            print(f"{args.apply} lists no programs", file=sys.stderr)
            return 2
    elif args.program:
        programs = [args.program]
    else:
        programs = _list_programs(args.folder, args.all)
    for extra in args.include:
        if extra not in programs:
            programs.append(extra)
    if not programs:
        print("no programs selected", file=sys.stderr)
        return 2

    # A refusal, not a truncation: silently sweeping the first 40 would report
    # corpus coverage it never had.
    if len(programs) > args.max_programs:
        print(f"REFUSING: {len(programs)} programs selected, cap is "
              f"{args.max_programs}.\nEvery program swept is opened by Ghidra and "
              f"~20 open programs crashes it.\nNarrow with --folder, or raise "
              f"--max-programs deliberately.", file=sys.stderr)
        for p in programs[:8]:
            print(f"    {p}", file=sys.stderr)
        if len(programs) > 8:
            print(f"    ... and {len(programs) - 8} more", file=sys.stderr)
        return 2

    print(f"sweeping {len(programs)} program(s)")
    print(f"mode: {'APPLY from ' + args.apply if args.apply else 'dry-run (report only)'}")
    print()

    reports = _sweep_all(programs)
    if not reports:
        print("\nno program produced a report -- nothing to do", file=sys.stderr)
        return 1

    # A program that read ZERO functions is not an empty binary, it is a failed
    # read, and the two look identical in the table. Measured 2026-08-07: a shell
    # rewrote every `/Mods/...` argument to `C:/Program Files/Git/Mods/...`, all
    # programs came back empty, and the run still printed a passing benchmark gate.
    empty = [r.binary for r in reports if r.total == 0]
    if empty:
        print(f"\n! {len(empty)} program(s) returned ZERO functions: "
              f"{', '.join(empty[:6])}", file=sys.stderr)
        print("  That is a failed read, not an empty binary. Check the program "
              "path is a GHIDRA PROJECT path and that your shell has not "
              "rewritten it (MSYS/Git Bash rewrites a leading '/').",
              file=sys.stderr)

    _print_table(reports)
    _print_samples(reports)

    gates = sg.gate_report(reports)
    print()
    for name, label in (("benchmark", "BENCHMARK GATE"),
                        ("cascade", "CASCADE CONTROL (PD2_EXT authored chain)")):
        g = gates[name]
        if g["violations"]:
            print(f"{label}: FAILED")
            for v in g["violations"]:
                print(f"    {v}")
        elif g["exercised"]:
            print(f"{label}: passed")
        else:
            print(f"{label}: NOT EXERCISED -- the control binary was not in this sweep")

    stamp = _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    out = {
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "applied": bool(args.apply),
        "applied_from": args.apply or None,
        "gates": gates,
        "programs": [r.to_json() for r in reports],
    }
    path = args.report or os.path.join(
        os.path.dirname(_HERE), "logs", f"scope_graph_{stamp}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nreport: {path}")

    if not args.apply:
        print("\ndry run -- nothing written. Read the swept list, then re-run "
              "with --apply <this report>.")
        return 0

    # ---- everything below here writes ----

    drift = sg.report_drift(saved, reports)
    if drift:
        print("\nREFUSING TO APPLY: the binary no longer matches the reviewed "
              "report.", file=sys.stderr)
        for d in drift:
            print(f"    {d}", file=sys.stderr)
        print("\nThe report you reviewed is not the set that would be written. "
              "Re-run the dry sweep, review the new report, and apply that one.",
              file=sys.stderr)
        return 1

    if not gates["passed"]:
        print("\nREFUSING TO APPLY: a control was violated. Fix the boundary "
              "rule; there is no override.", file=sys.stderr)
        return 1
    unexercised = [n for n in ("benchmark", "cascade")
                   if not gates[n]["exercised"]]
    if unexercised and not args.no_gate:
        print(f"\nREFUSING TO APPLY: {', '.join(unexercised)} control(s) never "
              f"ran, so nothing was verified.\nInclude the control binary "
              f"(--include /Mods/PD2-S12/PD2_EXT.dll, --include "
              f"/testing/benchmark/Benchmark.dll), or pass --no-gate to "
              f"acknowledge.", file=sys.stderr)
        return 1

    print()
    total = {"tagged": 0, "failed": 0}
    for rep in reports:
        st = sg.apply_scope(rep)
        total["tagged"] += st["tagged"]
        total["failed"] += st["failed"]
        print(f"  {rep.binary:<24} tagged {st['tagged']:>5}  failed {st['failed']:>4}")
    print(f"\nGhidra: {total['tagged']} tagged, {total['failed']} failed")

    if args.no_sql:
        print("SQL: skipped (--no-sql). The selector reads the FLAG, so these "
              "exclusions do nothing until a refresh pass re-derives it.")
    else:
        flags = sg.sync_scope_excluded_flags(reports)
        print(f"SQL: {flags.get('updated', 0)} flagged, "
              f"{flags.get('missing', 0)} not in the queue, "
              f"{flags.get('failed', 0)} failed")

    print("\nSave the programs in Ghidra to persist the tags "
          "(shared-server work also needs a checkin).")
    return 1 if total["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())

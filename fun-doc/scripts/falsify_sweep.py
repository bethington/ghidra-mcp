"""Whole-corpus falsifiability sweep: run falsify.py's contradiction checks
over every documented function in every project folder.

REPORT-FIRST, DRY-RUN DEFAULT. Without --apply this writes a JSON report and
nothing else — review the findings (especially the tier-2 calibration) before
letting any consequence land. With --apply:

  * SQL (functions_workflow): falsify_status / falsify_checked_at /
    falsify_findings / falsify_source='sweep' for EVERY scanned function —
    passed and contradicted alike, so the dashboard's verdict map is complete.
    Functions the workflow store has never seen get a minimal row upserted.
  * Ghidra: ONLY contradicted functions get the DOC_REFUTED tag, the
    `Falsify` property record and the idempotent [AUDIT falsify:*] plate
    flags (via falsify.sync_to_ghidra — the same single writer the worker
    stage uses). Stamping 'passed' Ghidra-side for tens of thousands of clean
    functions would cost 3 HTTP round-trips each for no actionable signal;
    the SQL layer carries the full map, Ghidra carries the refutations.
  * /save_program once per program that received writes. NOTE the shared-
    server rule: renames/properties are not persisted by save alone on a
    shared project — programs listed in the summary need a checkin.

The corpus-level library_domain_prefix check (doc_lint's rule) needs
cross-program calibration, so it runs over the whole scanned set after the
per-function checks and its findings are merged per function before verdicts
are finalized.

One program is processed at a time via explicit `program` params — never
switch_program (name-matching bug), never 5+ programs open.

Usage:
    python -m scripts.falsify_sweep --all-folders --json falsify_report.json
    python -m scripts.falsify_sweep --folder /Mods/PD2-S12 --json report.json
    python -m scripts.falsify_sweep --all-folders --apply
    python -m scripts.falsify_sweep --program /Mods/PD2-S12/D2Common.dll --limit 50
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_FUNDOC_DIR = Path(__file__).resolve().parent.parent
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

import falsify  # noqa: E402

# Pacing: a sweep must not monopolize Ghidra's HTTP thread pool while doc
# workers are running. Sleep between chunks, inventory_scorer style.
PAUSE_EVERY = 25
PAUSE_SECS = 0.5


def walk_folders(root: str = "/") -> list:
    """Every project folder path, depth-first from `root`."""
    resp = falsify._get("/list_project_files", folder=root)
    if not isinstance(resp, dict):
        return [root]
    out = [root]
    for name in resp.get("folders") or []:
        child = (root.rstrip("/") + "/" + name) if root != "/" else "/" + name
        out.extend(walk_folders(child))
    return out


def all_programs(root: str = "/") -> list:
    programs = []
    for folder in walk_folders(root):
        programs.extend(falsify.list_programs(folder))
    return programs


def merge_doclint(verdicts_by_program: dict, programs: list) -> None:
    """Run doc_lint's corpus-calibrated check and merge its findings into the
    per-function verdict map (statuses are recomputed for touched functions)."""
    import doc_lint
    recs = []
    for p in programs:
        try:
            recs.extend(doc_lint.collect(p))
        except Exception as e:  # noqa: BLE001
            print(f"  !! doc_lint collect {p}: {e}", file=sys.stderr)
    if not recs:
        return
    dl_findings = falsify.doclint_findings(recs, doc_lint.calibrate(recs))
    for f in dl_findings:
        rows = verdicts_by_program.setdefault(f.program, {})
        addr = f.address
        if addr in rows:
            name, _status, findings = rows[addr]
            findings = findings + [f]
        else:
            name, findings = f.function, [f]
        rows[addr] = (name, falsify.status_for(findings), findings)


def apply_sql(verdicts_by_program: dict, checked_at) -> dict:
    """Persist every verdict to functions_workflow. Returns counters."""
    from storage import make_engine, resolve_config
    from storage.repository import Repository

    cfg = resolve_config()
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    counters = {"updated": 0, "upserted": 0}
    try:
        for program, rows in verdicts_by_program.items():
            for addr, (name, status, findings) in rows.items():
                if status == "error":
                    continue                      # no information — don't stamp
                fields = {
                    "falsify_status": status,
                    "falsify_checked_at": checked_at,
                    "falsify_findings": [f.to_dict() for f in findings],
                    "falsify_source": "sweep",
                }
                if repo.update_function_fields(program, addr, **fields):
                    counters["updated"] += 1
                else:
                    repo.upsert_function({
                        "program_path": program,
                        "binary_name": program.rsplit("/", 1)[-1],
                        "address": addr,
                        "name": name,
                        **fields,
                    })
                    counters["upserted"] += 1
    finally:
        engine.dispose()
    return counters


def apply_ghidra(verdicts_by_program: dict, date: str) -> dict:
    """Write DOC_REFUTED + Falsify record + plate flags for contradicted
    functions only. Saves each touched program once."""
    counters = {"synced": 0, "failed": 0, "programs_touched": []}
    for program, rows in verdicts_by_program.items():
        touched = False
        for addr, (_name, status, findings) in rows.items():
            if status != "contradicted":
                continue
            ok = falsify.sync_to_ghidra(program, addr, status, findings,
                                        "sweep", date=date)
            counters["synced" if ok else "failed"] += 1
            touched = touched or ok
        if touched:
            try:
                falsify._post("/save_program", {}, program=program.rsplit("/", 1)[-1])
                counters["programs_touched"].append(program)
            except Exception as e:  # noqa: BLE001
                print(f"  !! save_program {program}: {e}", file=sys.stderr)
    return counters


def summarize(verdicts_by_program: dict) -> dict:
    per_check = defaultdict(int)
    per_binary = defaultdict(lambda: {"scanned": 0, "passed": 0,
                                      "contradicted": 0, "error": 0,
                                      "tier1": 0, "tier2": 0})
    for program, rows in verdicts_by_program.items():
        b = per_binary[program]
        for _addr, (_name, status, findings) in rows.items():
            b["scanned"] += 1
            b[status] = b.get(status, 0) + 1
            for f in findings:
                per_check[f.check_id] += 1
                b["tier1" if f.tier == 1 else "tier2"] += 1
    return {"per_check": dict(per_check),
            "per_binary": {k: dict(v) for k, v in per_binary.items()}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--all-folders", action="store_true",
                   help="sweep every Program in the whole project")
    g.add_argument("--folder", help="sweep one project folder")
    g.add_argument("--program", help="sweep a single program path")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--apply", action="store_true",
                    help="write verdicts to SQL + refutations to Ghidra "
                         "(default: dry-run report only)")
    ap.add_argument("--limit", type=int, default=0,
                    help="max functions per program (0 = all)")
    ap.add_argument("--enable", action="append", default=[], metavar="CHECK")
    ap.add_argument("--disable", action="append", default=[], metavar="CHECK")
    ap.add_argument("--no-doclint", action="store_true",
                    help="skip the corpus-level library_domain_prefix check")
    args = ap.parse_args()

    enabled = falsify.enabled_check_ids(args.enable, args.disable)
    if args.program:
        programs = [args.program]
    elif args.folder:
        programs = falsify.list_programs(args.folder)
    else:
        programs = all_programs()
    mode = "APPLY" if args.apply else "dry-run"
    print(f"# {mode}: sweeping {len(programs)} program(s), "
          f"checks: {', '.join(enabled)}", file=sys.stderr)

    verdicts_by_program: dict = {}
    for p in programs:
        t0 = time.time()
        try:
            verdicts = falsify.scan_program_verdicts(
                p, enabled, limit=args.limit,
                pause_every=PAUSE_EVERY, pause_secs=PAUSE_SECS)
        except Exception as e:  # noqa: BLE001
            print(f"  !! {p}: {e}", file=sys.stderr)
            continue
        verdicts_by_program[p] = {a: (n, s, fs) for a, n, s, fs in verdicts}
        n_bad = sum(1 for _, (_n, s, _f) in verdicts_by_program[p].items()
                    if s == "contradicted")
        print(f"  {p:44} {len(verdicts):6} scanned  {n_bad:5} contradicted  "
              f"({time.time() - t0:.0f}s)", file=sys.stderr)

    if not args.no_doclint:
        try:
            merge_doclint(verdicts_by_program, programs)
        except Exception as e:  # noqa: BLE001
            print(f"  !! library_domain_prefix sweep failed: {e}", file=sys.stderr)

    summary = summarize(verdicts_by_program)
    print("\n=== SWEEP SUMMARY ===")
    for check, n in sorted(summary["per_check"].items(), key=lambda kv: -kv[1]):
        print(f"  {check:28} {n:6}")
    total_bad = sum(v.get("contradicted", 0)
                    for v in summary["per_binary"].values())
    total_scanned = sum(v["scanned"] for v in summary["per_binary"].values())
    print(f"\n  scanned {total_scanned} function(s) across "
          f"{len(summary['per_binary'])} binaries — {total_bad} contradicted")

    applied = None
    if args.apply:
        now = datetime.now(timezone.utc)
        date = now.date().isoformat()
        print("\n# applying to SQL ...", file=sys.stderr)
        sql_counts = apply_sql(verdicts_by_program, now)
        print(f"  SQL: {sql_counts['updated']} updated, "
              f"{sql_counts['upserted']} upserted", file=sys.stderr)
        print("# applying refutations to Ghidra ...", file=sys.stderr)
        gh_counts = apply_ghidra(verdicts_by_program, date)
        print(f"  Ghidra: {gh_counts['synced']} synced, "
              f"{gh_counts['failed']} failed", file=sys.stderr)
        if gh_counts["programs_touched"]:
            print("\n  NOTE (shared server): these programs received writes and "
                  "need a CHECKIN to persist:", file=sys.stderr)
            for p in gh_counts["programs_touched"]:
                print(f"    {p}", file=sys.stderr)
        applied = {"sql": sql_counts,
                   "ghidra": {k: v for k, v in gh_counts.items()}}

    if args.json:
        report = {
            "mode": mode,
            "scanned_programs": programs,
            "checks": enabled,
            "summary": summary,
            "applied": applied,
            "verdicts": {
                prog: {
                    addr: {"name": n, "status": s,
                           "findings": [f.to_dict() for f in fs]}
                    for addr, (n, s, fs) in rows.items()
                    if s != "passed" or fs   # keep the report reviewable
                }
                for prog, rows in verdicts_by_program.items()
            },
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nwrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

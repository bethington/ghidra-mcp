#!/usr/bin/env python3
"""Analyze fun-doc debug logs to spot tool-call inefficiencies.

Usage:
    python analyze_debug.py                          # Today's logs
    python analyze_debug.py 2026-04-13               # Specific date
    python analyze_debug.py path/to/file.jsonl       # Single file
    python analyze_debug.py path/to/dir              # Whole directory
    python analyze_debug.py --top 20                 # Show top 20 worst-offenders
    python analyze_debug.py --tool create_struct     # Filter to one tool

Reports:
    - Per-function: total calls, tool frequency, consecutive same-tool runs,
      failed-then-retried sequences, time per tool, repeated args
    - Cross-function summary: which functions burned the most tool calls,
      which tools are called most often in long runs
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_LOG_ROOT = SCRIPT_DIR / "logs" / "debug"


def load_entries(path):
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def find_consecutive_runs(entries, min_run=3):
    """Detect runs of >= min_run consecutive calls to the same tool."""
    runs = []
    current_tool = None
    current_run = 0
    current_start = 0
    for i, e in enumerate(entries):
        if e["tool"] == current_tool:
            current_run += 1
        else:
            if current_run >= min_run:
                runs.append({
                    "tool": current_tool,
                    "count": current_run,
                    "start_iter": current_start,
                })
            current_tool = e["tool"]
            current_run = 1
            current_start = i
    if current_run >= min_run:
        runs.append({
            "tool": current_tool,
            "count": current_run,
            "start_iter": current_start,
        })
    return runs


def find_fail_retries(entries):
    """Find places where a failed call was immediately retried with the same tool."""
    retries = []
    for i, e in enumerate(entries[:-1]):
        if e.get("status") == "failed":
            nxt = entries[i + 1]
            if nxt["tool"] == e["tool"]:
                retries.append({
                    "tool": e["tool"],
                    "iteration": e.get("iteration"),
                    "failed_args": e.get("args"),
                    "retry_args": nxt.get("args"),
                })
    return retries


def find_repeated_args(entries):
    """Find calls to the same tool with identical args (likely no-op repeats)."""
    seen = defaultdict(list)
    repeats = []
    for e in entries:
        key = (e["tool"], json.dumps(e.get("args"), sort_keys=True, default=str))
        seen[key].append(e.get("iteration"))
    for (tool, args_str), iters in seen.items():
        if len(iters) >= 2:
            repeats.append({"tool": tool, "count": len(iters), "iterations": iters})
    return repeats


def analyze_file(path, tool_filter=None):
    entries = load_entries(path)
    if not entries:
        return None
    if tool_filter:
        entries = [e for e in entries if e["tool"] == tool_filter]
        if not entries:
            return None

    func_name = entries[0].get("function_name", "?")
    func_key = entries[0].get("function_key", "?")
    provider = entries[0].get("provider", "?")

    tool_counts = Counter(e["tool"] for e in entries)
    runs = find_consecutive_runs(entries)
    fail_retries = find_fail_retries(entries)
    repeats = find_repeated_args(entries)

    total_time = 0
    time_per_tool = defaultdict(int)
    for e in entries:
        d = e.get("duration_ms")
        if d:
            total_time += d
            time_per_tool[e["tool"]] += d

    return {
        "path": path,
        "func_name": func_name,
        "func_key": func_key,
        "provider": provider,
        "total_calls": len(entries),
        "unique_tools": len(tool_counts),
        "tool_counts": tool_counts,
        "consecutive_runs": runs,
        "fail_retries": fail_retries,
        "repeated_args": repeats,
        "total_time_ms": total_time,
        "time_per_tool": dict(time_per_tool),
        "failed_count": sum(1 for e in entries if e.get("status") == "failed"),
    }


def print_report(report, verbose=False):
    if report is None:
        return
    print(f"\n=== {report['func_name']} ===")
    print(f"  file:     {report['path'].name}")
    print(f"  provider: {report['provider']}")
    print(f"  calls:    {report['total_calls']}  ({report['unique_tools']} unique tools, {report['failed_count']} failed)")
    if report["total_time_ms"] > 0:
        print(f"  time:     {report['total_time_ms']}ms total")

    print("\n  Tool frequency:")
    for tool, count in report["tool_counts"].most_common(10):
        bar = "#" * min(40, count)
        print(f"    {count:3d}  {tool:40} {bar}")

    if report["consecutive_runs"]:
        print("\n  Consecutive same-tool runs (>=3):")
        for run in report["consecutive_runs"]:
            print(f"    {run['count']}x  {run['tool']}  (starting at call #{run['start_iter'] + 1})")

    if report["fail_retries"]:
        print("\n  Failed-then-retried (same tool):")
        retry_counts = Counter(r["tool"] for r in report["fail_retries"])
        for tool, count in retry_counts.most_common():
            print(f"    {count}x  {tool}")
        if verbose:
            for r in report["fail_retries"][:5]:
                print(f"      iter {r['iteration']}: {r['tool']}")

    if report["repeated_args"]:
        print("\n  Repeated calls with identical args:")
        for rep in sorted(report["repeated_args"], key=lambda x: -x["count"])[:5]:
            print(f"    {rep['count']}x  {rep['tool']}  (iters: {rep['iterations']})")

    if report["time_per_tool"]:
        print("\n  Time per tool (top 5):")
        for tool, ms in sorted(report["time_per_tool"].items(), key=lambda x: -x[1])[:5]:
            print(f"    {ms:6d}ms  {tool}")


def print_summary(reports):
    if not reports:
        print("\nNo reports to summarize.")
        return
    print(f"\n{'=' * 60}")
    print(f"SUMMARY ACROSS {len(reports)} FUNCTIONS")
    print(f"{'=' * 60}")

    total_calls = sum(r["total_calls"] for r in reports)
    total_failed = sum(r["failed_count"] for r in reports)
    total_time = sum(r["total_time_ms"] for r in reports)
    print(f"  Total tool calls:  {total_calls}")
    print(f"  Total failed:      {total_failed} ({100 * total_failed / max(total_calls, 1):.1f}%)")
    print(f"  Total time:        {total_time / 1000:.1f}s")

    # Worst offenders by call count
    worst = sorted(reports, key=lambda r: -r["total_calls"])[:10]
    print("\n  Highest tool-call counts (top 10):")
    for r in worst:
        print(f"    {r['total_calls']:4d}  {r['func_name']}")

    # Functions with most consecutive runs (suggests batch opportunities)
    longest_runs = sorted(
        reports,
        key=lambda r: -max((run["count"] for run in r["consecutive_runs"]), default=0),
    )[:10]
    print("\n  Longest consecutive same-tool runs (top 10):")
    for r in longest_runs:
        if not r["consecutive_runs"]:
            continue
        longest = max(r["consecutive_runs"], key=lambda x: x["count"])
        print(f"    {longest['count']}x {longest['tool']:30}  in  {r['func_name']}")

    # Aggregate tool frequency across all functions
    cross_tool = Counter()
    for r in reports:
        for tool, count in r["tool_counts"].items():
            cross_tool[tool] += count
    print("\n  Cross-function tool frequency (top 15):")
    for tool, count in cross_tool.most_common(15):
        print(f"    {count:5d}  {tool}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Date (YYYY-MM-DD), file, or directory. Default: today.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=0,
        help="Limit per-function reports to N worst offenders (default: all)",
    )
    parser.add_argument(
        "--tool",
        default=None,
        help="Filter all analysis to a single tool name",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Skip per-function reports, show only the cross-function summary",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show extra detail (failed-retry args, etc.)",
    )
    args = parser.parse_args()

    # Resolve target
    if args.target is None:
        log_dir = DEFAULT_LOG_ROOT / date.today().isoformat()
    else:
        target = Path(args.target)
        if target.is_file():
            files = [target]
            log_dir = None
        elif target.is_dir():
            log_dir = target
        else:
            # Maybe it's a date string
            log_dir = DEFAULT_LOG_ROOT / args.target
            if not log_dir.exists():
                print(f"Not found: {args.target}", file=sys.stderr)
                sys.exit(1)

    if log_dir is not None:
        if not log_dir.exists():
            print(f"No logs at {log_dir}", file=sys.stderr)
            sys.exit(1)
        files = sorted(log_dir.glob("*.jsonl"))

    if not files:
        print("No JSONL files found", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing {len(files)} file(s)...")
    reports = []
    for f in files:
        report = analyze_file(f, tool_filter=args.tool)
        if report is not None:
            reports.append(report)

    if not reports:
        print("No data after filtering.")
        sys.exit(0)

    # Sort by total calls desc for per-function output
    reports.sort(key=lambda r: -r["total_calls"])
    if args.top > 0:
        per_func_reports = reports[: args.top]
    else:
        per_func_reports = reports

    if not args.summary_only:
        for r in per_func_reports:
            print_report(r, verbose=args.verbose)

    print_summary(reports)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Analyze fun-doc run logs with a focus on provider handoffs.

Usage:
    python analyze_runs.py
    python analyze_runs.py --date 2026-04-22
    python analyze_runs.py --limit 500
    python analyze_runs.py --path logs/runs.jsonl
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_RUN_LOG = SCRIPT_DIR / "logs" / "runs.jsonl"


def load_runs(path, date_prefix=None, limit=None):
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if date_prefix and not str(row.get("timestamp", "")).startswith(
                date_prefix
            ):
                continue
            rows.append(row)
    if limit:
        rows = rows[-limit:]
    return rows


def avg(values):
    return round(sum(values) / len(values), 1) if values else 0


def summarize(rows):
    summary = {
        "total_runs": len(rows),
        "handoff_runs": 0,
        "top_pairs": [],
        "top_chains": [],
        "requested": [],
    }
    pair_stats = defaultdict(
        lambda: {"runs": 0, "success": 0, "deltas": [], "known_tools": []}
    )
    chain_counts = Counter()
    requested_stats = defaultdict(
        lambda: {"runs": 0, "handoffs": 0, "success": 0, "deltas": []}
    )

    for row in rows:
        effective = row.get("provider") or "unknown"
        requested = row.get("requested_provider") or effective
        chain = row.get("provider_chain") or [requested]
        if not isinstance(chain, list) or not chain:
            chain = [requested, effective] if requested != effective else [effective]

        requested_stats[requested]["runs"] += 1
        if row.get("result") == "completed":
            requested_stats[requested]["success"] += 1
        if row.get("score_before") is not None and row.get("score_after") is not None:
            requested_stats[requested]["deltas"].append(
                row.get("score_delta", row["score_after"] - row["score_before"])
            )

        if requested != effective or len(chain) > 1:
            summary["handoff_runs"] += 1
            requested_stats[requested]["handoffs"] += 1
            pair_key = (requested, effective)
            pair_stats[pair_key]["runs"] += 1
            if row.get("result") == "completed":
                pair_stats[pair_key]["success"] += 1
            if (
                row.get("score_before") is not None
                and row.get("score_after") is not None
            ):
                pair_stats[pair_key]["deltas"].append(
                    row.get("score_delta", row["score_after"] - row["score_before"])
                )
            if row.get("tool_calls_known") and isinstance(row.get("tool_calls"), int):
                pair_stats[pair_key]["known_tools"].append(row["tool_calls"])
            chain_counts[" -> ".join(str(x) for x in chain)] += 1

    summary["top_pairs"] = [
        {
            "requested": requested,
            "effective": effective,
            "runs": stats["runs"],
            "success_rate": (
                round(stats["success"] / stats["runs"] * 100, 1) if stats["runs"] else 0
            ),
            "avg_delta": avg(stats["deltas"]),
            "avg_tools": avg(stats["known_tools"]),
            "known_tool_runs": len(stats["known_tools"]),
        }
        for (requested, effective), stats in sorted(
            pair_stats.items(), key=lambda item: item[1]["runs"], reverse=True
        )
    ]
    summary["top_chains"] = [
        {"chain": chain, "runs": runs} for chain, runs in chain_counts.most_common(10)
    ]
    summary["requested"] = [
        {
            "provider": provider,
            "runs": stats["runs"],
            "handoffs": stats["handoffs"],
            "handoff_rate": (
                round(stats["handoffs"] / stats["runs"] * 100, 1)
                if stats["runs"]
                else 0
            ),
            "success_rate": (
                round(stats["success"] / stats["runs"] * 100, 1) if stats["runs"] else 0
            ),
            "avg_delta": avg(stats["deltas"]),
        }
        for provider, stats in sorted(
            requested_stats.items(), key=lambda item: item[1]["runs"], reverse=True
        )
    ]
    return summary


def main():
    parser = argparse.ArgumentParser(description="Analyze fun-doc runs.jsonl handoffs")
    parser.add_argument(
        "--path", default=str(DEFAULT_RUN_LOG), help="Path to runs.jsonl"
    )
    parser.add_argument("--date", help="Filter by YYYY-MM-DD timestamp prefix")
    parser.add_argument(
        "--limit", type=int, help="Only analyze the most recent N matching runs"
    )
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        raise SystemExit(f"Run log not found: {path}")

    rows = load_runs(path, date_prefix=args.date, limit=args.limit)
    if not rows:
        raise SystemExit("No matching runs found")

    summary = summarize(rows)
    print(f"Analyzed {summary['total_runs']} runs from {path}")
    print(
        f"Handoff runs: {summary['handoff_runs']} ({round(summary['handoff_runs'] / summary['total_runs'] * 100, 1) if summary['total_runs'] else 0}%)"
    )

    print("\nRequested Provider Summary")
    for item in summary["requested"]:
        print(
            f"  {item['provider']:<8} runs={item['runs']:<5} handoffs={item['handoffs']:<5} "
            f"handoff_rate={item['handoff_rate']:<5}% success={item['success_rate']:<5}% avg_delta={item['avg_delta']:+}"
        )

    if summary["top_pairs"]:
        print("\nTop Requested -> Effective Pairs")
        for item in summary["top_pairs"][:10]:
            tools = (
                f" avg_tools={item['avg_tools']} ({item['known_tool_runs']} known)"
                if item["known_tool_runs"]
                else ""
            )
            print(
                f"  {item['requested']} -> {item['effective']}: runs={item['runs']} success={item['success_rate']}% avg_delta={item['avg_delta']:+}{tools}"
            )

    if summary["top_chains"]:
        print("\nTop Provider Chains")
        for item in summary["top_chains"]:
            print(f"  {item['chain']}: {item['runs']}")


if __name__ == "__main__":
    main()

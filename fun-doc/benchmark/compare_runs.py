"""Diff two benchmark run JSON files into a terminal table.

Usage:
    python compare_runs.py runs/<before>.json runs/<after>.json
    python compare_runs.py runs/<before>.json runs/latest.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _delta_arrow(delta: float, positive_good: bool = True) -> str:
    """Up arrow for improvement, down for regression, matching user expectation.

    For 'positive-is-good' metrics (quality), delta > 0 is an improvement.
    For 'lower-is-better' metrics (tool_calls), delta < 0 is an improvement.
    """
    eps = 1e-9
    if abs(delta) < eps:
        return " "
    improved = (delta > 0) if positive_good else (delta < 0)
    return "+" if improved else "-"


def diff_runs(prior: dict[str, Any], curr: dict[str, Any]) -> None:
    print()
    print(
        f"  BENCHMARK DIFF   {prior.get('timestamp', '?')}  ->  {curr.get('timestamp', '?')}"
    )
    pc = prior.get("commit") or "?"
    cc = curr.get("commit") or "?"
    print(f"  commit           {pc}  ->  {cc}")
    print(f"  tier             {prior.get('tier')}  ->  {curr.get('tier')}")
    mock_note = ""
    if prior.get("mock") or curr.get("mock"):
        mock_note = "   (mock fixtures)"
    print(f"  mode             mock={prior.get('mock')} -> mock={curr.get('mock')}{mock_note}")
    print()

    # Per-function diff. Iterate union of function names.
    all_fns = sorted(set(prior.get("functions", {}).keys()) | set(curr.get("functions", {}).keys()))
    improved = regressed = unchanged = 0
    rows = []

    for fn in all_fns:
        prior_fn = prior.get("functions", {}).get(fn, {})
        curr_fn = curr.get("functions", {}).get(fn, {})
        # Walking skeleton has one provider per function; take the first. A
        # future --full run will produce multiple and we'll iterate them.
        if not prior_fn or not curr_fn:
            state = "NEW" if not prior_fn else "GONE"
            rows.append((fn, state, "", "", ""))
            continue
        prov = next(iter(curr_fn.keys()))
        prior_rec = prior_fn.get(prov) or next(iter(prior_fn.values()), {})
        curr_rec = curr_fn[prov]

        q_before = prior_rec.get("quality", 0.0)
        q_after = curr_rec.get("quality", 0.0)
        delta = q_after - q_before
        if abs(delta) < 0.001:
            unchanged += 1
            state = " "
        elif delta > 0:
            improved += 1
            state = "+"
        else:
            regressed += 1
            state = "-"

        # What dimensions moved? List the top-2 movers to explain the delta.
        movers = _dimension_movers(prior_rec, curr_rec, top=2)
        rows.append((fn, state, q_before, q_after, movers))

    print(
        f"  {'function':30s}  {'before':>6s}  {'after':>6s}  {'delta':>6s}   {'movers'}"
    )
    print(f"  {'-' * 30}  {'-' * 6}  {'-' * 6}  {'-' * 6}   {'-' * 40}")
    for fn, state, before, after, movers in rows:
        if state in ("NEW", "GONE"):
            print(f"  {fn[:30]:30s}  [{state}]")
            continue
        delta = after - before
        sign = _delta_arrow(delta, positive_good=True)
        print(
            f"{sign} {fn[:30]:30s}  {before:6.3f}  {after:6.3f}  "
            f"{delta:+6.3f}   {movers}"
        )

    print()
    print(f"  {improved} improved    {regressed} regressed    {unchanged} unchanged")

    # Aggregate guardrails
    pa = prior.get("aggregate", {})
    ca = curr.get("aggregate", {})

    def _cmp(key: str, positive_good: bool, fmt: str = "{:.3f}"):
        pv = pa.get(key)
        cv = ca.get(key)
        if pv is None or cv is None:
            return
        delta = cv - pv
        sign = _delta_arrow(delta, positive_good=positive_good)
        print(f"  {sign} {key:36s}  {fmt.format(pv):>10s}  ->  {fmt.format(cv):>10s}  ({delta:+.3f})")

    print()
    _cmp("quality_mean", positive_good=True)
    _cmp("tool_calls_per_quality_point", positive_good=False, fmt="{:.2f}")
    _cmp("duplicate_tool_call_ratio", positive_good=False)
    _cmp("wall_time_sec_total", positive_good=False, fmt="{:.1f}s")
    _cmp("tool_calls_total", positive_good=False, fmt="{:d}")


def _dimension_movers(prior: dict, curr: dict, top: int = 2) -> str:
    """Return a short 'name -0.20, plate +0.15' summary of the largest deltas."""
    pd = (prior.get("dimensions") or {})
    cd = (curr.get("dimensions") or {})
    deltas = []
    for dim in ("name", "signature", "plate", "algorithm", "locals"):
        p = (pd.get(dim) or {}).get("score", 0.0)
        c = (cd.get(dim) or {}).get("score", 0.0)
        d = c - p
        if abs(d) >= 0.05:
            deltas.append((dim, d))
    deltas.sort(key=lambda x: abs(x[1]), reverse=True)
    return ", ".join(f"{dim}{d:+.2f}" for dim, d in deltas[:top])


def main():
    ap = argparse.ArgumentParser(description="Diff two fun-doc benchmark runs")
    ap.add_argument("before", type=Path)
    ap.add_argument("after", type=Path)
    args = ap.parse_args()

    prior = json.loads(args.before.read_text(encoding="utf-8"))
    curr = json.loads(args.after.read_text(encoding="utf-8"))
    diff_runs(prior, curr)


if __name__ == "__main__":
    main()

"""Fun-doc benchmark runner.

Orchestrates: for each baseline function in the selected tier, capture
the worker's output (either from a stored fixture under --mock, or by
invoking fun-doc end-to-end under --real), score it against ground
truth, aggregate guardrails, and emit a timestamped run JSON plus
update runs/latest.json.

Walking skeleton status:
  * --mock path is fully implemented. Reads captures from
    fixtures/<function>.<variant>.capture.json and scores them. This
    is what CI and the smoke test exercise.
  * --real path is stubbed. Wiring it up is Phase 2 work — requires:
      - Benchmark.dll imported into a dedicated Ghidra project
      - A reset_ghidra script that restores a pristine state between suites
      - fun-doc's process_function driven from outside the worker loop
      - Ghidra MCP scraping of the resulting name / plate / signature /
        locals for each target function
    The stub raises NotImplementedError with a clear message so the flag
    doesn't silently succeed with bogus data.

Usage:
    python run_benchmark.py --mock
    python run_benchmark.py --mock --variant baseline --compare
    python run_benchmark.py --tier fast --real           # Phase 2
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from scorer import guardrails, score_function


BENCHMARK_DIR = Path(__file__).resolve().parent
GROUND_TRUTH_FILE = BENCHMARK_DIR / "ground_truth.json"
FIXTURES_DIR = BENCHMARK_DIR / "fixtures"
RUNS_DIR = BENCHMARK_DIR / "runs"
SUITES_DIR = BENCHMARK_DIR / "suites"
LATEST_FILE = RUNS_DIR / "latest.json"


def _git_commit() -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(BENCHMARK_DIR),
            text=True,
            stderr=subprocess.DEVNULL,
        )
        return out.strip()
    except Exception:
        return None


def _load_ground_truth() -> dict[str, Any]:
    if not GROUND_TRUTH_FILE.is_file():
        raise RuntimeError(
            f"{GROUND_TRUTH_FILE} not found. Run extract_truth.py first."
        )
    return json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))


def _tier_function_names(tier: str) -> list[str]:
    """Return the list of function names the given tier should benchmark.

    For the walking skeleton there's only one function (calc_crc16) and
    no suite yaml yet. Once we add suites/*.yaml the tier-> function
    resolution will move into a load-suite step.
    """
    gt = _load_ground_truth()
    all_fns = list(gt.get("functions", {}).keys())
    if tier == "fast":
        return all_fns[:5]
    if tier == "core":
        return all_fns[:15]
    if tier == "stretch":
        return all_fns[:50]
    if tier == "all":
        return all_fns
    raise ValueError(f"unknown tier {tier!r}; expected fast/core/stretch/all")


# ---------- Capture backends ----------


def _capture_mock(fn_name: str, variant: str) -> tuple[dict, list[dict], float]:
    """Load a pre-recorded capture fixture.

    Returns (captured_state, tool_calls, wall_time_sec) for the function.
    """
    fixture = FIXTURES_DIR / f"{fn_name}.{variant}.capture.json"
    if not fixture.is_file():
        raise RuntimeError(
            f"Fixture not found: {fixture}. Create one or pass a different --variant."
        )
    data = json.loads(fixture.read_text(encoding="utf-8"))
    return (
        data.get("captured", {}),
        data.get("tool_calls", []),
        float(data.get("wall_time_sec", 0.0)),
    )


def _capture_real(fn_name: str, provider: str, model: Optional[str]) -> tuple[dict, list[dict], float]:
    """Invoke fun-doc on the benchmark function and scrape Ghidra for the result.

    Phase 2 — stubbed. Implementing this requires:
      1. A dedicated Ghidra project with Benchmark.dll imported and
         default-analyzed. Path configurable via FUNDOC_BENCHMARK_PROJECT.
      2. A reset_ghidra.py Ghidra script (triggered via run_ghidra_script
         MCP) that clears prior documentation — rename -> FUN_<addr>,
         clear plate, clear EOL comments, reset local types to undefined.
      3. Direct invocation of fun_doc.process_function on the target
         function key (bypassing the priority-queue worker loop so the
         benchmark targets exactly one function per call).
      4. MCP-side scraping after the run: get_function_signature,
         get_plate_comment, get_function_variables.
    """
    raise NotImplementedError(
        "--real path not implemented yet (walking skeleton uses --mock). "
        "Implementing requires: Benchmark.dll imported into a dedicated Ghidra "
        "project; reset_ghidra.py script; direct process_function invocation; "
        "MCP state scrape. Tracked under the 'promote from skeleton' milestone."
    )


# ---------- Orchestration ----------


def run(
    tier: str,
    mock: bool,
    variant: str,
    provider: str,
    model: Optional[str],
    full_matrix: bool,
) -> dict[str, Any]:
    gt = _load_ground_truth()
    fn_names = _tier_function_names(tier)
    if not fn_names:
        raise RuntimeError(f"Tier {tier!r} has no functions.")

    providers = (
        # --full matrix enumerates all providers listed in the queue config.
        # Walking skeleton: just use whatever --provider picked (and mock's
        # fixture doesn't differ by provider anyway).
        _providers_from_queue_config() if full_matrix else [provider]
    )

    run_record: dict[str, Any] = {
        "version": 1,
        "timestamp": _dt.datetime.now().isoformat(timespec="seconds"),
        "commit": _git_commit(),
        "tier": tier,
        "providers": providers,
        "mock": mock,
        "variant": variant if mock else None,
        "functions": {},
        "aggregate": {},
    }

    all_qualities = []
    tool_calls_total = 0
    wall_time_total = 0.0
    all_tool_call_records: list[dict] = []

    for fn_name in fn_names:
        truth = gt["functions"].get(fn_name)
        if truth is None:
            print(f"  SKIP: {fn_name} has no ground truth", file=sys.stderr)
            continue

        for prov in providers:
            if mock:
                captured, tool_calls, wall_time = _capture_mock(fn_name, variant)
            else:
                captured, tool_calls, wall_time = _capture_real(fn_name, prov, model)

            scored = score_function(captured, truth)
            gr = guardrails(tool_calls, scored["quality"])
            run_record["functions"].setdefault(fn_name, {})[prov] = {
                "provider": prov,
                "model": model,
                "wall_time_sec": round(wall_time, 2),
                "quality": scored["quality"],
                "dimensions": scored["dimensions"],
                "weights": scored["weights"],
                "tool_calls_total": gr["tool_calls_total"],
                "tool_calls_per_quality_point": gr["tool_calls_per_quality_point"],
                "duplicate_tool_call_ratio": gr["duplicate_tool_call_ratio"],
                "captured": captured,
            }
            all_qualities.append(scored["quality"])
            tool_calls_total += gr["tool_calls_total"]
            wall_time_total += wall_time
            all_tool_call_records.extend(tool_calls)

    agg_q = sum(all_qualities) / len(all_qualities) if all_qualities else 0.0
    agg_guardrails = guardrails(all_tool_call_records, agg_q)
    run_record["aggregate"] = {
        "quality_mean": round(agg_q, 3),
        "wall_time_sec_total": round(wall_time_total, 2),
        "tool_calls_total": agg_guardrails["tool_calls_total"],
        "tool_calls_per_quality_point": agg_guardrails["tool_calls_per_quality_point"],
        "duplicate_tool_call_ratio": agg_guardrails["duplicate_tool_call_ratio"],
        "function_count": len(run_record["functions"]),
    }
    return run_record


def _providers_from_queue_config() -> list[str]:
    """Read priority_queue.config.provider_models for the provider list.

    Walking skeleton: if the queue config is unreadable, fall back to
    the single workhorse. `--full` is rarely used during the skeleton.
    """
    try:
        queue_file = BENCHMARK_DIR.parent / "priority_queue.json"
        if not queue_file.is_file():
            return ["minimax"]
        queue = json.loads(queue_file.read_text(encoding="utf-8"))
        models = (queue.get("config") or {}).get("provider_models") or {}
        provs = [p for p in models.keys() if isinstance(p, str)]
        return provs or ["minimax"]
    except Exception:
        return ["minimax"]


def _print_aggregate_table(run: dict[str, Any]):
    """Compact one-liner-per-function summary printed after a run."""
    agg = run["aggregate"]
    print()
    print(
        f"  {'function':30s}  {'provider':10s}  "
        f"{'qual':>5s}  {'tc':>4s}  {'tc/qp':>6s}  {'dup':>5s}  {'wall':>6s}"
    )
    print(f"  {'-' * 30}  {'-' * 10}  {'-' * 5}  {'-' * 4}  {'-' * 6}  {'-' * 5}  {'-' * 6}")
    for fn, per_prov in run["functions"].items():
        for prov, rec in per_prov.items():
            print(
                f"  {fn[:30]:30s}  {prov[:10]:10s}  "
                f"{rec['quality']:5.2f}  "
                f"{rec['tool_calls_total']:4d}  "
                f"{rec['tool_calls_per_quality_point'] or 0:6.2f}  "
                f"{rec['duplicate_tool_call_ratio']:5.2f}  "
                f"{rec['wall_time_sec']:5.1f}s"
            )
    print()
    print(
        f"  aggregate  quality_mean={agg['quality_mean']:.3f}  "
        f"tc_total={agg['tool_calls_total']}  "
        f"tc/qp={agg['tool_calls_per_quality_point'] or 0:.2f}  "
        f"dup_ratio={agg['duplicate_tool_call_ratio']:.3f}  "
        f"wall_total={agg['wall_time_sec_total']:.1f}s"
    )


def _write_run(run: dict[str, Any]) -> Path:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    # Include microseconds so two runs in the same second get distinct
    # filenames. The iso timestamp in the JSON body keeps second-level
    # precision for readability; the filename needs finer resolution to
    # preserve history when runs stack up during iterative work.
    now = _dt.datetime.now()
    stamp = now.strftime("%Y%m%dT%H%M%S_%f")
    path = RUNS_DIR / f"{stamp}.json"
    path.write_text(json.dumps(run, indent=2), encoding="utf-8")
    shutil.copyfile(path, LATEST_FILE)
    return path


def _snapshot_prior_latest() -> Optional[dict[str, Any]]:
    """Capture the current latest.json BEFORE we overwrite it.

    --compare needs "what was latest right before this run". Reading
    latest.json after writing is circular. Reading before is clean.
    """
    if not LATEST_FILE.is_file():
        return None
    try:
        return json.loads(LATEST_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _maybe_compare(run: dict[str, Any], prior: Optional[dict[str, Any]]):
    """Diff current run against a prior run snapshot."""
    if prior is None:
        print("  (no prior run available for comparison)")
        return
    from compare_runs import diff_runs
    diff_runs(prior, run)


def main():
    ap = argparse.ArgumentParser(description="Run fun-doc benchmark")
    ap.add_argument("--tier", default="fast", choices=["fast", "core", "stretch", "all"])
    ap.add_argument(
        "--mock",
        action="store_true",
        help="Walking-skeleton mode: read captures from fixtures/ instead of invoking fun-doc",
    )
    ap.add_argument(
        "--variant",
        default="baseline",
        help="Which mock fixture variant to use (reads fixtures/<fn>.<variant>.capture.json)",
    )
    ap.add_argument("--provider", default="minimax")
    ap.add_argument("--model", default=None)
    ap.add_argument(
        "--full",
        action="store_true",
        help="Run every provider listed in priority_queue config instead of just --provider",
    )
    ap.add_argument(
        "--compare",
        action="store_true",
        help="After writing the run, diff it against the previous latest",
    )
    args = ap.parse_args()

    if not args.mock:
        # The --real path is unimplemented for the walking skeleton.
        # Make that explicit; don't silently succeed with nonsense data.
        _capture_real("", args.provider, args.model)

    # Snapshot the CURRENT latest.json now, before we overwrite it —
    # that's the "prior" the --compare flag should diff against.
    prior_snapshot = _snapshot_prior_latest() if args.compare else None

    run_record = run(
        tier=args.tier,
        mock=args.mock,
        variant=args.variant,
        provider=args.provider,
        model=args.model,
        full_matrix=args.full,
    )
    path = _write_run(run_record)
    _print_aggregate_table(run_record)
    print(f"\n  wrote {path}")
    print(f"  wrote {LATEST_FILE}")

    if args.compare:
        _maybe_compare(run_record, prior_snapshot)


if __name__ == "__main__":
    main()

"""The benchmark pipeline, end to end, with the providers replayed.

This is the CI-safe half of the undocumented -> documented gate. It runs the
REAL runner, the REAL scorer and the REAL aggregation over pre-captured
provider output, then applies the floors to the result. Nothing is stubbed
except the provider itself.

What it proves: the plumbing. A change that breaks capture loading, scoring,
dimension weighting, aggregation or the run-JSON shape fails here, in
seconds, with no Ghidra and no tokens.

What it does NOT prove: documentation quality. The captures are fixed, so
the score is fixed; a prompt regression is invisible here by construction.
That is what the `--real-provider` tier is for, and why the two are separate
markers rather than one suite with a flag.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import floors

pytestmark = pytest.mark.benchmark_e2e


@pytest.fixture
def mock_run(tmp_path: Path, monkeypatch):
    """Execute the real runner over the committed fixtures.

    `runs/` is redirected into tmp_path: a test must never append to the
    run history or rewrite `runs/latest.json`, which is the committed
    baseline that `git blame` is supposed to tie to a specific commit.
    """
    import run_benchmark

    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    monkeypatch.setattr(run_benchmark, "RUNS_DIR", runs_dir)
    monkeypatch.setattr(run_benchmark, "LATEST_FILE", runs_dir / "latest.json")

    return run_benchmark.run(
        tier="fast",
        mock=True,
        variant="baseline",
        provider="minimax",
        model=None,
        full_matrix=False,
    )


# --------------------------------------------------------------------------
# the run itself
# --------------------------------------------------------------------------


def test_the_pipeline_produces_a_scored_run(mock_run):
    assert mock_run["functions"], "the runner scored nothing"
    assert mock_run["aggregate"]["function_count"] == len(mock_run["functions"])


def test_every_fast_tier_function_was_scored(mock_run):
    """The fast tier's five archetypes: CRC, state machine, strlen, struct
    mutator, recursion. A tier that silently scores four of five still
    reports a mean."""
    expected = {
        "calc_crc16",
        "advance_parser_state",
        "compute_str_len",
        "stat_list_add",
        "compute_gcd",
    }
    assert set(mock_run["functions"]) == expected


def test_quality_is_a_real_number_in_range(mock_run):
    mean = mock_run["aggregate"]["quality_mean"]
    assert isinstance(mean, (int, float))
    assert 0.0 <= mean <= 1.0, f"quality_mean {mean} outside 0-1"
    for name, entry in mock_run["functions"].items():
        for provider, result in entry.items():
            q = result["quality"]
            assert 0.0 <= q <= 1.0, f"{name}/{provider} scored {q}, outside 0-1"


def test_every_scoring_dimension_is_present(mock_run):
    """A dimension silently dropping to nothing would move the mean without
    any obvious symptom."""
    required = {"name", "signature", "plate", "algorithm", "locals"}
    for name, entry in mock_run["functions"].items():
        for provider, result in entry.items():
            missing = required - set(result["dimensions"])
            assert not missing, f"{name}/{provider} lost dimensions: {sorted(missing)}"


def test_guardrail_metrics_are_computed(mock_run):
    agg = mock_run["aggregate"]
    for key in ("tool_calls_total", "duplicate_tool_call_ratio"):
        assert key in agg, f"aggregate lost the {key!r} guardrail"


# --------------------------------------------------------------------------
# the floors applied to a real run
# --------------------------------------------------------------------------


def test_the_baseline_fixtures_clear_the_non_convention_floors(mock_run, authored_functions):
    """The committed baseline captures must pass everything that is not a
    fun-doc convention assertion.

    Convention checks are skipped here for the reason documented on
    `floors.CONVENTION_CHECKS`: these captures are hand-authored artifacts,
    so asserting fun-doc's plate/type conventions against them would be
    testing the fixture author.
    """
    report = floors.evaluate(
        mock_run,
        baseline=None,
        authored=authored_functions,
        library_claims=[],
        skip_checks=floors.CONVENTION_CHECKS,
    )
    assert report.ok, report.format()


def test_a_name_regression_in_the_pipeline_would_be_caught(mock_run):
    """Sabotage the run and confirm the gate fires.

    Without this, "the floors passed" is unfalsifiable -- the same green tick
    would appear if `evaluate` silently examined nothing.
    """
    sabotaged = json.loads(json.dumps(mock_run))
    first = next(iter(sabotaged["functions"]))
    provider = next(iter(sabotaged["functions"][first]))
    sabotaged["functions"][first][provider]["captured"]["name"] = "FUN_10001010"

    report = floors.evaluate(sabotaged, skip_checks=floors.CONVENTION_CHECKS)
    assert not report.ok
    assert any(v.floor == "name-applied" for v in report.mechanical)


def test_the_run_is_comparable_against_the_committed_baseline(mock_run, baseline_run):
    """The mock path must stay stable against `runs/latest.json`.

    Same fixtures in, same score out. A drift here is a scorer or weighting
    change, and it should be a deliberate, reviewed one -- which is exactly
    why `runs/latest.json` is committed alongside the code change.
    """
    if baseline_run is None:
        pytest.skip("no runs/latest.json on this machine yet")
    if not baseline_run.get("mock"):
        pytest.skip("runs/latest.json is from a --real run; not comparable")
    violations = floors.check_semantic_delta(mock_run, baseline_run)
    assert not violations, "\n".join(str(v) for v in violations)


def test_the_runner_did_not_touch_the_committed_run_history():
    """`runs/latest.json` is the baseline `git blame` ties to a commit.

    A test that rewrote it would destroy the one artifact that tells you
    which change moved a score.
    """
    latest = Path(__file__).resolve().parents[2] / "fun-doc" / "benchmark" / "runs" / "latest.json"
    if not latest.is_file():
        pytest.skip("no committed baseline to protect")
    payload = json.loads(latest.read_text(encoding="utf-8"))
    assert "aggregate" in payload, "runs/latest.json was overwritten by a test run"

"""Offline tests for the CONF_* backfill planner's safety rules.

The planner decides ~2,400 Ghidra tag writes across D2Client/D2Common. Every
rule that can silently corrupt that set lives in the pure `decide()` function,
so it is tested here without Ghidra or state.db.

The rules exist because of specific incidents:
  * promote-only -- D2Common has 33 CONF_BATTLETESTED functions whose
    port_status is still an earlier stage; a naive map would demote them.
  * BLOCKED-never-overwrites -- CONF_BLOCKED is OFF-ladder, so comparing it by
    rung strength would let a stale "stateful_skip" erase a real live proof.
  * quarantine -- the wrong-binary default (fixed 2026-07-27) mis-recorded
    proofs under program="D2Common.dll"; those must be re-proven, not tagged.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

_PLANNER = (Path(__file__).resolve().parents[2]
            / "fun-doc" / "scripts" / "plan_conf_backfill.py")


@pytest.fixture(scope="module")
def planner():
    """Import the planner by path -- fun-doc/ isn't a package on sys.path, and
    importing it must not require requests to reach a live Ghidra."""
    if not _PLANNER.exists():
        pytest.skip(f"planner not found at {_PLANNER}")
    spec = importlib.util.spec_from_file_location("plan_conf_backfill", _PLANNER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["plan_conf_backfill"] = mod
    spec.loader.exec_module(mod)
    return mod


# --- the mapping itself -----------------------------------------------------

def test_static_harness_pass_maps_to_vectors(planner):
    """The 35 D2Client `proven_pending_review` rows are static-harness passes.
    They are CONF_VECTORS -- not CONF_LIVE; no game process was involved."""
    bucket, rung, _ = planner.decide("proven_pending_review", None)
    assert (bucket, rung) == ("promote", "CONF_VECTORS")


def test_live_prove_maps_to_live(planner):
    for status in ("proven_live_pending_review", "proven_live"):
        bucket, rung, _ = planner.decide(status, None)
        assert (bucket, rung) == ("promote", "CONF_LIVE"), status


def test_blocked_statuses_carry_a_reason(planner):
    """CONF_BLOCKED is only useful if it says WHY -- the reason is what makes it
    a work queue for the next oracle capability rather than a dead end."""
    for status, reason in [("stateful_skip", "stateful"),
                           ("unsupported_abi", "unsupported_abi"),
                           ("no_vectors", "no_vectors"),
                           ("handle_abort_hazard_skip", "abort_hazard")]:
        bucket, rung, got = planner.decide(status, None)
        assert (bucket, rung, got) == ("promote", "CONF_BLOCKED", reason), status


def test_transient_failures_do_not_change_the_rung(planner):
    """A failed attempt is not a rung. The candidate was deleted; the detail
    lives in port_status."""
    for status in ("live_prove_failed", "harness_failed", "malformed_response", "error"):
        bucket, rung, _ = planner.decide(status, None)
        assert (bucket, rung) == ("skipped_no_rung", None), status


def test_unmapped_status_is_reported_not_guessed(planner):
    bucket, rung, reason = planner.decide("some_future_status", None)
    assert bucket == "skipped_no_rung" and rung is None
    assert "unmapped" in reason


# --- the safety rules -------------------------------------------------------

def test_never_demotes_an_earned_rung(planner):
    """A CONF_BATTLETESTED function whose SQL still says shadow_leaf_pending
    keeps its rung."""
    bucket, _, _ = planner.decide("shadow_leaf_pending", "CONF_BATTLETESTED")
    assert bucket == "skipped_demotion"
    bucket, _, _ = planner.decide("proven_pending_review", "CONF_LIVE")
    assert bucket == "skipped_demotion"


def test_blocked_never_overwrites_a_ladder_rung(planner):
    """CONF_BLOCKED is off-ladder. A stale stateful_skip must not erase a proof
    earned via the live/shadow path -- it means the SQL row is stale."""
    for cur in ("CONF_LIVE", "CONF_BATTLETESTED", "CONF_VECTORS"):
        bucket, rung, _ = planner.decide("stateful_skip", cur)
        assert (bucket, rung) == ("stale_sql_proven", None), cur


def test_quarantine_beats_every_other_rule(planner):
    """A misattributed proof is quarantined even when it would otherwise be a
    clean promotion -- the proof ran under a mis-set program argument."""
    bucket, rung, reason = planner.decide(
        "proven_live_pending_review", None, misattributed="D2Common.dll")
    assert (bucket, rung) == ("quarantined", None)
    assert "re-prove" in reason


def test_out_of_scope_never_enters_the_ladder(planner):
    """LIB_CRT/THUNK/STUB are excluded from the ladder AND the denominator --
    not even CONF_BLOCKED."""
    bucket, rung, _ = planner.decide("stateful_skip", None, out_of_scope=True)
    assert (bucket, rung) == ("skipped_out_of_scope", None)


def test_idempotent_when_tag_already_matches(planner):
    """Re-running the backfill must not re-write tags that are already right."""
    bucket, _, _ = planner.decide("proven_pending_review", "CONF_VECTORS")
    assert bucket == "already_correct"


# --- ladder invariants ------------------------------------------------------

def test_ladder_is_ordered_low_to_high(planner):
    assert planner.CONF_LADDER == [
        "CONF_DRAFT", "CONF_VECTORS", "CONF_LIVE",
        "CONF_VETTED", "CONF_BATTLETESTED", "CONF_SHIPPED",
    ]
    strengths = [planner._rung_strength(t) for t in planner.CONF_LADDER]
    assert strengths == sorted(strengths)


def test_blocked_is_off_ladder(planner):
    """-1, so it can never win a strength comparison against a real rung."""
    assert planner._rung_strength(planner.CONF_BLOCKED) == -1


def test_legacy_regression_sorts_top_so_it_is_never_demoted(planner):
    """CONF_REGRESSION is retired (now a `regression_frozen` property flag), but
    3 functions still carry it. It must outrank everything until retagged."""
    assert planner._rung_strength("CONF_REGRESSION") >= max(
        planner._rung_strength(t) for t in planner.CONF_LADDER)


# --- CONF_REFUTED: falsification (added 2026-07-29) -------------------------

def test_refutation_demotes_from_any_earned_rung(planner):
    import conf_ladder
    for cur in conf_ladder.CONF_LADDER:
        demote, rung, rec = conf_ladder.decide_refutation(cur, "shadow_divergence")
        assert demote and rung == conf_ladder.CONF_REFUTED, cur
        assert rec["refuted_from"] == cur and rec["source"] == "shadow_divergence"


def test_refutation_preserves_the_counterexample(planner):
    """The whole reason CONF_REFUTED is distinct from CONF_DRAFT -- lose the
    counterexample and the next pass re-promotes the same broken reimpl."""
    import conf_ladder
    ce = {"input": 7, "expected": 3, "actual": 4}
    _d, _r, rec = conf_ladder.decide_refutation("CONF_LIVE", "shadow_divergence", ce)
    assert rec["counterexample"] == ce


def test_nothing_to_refute_when_no_rung_is_held(planner):
    import conf_ladder
    for cur in (None, conf_ladder.CONF_BLOCKED, conf_ladder.CONF_REFUTED):
        assert conf_ladder.decide_refutation(cur, "shadow_divergence")[0] is False, cur


def test_unknown_refutation_source_is_rejected(planner):
    import conf_ladder
    with pytest.raises(ValueError):
        conf_ladder.decide_refutation("CONF_LIVE", "vibes")


def test_refuted_function_is_never_silently_re_promoted(planner):
    """The regression loop this state exists to break: re-draft -> re-prove on
    its own vectors -> re-promote the reimpl the divergence disproved."""
    import conf_ladder
    for status in ("shadow_leaf_pending", "proven_pending_review",
                   "proven_live_pending_review", "proven_live"):
        bucket, rung, _ = conf_ladder.decide(status, conf_ladder.CONF_REFUTED)
        assert (bucket, rung) == ("skipped_refuted", None), status


def test_refuted_is_off_ladder(planner):
    import conf_ladder
    assert conf_ladder.rung_strength(conf_ladder.CONF_REFUTED) == -1


# --- promotion thresholds: volume AND diversity -----------------------------

def test_high_volume_low_diversity_does_not_promote(planner):
    """'1M calls with 3 inputs is not coverage' -- the exact case the plan warns
    about, and the reason NET_MapMessageIdToCommand needed a diversity floor."""
    import conf_ladder
    assert conf_ladder.meets_promotion_bar("CONF_BATTLETESTED", 1_000_000, 3) is False


def test_both_thresholds_must_be_met(planner):
    import conf_ladder
    assert conf_ladder.meets_promotion_bar("CONF_BATTLETESTED", 1_000, 20) is True
    assert conf_ladder.meets_promotion_bar("CONF_BATTLETESTED", 999, 20) is False
    assert conf_ladder.meets_promotion_bar("CONF_BATTLETESTED", 1_000, 19) is False


def test_shipped_needs_the_higher_volume_bar(planner):
    import conf_ladder
    assert conf_ladder.meets_promotion_bar("CONF_SHIPPED", 1_000, 50) is False
    assert conf_ladder.meets_promotion_bar("CONF_SHIPPED", 10_000, 50) is True


def test_lower_rungs_are_not_volume_gated(planner):
    import conf_ladder
    for rung in ("CONF_DRAFT", "CONF_VECTORS", "CONF_LIVE", "CONF_VETTED"):
        assert conf_ladder.meets_promotion_bar(rung, 0, 0) is True, rung


# --- saturation, replacing the retired input_domain approach (2026-07-29) ---

def test_flat_floor_applies_when_not_saturated(planner):
    import conf_ladder
    assert conf_ladder.effective_distinct_floor("CONF_BATTLETESTED") == 20
    assert conf_ladder.meets_promotion_bar("CONF_BATTLETESTED", 5000, 3) is False


def test_saturation_waives_the_diversity_floor(planner):
    """3 distinct IS 100% of reachable coverage once the space stops yielding
    new inputs. Requiring 20 would be requiring the impossible."""
    import conf_ladder
    assert conf_ladder.effective_distinct_floor("CONF_BATTLETESTED", saturated=True) == 0
    assert conf_ladder.meets_promotion_bar(
        "CONF_BATTLETESTED", 5000, 3, saturated=True) is True


def test_saturation_never_waives_the_volume_bar(planner):
    """The whole point of the volume bar survives saturation."""
    import conf_ladder
    assert conf_ladder.meets_promotion_bar(
        "CONF_BATTLETESTED", 999, 3, saturated=True) is False
    assert conf_ladder.meets_promotion_bar(
        "CONF_SHIPPED", 5000, 3, saturated=True) is False
    assert conf_ladder.meets_promotion_bar(
        "CONF_SHIPPED", 10000, 3, saturated=True) is True


def test_is_saturated_needs_a_watermark(planner):
    """No recorded watermark -> cannot claim saturation."""
    import conf_ladder
    assert conf_ladder.is_saturated(10_000, None) is False


def test_is_saturated_measures_calls_since_last_new_input(planner):
    import conf_ladder
    n = conf_ladder.SATURATION_HITS
    assert conf_ladder.is_saturated(1000 + n - 1, 1000) is False
    assert conf_ladder.is_saturated(1000 + n, 1000) is True


def test_zero_arg_still_exempt(planner):
    import conf_ladder
    assert conf_ladder.effective_distinct_floor("CONF_BATTLETESTED", argc=0) == 0

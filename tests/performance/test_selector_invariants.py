"""
Regression tests for fun-doc's select_candidates() selector invariants.

select_candidates is the single source of truth for worker pick order. Bugs
here manifest as "worker keeps processing the same function" or "worker picks
already-done functions" — both of which we hit this session.

Rules the selector must maintain (from the docstring + hard-won experience):
  1. Thunks and externals are always excluded
  2. score >= good_enough_score → excluded (unless pinned or needs_scoring)
  3. fixable <= 0 and not pinned → excluded (nothing concrete to fix)
  4. consecutive_fails >= 3 and not pinned → excluded (stuck function)
  5. active_binary filter: drop any func from a different binary
  6. needs_scoring=True only when require_scored=True AND last_processed=None
  7. pinned functions sort first, in pin order
  8. low-completeness boost: (good_enough - score) * 2 added to ROI when
     score < good_enough AND fixable > 0
  9. partial_runs >= 3 deprioritizes by 0.1x multiplier (not pinned)
 10. recovery_pass_done=True and not pinned → excluded (one-shot recovery
     pass — stops re-queue-forever loop on massive functions that cost
     opus tokens without reaching good_enough_score)
 11. decompile_timeout=True and not pinned → excluded (one-shot pathological
     function blacklist — decompile exceeds the 12s scoring-path cap, so
     re-picking just wastes HTTP thread time)
 12. stagnation_runs >= 3 and not pinned → excluded (general safety net for
     infinite re-pick loops where the function completes but makes no
     meaningful progress — catches the codex-tool_calls=-1 loop, regression
     oscillations, and "all fixes applied but scorer floor is dominating")

These tests exercise each rule independently with synthetic state. Fast, pure
Python, no network, no Ghidra.
"""
import sys
from pathlib import Path

import pytest

# Ensure fun-doc is importable
FUN_DOC = Path(__file__).parent.parent.parent / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

from fun_doc import select_candidates  # noqa: E402


def _func(**overrides):
    """Build a synthetic function entry with sensible defaults."""
    base = {
        "program": "/test/p",
        "program_name": "p",
        "address": "1000",
        "name": "TestFunc",
        "score": 50,
        "fixable": 10.0,
        "caller_count": 5,
        "is_leaf": False,
        "classification": "worker",
        "is_thunk": False,
        "is_external": False,
        "last_processed": "2026-01-01T00:00:00",
        "last_result": None,
        "consecutive_fails": 0,
        "partial_runs": 0,
    }
    base.update(overrides)
    return base


def _state(**funcs):
    return {k: _func(**v) for k, v in funcs.items()}


def _queue(pinned=None, good_enough=80, require_scored=False):
    return {
        "pinned": list(pinned or []),
        "config": {
            "good_enough_score": good_enough,
            "require_scored": require_scored,
        },
    }


def _keys(candidates):
    return [c["key"] for c in candidates]


def test_thunks_always_excluded():
    state = _state(
        **{
            "a::1": {"is_thunk": True, "score": 10, "fixable": 50},
            "a::2": {"score": 10, "fixable": 50},
        }
    )
    result = select_candidates(state, _queue())
    assert _keys(result) == ["a::2"]


def test_externals_always_excluded():
    state = _state(
        **{
            "a::1": {"is_external": True, "score": 10, "fixable": 50},
            "a::2": {"score": 10, "fixable": 50},
        }
    )
    result = select_candidates(state, _queue())
    assert _keys(result) == ["a::2"]


def test_done_functions_excluded_unless_pinned():
    state = _state(
        **{
            "a::1": {"score": 95, "fixable": 0.0},  # done, no fix
            "a::2": {"score": 50, "fixable": 10},  # needs work
        }
    )
    # Unpinned done func is excluded
    result = select_candidates(state, _queue(good_enough=80))
    assert _keys(result) == ["a::2"]

    # Pinned done func is included (so auto-dequeue can drain it)
    result = select_candidates(state, _queue(pinned=["a::1"], good_enough=80))
    assert "a::1" in _keys(result)


def test_zero_fixable_excluded_when_not_pinned():
    state = _state(
        **{
            "a::1": {"score": 50, "fixable": 0.0},  # low score but nothing to fix
            "a::2": {"score": 50, "fixable": 10},
        }
    )
    result = select_candidates(state, _queue())
    assert _keys(result) == ["a::2"]

    # Pinned bypass
    result = select_candidates(state, _queue(pinned=["a::1"]))
    assert "a::1" in _keys(result)


def test_consecutive_fails_excluded_when_not_pinned():
    state = _state(
        **{
            "a::1": {"score": 50, "fixable": 10, "consecutive_fails": 3},
            "a::2": {"score": 50, "fixable": 10, "consecutive_fails": 2},
        }
    )
    result = select_candidates(state, _queue())
    assert _keys(result) == ["a::2"]


def test_active_binary_filter():
    state = _state(
        **{
            "a::1": {"program_name": "foo.dll", "fixable": 10},
            "a::2": {"program_name": "bar.dll", "fixable": 10},
            "a::3": {"program_name": "foo.dll", "fixable": 10},
        }
    )
    result = select_candidates(state, _queue(), active_binary="foo.dll")
    assert set(_keys(result)) == {"a::1", "a::3"}


def test_cold_start_lane_only_fires_when_require_scored_on():
    state = _state(
        **{
            "a::1": {"score": 0, "fixable": 0, "last_processed": None},
        }
    )
    # require_scored=False: still excluded because fixable=0
    result = select_candidates(state, _queue(require_scored=False))
    assert _keys(result) == []

    # require_scored=True: included with priority 1M
    result = select_candidates(state, _queue(require_scored=True))
    assert _keys(result) == ["a::1"]
    assert result[0]["roi"] == 1_000_000
    assert result[0]["needs_scoring"] is True


def test_cold_start_does_not_fire_for_processed_entries():
    """A function with last_processed set is not 'unscored' even if score=0."""
    state = _state(
        **{
            "a::1": {
                "score": 0,
                "fixable": 0,
                "last_processed": "2026-04-13T00:00:00",
            },
        }
    )
    result = select_candidates(state, _queue(require_scored=True))
    # Processed + zero fixable = skip
    assert _keys(result) == []


def test_pinned_sorts_first_in_pin_order():
    state = _state(
        **{
            "a::1": {"score": 40, "fixable": 10},
            "a::2": {"score": 40, "fixable": 10},
            "a::3": {"score": 40, "fixable": 10},
        }
    )
    # Pin in a specific order
    result = select_candidates(state, _queue(pinned=["a::3", "a::1"]))
    keys = _keys(result)
    # Both pinned first, in pin order
    assert keys[0] == "a::3"
    assert keys[1] == "a::1"
    # Non-pinned last
    assert keys[2] == "a::2"


def test_low_completeness_boost_beats_high_completeness_fixable():
    """A low-score function with modest fixable points should rank ABOVE a
    mid-score function with larger fixable points, because the boost adds
    (good_enough - score) * 2 to the former's ROI."""
    state = _state(
        **{
            "a::low": {"score": 20, "fixable": 3, "caller_count": 2},
            "a::mid": {"score": 50, "fixable": 10, "caller_count": 5},
        }
    )
    result = select_candidates(state, _queue(good_enough=80))
    keys = _keys(result)
    # Low-score with boost should beat mid-score without boost
    assert keys[0] == "a::low", (
        f"Expected low-completeness to rank first, got {keys}. "
        f"The completeness boost is not being applied correctly."
    )


def test_partial_runs_deprioritize_not_pinned():
    state = _state(
        **{
            "a::bad": {"score": 40, "fixable": 10, "partial_runs": 3},
            "a::ok": {"score": 40, "fixable": 10, "partial_runs": 0},
        }
    )
    result = select_candidates(state, _queue())
    keys = _keys(result)
    # The partial_runs penalty is 0.1x, so ok should rank higher
    assert keys[0] == "a::ok"


def test_empty_state_returns_empty():
    assert select_candidates({}, _queue()) == []


def test_selector_never_returns_duplicates():
    """Pathological test: ensure a key never appears twice in the output even
    under unusual pin/skip combinations."""
    state = _state(**{f"a::{i}": {"fixable": 10, "score": 40} for i in range(20)})
    result = select_candidates(state, _queue(pinned=["a::5", "a::10"]))
    keys = _keys(result)
    assert len(keys) == len(set(keys))


def test_recovery_pass_done_excluded_when_not_pinned():
    """Functions flagged with recovery_pass_done (one-shot recovery pass
    completed) must be excluded from selection unless pinned. This stops the
    re-queue-forever loop on complexity-forced recovery passes where massive
    functions legitimately can't reach good_enough_score in one pass."""
    state = _state(
        **{
            "a::done": {
                "score": 55,
                "fixable": 20,  # still has fixable points
                "recovery_pass_done": True,  # but recovery pass already ran
            },
            "a::fresh": {"score": 55, "fixable": 20},
        }
    )
    result = select_candidates(state, _queue())
    # The flagged function is skipped, fresh one remains
    assert _keys(result) == ["a::fresh"]


def test_recovery_pass_done_bypassed_by_pin():
    """Pinning a recovery-done function should restore it to the queue —
    the user has explicitly asked for it back."""
    state = _state(
        **{
            "a::done": {
                "score": 55,
                "fixable": 20,
                "recovery_pass_done": True,
            },
        }
    )
    # Not pinned: excluded
    assert _keys(select_candidates(state, _queue())) == []
    # Pinned: included (despite the flag)
    result = select_candidates(state, _queue(pinned=["a::done"]))
    assert _keys(result) == ["a::done"]


def test_decompile_timeout_excluded_when_not_pinned():
    """Functions flagged with decompile_timeout (pathological — Ghidra
    decompile exceeds the 12s scoring-path cap) must be excluded from
    selection unless pinned. This stops the selector from re-picking
    pathological functions that would just wedge the HTTP thread pool
    on every attempt."""
    state = _state(
        **{
            "a::timeout": {
                "score": 31,
                "fixable": 20,
                "decompile_timeout": True,
            },
            "a::fresh": {"score": 31, "fixable": 20},
        }
    )
    result = select_candidates(state, _queue())
    assert _keys(result) == ["a::fresh"]


def test_decompile_timeout_bypassed_by_pin():
    """Pinning a decompile-timeout function should restore it to the queue."""
    state = _state(
        **{
            "a::timeout": {
                "score": 31,
                "fixable": 20,
                "decompile_timeout": True,
            },
        }
    )
    # Not pinned: excluded
    assert _keys(select_candidates(state, _queue())) == []
    # Pinned: included (user wants to retry)
    result = select_candidates(state, _queue(pinned=["a::timeout"]))
    assert _keys(result) == ["a::timeout"]


def test_stagnation_runs_excluded_at_threshold():
    """Functions with stagnation_runs >= 3 must be excluded from selection
    unless pinned. This is the general safety net for any re-pick loop
    where the function completes but makes no meaningful progress — the
    observed real-world case was codex on GetUnitSoundId making 7 runs in
    2 hours with score oscillating between 57-61% (never reaching
    good_enough_score of 80)."""
    state = _state(
        **{
            "a::at_threshold": {
                "score": 60,
                "fixable": 30,
                "stagnation_runs": 3,  # hit the threshold
            },
            "a::over_threshold": {
                "score": 60,
                "fixable": 30,
                "stagnation_runs": 5,  # well over
            },
            "a::under_threshold": {
                "score": 60,
                "fixable": 30,
                "stagnation_runs": 2,  # still eligible
            },
            "a::fresh": {"score": 60, "fixable": 30},
        }
    )
    result = select_candidates(state, _queue())
    keys = _keys(result)
    # Both at-threshold and over-threshold are excluded
    assert "a::at_threshold" not in keys
    assert "a::over_threshold" not in keys
    # Under-threshold and fresh are still eligible
    assert "a::under_threshold" in keys
    assert "a::fresh" in keys


def test_stagnation_runs_bypassed_by_pin():
    """Pinning a stagnation-blacklisted function should restore it."""
    state = _state(
        **{
            "a::stuck": {
                "score": 60,
                "fixable": 30,
                "stagnation_runs": 5,
            },
        }
    )
    # Not pinned: excluded
    assert _keys(select_candidates(state, _queue())) == []
    # Pinned: included (user is asking to retry it despite stagnation)
    result = select_candidates(state, _queue(pinned=["a::stuck"]))
    assert _keys(result) == ["a::stuck"]


def test_stagnation_runs_does_not_affect_unflagged():
    """Sanity: the check only fires when stagnation_runs >= 3."""
    state = _state(
        **{
            "a::zero": {"score": 60, "fixable": 30, "stagnation_runs": 0},
            "a::one": {"score": 60, "fixable": 30, "stagnation_runs": 1},
            "a::two": {"score": 60, "fixable": 30, "stagnation_runs": 2},
            "a::none": {"score": 60, "fixable": 30},  # field missing
        }
    )
    result = select_candidates(state, _queue())
    assert set(_keys(result)) == {"a::zero", "a::one", "a::two", "a::none"}


def test_decompile_timeout_does_not_affect_unflagged():
    """Sanity: the check only fires when the flag is truthy."""
    state = _state(
        **{
            "a::normal": {"score": 31, "fixable": 20},
            "a::explicit_false": {
                "score": 31,
                "fixable": 20,
                "decompile_timeout": False,
            },
        }
    )
    result = select_candidates(state, _queue())
    assert set(_keys(result)) == {"a::normal", "a::explicit_false"}


def test_recovery_pass_done_does_not_affect_unflagged_functions():
    """Sanity: the new check only fires when the flag is truthy. A function
    without the field should behave exactly as before."""
    state = _state(
        **{
            "a::normal": {"score": 55, "fixable": 20},
            # Explicit False should also be treated as "not done"
            "a::explicit_false": {
                "score": 55,
                "fixable": 20,
                "recovery_pass_done": False,
            },
        }
    )
    result = select_candidates(state, _queue())
    assert set(_keys(result)) == {"a::normal", "a::explicit_false"}

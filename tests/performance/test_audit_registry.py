"""
Tests for fun-doc/audit/registry.py — signature state machine.

The registry is pure state. Every test drives check_and_record_fire with
controlled timestamps, asserts the decision is what the cooldown + circuit
breaker rules require, and occasionally reloads from disk to verify
persistence.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"


@pytest.fixture(scope="module", autouse=True)
def fun_doc_on_path():
    path_str = str(FUN_DOC_DIR)
    added = False
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
        added = True
    yield
    if added:
        try:
            sys.path.remove(path_str)
        except ValueError:
            pass


@pytest.fixture
def registry(tmp_path):
    from audit.registry import AuditRegistry

    return AuditRegistry(tmp_path / "registry.json")


def _t(h: int = 0, m: int = 0, s: int = 0) -> datetime:
    return datetime(2026, 4, 24, h, m, s, tzinfo=timezone.utc)


# --- dedup / cooldown ----------------------------------------------------


def test_fresh_registry_allows_first_fire(registry):
    decision = registry.check_and_record_fire("sig1", ts=_t(0))
    assert decision.action == "fire"


def test_second_fire_within_cooldown_suppressed(registry):
    registry.check_and_record_fire("sig1", ts=_t(0))
    decision = registry.check_and_record_fire("sig1", ts=_t(1))  # 1h later
    assert decision.action == "skip_cooldown"
    assert decision.cooldown_expires_at is not None


def test_fire_after_cooldown_expires(registry):
    from audit.registry import COOLDOWN_SECONDS

    registry.check_and_record_fire("sig1", ts=_t(0))
    later = _t(0) + timedelta(seconds=COOLDOWN_SECONDS + 1)
    decision = registry.check_and_record_fire("sig1", ts=later)
    assert decision.action == "fire"


def test_different_signatures_do_not_share_cooldown(registry):
    registry.check_and_record_fire("sig_a", ts=_t(0))
    decision = registry.check_and_record_fire("sig_b", ts=_t(0, 1))
    assert decision.action == "fire"


# --- circuit breaker -----------------------------------------------------


def test_circuit_breaker_trips_at_short_threshold(registry):
    from audit.registry import CB_SHORT_THRESHOLD

    for i in range(CB_SHORT_THRESHOLD):
        registry.check_and_record_fire(f"sig_{i}", ts=_t(0, i))
    cb = registry.get_circuit_breaker_state()
    assert cb["state"] == "tripped"
    assert cb["halt_until"] is not None


def test_circuit_breaker_suppresses_subsequent_fires(registry):
    from audit.registry import CB_SHORT_THRESHOLD

    for i in range(CB_SHORT_THRESHOLD):
        registry.check_and_record_fire(f"sig_{i}", ts=_t(0, i))
    decision = registry.check_and_record_fire("sig_new", ts=_t(0, 10))
    assert decision.action == "skip_circuit_breaker"
    assert decision.circuit_breaker_halt_until is not None


def test_circuit_breaker_tripped_this_fire_flag(registry):
    """The fire that causes the trip should report tripped_this_fire=True."""
    from audit.registry import CB_SHORT_THRESHOLD

    decisions = [
        registry.check_and_record_fire(f"sig_{i}", ts=_t(0, i))
        for i in range(CB_SHORT_THRESHOLD)
    ]
    # Only the Nth fire trips the breaker.
    assert [d.circuit_breaker_tripped_this_fire for d in decisions] == [
        False
    ] * (CB_SHORT_THRESHOLD - 1) + [True]


def test_circuit_breaker_rearms_after_halt(registry):
    from audit.registry import CB_HALT_DURATION, CB_SHORT_THRESHOLD

    for i in range(CB_SHORT_THRESHOLD):
        registry.check_and_record_fire(f"sig_{i}", ts=_t(0, i))
    later = _t(0, CB_SHORT_THRESHOLD) + timedelta(seconds=CB_HALT_DURATION + 1)
    decision = registry.check_and_record_fire("sig_after", ts=later)
    assert decision.action == "fire"
    assert registry.get_circuit_breaker_state()["state"] == "armed"


def test_circuit_breaker_long_window_threshold(registry):
    """Long-window threshold should trip even when fires are spread thin."""
    from audit.registry import (
        CB_LONG_THRESHOLD,
        CB_LONG_WINDOW,
        CB_SHORT_THRESHOLD,
        CB_SHORT_WINDOW,
    )

    # Space fires so each short window only holds < CB_SHORT_THRESHOLD,
    # but the long window accumulates beyond CB_LONG_THRESHOLD.
    assert CB_LONG_THRESHOLD > CB_SHORT_THRESHOLD, "test assumes long > short"
    spacing = (CB_SHORT_WINDOW // CB_SHORT_THRESHOLD) + 60  # safely > short/short threshold
    base = _t(0)
    for i in range(CB_LONG_THRESHOLD):
        ts = base + timedelta(seconds=spacing * i)
        registry.check_and_record_fire(f"sig_long_{i}", ts=ts)
        # Safety: every fire must be within the long window of the first
        assert (ts - base).total_seconds() < CB_LONG_WINDOW

    assert registry.get_circuit_breaker_state()["state"] == "tripped"


def test_force_reset_circuit_breaker(registry):
    from audit.registry import CB_SHORT_THRESHOLD

    for i in range(CB_SHORT_THRESHOLD):
        registry.check_and_record_fire(f"sig_{i}", ts=_t(0, i))
    assert registry.get_circuit_breaker_state()["state"] == "tripped"

    registry.force_reset_circuit_breaker()
    assert registry.get_circuit_breaker_state()["state"] == "armed"
    assert registry.get_circuit_breaker_state()["fires_window"] == []


# --- merge / revert ------------------------------------------------------


def test_mark_merged_increments_counter(registry):
    registry.check_and_record_fire("sig1", ts=_t(0))
    registry.mark_merged("sig1", sha="abc123", ts=_t(0, 5))
    state = registry.get_signature_state("sig1")
    assert state["merged_count"] == 1
    assert state["last_merge_sha"] == "abc123"


def test_mark_reverted_increments_counter(registry):
    registry.check_and_record_fire("sig1", ts=_t(0))
    registry.mark_reverted(
        "sig1", sha="abc123", reason="symptom_not_resolved", ts=_t(0, 10)
    )
    state = registry.get_signature_state("sig1")
    assert state["revert_count"] == 1


def test_mark_merged_on_unknown_signature_is_noop(registry):
    # Defensive: don't crash if a phase-4 merge message arrives for a sig
    # that was GC'd out of the registry.
    registry.mark_merged("never_fired", sha="abc123", ts=_t(0))
    assert registry.get_signature_state("never_fired") is None


# --- persistence ---------------------------------------------------------


def test_persistence_round_trip(tmp_path):
    from audit.registry import AuditRegistry

    path = tmp_path / "reg.json"
    r1 = AuditRegistry(path)
    r1.check_and_record_fire("sig1", ts=_t(0))
    r1.mark_merged("sig1", "abc123", ts=_t(0, 5))

    r2 = AuditRegistry(path)
    state = r2.get_signature_state("sig1")
    assert state["fire_count"] == 1
    assert state["merged_count"] == 1


def test_persistence_survives_corruption(tmp_path):
    """A corrupt registry file should not crash — start fresh instead."""
    from audit.registry import AuditRegistry

    path = tmp_path / "reg.json"
    path.write_text("{{{ not json", encoding="utf-8")
    r = AuditRegistry(path)
    # Should behave like a fresh registry
    decision = r.check_and_record_fire("sig1", ts=_t(0))
    assert decision.action == "fire"


# --- history truncation --------------------------------------------------


def test_history_truncation(registry):
    from audit.registry import HISTORY_PER_SIG

    registry.check_and_record_fire("sig1", ts=_t(0))  # seeds sig_state
    for i in range(HISTORY_PER_SIG + 5):
        registry.mark_merged(
            "sig1", sha=f"sha_{i}", ts=_t(0) + timedelta(hours=i + 1)
        )
    state = registry.get_signature_state("sig1")
    assert len(state["history"]) == HISTORY_PER_SIG
    # The oldest entries should have been dropped; most recent preserved.
    assert state["history"][-1]["sha"] == f"sha_{HISTORY_PER_SIG + 5 - 1}"


# --- snapshot ------------------------------------------------------------


def test_snapshot_is_deep_copy(registry):
    registry.check_and_record_fire("sig1", ts=_t(0))
    snap1 = registry.snapshot()
    # Mutate the snapshot — registry should be unaffected.
    snap1["signatures"]["sig1"]["fire_count"] = 9999
    snap2 = registry.snapshot()
    assert snap2["signatures"]["sig1"]["fire_count"] == 1

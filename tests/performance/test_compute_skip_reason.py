"""Regression tests for `web.compute_skip_reason()`.

This helper mirrors the gates in `fun_doc.select_candidates` so the
dashboard's function-list APIs can render "why isn't this function
getting picked?" without users reading source. The contract is:

  * Each row in the dashboard API gets a `skip_reason` field
  * The value is one of: `library_code` / `propagation` / `decompile_timeout`
    / `stagnation` / `recovery_done` / `None` (eligible)
  * Pinning bypasses every gate that respects pinning -- the helper
    must consult `pinned_keys` before those checks

Property-test parity: for every gate the selector enforces, this
helper must report the same reason. Drift here means the UI lies to
the user about why a row is or isn't being picked.

The performance/test_selector_invariants.py suite covers the selector
side; this file covers the dashboard mirror side. Together they pin
both ends of the contract.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

from web import compute_skip_reason  # noqa: E402


def _func(**overrides):
    base = {
        "name": "TestFunc",
        "score": 50,
        "fixable": 10.0,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Eligible rows return None
# ---------------------------------------------------------------------------

def test_eligible_row_returns_none():
    assert compute_skip_reason(_func(), "a::1", set()) is None


def test_default_name_source_does_not_skip():
    """The 'scan' default for name_source must never trigger a skip."""
    assert compute_skip_reason(_func(name_source="scan"), "a::1", set()) is None


def test_missing_name_source_key_does_not_skip():
    """Pre-migration rows (no name_source key at all) flow through."""
    assert compute_skip_reason(_func(), "a::1", set()) is None


# ---------------------------------------------------------------------------
# library_code gate (#198)
# ---------------------------------------------------------------------------

def test_library_code_skip():
    f = _func(library_code=True)
    assert compute_skip_reason(f, "a::1", set()) == "library_code"


def test_library_code_pin_bypasses():
    """Pinning a library_code row bypasses the gate (selector parity):
    ``if func.get("library_code") and not is_pinned: continue``. The
    helper must match -- a pinned library_code row is NOT being skipped."""
    f = _func(library_code=True)
    assert compute_skip_reason(f, "a::1", {"a::1"}) is None


def test_decompile_timeout_pin_bypasses():
    """Same pinning-bypass contract for decompile_timeout."""
    f = _func(decompile_timeout=True)
    assert compute_skip_reason(f, "a::1", {"a::1"}) is None


# ---------------------------------------------------------------------------
# propagation gate (#204)
# ---------------------------------------------------------------------------

def test_propagation_no_confidence_skipped():
    f = _func(name_source="propagation", name_confidence=None)
    assert compute_skip_reason(f, "a::1", set()) == "propagation"


def test_propagation_low_confidence_skipped():
    f = _func(name_source="propagation", name_confidence=0.4)
    assert compute_skip_reason(f, "a::1", set()) == "propagation"


def test_propagation_high_confidence_admitted():
    f = _func(name_source="propagation", name_confidence=0.5)
    assert compute_skip_reason(f, "a::1", set()) is None


def test_propagation_pin_bypasses():
    """Pinning a propagated row must bypass the gate."""
    f = _func(name_source="propagation", name_confidence=None)
    assert compute_skip_reason(f, "a::1", {"a::1"}) is None


def test_other_sources_not_skipped():
    """'scan', 'manual', 'pdb', 'archive' all flow through."""
    for src in ("scan", "manual", "pdb", "archive"):
        f = _func(name_source=src)
        assert compute_skip_reason(f, "a::1", set()) is None, src


# ---------------------------------------------------------------------------
# decompile_timeout / stagnation / recovery gates
# ---------------------------------------------------------------------------

def test_decompile_timeout_skip():
    assert compute_skip_reason(_func(decompile_timeout=True), "a::1", set()) == "decompile_timeout"


def test_stagnation_at_threshold():
    f = _func(stagnation_runs=3)
    assert compute_skip_reason(f, "a::1", set()) == "stagnation"


def test_stagnation_below_threshold_admitted():
    f = _func(stagnation_runs=2)
    assert compute_skip_reason(f, "a::1", set()) is None


def test_stagnation_pin_bypasses():
    f = _func(stagnation_runs=10)
    assert compute_skip_reason(f, "a::1", {"a::1"}) is None


def test_recovery_done_skip():
    f = _func(recovery_pass_done=True)
    assert compute_skip_reason(f, "a::1", set()) == "recovery_done"


def test_recovery_done_pin_bypasses():
    f = _func(recovery_pass_done=True)
    assert compute_skip_reason(f, "a::1", {"a::1"}) is None


# ---------------------------------------------------------------------------
# Gate ordering — first gate wins
# ---------------------------------------------------------------------------

def test_library_code_wins_over_propagation():
    """If both gates would fire, library_code takes precedence (it's the
    cheapest classification and the most certain). This matches the
    selector's order of checks."""
    f = _func(library_code=True, name_source="propagation", name_confidence=None)
    assert compute_skip_reason(f, "a::1", set()) == "library_code"


def test_propagation_wins_over_stagnation():
    """Propagation gate runs before stagnation in the selector. Same
    ordering here so the UI matches."""
    f = _func(name_source="propagation", name_confidence=None, stagnation_runs=10)
    assert compute_skip_reason(f, "a::1", set()) == "propagation"

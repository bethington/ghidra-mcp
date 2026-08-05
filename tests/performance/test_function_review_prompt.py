"""The function AUDIT must be a review, not a second drafting pass.

Measured 2026-08-05 on SGD2FreeRes-GDI. A minimax documentation pass asserted
that FUN_10005ca0 means "the game is active" and that perspective correction is
"skipped for non-game states (menus, etc.)". Both were invented -- the callee is
a magic-static accessor returning *DAT_10042e00.

Nothing caught it. falsify passed (all six checks are structural: convention,
arity, return width, parameter counts, name verb, phantom callee), and the audit
pass called build_fix_prompt -- byte-identical to the worker's own FIX prompt --
so the auditor was never told it was auditing. Re-run as a controlled experiment
with audit_provider=minimax, it spent 24 tool calls and ~440K tokens, grew the
plate from 42 to ~91 lines, ADDED a second unverified provenance claim, and left
the falsehood untouched.

Globals already had the right prompt (_build_global_review_prompt). These pin the
function equivalent.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

fd = pytest.importorskip("fun_doc")

DATA = {
    "decompiled": "void FUN_1001bcc0(void) { return; }",
    "fixable_categories": [],
    "variables": [],
    "completeness": {"function_name": "CLIENT_SetWorldView", "score": 52},
}


@pytest.fixture
def review():
    return fd.build_function_review_prompt("CLIENT_SetWorldView", "1001bcc0",
                                           DATA, program="/Lab/x.dll")


# --- the prompt must actually brief a reviewer -------------------------------

def test_declares_the_reviewer_role(review):
    assert "REVIEWER" in review


def test_says_the_documentation_is_a_claim_to_be_checked(review):
    low = review.lower()
    assert "ground truth" in low
    assert "claim" in low


def test_directs_the_reviewer_at_callee_semantics(review):
    """The measured failure was an invented meaning for a CALLED function."""
    low = review.lower()
    assert "callee" in low
    assert "decompile" in low


def test_explains_that_nothing_else_can_catch_a_semantic_claim(review):
    """Without this the reviewer has no reason to prioritise truth over polish."""
    low = review.lower()
    assert "falsify" in low and "structural" in low


def test_forbids_replacing_a_wrong_guess_with_another_guess(review):
    low = review.lower()
    assert "unknown" in low


def test_allows_agreeing_so_a_review_does_not_become_churn(review):
    """Mirrors the globals reviewer's guard: a second provider must not rewrite
    correct work to prove it ran."""
    low = review.lower()
    assert "change nothing" in low
    assert "churn" in low


def test_still_carries_the_underlying_fix_prompt(review):
    """The reviewer needs the same data and the same conventions as the drafter."""
    assert DATA["decompiled"] in review
    assert review.endswith(
        fd.build_fix_prompt("CLIENT_SetWorldView", "1001bcc0", DATA,
                            program="/Lab/x.dll"))


def test_review_prompt_differs_from_the_fix_prompt():
    """The whole defect was that these two were identical."""
    fix = fd.build_fix_prompt("F", "1001bcc0", DATA, program="/Lab/x.dll")
    rev = fd.build_function_review_prompt("F", "1001bcc0", DATA, program="/Lab/x.dll")
    assert rev != fix and len(rev) > len(fix)


# --- plate delimiter hygiene (F8) --------------------------------------------

def test_strips_a_wrapped_plate():
    assert fd.strip_plate_delimiters("/* Does a thing. */") == "Does a thing."


def test_strips_nested_wrappers_from_repeated_passes():
    assert fd.strip_plate_delimiters("/* /* Does a thing. */") == "Does a thing."


def test_strips_a_leading_asterisk_gutter():
    got = fd.strip_plate_delimiters("/* Line one\n * Line two\n * Line three\n */")
    assert got == "Line one\nLine two\nLine three"


def test_leaves_a_clean_plate_untouched():
    clean = "Does a thing.\n\nAlgorithm:\n  1. step"
    assert fd.strip_plate_delimiters(clean) == clean


def test_does_not_eat_multiplication_or_pointer_text():
    """A plate legitimately contains '*' -- only wrappers may be removed."""
    s = "Computes a * b and writes through pViewports->rc."
    assert fd.strip_plate_delimiters(s) == s


def test_tolerates_empty_input():
    assert fd.strip_plate_delimiters("") == ""
    assert fd.strip_plate_delimiters(None) is None


# --- review gating: skipped_delta is retired ---------------------------------
# It skipped review whenever the worker gained >= audit_min_delta, on the theory
# that a productive pass needs no second look. For truth-checking that is
# backwards -- a large gain means a large amount of NEW TEXT, which is exactly
# when a fabrication is most likely. The measured case gained +52 and carried an
# invented causal claim that only the review pass caught.

def test_the_delta_skip_is_gone_from_the_audit_gate():
    import inspect
    src = inspect.getsource(fd.process_function)
    assert 'audit_outcome = "skipped_delta"' not in src, (
        "the delta skip is back: a large-gain pass would go unreviewed again")


def test_the_good_enough_skip_is_retained():
    """A function already at target has little new text to be wrong about."""
    import inspect
    src = inspect.getsource(fd.process_function)
    assert 'audit_outcome = "skipped_good_enough"' in src


def test_audit_min_delta_is_still_accepted_for_back_compat():
    """Retained in config and the snapshot; simply unused by the gate now."""
    assert "audit_min_delta" in fd.DEFAULT_QUEUE_CONFIG

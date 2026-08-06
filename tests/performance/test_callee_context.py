"""Callee bodies in the documentation prompt.

MEASURED ORIGIN, 2026-08-06, against SGD2FreeRes -- the binary whose original
source we have.

`Sgd2fr_D2Client_IsMouseOver800NewStatsButton` is one line:

    return IsMouseOverNewStatsButton();

The prompt told the model a callee existed and was undocumented, and nothing
else. It could not decline to answer, so it produced
`CLIENT_CheckViewportVisible` -- a coherent, well-structured, internally
consistent, hedged description of a function that does not exist. Name recall
against ground truth: 0.167. Every structural claim in the plate was correct
(thin pass-through wrapper, no parameters, byte return zero-extended to uint,
delegation to FUN_10001d70); only the purpose was invented.

The answer was ONE HOP away. The callee builds a rect from half the screen
dimensions and runs a four-sided containment test returning 1/0 -- which reads
as a hit test to anyone who sees it. Nobody showed it to the model.

This is not a rare shape: 12 of 140 decompiled real-code functions (8.6%) are
three statements or fewer with exactly one callee.

THE REFINEMENT THAT THE MEASUREMENT FORCED. Callee context is necessary but not
sufficient, and the corpus says so plainly:

    0x0202f0 -> FUN_10020260   d2::d2client::GetGeneralDisplayHeight
    0x020300 -> FUN_10020260   d2::d2client::SetGeneralDisplayHeight
    0x0203b0 -> FUN_10020320   d2::d2client::GetGeneralDisplayWidth
    0x0203c0 -> FUN_10020320   d2::d2client::SetGeneralDisplayWidth

Two wrappers over the SAME callee with OPPOSITE meanings. A getter and a setter
sharing one helper are distinguishable only by how the wrapper passes arguments
and uses the return -- never by the callee's body alone. The rendered section
says so explicitly, so the extra evidence cannot be mistaken for the answer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

fd = pytest.importorskip("fun_doc")


# --- rendering ---------------------------------------------------------------

def test_no_callees_renders_nothing():
    """A leaf function's prompt must not grow an empty section."""
    assert fd.render_callee_context([]) == ""
    assert fd.render_callee_context(None) == ""


def test_the_body_reaches_the_prompt():
    """The measured defect: the model got the callee's NAME and nothing else."""
    out = fd.render_callee_context(
        [{"name": "FUN_10001d70", "undocumented": True,
          "body": "undefined1 FUN_10001d70(void){ SetRect(&r,-0xc2,-0xa0,-0x2a,-8); }"}])
    assert "FUN_10001d70" in out and "SetRect" in out


def test_documented_and_undocumented_are_distinguished():
    out = fd.render_callee_context([
        {"name": "GetScreenWidth", "undocumented": False, "body": "int f(){return w;}"},
        {"name": "FUN_1000", "undocumented": True, "body": "int f(){return 1;}"},
    ])
    assert "GetScreenWidth (documented)" in out
    assert "FUN_1000 (undocumented)" in out


def test_it_warns_that_the_callee_is_not_the_answer():
    """Get/Set pairs over one helper are the measured counterexample; the
    section must not invite the model to just describe the callee."""
    out = fd.render_callee_context([{"name": "F", "undocumented": True, "body": "x"}])
    low = out.lower()
    assert "getter" in low and "setter" in low


def test_an_unavailable_body_is_stated_not_faked():
    out = fd.render_callee_context([{"name": "F", "undocumented": True}])
    assert "body unavailable" in out


# --- gathering ---------------------------------------------------------------

def test_gather_tolerates_a_missing_analysis():
    """Missing context must degrade the prompt, never fail the run."""
    assert fd._gather_callee_context(None, "P") == []
    assert fd._gather_callee_context({}, "P") == []
    assert fd._gather_callee_context({"callees": "not-a-list"}, "P") == []


def test_gather_survives_ghidra_being_down(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(fd, "ghidra_get", boom)
    out = fd._gather_callee_context({"callees": [{"name": "F", "undocumented": True}]}, "P")
    assert out == [{"name": "F", "undocumented": True}]      # named, no body


def test_gather_rejects_an_error_string_as_a_body(monkeypatch):
    """/decompile_function reports a failure as a STRING VALUE inside a 200,
    not as an HTTP error. Stored as a body it would put an error message into
    the prompt as though it were the callee's code."""
    monkeypatch.setattr(fd, "ghidra_get",
                        lambda *a, **k: {"decompiled": "Error: Function not found"})
    out = fd._gather_callee_context({"callees": [{"name": "F", "undocumented": True}]}, "P")
    assert "body" not in out[0]


def test_a_long_callee_is_truncated_with_a_marker(monkeypatch):
    """Evidence, not a second function's worth of tokens -- and the truncation
    is stated so the model does not read a cut body as the whole story."""
    body = "int f(void){\n" + "\n".join(f"  s{i}();" for i in range(200)) + "\n}"
    monkeypatch.setattr(fd, "ghidra_get", lambda *a, **k: {"decompiled": body})
    out = fd._gather_callee_context({"callees": [{"name": "F", "undocumented": True}]}, "P")
    assert out[0]["body"].count("\n") <= fd._CALLEE_BODY_MAX_LINES + 1
    assert "more lines" in out[0]["body"]


def test_the_callee_count_is_bounded(monkeypatch):
    monkeypatch.setattr(fd, "ghidra_get", lambda *a, **k: {})
    many = [{"name": f"F{i}", "undocumented": True} for i in range(50)]
    assert len(fd._gather_callee_context({"callees": many}, "P")) == fd._CALLEE_CONTEXT_MAX


# --- the prompt --------------------------------------------------------------

def test_the_section_lands_in_the_full_doc_prompt():
    prompt = fd.build_full_doc_prompt(
        "FUN_10018860", "10018860",
        {"analyze_for_doc": {"name": "FUN_10018860", "callees": [{"name": "FUN_10001d70"}]},
         "decompiled": "uint f(void){ return FUN_10001d70(); }",
         "callee_context": [{"name": "FUN_10001d70", "undocumented": True,
                             "body": "undefined1 FUN_10001d70(void){ /* rect test */ }"}]},
        program="/Lab/SGD2FreeRes-GDI.dll")
    assert "Callees (what this function delegates to)" in prompt
    assert "rect test" in prompt


def test_a_prompt_without_callee_context_is_unchanged():
    """Functions with no callees must not pay for this."""
    prompt = fd.build_full_doc_prompt(
        "F", "1000",
        {"analyze_for_doc": {"name": "F"}, "decompiled": "int f(void){ return 1; }"},
        program="/P")
    assert "Callees (what this function delegates to)" not in prompt

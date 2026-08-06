"""Judging a plate comment against the original source.

MEASURED ORIGIN. The plate that motivated this was coherent, well-structured,
correct in every mechanical particular, honestly hedged -- and about a function
that does not exist:

    documented : "Tests whether the current viewport is visible."
    actually   : a mouse-over hit test for the 800x600 new-stats button

Nothing mechanical catches that. `analyze_function_completeness` is computed
FROM the documentation, so no fact about the binary can lower it, and `falsify`
finds contradictions against the DISASSEMBLY -- of which there were none, since
the plate agreed with every instruction it described. Only the original source
disagrees, and only a reader can see it.

minimax writes the documentation and must not grade it; the judge is a
measuring instrument, not part of the pipeline under test.

Everything here runs offline: prompt building and response parsing are separate
from invocation, and `invoke` is injected.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

pj = pytest.importorskip("plate_judge")


def _resp(**kw):
    payload = {"describes_right_function": True, "confidence": 0.9,
               "supported_claims": [], "unsupported_claims": [],
               "missing_key_behaviour": [], "summary": ""}
    payload.update(kw)
    return json.dumps(payload)


# --- parsing -----------------------------------------------------------------

def test_a_clean_verdict_parses():
    v = pj.parse_judge_response(_resp(supported_claims=["sets the rect"]))
    assert v.scorable and v.right_function and v.verdict == "accurate"


def test_the_measured_failure_is_wrong_function():
    v = pj.parse_judge_response(_resp(
        describes_right_function=False,
        unsupported_claims=["claims it tests viewport visibility"],
        summary="describes a viewport check; the source is a hit test"))
    assert v.verdict == "wrong_function"


def test_a_right_function_with_invention_is_distinguished():
    """Describing the right function and adding claims the source does not
    support is a different failure from describing the wrong function, and
    collapsing them would hide which one the workflow needs to fix."""
    v = pj.parse_judge_response(_resp(unsupported_claims=["invented a cache"]))
    assert v.verdict == "accurate_with_invention"


def test_json_embedded_in_prose_is_still_read():
    v = pj.parse_judge_response("Here is my answer:\n" + _resp() + "\nHope that helps.")
    assert v.scorable


def test_a_dict_response_is_accepted():
    v = pj.parse_judge_response(json.loads(_resp()))
    assert v.scorable


# --- abstention --------------------------------------------------------------
# "Cannot tell" is not "passed" and is not "failed" -- the same rule falsify's
# CONF_BLOCKED and the port classifier's `unknown` follow.

@pytest.mark.parametrize("bad", [
    "the documentation looks fine to me",          # prose, no JSON
    "{not valid json",                             # malformed
    '{"confidence": 0.9}',                         # missing the load-bearing key
    '{"describes_right_function": "yes"}',         # not a boolean
])
def test_an_unusable_response_is_unscorable(bad):
    v = pj.parse_judge_response(bad)
    assert not v.scorable and v.verdict == "unscorable"
    assert v.unscorable_reason


def test_unscorable_is_neither_pass_nor_fail():
    v = pj.parse_judge_response("nonsense")
    assert v.right_function is None


def test_an_empty_plate_is_unscorable_not_wrong(tmp_path):
    src = tmp_path / "f.c"
    src.write_text("int f(void){return 1;}\n", encoding="utf-8")
    v = pj.judge_plate("F", "", str(src), 1, 1, invoke=lambda p: _resp())
    assert v.verdict == "unscorable" and "no plate" in v.unscorable_reason


def test_missing_source_is_unscorable_not_wrong():
    """A source file we cannot read says nothing about the documentation."""
    v = pj.judge_plate("F", "a plate", "C:/nope/missing.c", 1, 5,
                       invoke=lambda p: _resp())
    assert v.verdict == "unscorable" and "unreadable" in v.unscorable_reason


def test_a_failing_judge_call_is_unscorable():
    def boom(prompt):
        raise RuntimeError("provider down")
    v = pj.judge_plate("F", "a plate", __file__, 1, 5, invoke=boom)
    assert v.verdict == "unscorable" and "provider down" in v.unscorable_reason


# --- source extraction -------------------------------------------------------

def test_source_is_read_with_line_numbers(tmp_path):
    f = tmp_path / "s.c"
    f.write_text("\n".join(f"line{i}" for i in range(1, 21)), encoding="utf-8")
    out = pj.read_source(str(f), 5, 7, context=1)
    assert "line5" in out and "line7" in out and "line4" in out    # context
    assert "line9" not in out


def test_a_huge_function_is_truncated_with_a_marker(tmp_path):
    f = tmp_path / "s.c"
    f.write_text("\n".join(f"line{i}" for i in range(1, 600)), encoding="utf-8")
    out = pj.read_source(str(f), 1, 500, context=0)
    assert "more lines" in out


def test_an_unreadable_file_returns_empty_not_an_exception():
    assert pj.read_source("C:/nope/missing.c", 1, 5) == ""


# --- the prompt --------------------------------------------------------------

def test_the_prompt_carries_plate_and_source():
    p = pj.build_judge_prompt("CLIENT_CheckViewportVisible",
                              "Tests whether the viewport is visible.",
                              "  62| return IsMouseOverNewStatsButton();")
    assert "CheckViewportVisible" in p and "IsMouseOverNewStatsButton" in p


def test_the_prompt_says_the_source_is_the_authority():
    p = pj.build_judge_prompt("F", "plate", "src")
    assert "authority" in p.lower()


def test_the_prompt_asks_for_meaning_not_wording():
    """Scoring vocabulary would teach the workflow to copy words, not read code."""
    p = pj.build_judge_prompt("F", "plate", "src").lower()
    assert "meaning, not wording" in p or "judge meaning" in p


def test_the_prompt_names_the_failure_that_matters_most():
    p = pj.build_judge_prompt("F", "plate", "src").lower()
    assert "different function" in p


# --- aggregation -------------------------------------------------------------

def test_unscorable_rows_stay_out_of_the_rates():
    """Same rule as deferrals in the name measurement: a row nobody could judge
    is not evidence in either direction."""
    vs = [pj.parse_judge_response(_resp()),
          pj.parse_judge_response(_resp(describes_right_function=False)),
          pj.parse_judge_response("prose")]
    s = pj.summarise(vs)
    assert s["reviewed"] == 3 and s["scorable"] == 2 and s["unscorable"] == 1
    assert s["right_function_rate"] == 0.5


def test_invention_rate_is_measured_among_right_functions_only():
    """Inventing claims about the WRONG function is already counted as wrong;
    counting it twice would conflate two distinct defects."""
    vs = [pj.parse_judge_response(_resp()),
          pj.parse_judge_response(_resp(unsupported_claims=["made this up"]))]
    s = pj.summarise(vs)
    assert s["right_function"] == 2 and s["free_of_invention"] == 1
    assert s["invention_rate"] == 0.5


def test_summarising_nothing_does_not_divide_by_zero():
    assert pj.summarise([])["reviewed"] == 0


# --- the parser must not discard a correct verdict ---------------------------
# MEASURED 2026-08-06. The judge answered correctly for all 8 functions of the
# warming experiment and every row came back `unscorable`: a greedy `\{.*\}`
# spans from the first brace anywhere in the reply to the last, so a fenced
# object preceded by a sentence yields text that is not valid JSON. The
# verdicts were real; the parser threw them away -- and because unscorable rows
# stay out of the rates, that silently produced "0/8 scorable" rather than an
# error anyone would chase.

def test_a_fenced_object_after_prose_is_read():
    raw = ("Here is my assessment of the documentation:\n\n```json\n"
           + _resp(describes_right_function=False) + "\n```\n")
    v = pj.parse_judge_response(raw)
    assert v.scorable and v.right_function is False


def test_prose_containing_braces_does_not_break_it():
    raw = ("The plate mentions a struct {foo} and a set {bar}.\n" + _resp())
    assert pj.parse_judge_response(raw).scorable


def test_the_object_with_the_verdict_key_wins():
    """A reply may carry more than one object; pick the one that answers."""
    raw = '{"note": "thinking"}\n' + _resp(describes_right_function=False)
    v = pj.parse_judge_response(raw)
    assert v.scorable and v.right_function is False


def test_genuinely_unusable_output_is_still_unscorable():
    assert not pj.parse_judge_response("I could not assess this.").scorable

"""The ground-truth review: scoring documentation against the ORIGINAL SOURCE.

MEASURED ORIGIN, 2026-08-05. The first function taken end-to-end through the
vertical slice was documented `CLIENT_SetWorldView`. It scored well, passed
falsify, and passed a live shadow comparison byte-for-byte on every call the
game makes. Its real name -- from the PDB of a binary we build ourselves, with
the source on disk -- is `Sgd2fr_D2Client_SetTileCullingBound`: it sets the
draw-window rect and then the tile-culling window, with perspective-mode
compensation.

Every quality signal we had was blind to this. `analyze_function_completeness`
is computed FROM the documentation, so no fact about the binary can lower it.
`falsify.py` finds mechanical contradictions against the disassembly, and there
was none: the documentation was internally consistent and described the wrong
thing. A function can be structurally perfect and semantically false.

The rule that keeps the corpus worth having: ground truth is a MEASURING STICK
and is never written into Ghidra, so the pipeline stays blind and its output
stays scorable. 661 functions, versus Benchmark.dll's 9.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

gtr = pytest.importorskip("ground_truth_review")


# --- the measured case -------------------------------------------------------

TRUTH = "Sgd2fr_D2Client_SetTileCullingBound"


def test_the_specimen_is_scored_wrong():
    """The whole reason this module exists."""
    v = gtr.compare_names("CLIENT_SetWorldView", TRUTH)
    assert v.verdict == "wrong"


def test_it_names_which_concepts_were_missed():
    """A verdict alone does not tell the workflow what to fix."""
    v = gtr.compare_names("CLIENT_SetWorldView", TRUTH)
    assert "tile" in v.missed and "cull" in " ".join(v.missed)


def test_it_names_what_was_invented():
    v = gtr.compare_names("CLIENT_SetWorldView", TRUTH)
    assert any(t in v.invented for t in ("world", "view"))


def test_the_specimen_was_structurally_right_all_along():
    """Derived from disassembly alone: CullingSpec is 4+16+16 = 36 bytes, cdecl,
    void, out-param at arg 0, 5 args. Every field matched the real struct."""
    r = gtr.review_function(
        {"name": "CLIENT_SetWorldView", "arg_count": 5, "ret_bits": 0,
         "outbuf_bytes": 36, "callconv": "cdecl", "address": "1001bcc0"},
        {"name": TRUTH, "arg_count": 5, "ret_bits": 0, "outbuf_bytes": 36,
         "callconv": "cdecl"})
    assert r["structure"]["verdict"] == "agrees"
    assert r["verdict"] == "misnamed"       # not structurally_wrong


# --- names are compared SEMANTICALLY, not as strings -------------------------

def test_our_conventions_are_not_penalised():
    """Ground truth `Sgd2fr_D2Client_SetTileCullingBound` VIOLATES this
    project's NamingConventions (underscores, no leading verb). Scoring the
    literal string would mark the pipeline wrong for obeying the rules we
    impose on it."""
    v = gtr.compare_names("CLIENT_SetTileCullingBound", TRUTH)
    assert v.verdict == "correct"


def test_module_prefixes_carry_no_credit():
    """Matching `Sgd2fr`/`Client` is not evidence of understanding anything."""
    v = gtr.compare_names("CLIENT_DoThing", TRUTH)
    assert v.verdict == "wrong"
    assert "client" not in v.matched


@pytest.mark.parametrize("documented", [
    "SetTileCullingBounds",       # plural
    "UpdateTileCullingBound",     # synonym verb
    "AssignTileCullingBound",
    "SetTileCullBound",           # stem
])
def test_synonyms_and_inflections_count_as_correct(documented):
    """A pipeline that says Update where truth says Set understood the code.
    Scoring that as a miss teaches it to copy vocabulary, not to read."""
    assert gtr.compare_names(documented, TRUTH).verdict == "correct"


def test_a_partially_right_name_is_partial_not_correct():
    v = gtr.compare_names("SetCullingBound", TRUTH)     # loses "tile"
    assert v.verdict == "partial"
    assert v.missed == ["tile"]


def test_recall_is_reported_for_ranking():
    v = gtr.compare_names("SetCullingBound", TRUTH)
    assert 0.5 <= v.recall < 1.0


# --- structure is compared EXACTLY -------------------------------------------

def test_a_wrong_arg_count_is_structurally_wrong():
    """The ABI depends on it -- a wrong count on a callee-cleans convention
    skews ESP and access-violates the game."""
    r = gtr.review_function(
        {"name": TRUTH, "arg_count": 4, "outbuf_bytes": 36},
        {"name": TRUTH, "arg_count": 5, "outbuf_bytes": 36})
    assert r["verdict"] == "structurally_wrong"
    assert r["structure"]["disagreements"][0]["field"] == "arg_count"


def test_a_wrong_outbuf_size_is_caught():
    r = gtr.review_function(
        {"name": TRUTH, "outbuf_bytes": 20},
        {"name": TRUTH, "outbuf_bytes": 36})
    assert r["verdict"] == "structurally_wrong"


def test_unknown_fields_are_not_disagreements():
    """Absent data is not evidence of error -- fail open on the SCORE, never
    manufacture a finding from a field nobody recorded."""
    r = gtr.review_function({"name": TRUTH}, {"name": TRUTH, "arg_count": 5})
    assert r["structure"]["verdict"] == "unscorable"
    assert r["verdict"] == "accurate"


def test_both_halves_must_pass_to_be_accurate():
    r = gtr.review_function(
        {"name": "CLIENT_SetWorldView", "arg_count": 5},
        {"name": TRUTH, "arg_count": 5})
    assert r["verdict"] != "accurate"


# --- batch summary -----------------------------------------------------------

def test_batch_accuracy_counts_correct_not_documented():
    """The number that should drive workflow changes is how many functions we
    documented CORRECTLY, not how many we documented."""
    pairs = [
        ({"name": "CLIENT_SetTileCullingBound", "arg_count": 5},
         {"name": TRUTH, "arg_count": 5}),
        ({"name": "CLIENT_SetWorldView", "arg_count": 5},
         {"name": TRUTH, "arg_count": 5}),
    ]
    out = gtr.review_batch(pairs)
    assert out["reviewed"] == 2 and out["accurate"] == 1
    assert out["accuracy"] == 0.5


def test_batch_reports_the_verdict_spread():
    pairs = [({"name": "CLIENT_SetWorldView"}, {"name": TRUTH})] * 3
    out = gtr.review_batch(pairs)
    assert out["name_verdicts"]["wrong"] == 3


# --- the review writes nothing ----------------------------------------------

def test_the_module_never_writes_to_ghidra_or_sql():
    """Report-only by construction. Writing truth into Ghidra would destroy the
    corpus permanently -- the pipeline must stay blind to stay scorable."""
    src = (_FUNDOC / "ground_truth_review.py").read_text(encoding="utf-8")
    for forbidden in ("rename_function", "add_function_tag", "set_comment",
                      "update_function_state", "save_state", "requests.post"):
        assert forbidden not in src, forbidden


# --- C++ constructors and destructors ---------------------------------------
# MEASURED 2026-08-06 during the blind run: `GetGlobalBeltRecordPatch_1_09D_ctor`
# against truth `...::GetGlobalBeltRecordPatch_1_09D::GetGlobalBeltRecordPatch_1_09D`
# scored `partial` at recall 1.0 -- penalised solely for the conventional
# suffix. C++ spells a constructor `Class::Class`, so the operation has no verb
# of its own and the class name simply repeats; `_ctor` names the same fact and
# is arguably clearer than the truth. A correctly identified constructor must
# not read as a partial miss.

_CTOR_TRUTH = "sgd2fr::d2common::GetGlobalBeltRecordPatch_1_09D::GetGlobalBeltRecordPatch_1_09D"


def test_a_constructor_suffix_is_not_invention():
    v = gtr.compare_names("GetGlobalBeltRecordPatch_1_09D_ctor", _CTOR_TRUTH)
    assert v.verdict == "correct", v.invented


def test_a_destructor_suffix_is_not_invention():
    v = gtr.compare_names("Widget_dtor", "Widget::~Widget")
    assert v.verdict == "correct", v.invented


def test_structors_are_detected_by_shape_not_a_name_list():
    """The class name is arbitrary, so the rule keys on the trailing A::A."""
    assert gtr._is_structor("a::b::Thing::Thing")
    assert gtr._is_structor("Thing::~Thing")
    assert not gtr._is_structor("ns::Thing::Apply")
    assert not gtr._is_structor("PrintLicenseNotice")


def test_the_credit_does_not_leak_to_ordinary_functions():
    """`_ctor` on a non-constructor is still an invented concept."""
    v = gtr.compare_names("ApplyPatch_ctor", "sgd2fr::ApplyPatch")
    assert "ctor" in v.invented


def test_a_genuinely_wrong_constructor_is_still_wrong():
    v = gtr.compare_names("SomethingElse_ctor", _CTOR_TRUTH)
    assert v.verdict == "wrong"


# --- constructor VERBS, not just suffixes ------------------------------------
# MEASURED 2026-08-06: five constructors in the blind sample scored `partial`,
# four with missed=[] (FULL recall), penalised solely for saying `Initialize` or
# `Build`. C++ gives a constructor no verb of its own -- `Class::Class` names
# the class twice -- so there is no token for a correct verb to match against.

def test_a_constructor_verb_is_credited():
    v = gtr.compare_names("InitializeSetScreenShiftPatch109D",
                          "sgd2fr::d2client::SetScreenShiftPatch_1_09D::SetScreenShiftPatch_1_09D")
    assert v.verdict == "correct", (v.missed, v.invented)


def test_build_counts_as_a_constructor_verb():
    v = gtr.compare_names(
        "CLIENT_BuildSetGeneralDisplayWidthAndHeightPatch109D",
        "sgd2fr::d2client::SetGeneralDisplayWidthAndHeightPatch_1_09D::"
        "SetGeneralDisplayWidthAndHeightPatch_1_09D")
    assert v.verdict == "correct", (v.missed, v.invented)


def test_a_dropped_concept_still_costs_the_constructor():
    """The measured fifth row: it lost 'Get'. The rule credits the missing VERB,
    never a missing concept -- otherwise it would flatter everything."""
    v = gtr.compare_names(
        "InitializeGlobalEquipmentSlotLayoutPatch",
        "sgd2fr::d2common::GetGlobalEquipmentSlotLayoutPatch_1_09D::"
        "GetGlobalEquipmentSlotLayoutPatch_1_09D")
    assert v.verdict == "partial" and "get" in v.missed


def test_constructor_verbs_are_not_credited_on_ordinary_functions():
    v = gtr.compare_names("InitializeApplyPatch", "sgd2fr::ApplyPatch")
    assert "initialize" in v.invented


# --- operation vs context ----------------------------------------------------
# MEASURED 2026-08-06. Truth names carry C++ class/namespace context that a
# STRIPPED BINARY DOES NOT CONTAIN. Scoring both together penalised the pipeline
# for information nobody could recover: `d2::CelFile_Api::GetCel` demanded
# cel/file/api before a single token about what the function does, so a perfect
# reading of the machine code still scored partial. Reported separately, the
# operation figure says how well the CODE was read and the context figure says
# how much STRUCTURE was inferred -- two different abilities.

def test_the_operation_is_the_final_component():
    ctx, op = gtr.split_truth("d2::CelFile_Api::GetCel")
    assert op == ["get", "cel"]
    assert "api" in ctx


def test_class_context_does_not_count_against_the_operation():
    """`GetCel` is a correct reading of the code even without the class."""
    v = gtr.compare_names("GetCel", "d2::CelFile_Api::GetCel")
    assert v.verdict == "correct"


def test_context_recall_is_reported_separately():
    bare = gtr.compare_names("GetCel", "d2::CelFile_Api::GetCel")
    rich = gtr.compare_names("CelFileApi_GetCel", "d2::CelFile_Api::GetCel")
    assert bare.verdict == rich.verdict == "correct"
    assert rich.context_recall > bare.context_recall


def test_echoing_the_class_is_not_invention():
    v = gtr.compare_names("CelFileApi_GetCel", "d2::CelFile_Api::GetCel")
    assert v.invented == []


def test_a_wrong_operation_is_still_wrong():
    """The split must not rescue a genuine miss -- these are the measured
    wrong answers and they stay wrong."""
    assert gtr.compare_names("ResolveLookupResult",
                             "d2::CelFile_Api::GetCel").verdict == "wrong"
    assert gtr.compare_names("FreeGdiResHandle",
                             "d2::MpqArchiveHandle_Api::Close").verdict == "wrong"


def test_a_constructor_still_needs_the_class_name():
    """For a constructor the final component IS the class, so naming it is the
    operation -- the split must not hand it over for free."""
    v = gtr.compare_names("SomethingElse_ctor",
                          "sgd2fr::FooPatch_1_09D::FooPatch_1_09D")
    assert v.verdict == "wrong"

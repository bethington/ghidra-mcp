"""The floors themselves, proven against known-good and known-bad input.

A quality gate that cannot fail is worse than no quality gate: it produces a
green tick that means nothing. Every check below is exercised in both
directions -- it passes clean input AND it catches the specific defect it
exists for.

Offline: no Ghidra, no provider, no browser. Runs in CI.
"""

from __future__ import annotations

import pytest

import floors

GOOD = {
    "name": "ComputeCrc16Checksum",
    "return_type": "unsigned short",
    "parameters": [
        {"name": "pbBuffer", "type": "byte *"},
        {"name": "dwLength", "type": "uint"},
    ],
    "locals": [{"name": "wCrc", "type": "ushort"}],
    "plate": (
        "Computes a CRC-16-CCITT checksum.\n\n"
        "Algorithm: polynomial 0x1021, initial value 0xFFFF, no reflection.\n"
        "Parameters: pbBuffer - the data; dwLength - byte count.\n"
        "Returns: the 16-bit checksum.\n"
    ),
}


def _captured(**overrides):
    return {**GOOD, **overrides}


# --------------------------------------------------------------------------
# name applied
# --------------------------------------------------------------------------


def test_clean_name_passes():
    assert floors.check_name_applied("calc_crc16", GOOD) == []


@pytest.mark.parametrize("name", ["FUN_10001010", "SUB_10001010", "thunk_FUN_10001010", "entry"])
def test_ghidra_default_name_is_caught(name):
    """"The run said `completed`" is not evidence that anything was written.

    A worker that reports success while the function still carries its
    Ghidra default is the single most important thing this gate catches --
    the score is computed from documentation that does not exist.
    """
    v = floors.check_name_applied("calc_crc16", _captured(name=name))
    assert len(v) == 1 and v[0].floor == "name-applied"


def test_empty_name_is_caught():
    assert floors.check_name_applied("calc_crc16", _captured(name="")) != []


# --------------------------------------------------------------------------
# naming convention
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "ComputeCrc16Checksum",
        "DATATBLS_ParseRecord",   # UPPERCASE_ module prefix
        "GetStatListOwner",
        "D2COMMON_AddStat",       # prefix with digits
        "ParseHTTPHeader",        # embedded acronym must NOT be rejected
        "AdvanceParserState",
    ],
)
def test_conventional_names_pass(name):
    assert floors.check_name_convention("f", _captured(name=name)) == []


@pytest.mark.parametrize(
    "name",
    [
        "compute_crc16",      # snake_case
        "computeCrc16",       # camelCase
        "CRC",                # all caps, and too short
        "CRCCHECKSUM",        # all caps, long enough -- still not PascalCase
        "Crc",                # single word, too short
        "Checksum",           # single word: no verb
        "calc crc16",         # space
        "Compute_Crc16",      # underscore outside a module prefix
    ],
)
def test_unconventional_names_are_caught(name):
    v = floors.check_name_convention("f", _captured(name=name))
    assert len(v) == 1 and v[0].floor == "name-convention"


def test_convention_check_defers_to_name_applied_on_a_default_name():
    """One defect, one violation.

    A function still named FUN_xxxx is not ALSO a convention violation --
    reporting it twice buries the real message under noise.
    """
    assert floors.check_name_convention("f", _captured(name="FUN_10001010")) == []


# --------------------------------------------------------------------------
# plate sections
# --------------------------------------------------------------------------


def test_full_plate_passes():
    assert floors.check_plate_sections("f", GOOD) == []


def test_missing_plate_is_caught():
    v = floors.check_plate_sections("f", _captured(plate="   "))
    assert len(v) == 1 and v[0].floor == "plate-present"


def test_plate_without_required_sections_is_caught():
    v = floors.check_plate_sections("f", _captured(plate="Does a thing with bytes."))
    assert len(v) == 1 and v[0].floor == "plate-sections"
    for section in ("Algorithm", "Parameters", "Returns"):
        assert section in v[0].detail


def test_plate_sections_are_matched_case_insensitively():
    assert floors.check_plate_sections(
        "f", _captured(plate="ALGORITHM: x\nPARAMETERS: y\nRETURNS: z")
    ) == []


# --------------------------------------------------------------------------
# parameter typing
# --------------------------------------------------------------------------


def test_typed_parameters_pass():
    assert floors.check_parameters_typed("f", GOOD) == []


@pytest.mark.parametrize("bad_type", ["undefined", "undefined4", "undefined8 *"])
def test_undefined_parameter_type_is_caught(bad_type):
    v = floors.check_parameters_typed(
        "f", _captured(parameters=[{"name": "p", "type": bad_type}])
    )
    assert len(v) == 1 and v[0].floor == "params-typed"


def test_a_type_merely_containing_the_substring_is_not_flagged():
    """`\\bundefined\\d*\\b` is a word boundary for a reason.

    A user type named `UndefinedBehaviorFlags` is a legitimate type; matching
    it would be a false accusation, and the type axis is exactly where those
    are expensive.
    """
    assert floors.check_parameters_typed(
        "f", _captured(parameters=[{"name": "p", "type": "UndefinedBehaviorFlags *"}])
    ) == []


# --------------------------------------------------------------------------
# terminal result codes
# --------------------------------------------------------------------------


@pytest.mark.parametrize("code", ["completed", "partial", "skipped", None])
def test_non_fatal_result_codes_pass(code):
    assert floors.check_result_code("f", code) == []


@pytest.mark.parametrize("code", ["failed", "blocked", "stopped"])
def test_fatal_result_codes_are_caught(code):
    v = floors.check_result_code("f", code)
    assert len(v) == 1 and v[0].floor == "run-completed"


# --------------------------------------------------------------------------
# the library positive control
# --------------------------------------------------------------------------


AUTHORED = [
    "calc_crc16", "advance_parser_state", "compute_str_len", "stat_list_add",
    "compute_gcd", "get_stat_list_flags", "get_stat_list_layer",
    "get_stat_list_owner_guid", "get_stat_list_prev_link",
]


def test_no_claim_over_library_functions_is_fine():
    """Claiming _strlen and _memset is correct and must not fail the run."""
    assert floors.check_no_authored_function_claimed_as_library(
        AUTHORED, ["_strlen", "_memset", "__security_check_cookie"]
    ) == []


def test_claiming_an_authored_function_fails_the_run():
    v = floors.check_no_authored_function_claimed_as_library(
        AUTHORED, ["_strlen", "calc_crc16"]
    )
    assert len(v) == 1
    assert v[0].function == "calc_crc16"
    assert "PERMANENTLY" in v[0].detail


def test_every_authored_function_claimed_is_reported_not_just_the_first():
    v = floors.check_no_authored_function_claimed_as_library(
        AUTHORED, ["calc_crc16", "compute_gcd", "stat_list_add"]
    )
    assert {x.function for x in v} == {"calc_crc16", "compute_gcd", "stat_list_add"}


# --------------------------------------------------------------------------
# semantic delta
# --------------------------------------------------------------------------


def _run(mean, per_fn):
    return {
        "aggregate": {"quality_mean": mean},
        "functions": {k: {"minimax": {"quality": v}} for k, v in per_fn.items()},
    }


def test_no_baseline_means_no_semantic_violations():
    """The first run on a new machine has nothing to regress against.

    Inventing an absolute bar here would be the pure-thresholds design under
    another name, with all of its retuning cost.
    """
    assert floors.check_semantic_delta(_run(0.5, {"a": 0.5}), None) == []
    assert floors.check_semantic_delta(_run(0.5, {"a": 0.5}), {}) == []


def test_matching_quality_passes():
    base = _run(0.81, {"a": 0.88, "b": 0.74})
    assert floors.check_semantic_delta(base, base) == []


def test_noise_within_tolerance_does_not_fire():
    base = _run(0.810, {"a": 0.880})
    run = _run(0.795, {"a": 0.860})
    assert floors.check_semantic_delta(run, base) == []


def test_mean_regression_beyond_tolerance_fires():
    base = _run(0.810, {"a": 0.880})
    run = _run(0.700, {"a": 0.860})
    v = floors.check_semantic_delta(run, base)
    assert any(x.floor == "semantic-mean" for x in v)


def test_a_single_function_collapsing_fires_even_when_the_mean_holds():
    """A mean over nine functions absorbs one of them collapsing.

    This is the reason there are two semantic checks and not one.
    """
    base = _run(0.810, {"a": 0.900, "b": 0.720})
    run = _run(0.805, {"a": 0.500, "b": 0.900})  # mean barely moves
    v = floors.check_semantic_delta(run, base)
    assert [x.floor for x in v] == ["semantic-function"]
    assert v[0].function == "a"


def test_a_function_dropped_entirely_is_not_silently_ignored():
    base = _run(0.810, {"a": 0.900, "b": 0.720})
    run = _run(0.900, {"a": 0.900})
    v = floors.check_semantic_delta(run, base)
    assert [(x.floor, x.function) for x in v] == [("semantic-missing", "b")]


def test_improvement_never_fires():
    base = _run(0.700, {"a": 0.700})
    run = _run(0.950, {"a": 0.990})
    assert floors.check_semantic_delta(run, base) == []


# --------------------------------------------------------------------------
# top level
# --------------------------------------------------------------------------


def test_evaluate_collects_every_violation_rather_than_stopping_at_the_first():
    run = {
        "aggregate": {"quality_mean": 0.8},
        "functions": {
            "a": {"minimax": {"quality": 0.8, "captured": _captured(name="FUN_1")}},
            "b": {"minimax": {"quality": 0.8, "captured": _captured(plate="nope")}},
        },
    }
    report = floors.evaluate(run)
    assert not report.ok
    floors_hit = {v.floor for v in report.mechanical}
    assert "name-applied" in floors_hit and "plate-sections" in floors_hit


def test_evaluate_skips_convention_checks_when_asked():
    run = {
        "functions": {"a": {"minimax": {"quality": 0.8, "captured": _captured(plate="prose")}}}
    }
    assert floors.evaluate(run).mechanical  # plate-sections fires by default
    assert floors.evaluate(run, skip_checks=floors.CONVENTION_CHECKS).ok


def test_a_clean_run_reports_ok():
    run = {
        "aggregate": {"quality_mean": 0.85},
        "functions": {"calc_crc16": {"minimax": {"quality": 0.9, "captured": GOOD}}},
    }
    report = floors.evaluate(run, authored=AUTHORED, library_claims=["_strlen"])
    assert report.ok, report.format()
    assert report.format() == "all floors passed"

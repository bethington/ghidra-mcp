"""Offline tests for the fun-doc benchmark scorer.

These tests exercise the multi-level rubric + structural scoring
pipeline against the crc16 walking-skeleton fixtures. They run with
no Ghidra and no provider calls, so they belong to the offline suite.

What's locked in here:
  * Exact-match and synonym matching at tier 1 (1.00)
  * Prefix / containment matching at tier 2 (0.70)
  * LLM-stub fall-through for non-obvious but related names (<=0.50)
  * Structural signature scoring with type-alias normalization
  * Algorithm tag detection in plate text (0 or 1)
  * Guardrail computation on tool-call records
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


BENCHMARK_DIR = Path(__file__).resolve().parents[2] / "fun-doc" / "benchmark"
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from scorer import (  # noqa: E402
    _normalize_identifier,
    _normalize_type,
    _rubric_score_name,
    guardrails,
    score_function,
)


TRUTH = {
    "name": "calc_crc16",
    "name_synonyms": ["CalcCrc16", "ComputeCrc16", "Crc16Ccitt"],
    "return_type": "unsigned short",
    "parameters": [
        {"name": "data", "type": "const unsigned char *"},
        {"name": "length", "type": "unsigned int"},
    ],
    "locals": [
        {"name": "crc", "type": "unsigned short"},
        {"name": "byte_index", "type": "unsigned int"},
        {"name": "bit_index", "type": "unsigned int"},
    ],
    "canonical_plate": (
        "Computes a CRC-16 checksum over a byte buffer using the CCITT / "
        "XMODEM variant. Polynomial 0x1021. Initial value 0xFFFF."
    ),
    "algorithm_tag": "CRC-16-CCITT",
    "algorithm_synonyms": ["CRC16-CCITT", "CCITT CRC", "XMODEM CRC"],
    "weights": {
        "name": 0.25,
        "signature": 0.25,
        "plate": 0.20,
        "algorithm": 0.15,
        "locals": 0.15,
    },
}


# ---------- tier-1 primitives ----------


def test_normalize_identifier_strips_stdcall_and_case():
    assert _normalize_identifier("_calc_crc16@8") == "calccrc16"
    assert _normalize_identifier("CalcCrc16") == "calccrc16"
    assert _normalize_identifier("calc_crc16") == "calccrc16"


def test_normalize_type_canonicalizes_aliases():
    assert _normalize_type("ushort") == _normalize_type("unsigned short")
    assert _normalize_type("uint") == _normalize_type("unsigned int")
    assert _normalize_type("byte") == _normalize_type("unsigned char")


# ---------- multi-level rubric for names ----------


def test_name_exact_match_against_canonical():
    r = _rubric_score_name("calc_crc16", "calc_crc16", [])
    assert r["score"] == 1.0
    assert r["tier"] == "exact"


def test_name_exact_match_against_synonym_modulo_case_and_underscores():
    # "CalcCrc16" normalizes to the same thing as "calc_crc16" (the
    # truth name), so the exact tier finds a match on the canonical
    # first and reports that as the match target. Order matters: the
    # canonical is candidate[0], synonyms fill the rest.
    r = _rubric_score_name("CalcCrc16", "calc_crc16", ["CalcCrc16", "ComputeCrc16"])
    assert r["score"] == 1.0
    assert r["tier"] == "exact"
    # It happens to also match the synonym at tier 1, but the canonical
    # is preferred because it's checked first.
    assert r["matched_against"] == "calc_crc16"


def test_name_exact_match_against_synonym_only():
    # Worker generated a PascalCase synonym; truth canonical is different.
    # Normalized equality still fires against the synonym at tier 1.
    r = _rubric_score_name(
        "ComputeCrc16Ccitt", "calc_crc16", ["ComputeCrc16Ccitt", "CalcCrc16"]
    )
    assert r["score"] == 1.0
    assert r["tier"] == "exact"
    assert r["matched_against"] == "ComputeCrc16Ccitt"


def test_name_containment_lands_on_prefix_tier():
    # Worker wrote CalcCrc16Ccitt; truth is calc_crc16 (containment).
    r = _rubric_score_name("CalcCrc16Ccitt", "calc_crc16", [])
    assert r["tier"] == "prefix"
    assert r["score"] == 0.7


def test_name_unrelated_lands_on_miss():
    r = _rubric_score_name("ProcessBuffer", "calc_crc16", ["CalcCrc16"])
    assert r["tier"] == "miss"
    assert r["score"] == 0.0


def test_name_llm_stub_partial_credit_for_rearranged_name():
    # A worker named "Crc16Calc" (truth: calc_crc16) has 100% character
    # overlap but word order scrambled — neither exact nor a 5-char
    # prefix match. The stubbed llm-judge band should give it partial
    # credit between 0.3 and 0.5. Real Haiku may rank differently; this
    # test locks in the stub behavior so regression to 0 would fail.
    r = _rubric_score_name("Crc16Calc", "calc_crc16", [])
    # Containment check is substring-level on normalized form — neither
    # "crc16calc" contains "calccrc16" nor vice versa, so tier 2 misses
    # and the llm stub handles it.
    assert r["tier"] == "llm_stub"
    assert 0.3 <= r["score"] <= 0.5


def test_name_clearly_unrelated_scores_zero_even_with_stub():
    # "RenderTexture" has almost no character overlap with "calc_crc16";
    # stub threshold 0.6 keeps it at 0.0 rather than leaking partial
    # credit to genuinely unrelated names.
    r = _rubric_score_name("RenderTexture", "calc_crc16", [])
    assert r["tier"] == "miss"
    assert r["score"] == 0.0


def test_name_missing_generated_scores_zero():
    r = _rubric_score_name(None, "calc_crc16", ["CalcCrc16"])
    assert r["score"] == 0.0
    assert r["tier"] == "miss"


# ---------- structural scoring ----------


def test_signature_perfect_match():
    captured = {
        "return_type": "unsigned short",
        "parameters": [
            {"name": "data", "type": "const unsigned char *"},
            {"name": "length", "type": "unsigned int"},
        ],
    }
    s = score_function(captured, TRUTH)
    assert s["dimensions"]["signature"]["score"] == 1.0
    assert s["dimensions"]["signature"]["return_type_match"] is True


def test_signature_type_alias_still_counts_as_match():
    # Ghidra often writes `ushort` instead of `unsigned short`.
    captured = {
        "return_type": "ushort",
        "parameters": [
            {"name": "buf", "type": "byte *"},
            {"name": "n", "type": "uint"},
        ],
    }
    s = score_function(captured, TRUTH)
    # return type: unsigned short <-> ushort aliases; param 0:
    # const unsigned char * vs byte * — prefix doesn't match, score 0
    # param 1: unsigned int vs uint aliases -> match
    # return_type_match true + param matched 1/2 -> 0.5 + 0.5 * 0.5 = 0.75
    assert s["dimensions"]["signature"]["return_type_match"] is True
    assert s["dimensions"]["signature"]["score"] == pytest.approx(0.75, abs=0.01)


def test_signature_undefined_types_penalized():
    captured = {
        "return_type": "undefined4",
        "parameters": [
            {"name": "param_1", "type": "undefined4"},
            {"name": "param_2", "type": "undefined4"},
        ],
    }
    s = score_function(captured, TRUTH)
    # No types match; return_type miss + 0/2 params = 0.0
    assert s["dimensions"]["signature"]["score"] == 0.0


# ---------- algorithm detection ----------


def test_algorithm_mentioned_in_plate_scores_full():
    captured = {
        "name": "CalcCrc16",
        "plate": "Computes a CRC-16-CCITT checksum over a buffer.",
    }
    s = score_function(captured, TRUTH)
    assert s["dimensions"]["algorithm"]["score"] == 1.0
    assert s["dimensions"]["algorithm"]["mention_found"] is True
    assert s["dimensions"]["algorithm"]["matched_tag"] == "CRC-16-CCITT"


def test_algorithm_synonym_also_counts():
    captured = {
        "name": "CalcCrc16",
        "plate": "Classic XMODEM CRC calculation.",
    }
    s = score_function(captured, TRUTH)
    assert s["dimensions"]["algorithm"]["score"] == 1.0


def test_algorithm_missing_scores_zero():
    captured = {
        "name": "ProcessBuffer",
        "plate": "Processes a buffer and returns a value.",
    }
    s = score_function(captured, TRUTH)
    assert s["dimensions"]["algorithm"]["score"] == 0.0
    assert s["dimensions"]["algorithm"]["mention_found"] is False


# ---------- guardrails ----------


def test_guardrails_detect_duplicate_tool_calls():
    tool_calls = [
        {"tool": "decompile_function", "args": {"address": "0x1000"}},
        {"tool": "decompile_function", "args": {"address": "0x1000"}},  # dup
        {"tool": "decompile_function", "args": {"address": "0x1000"}},  # dup
        {"tool": "get_function_signature", "args": {"address": "0x1000"}},
    ]
    g = guardrails(tool_calls, quality=0.5)
    assert g["tool_calls_total"] == 4
    assert g["duplicate_tool_call_ratio"] == 0.5  # 2 dups out of 4


def test_guardrails_tool_calls_per_quality_point():
    tool_calls = [{"tool": "t", "args": {"i": i}} for i in range(10)]
    g = guardrails(tool_calls, quality=0.5)
    # 10 calls / 0.5 quality = 20
    assert g["tool_calls_per_quality_point"] == 20.0


def test_guardrails_zero_quality_emits_none_for_per_qp():
    g = guardrails([{"tool": "t", "args": {}}], quality=0.0)
    assert g["tool_calls_per_quality_point"] is None


# ---------- end-to-end scoring on the real fixtures ----------


def test_baseline_fixture_scores_reasonably():
    """Baseline fixture represents typical fun-doc output; score must
    land in the 'good but not perfect' band (0.7–0.9). Regression
    below 0.7 or above 0.9 indicates the scorer drifted."""
    gt_file = BENCHMARK_DIR / "ground_truth.json"
    fx = BENCHMARK_DIR / "fixtures" / "calc_crc16.baseline.capture.json"
    gt = json.loads(gt_file.read_text(encoding="utf-8"))
    cap = json.loads(fx.read_text(encoding="utf-8"))

    truth = gt["functions"]["calc_crc16"]
    result = score_function(cap["captured"], truth)
    assert 0.7 <= result["quality"] <= 0.9, (
        f"baseline quality drifted: {result['quality']}"
    )


def test_poor_fixture_scores_low():
    """Poor fixture represents a botched run; score must be below 0.25."""
    gt_file = BENCHMARK_DIR / "ground_truth.json"
    fx = BENCHMARK_DIR / "fixtures" / "calc_crc16.poor.capture.json"
    gt = json.loads(gt_file.read_text(encoding="utf-8"))
    cap = json.loads(fx.read_text(encoding="utf-8"))

    truth = gt["functions"]["calc_crc16"]
    result = score_function(cap["captured"], truth)
    assert result["quality"] < 0.25, (
        f"poor fixture scored too high: {result['quality']}"
    )

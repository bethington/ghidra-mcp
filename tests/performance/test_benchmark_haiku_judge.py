"""Offline tests for the Haiku 4.5 plate-judge integration.

Scorer's plate-dimension scoring has two paths:
  1. Real Haiku call when ANTHROPIC_API_KEY is set and the SDK
     responds cleanly. Tier: "llm_haiku".
  2. Jaccard word-overlap fallback when: no key, SDK not installed,
     FUNDOC_BENCHMARK_NO_LLM=1, or the Haiku call errored. Tier:
     "jaccard".

These tests mock the anthropic client so we don't hit the real API.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


BENCHMARK_DIR = Path(__file__).resolve().parents[2] / "fun-doc" / "benchmark"
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

import scorer


TRUTH = {
    "canonical_plate": (
        "Computes a CRC-16 checksum using CCITT variant. "
        "Polynomial 0x1021, initial value 0xFFFF."
    ),
}


def _fake_anthropic_response(text: str):
    """Build a fake anthropic messages.create response."""
    block = MagicMock()
    block.type = "text"
    block.text = text
    resp = MagicMock()
    resp.content = [block]
    return resp


# ---------- Fallback path ----------


def test_plate_uses_jaccard_fallback_when_no_api_key(monkeypatch):
    """No ANTHROPIC_API_KEY -> fall back to Jaccard immediately, don't
    even try to import anthropic. Deterministic and offline-safe."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(scorer, "_LLM_DISABLED", False)

    captured = {"plate": "Computes a CRC-16 checksum. Polynomial 0x1021."}
    result = scorer._score_plate(captured, TRUTH)
    assert result["tier"] == "jaccard"
    assert 0.0 < result["score"] <= 1.0


def test_plate_respects_no_llm_env(monkeypatch):
    """FUNDOC_BENCHMARK_NO_LLM=1 forces fallback even with key set."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-key")
    monkeypatch.setattr(scorer, "_LLM_DISABLED", True)

    captured = {"plate": "Computes a CRC-16 checksum. Polynomial 0x1021."}
    result = scorer._score_plate(captured, TRUTH)
    assert result["tier"] == "jaccard"


def test_plate_fallback_on_haiku_exception(monkeypatch):
    """If the Haiku call raises (network, rate-limit, bad response),
    the scorer must catch and fall back to Jaccard — a benchmark run
    shouldn't abort on a transient API hiccup."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-key")
    monkeypatch.setattr(scorer, "_LLM_DISABLED", False)

    fake_anthropic = MagicMock()
    fake_anthropic.Anthropic.return_value.messages.create.side_effect = (
        RuntimeError("rate limit exceeded")
    )
    with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
        captured = {"plate": "Computes a CRC-16 checksum."}
        result = scorer._score_plate(captured, TRUTH)

    assert result["tier"] == "jaccard"


# ---------- Haiku path ----------


def test_plate_uses_haiku_when_available(monkeypatch):
    """Haiku returns a decimal; scorer uses it verbatim as the score."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-key")
    monkeypatch.setattr(scorer, "_LLM_DISABLED", False)

    fake_anthropic = MagicMock()
    fake_anthropic.Anthropic.return_value.messages.create.return_value = (
        _fake_anthropic_response("0.85")
    )
    with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
        captured = {"plate": "CRC-16-CCITT checksum, polynomial 0x1021."}
        result = scorer._score_plate(captured, TRUTH)

    assert result["tier"] == "llm_haiku"
    assert result["score"] == 0.85
    assert result["model"] == scorer.HAIKU_JUDGE_MODEL


def test_haiku_response_parses_score_from_mixed_text(monkeypatch):
    """Models occasionally emit e.g. 'Score: 0.72' despite instructions
    saying 'only the number'. Extractor grabs the first float."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-key")
    monkeypatch.setattr(scorer, "_LLM_DISABLED", False)

    fake_anthropic = MagicMock()
    fake_anthropic.Anthropic.return_value.messages.create.return_value = (
        _fake_anthropic_response("Score: 0.72 (partial match)")
    )
    with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
        result = scorer._score_plate({"plate": "something"}, TRUTH)

    assert result["tier"] == "llm_haiku"
    assert result["score"] == 0.72


def test_haiku_clamps_out_of_range_scores(monkeypatch):
    """Models sometimes emit scores outside [0, 1]. Clamp to the
    valid range so the aggregate quality math doesn't blow up."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-key")
    monkeypatch.setattr(scorer, "_LLM_DISABLED", False)

    fake_anthropic = MagicMock()
    fake_anthropic.Anthropic.return_value.messages.create.return_value = (
        _fake_anthropic_response("1.4")
    )
    with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
        result = scorer._score_plate({"plate": "x"}, TRUTH)
    assert result["score"] == 1.0

    fake_anthropic.Anthropic.return_value.messages.create.return_value = (
        _fake_anthropic_response("-0.2")
    )
    with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
        result = scorer._score_plate({"plate": "x"}, TRUTH)
    assert result["score"] == 0.0


def test_haiku_unparseable_response_falls_back(monkeypatch):
    """Response with no number in it (e.g. 'unable to score') falls
    back to Jaccard rather than returning a bogus score."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-key")
    monkeypatch.setattr(scorer, "_LLM_DISABLED", False)

    fake_anthropic = MagicMock()
    fake_anthropic.Anthropic.return_value.messages.create.return_value = (
        _fake_anthropic_response("unable to score")
    )
    with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
        result = scorer._score_plate(
            {"plate": "Computes a CRC-16 checksum."}, TRUTH
        )
    assert result["tier"] == "jaccard"


# ---------- Edge cases (pre-LLM) ----------


def test_plate_empty_canonical_returns_zero(monkeypatch):
    """No canonical plate -> score 0 with tier 'no_canonical'. Never
    calls Haiku (nothing to compare against)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-key")
    monkeypatch.setattr(scorer, "_LLM_DISABLED", False)

    result = scorer._score_plate({"plate": "x"}, {"canonical_plate": ""})
    assert result["tier"] == "no_canonical"
    assert result["score"] == 0.0


def test_plate_empty_generated_returns_zero(monkeypatch):
    """Worker produced no plate -> score 0 with tier 'miss'. Never
    calls Haiku (nothing to evaluate)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-key")
    monkeypatch.setattr(scorer, "_LLM_DISABLED", False)

    result = scorer._score_plate({"plate": ""}, TRUTH)
    assert result["tier"] == "miss"
    assert result["score"] == 0.0

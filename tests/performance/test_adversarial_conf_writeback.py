"""Tests for adversarial_reproof's CONF_ rung write-back.

Before this existed, an adversarial result lived ONLY in
proven_functions.jsonl as a `vetted` field: 7 of 199 proven functions were
vetted while all 199 read CONF_LIVE in Ghidra, and a DIVERGED result -- which
REOPENS the reimpl -- left the disproved rung standing.

Pinned here:
  * a pass promotes to CONF_VETTED only when that OUTRANKS the held rung
  * a divergence refutes whatever rung is held
  * the Ghidra read is the authority, not the registry mirror (which lags)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

ar = pytest.importorskip("adversarial_reproof")
import conf_ladder  # noqa: E402

PASS = {"vectors": 40, "used_model": True}
FAIL = {"mismatches": 3, "vectors": 40, "regression_case": "x.cases.json"}
DATE = "2026-07-29"


# --- a pass promotes, but only upward --------------------------------------

def test_pass_promotes_from_live():
    rung, rec = ar.decide_adversarial_outcome("CONF_LIVE", "vetted", PASS, DATE)
    assert rung == "CONF_VETTED"
    assert rec["method"] == "adversarial" and rec["vectors"] == 40


def test_pass_promotes_from_untagged_or_lower():
    for held in (None, "CONF_DRAFT", "CONF_VECTORS"):
        rung, _ = ar.decide_adversarial_outcome(held, "vetted", PASS, DATE)
        assert rung == "CONF_VETTED", held


def test_pass_does_not_knock_down_a_higher_rung():
    """InitRngSeed is CONF_BATTLETESTED live. Passing an adversarial check it
    already outranks must not demote it to CONF_VETTED."""
    for held in ("CONF_BATTLETESTED", "CONF_SHIPPED", "CONF_VETTED"):
        rung, rec = ar.decide_adversarial_outcome(held, "vetted", PASS, DATE)
        assert (rung, rec) == (None, None), held


# --- a divergence refutes ---------------------------------------------------

def test_divergence_refutes_any_held_rung():
    for held in conf_ladder.CONF_LADDER:
        rung, rec = ar.decide_adversarial_outcome(held, "DIVERGED", FAIL, DATE)
        assert rung == conf_ladder.CONF_REFUTED, held
        assert rec["refuted_from"] == held
        assert rec["source"] == "adversarial_failure"


def test_divergence_preserves_the_counterexample():
    _rung, rec = ar.decide_adversarial_outcome("CONF_LIVE", "DIVERGED", FAIL, DATE)
    ce = rec["counterexample"]
    assert ce["mismatches"] == 3 and ce["vectors"] == 40
    assert ce["regression_case"] == "x.cases.json"


def test_divergence_on_an_untagged_function_is_a_noop():
    """Nothing to refute -- no claim was ever made."""
    for held in (None, conf_ladder.CONF_BLOCKED, conf_ladder.CONF_REFUTED):
        assert ar.decide_adversarial_outcome(held, "DIVERGED", FAIL, DATE) == (None, None)


def test_other_statuses_write_nothing():
    for status in ("skipped_shadow_only", "skipped_no_spec", ""):
        assert ar.decide_adversarial_outcome("CONF_LIVE", status, PASS, DATE) == (None, None)


# --- the Ghidra read is the authority --------------------------------------

def test_current_rung_reads_ghidra_not_the_registry(monkeypatch):
    """The registry mirror lags: a shadow promotion updates Ghidra first. Using
    the mirror's own `conf` field would let a stale CONF_LIVE demote a function
    Ghidra already promoted past it."""
    class _Resp:
        def read(self):
            return b'{"tags":[{"name":"CONF_BATTLETESTED"},{"name":"DOC_DRAFT"}]}'

    class _Conn:
        def __init__(self, *a, **k):
            pass

        def request(self, *a, **k):
            pass

        def getresponse(self):
            return _Resp()

        def close(self):
            pass

    monkeypatch.setattr(ar.http.client, "HTTPConnection", _Conn)
    # registry row deliberately claims a LOWER rung than Ghidra holds
    row = {"name": "InitRngSeed", "address": "6fd86740",
           "program": "D2Common.dll", "conf": "CONF_LIVE"}
    assert ar._current_conf_rung(row) == "CONF_BATTLETESTED"


def test_current_rung_is_none_without_a_program():
    """No program means no safe write -- a defaulted program is what caused the
    wrong-binary bug."""
    assert ar._current_conf_rung({"name": "x", "address": "6fd86740"}) is None

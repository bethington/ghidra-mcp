"""Regression: conformance matrix/intake must report a real in_scope.

Bug (2026-07-24): D2Client's "Functions - Documentation" bar read
"0.0% at VERIFIED - 326700.0% any". The conformance `summary` program
option — the source of `in_scope` — is only written by the sync tool, so
for a binary that never went through conformance intake it is absent and
`summary()` returned `in_scope: None`. `matrix()` passed that null through,
and the dashboard's `renderBars` divided the 3267 doc-tagged functions by
its `in_scope || 1` fallback: 3267 / 1 = 326700%.

`bands()` already guarded this with the defined-minus-library `_in_scope_fn`
fallback; `matrix()` and `intake()` did not. These tests pin that they now
do, so the doc/conformance bars always have a real denominator.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"


@pytest.fixture
def cdash(monkeypatch):
    """Load conformance_dashboard.py with its Ghidra-facing helpers stubbed,
    so matrix()/intake() run without a live server."""
    monkeypatch.syspath_prepend(str(FUN_DOC_DIR))
    spec = importlib.util.spec_from_file_location(
        "cdash_uut", FUN_DOC_DIR / "conformance_dashboard.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cdash_uut"] = mod
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pytest.skip("conformance_dashboard raised SystemExit during import")
    yield mod
    sys.modules.pop("cdash_uut", None)


def _stub_tags(mod, monkeypatch, doc_draft_addrs):
    """Every DOC_DRAFT tag maps to the given addresses; all other tags empty."""
    def fake_tag_addrs(tag, program=None):
        return set(doc_draft_addrs) if tag == "DOC_DRAFT" else set()

    monkeypatch.setattr(mod, "_tag_addrs", fake_tag_addrs)


def test_matrix_falls_back_to_computed_in_scope_when_option_absent(cdash, monkeypatch):
    # 3267 functions tagged DOC_DRAFT, no conformance summary option written.
    draft = {f"0x{i:06x}" for i in range(3267)}
    _stub_tags(cdash, monkeypatch, draft)
    monkeypatch.setattr(cdash, "summary", lambda program=None: {})  # no in_scope
    monkeypatch.setattr(cdash, "_in_scope_fn", lambda program, s: 3327)

    m = cdash.matrix("/Mods/PD2-S12/D2Client.dll")

    assert m["in_scope"] == 3327, "must compute in_scope instead of passing None"
    assert m["evaluated"] == 3267
    # never-evaluated cell = in_scope - evaluated, and stays non-negative.
    assert m["cell"]["none"]["none"] == 3327 - 3267

    # The doc bar's denominator is now real: 3267 / 3327 ~= 98.2%, not 326700%.
    col = lambda c: sum((m["cell"].get(rk, {}) or {}).get(c, 0) for rk in m["rows"])
    any_pct = 100 * col("DOC_DRAFT") / m["in_scope"]
    assert 0 <= any_pct <= 100, f"doc coverage must be a real percentage, got {any_pct}"


def test_matrix_prefers_option_in_scope_when_present(cdash, monkeypatch):
    """When the sync tool did write the option, matrix uses it verbatim and
    does not pay for the fallback computation."""
    _stub_tags(cdash, monkeypatch, {"0x001000", "0x001010"})
    monkeypatch.setattr(cdash, "summary", lambda program=None: {"in_scope": 2547})

    def _should_not_run(program, s):  # pragma: no cover - asserts it isn't called
        raise AssertionError("_in_scope_fn must not run when the option has in_scope")

    monkeypatch.setattr(cdash, "_in_scope_fn", _should_not_run)

    m = cdash.matrix("/Mods/PD2-S12/D2Common.dll")
    assert m["in_scope"] == 2547


def test_intake_reports_computed_in_scope(cdash, monkeypatch):
    """The 'X / Y in scope' header reads from the matrix's in_scope, so it is
    populated even when the summary option is missing."""
    _stub_tags(cdash, monkeypatch, {"0x2000", "0x2010", "0x2020"})
    monkeypatch.setattr(cdash, "summary", lambda program=None: {})
    monkeypatch.setattr(cdash, "_in_scope_fn", lambda program, s: 42)

    ik = cdash.intake("/Mods/PD2-S12/D2Client.dll")
    assert ik["in_scope"] == 42


def test_matrix_in_scope_none_only_if_ghidra_unreachable(cdash, monkeypatch):
    """If even the fallback can't determine a count (Ghidra unreachable ->
    _in_scope_fn returns None), matrix reports None rather than a wrong number;
    the frontend then renders an em dash instead of a bogus percentage."""
    _stub_tags(cdash, monkeypatch, {"0x3000"})
    monkeypatch.setattr(cdash, "summary", lambda program=None: {})
    monkeypatch.setattr(cdash, "_in_scope_fn", lambda program, s: None)

    m = cdash.matrix("/Mods/PD2-S12/D2Client.dll")
    assert m["in_scope"] is None
    # and it must not have fabricated a never-evaluated count from a null scope
    assert m["cell"]["none"]["none"] == 0

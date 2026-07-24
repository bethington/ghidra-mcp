"""Offline tests for the provider-disable and audit-watcher toggles.

Added 2026-07-24 after Google retired Gemini Code Assist for individuals,
which turned every gemini call into a terminal IneligibleTierError. Rather
than special-case gemini, the operator gets two general switches:

  * disabled_providers — a provider named here (config or the
    FUNDOC_DISABLED_PROVIDERS env var) is refused for every role: primary
    worker, audit pass, escalation, and complexity handoff.
  * audit_watcher — the always-on system-health watcher (fun-doc/audit/)
    finally has an off switch (config.audit_watcher / FUNDOC_AUDIT_WATCHER).

These pin the contract so a future refactor can't quietly route work to a
retired provider or lose the watcher toggle.
"""

from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"


@pytest.fixture
def fd(monkeypatch):
    """Import fun_doc.py with siblings resolvable, isolated per test."""
    monkeypatch.setenv("FUNDOC_DASHBOARD", "false")
    monkeypatch.syspath_prepend(str(FUN_DOC_DIR))
    monkeypatch.delenv("FUNDOC_DISABLED_PROVIDERS", raising=False)
    monkeypatch.delenv("FUNDOC_AUDIT_WATCHER", raising=False)
    spec = importlib.util.spec_from_file_location(
        "fun_doc_toggles_uut", FUN_DOC_DIR / "fun_doc.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fun_doc_toggles_uut"] = mod
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pytest.skip("fun_doc.py raised SystemExit during import")
    yield mod
    sys.modules.pop("fun_doc_toggles_uut", None)


def _queue(**cfg):
    return {"config": cfg}


# ---------- disabled_providers ----------


def test_disabled_from_config(fd):
    q = _queue(disabled_providers=["gemini"])
    assert fd.get_disabled_providers(q) == {"gemini"}
    assert fd.provider_is_disabled("gemini", q)
    assert not fd.provider_is_disabled("minimax", q)


def test_disabled_from_env_is_additive(fd, monkeypatch):
    monkeypatch.setenv("FUNDOC_DISABLED_PROVIDERS", "codex")
    q = _queue(disabled_providers=["gemini"])
    # Env adds to the config list, doesn't replace it.
    assert fd.get_disabled_providers(q) == {"gemini", "codex"}


def test_disabled_case_and_whitespace_insensitive(fd, monkeypatch):
    monkeypatch.setenv("FUNDOC_DISABLED_PROVIDERS", "  GEMINI , Codex ")
    assert fd.get_disabled_providers(_queue()) == {"gemini", "codex"}


def test_unknown_provider_names_ignored(fd):
    # A typo must not silently disable "everything" or crash a lookup.
    q = _queue(disabled_providers=["gemmini", "notaprovider"])
    assert fd.get_disabled_providers(q) == set()


def test_escalation_target_that_is_disabled_returns_none(fd):
    q = _queue(
        pre_escalate_retry=True,
        auto_escalate_provider="gemini",
        disabled_providers=["gemini"],
    )
    assert fd.get_auto_escalation_provider("minimax", q) is None


def test_escalation_target_not_disabled_still_returned(fd):
    q = _queue(
        pre_escalate_retry=True,
        auto_escalate_provider="claude",
        disabled_providers=["gemini"],
    )
    assert fd.get_auto_escalation_provider("minimax", q) == "claude"


def test_snapshot_drops_disabled_audit_and_handoff_providers(fd):
    q = _queue(
        audit_provider="gemini",
        complexity_handoff_provider="gemini",
        disabled_providers=["gemini"],
        provider_models={"minimax": {"FULL": "MiniMax-M3"}},
    )
    snap = fd.build_worker_config_snapshot(q, "minimax")

    assert snap["audit_provider"] is None
    assert snap["complexity_handoff_provider"] is None
    # ...and the disabled provider's slice is never frozen in.
    assert "gemini" not in snap["providers"]
    assert "minimax" in snap["providers"]


def test_snapshot_keeps_enabled_roles(fd):
    q = _queue(
        audit_provider="claude",
        disabled_providers=["gemini"],
        provider_models={
            "minimax": {"FULL": "MiniMax-M3"},
            "claude": {"FULL": "claude-sonnet-4-6"},
        },
    )
    snap = fd.build_worker_config_snapshot(q, "minimax")

    assert snap["audit_provider"] == "claude"
    assert "claude" in snap["providers"]


# ---------- audit_watcher toggle ----------


def test_audit_watcher_on_by_default(fd):
    assert fd.audit_watcher_enabled(_queue()) is True


def test_audit_watcher_off_via_config(fd):
    assert fd.audit_watcher_enabled(_queue(audit_watcher=False)) is False


@pytest.mark.parametrize("val", ["0", "false", "off", "no", "OFF", " false "])
def test_audit_watcher_off_via_env(fd, monkeypatch, val):
    monkeypatch.setenv("FUNDOC_AUDIT_WATCHER", val)
    # Env wins even when config says on.
    assert fd.audit_watcher_enabled(_queue(audit_watcher=True)) is False


def test_audit_watcher_env_on_overrides_config_off(fd, monkeypatch):
    monkeypatch.setenv("FUNDOC_AUDIT_WATCHER", "1")
    assert fd.audit_watcher_enabled(_queue(audit_watcher=False)) is True


# ---------- start_worker rejects a disabled primary provider ----------


@pytest.fixture
def web_mod(monkeypatch):
    monkeypatch.setenv("FUNDOC_DASHBOARD", "false")
    monkeypatch.syspath_prepend(str(FUN_DOC_DIR))
    for name in ("web",):
        sys.modules.pop(name, None)
    try:
        import web  # noqa: WPS433
    except SystemExit:
        pytest.skip("web.py raised SystemExit during import")
    yield web
    sys.modules.pop("web", None)


def _mgr(web):
    return web.WorkerManager(
        state_file=Path("/tmp/none.json"),
        bus=MagicMock(),
        socketio=MagicMock(),
        load_queue=MagicMock(return_value={"config": {}, "meta": {}}),
        save_queue=MagicMock(),
    )


def test_start_worker_rejects_disabled_provider(web_mod, monkeypatch):
    import fun_doc

    monkeypatch.setattr(fun_doc, "provider_is_disabled", lambda p, q=None: p == "gemini")
    mgr = _mgr(web_mod)

    with pytest.raises(ValueError, match="disabled"):
        mgr.start_worker(provider="gemini", count=1)


def test_start_worker_allows_enabled_provider(web_mod, monkeypatch):
    import fun_doc

    monkeypatch.setattr(fun_doc, "provider_is_disabled", lambda p, q=None: p == "gemini")
    # Stop the launch right after the disabled-check so we don't spin a real
    # worker thread: a MAX_WORKERS bump isn't needed — patch the thread start.
    monkeypatch.setattr(web_mod.threading, "Thread", MagicMock())
    mgr = _mgr(web_mod)

    wid = mgr.start_worker(provider="minimax", count=1)
    assert isinstance(wid, str) and wid

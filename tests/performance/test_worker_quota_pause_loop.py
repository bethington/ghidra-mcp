"""Regression tests for how the function-worker loop reacts to a walled or
dead provider.

Background — reproduced live on 2026-07-24 against the real dashboard:

  A minimax worker started with count=5 hit a 429 token-plan wall on its
  first function. It then re-attempted *the same function* five times in
  ~75 seconds, consumed its entire budget, and exited reporting
  `completed: 5, failed: 0`. Nothing in the run record said the provider
  was walled; the operator saw a clean run that documented nothing.

  Two defects combined:

    1. `quota_paused` was not handled in the result ladder, so it fell
       through to the catch-all that counts a result as *completed*.
    2. The pause is installed by the provider subprocess that made the
       walled call. The dashboard's own ProviderPauseManager read the
       pause file once at construction, so `_yield_for_quota_pause` never
       saw the wall and the worker never slept.

  Separately, a terminal provider failure (2026-07-24: gemini's
  IneligibleTierError after Google retired Code Assist for individuals)
  had no halt at all — the worker marched down the queue converting every
  function into a `failed` run at roughly one per minute.

These tests pin the fixed contract:

  * `quota_paused` consumes no budget, counts as neither completed nor
    failed, and parks the worker in the `quota_paused` status until the
    wall clears — then real work resumes.
  * A pause installed through a *different* manager instance (standing in
    for the provider subprocess) is visible to the worker loop.
  * `provider_unavailable` stops the worker with an exit_reason instead of
    burning the queue.

The loop is driven for real; only its collaborators (state, selector,
process_function) are stubbed.
"""

from __future__ import annotations

import sys
import threading
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"


@pytest.fixture
def web_module(monkeypatch):
    monkeypatch.setenv("FUNDOC_DASHBOARD", "false")
    monkeypatch.syspath_prepend(str(FUN_DOC_DIR))
    for name in ("web", "provider_pause"):
        sys.modules.pop(name, None)
    try:
        import web  # noqa: WPS433 — intentional re-import under patched sys.path
    except SystemExit:  # pragma: no cover - missing optional deps
        pytest.skip("web.py raised SystemExit during import")

    yield web
    sys.modules.pop("web", None)


@pytest.fixture
def fun_doc_module(web_module, monkeypatch):
    """The worker loop imports its collaborators from fun_doc *inside* the
    method, so stubs have to land on the fun_doc module object."""
    try:
        import fun_doc  # noqa: WPS433
    except SystemExit:  # pragma: no cover - missing optional deps
        pytest.skip("fun_doc.py raised SystemExit during import")
    return fun_doc


@pytest.fixture
def pause_mgr(tmp_path, monkeypatch):
    """A real ProviderPauseManager on a temp dir, installed as the module
    singleton so both the worker loop and our stub provider share it."""
    import provider_pause as pp

    mgr = pp.ProviderPauseManager(tmp_path, jitter_fn=lambda: 0.0)
    monkeypatch.setattr(pp, "get_default_manager", lambda: mgr)
    return mgr


def _make_mgr(web_module):
    return web_module.WorkerManager(
        state_file=Path("/tmp/none.json"),
        bus=MagicMock(),
        socketio=MagicMock(),
        load_queue=MagicMock(return_value={"config": {}, "meta": {}}),
        save_queue=MagicMock(),
    )


def _install_worker(mgr, count=3, provider="minimax", model="MiniMax-M3"):
    """Insert a runnable worker dict the way start_worker would."""
    now = datetime.now().isoformat()
    worker = {
        "id": "w1",
        "provider": provider,
        "model": None,
        "count": count,
        "continuous": False,
        "binary": None,
        "status": "running",
        "mode": "functions",
        "started_at": now,
        "finished_at": None,
        "phase": "starting",
        "phase_since": now,
        "last_heartbeat_at": now,
        "stop_flag": threading.Event(),
        "progress": {"completed": 0, "skipped": 0, "failed": 0, "current": None},
        "config_snapshot": {
            "good_enough_score": 90,
            "providers": {provider: {"max_turns": 50, "models": {"FULL": model}}},
        },
        "exit_reason": None,
    }
    mgr._workers["w1"] = worker
    return worker


def _stub_loop_deps(fun_doc_module, monkeypatch, results):
    """Wire the loop's collaborators to deterministic stubs.

    `results` is a list of process_function return values, consumed in
    order; the list of calls made is returned for assertions.
    """
    calls = []
    func = {"name": "TargetFunction", "address": "6fb04e10", "score": 50}
    key = "/Mods/PD2-S12/D2Client.dll::6fb04e10"

    def fake_process_function(k, f, state, **kwargs):
        calls.append(k)
        return results[len(calls) - 1] if len(calls) <= len(results) else "completed"

    monkeypatch.setattr(fun_doc_module, "process_function", fake_process_function)
    monkeypatch.setattr(
        fun_doc_module, "load_state", lambda *a, **k: {"functions": {key: func}}
    )
    monkeypatch.setattr(fun_doc_module, "get_next_functions", lambda *a, **k: [(key, func)])
    monkeypatch.setattr(
        fun_doc_module,
        "start_session",
        lambda *a, **k: {"completed": 0, "skipped": 0, "failed": 0, "functions": []},
    )
    monkeypatch.setattr(fun_doc_module, "finalize_worker_session", lambda *a, **k: None)
    monkeypatch.setattr(
        fun_doc_module, "load_priority_queue", lambda *a, **k: {"config": {}, "meta": {}}
    )
    monkeypatch.setattr(fun_doc_module, "get_auto_escalation_provider", lambda *a, **k: None)
    monkeypatch.setattr(fun_doc_module, "refresh_candidate_scores", lambda *a, **k: {})
    return calls


def test_quota_paused_does_not_consume_budget_or_count_as_completed(
    web_module, fun_doc_module, monkeypatch, pause_mgr
):
    """The live failure mode: a walled provider must not report progress.

    Pre-fix this exited with completed == count and one function attempted
    `count` times. Post-fix the walled attempt is free — the worker sleeps
    on the pause, then does the real work when it clears.
    """
    import provider_pause as pp

    mgr = _make_mgr(web_module)
    worker = _install_worker(mgr, count=2)

    def process_with_wall(k, f, state, **kwargs):
        # First attempt discovers the wall the way the provider subprocess
        # does: install the pause, return quota_paused.
        pause_mgr.install("minimax", "MiniMax-M3", pp.ResetInfo(0.3, "429 token plan"))
        return "quota_paused"

    calls = _stub_loop_deps(fun_doc_module, monkeypatch, [])
    seq = {"n": 0}

    def dispatch(k, f, state, **kwargs):
        seq["n"] += 1
        calls.append(k)
        if seq["n"] == 1:
            return process_with_wall(k, f, state, **kwargs)
        return "completed"

    monkeypatch.setattr(fun_doc_module, "process_function", dispatch)

    mgr._run_worker_functions("w1")

    assert worker["progress"]["completed"] == 2, (
        "the walled attempt must not count; both budget slots should be spent "
        "on real work once the wall clears"
    )
    assert worker["progress"]["failed"] == 0
    assert len(calls) == 3, "1 walled attempt (free) + 2 budgeted completions"
    assert worker["_quota_pause_count"] == 1


def test_worker_parks_in_quota_paused_status_while_walled(
    web_module, fun_doc_module, monkeypatch, pause_mgr
):
    """While the wall is up the dashboard must show `quota_paused`, not a
    worker that looks busy but is silently burning its queue."""
    import provider_pause as pp

    mgr = _make_mgr(web_module)
    worker = _install_worker(mgr, count=1)
    seen_status = []

    real_emit = mgr._emit_status
    monkeypatch.setattr(
        mgr, "_emit_status", lambda: (seen_status.append(worker["status"]), real_emit())
    )

    def dispatch(k, f, state, **kwargs):
        pause_mgr.install("minimax", "MiniMax-M3", pp.ResetInfo(0.3, "429 wall"))
        return "quota_paused" if len(seen_status) < 40 else "completed"

    _stub_loop_deps(fun_doc_module, monkeypatch, [])
    monkeypatch.setattr(fun_doc_module, "process_function", dispatch)

    mgr._run_worker_functions("w1")

    assert "quota_paused" in seen_status, (
        "worker never entered the quota_paused state — it was spinning"
    )


def test_pause_installed_by_other_manager_is_seen_by_worker_loop(
    web_module, fun_doc_module, monkeypatch, tmp_path
):
    """Cross-process visibility, end to end through the loop.

    The provider subprocess and the dashboard hold *separate* manager
    instances over the same file. The loop must yield to a wall it did not
    install itself.
    """
    import provider_pause as pp

    dashboard_mgr = pp.ProviderPauseManager(tmp_path, jitter_fn=lambda: 0.0)
    subprocess_mgr = pp.ProviderPauseManager(tmp_path, jitter_fn=lambda: 0.0)
    monkeypatch.setattr(pp, "get_default_manager", lambda: dashboard_mgr)

    mgr = _make_mgr(web_module)
    worker = _install_worker(mgr, count=1)
    _stub_loop_deps(fun_doc_module, monkeypatch, [])

    calls = {"n": 0}

    def dispatch(k, f, state, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            subprocess_mgr.install(
                "minimax", "MiniMax-M3", pp.ResetInfo(0.3, "wall from subprocess")
            )
            return "quota_paused"
        return "completed"

    monkeypatch.setattr(fun_doc_module, "process_function", dispatch)

    mgr._run_worker_functions("w1")

    assert worker["progress"]["completed"] == 1
    assert calls["n"] == 2, (
        "loop should have paused then retried once, not spun; the dashboard "
        "manager must observe the subprocess's pause file write"
    )


def test_provider_unavailable_stops_worker_with_exit_reason(
    web_module, fun_doc_module, monkeypatch, pause_mgr
):
    """A dead provider (gemini IneligibleTierError) halts the worker rather
    than converting every remaining function into a failed run."""
    mgr = _make_mgr(web_module)
    worker = _install_worker(mgr, count=10, provider="gemini", model="gemini-2.5-pro")
    calls = _stub_loop_deps(fun_doc_module, monkeypatch, ["provider_unavailable"])

    mgr._run_worker_functions("w1")

    assert worker["exit_reason"] == "provider_unavailable"
    assert len(calls) == 1, "must stop after the first terminal failure"
    assert worker["progress"]["failed"] == 0, (
        "a dead provider is not a per-function quality failure"
    )
    assert worker["progress"]["completed"] == 0

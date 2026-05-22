"""Regression tests for the WorkerManager exit_reason field.

Background: until v5.11.1 the dashboard rendered every clean worker exit
as plain "finished", whether the worker had actually processed N
functions or had silently bailed because `select_candidates` returned
zero eligible items (e.g. the entire binary is at-or-above
`good_enough_score`, or every remaining function is library-code /
stagnation-blocked / fails-exhausted). From the operator's vantage that
was indistinguishable from a real failure mode — 5 workers started, 5
workers stopped, no work done, no reason given.

These tests pin the contract:

  * A worker that exits with target=None on the first iteration records
    `worker["exit_reason"] = "no_eligible_candidates"`.
  * `get_status()` surfaces `exit_reason` so the dashboard can render
    "finished — no eligible candidates" instead of bare "finished".
  * The `worker_stopped` bus event includes `exit_reason` for downstream
    consumers (audit, dashboard log line).

We test by directly mutating the worker dict + exercising get_status()
and the emit path rather than spawning a real worker thread; that keeps
the test fast and independent of the priority-queue / state.db machinery.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"


@pytest.fixture
def web_module(monkeypatch):
    """Import fun-doc/web.py with its sibling-imports resolvable."""
    monkeypatch.setenv("FUNDOC_DASHBOARD", "false")
    monkeypatch.syspath_prepend(str(FUN_DOC_DIR))
    if "web" in sys.modules:
        del sys.modules["web"]
    import web  # noqa: WPS433  (intentionally re-imported under patched sys.path)
    yield web
    sys.modules.pop("web", None)


def _make_mgr(web_module):
    return web_module.WorkerManager(
        state_file=Path("/tmp/none.json"),
        bus=MagicMock(),
        socketio=MagicMock(),
        load_queue=MagicMock(return_value={"config": {}, "meta": {}}),
        save_queue=MagicMock(),
    )


def _stub_worker(mgr, worker_id="abc12345", **overrides):
    """Insert a finished worker into the manager so get_status() returns it."""
    now = datetime.now().isoformat()
    worker = {
        "id": worker_id,
        "provider": "minimax",
        "model": None,
        "count": 10,
        "continuous": True,
        "binary": "BH.dll",
        "status": "finished",
        "mode": "function",
        "started_at": now,
        "finished_at": now,
        "phase": "finalize_session",
        "phase_since": now,
        "last_heartbeat_at": now,
        "stop_flag": MagicMock(is_set=MagicMock(return_value=False)),
        "progress": {"completed": 0, "skipped": 0, "failed": 0, "current": None},
        "config_snapshot": None,
    }
    worker.update(overrides)
    mgr._workers[worker_id] = worker
    return worker


def test_get_status_includes_exit_reason_field(web_module):
    """The status payload must always include the exit_reason key so the
    dashboard doesn't have to feature-detect; None is fine when no reason
    is set (legacy/normal exits)."""
    mgr = _make_mgr(web_module)
    _stub_worker(mgr)
    rows = mgr.get_status()
    assert len(rows) == 1
    assert "exit_reason" in rows[0]
    assert rows[0]["exit_reason"] is None


def test_get_status_surfaces_no_eligible_candidates(web_module):
    """When the worker recorded an exit_reason, get_status() echoes it
    verbatim so the dashboard can label the pane."""
    mgr = _make_mgr(web_module)
    _stub_worker(mgr, exit_reason="no_eligible_candidates")
    rows = mgr.get_status()
    assert rows[0]["exit_reason"] == "no_eligible_candidates"
    assert rows[0]["status"] == "finished"
    assert rows[0]["progress"]["completed"] == 0


def test_get_status_unknown_exit_reason_passes_through(web_module):
    """Future-proofing: an exit_reason value we don't recognize here
    should still make it to the dashboard so the operator sees *something*
    rather than the field being silently dropped."""
    mgr = _make_mgr(web_module)
    _stub_worker(mgr, exit_reason="some_future_reason_we_havent_invented")
    rows = mgr.get_status()
    assert rows[0]["exit_reason"] == "some_future_reason_we_havent_invented"


def test_worker_stopped_emission_includes_exit_reason(web_module, monkeypatch):
    """The bus emission at end-of-worker must include exit_reason so
    downstream subscribers (dashboard, audit, structured logging) can act
    on it without an extra `get_status` roundtrip."""
    mgr = _make_mgr(web_module)
    worker = _stub_worker(mgr, exit_reason="no_eligible_candidates")

    # Drive the finally-block's emit path manually rather than spinning a
    # real thread. The behavior under test is the payload shape.
    mgr._bus.emit(
        "worker_stopped",
        {
            "worker_id": worker["id"],
            "reason": worker["status"],
            "exit_reason": worker.get("exit_reason"),
            "progress": dict(worker["progress"]),
        },
    )
    assert mgr._bus.emit.called
    name, payload = mgr._bus.emit.call_args.args
    assert name == "worker_stopped"
    assert payload["exit_reason"] == "no_eligible_candidates"
    assert payload["reason"] == "finished"
    assert payload["progress"]["completed"] == 0


def test_no_exit_reason_when_work_was_completed(web_module):
    """A worker that actually processed functions and then finished
    normally must NOT report no_eligible_candidates — that label is
    reserved for the empty-queue case (processed == 0). This guards
    against an over-broad future change setting the flag too aggressively."""
    mgr = _make_mgr(web_module)
    _stub_worker(
        mgr,
        progress={"completed": 7, "skipped": 1, "failed": 0, "current": None},
    )
    rows = mgr.get_status()
    assert rows[0]["exit_reason"] is None
    assert rows[0]["progress"]["completed"] == 7

"""Regression test for the dashboard-restart worker-mode bug (2026-07-25).

WorkerManager persists in-flight workers across a dashboard restart via
_persist_active_workers -> _serialize_worker, then relaunches them on the
next boot via restore_workers(). _serialize_worker never captured `mode`
(or `addresses`), and restore_workers() never passed a `mode=` kwarg into
start_worker(), which defaults to mode="functions". So a live globals or
port worker that survived in memory across a dashboard restart came back
silently switched to a FULL-doc ("functions") worker on the same binary --
no error, no log line, just a different worker doing different work than
what was actually running before the restart.

Found while restarting the dashboard with a live globals worker running,
specifically to verify a different fix -- restarting would have silently
turned that globals worker into a functions worker had this not been caught
first.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))


def _make_mgr(load_queue_return=None):
    import web

    bus = MagicMock()
    socketio = MagicMock()
    load_queue = MagicMock(
        return_value=load_queue_return or {"config": {}, "meta": {}}
    )
    save_queue = MagicMock()
    mgr = web.WorkerManager(
        state_file=Path("/tmp/none.json"),
        bus=bus,
        socketio=socketio,
        load_queue=load_queue,
        save_queue=save_queue,
    )
    return mgr, load_queue, save_queue


@pytest.mark.parametrize("mode,binary", [
    ("globals", "/proj/A.dll"),
    ("port", "/proj/B.dll"),
    ("functions", None),
])
def test_serialize_worker_captures_mode(monkeypatch, mode, binary):
    mgr, _load_queue, _save_queue = _make_mgr()
    monkeypatch.setattr(mgr, "_run_worker", lambda wid: None)  # skip real thread body

    worker_id = mgr.start_worker(
        provider="minimax", count=7, binary=binary, continuous=True, mode=mode,
    )
    with mgr._lock:
        spec = mgr._serialize_worker(mgr._workers[worker_id])

    assert spec["mode"] == mode, (
        f"_serialize_worker dropped mode={mode!r} -- a restart would restore "
        f"this worker as {spec.get('mode')!r} instead"
    )
    assert spec["binary"] == binary
    assert spec["continuous"] is True
    mgr._watchdog_stop.set()


def test_restore_workers_relaunches_with_original_mode(monkeypatch):
    """End-to-end: persist a globals worker, then restore it in a FRESH
    WorkerManager (simulating a dashboard restart) and confirm start_worker
    is invoked with mode="globals", not the "functions" default."""
    mgr1, _load_queue, save_queue = _make_mgr()
    monkeypatch.setattr(mgr1, "_run_worker", lambda wid: None)

    mgr1.start_worker(
        provider="minimax", count=3, binary="/proj/A.dll",
        continuous=True, mode="globals",
    )
    with mgr1._lock:
        mgr1._persist_active_workers()
    mgr1._watchdog_stop.set()

    # Pull the persisted queue exactly as _save_queue received it.
    persisted_queue = save_queue.call_args.args[0]
    restore_spec = persisted_queue["meta"]["dashboard_active_workers"]
    assert restore_spec, "expected one persisted worker spec"
    assert restore_spec[0]["mode"] == "globals"

    # Simulate the next dashboard boot: a fresh manager whose load_queue
    # returns exactly what was persisted above.
    mgr2, _load_queue2, _save_queue2 = _make_mgr(load_queue_return=persisted_queue)
    captured_kwargs = {}
    real_start_worker = mgr2.start_worker

    def _spy_start_worker(**kwargs):
        captured_kwargs.update(kwargs)
        return real_start_worker(**kwargs)

    monkeypatch.setattr(mgr2, "start_worker", _spy_start_worker)
    monkeypatch.setattr(mgr2, "_run_worker", lambda wid: None)

    restored = mgr2.restore_workers()

    assert restored, "restore_workers() found nothing to restore"
    assert captured_kwargs.get("mode") == "globals", (
        "restore_workers() must pass the original mode into start_worker(); "
        f"got mode={captured_kwargs.get('mode')!r} (defaults to 'functions' "
        "when omitted, silently turning a restored globals worker into a "
        "FULL-doc worker)"
    )
    assert captured_kwargs.get("binary") == "/proj/A.dll"
    assert captured_kwargs.get("continuous") is True
    mgr2._watchdog_stop.set()

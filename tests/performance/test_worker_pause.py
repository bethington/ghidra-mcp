"""Pause is not stop.

Built 2026-07-31 after stopping six workers took minutes and looked hung, and
after stopping them did NOT stop the oracle monitor relaunching the game the
operator had just closed on purpose.
"""
import threading
import time

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "fun-doc"))


def _manager():
    import web
    mgr = object.__new__(web.WorkerManager)
    mgr._workers = {}
    mgr._lock = threading.RLock()
    mgr._paused = threading.Event()
    mgr._pause_reason = None
    mgr._emit_status = lambda *a, **k: None
    return mgr


def _worker():
    return {"status": "running", "stop_flag": threading.Event(),
            "last_heartbeat_at": None}


def test_pause_sets_state_and_resume_clears_it():
    mgr = _manager()
    assert mgr.is_paused() is False
    mgr.pause_workers("closing the game")
    assert mgr.is_paused() is True
    assert mgr.pause_state()["reason"] == "closing the game"
    mgr.resume_workers()
    assert mgr.is_paused() is False
    assert mgr.pause_state()["reason"] is None


def test_paused_fleet_stands_oracle_recovery_down():
    """THE regression: stopping workers did not stop the relaunch, because the
    need-predicate is 'worker running OR candidates queued'."""
    mgr = _manager()
    mgr.port_work_pending = lambda: True          # candidates ARE queued
    assert mgr._oracle_wanted() is True
    mgr.pause_workers()
    assert mgr._oracle_wanted() is False, "a paused fleet must not relaunch the game"
    mgr.resume_workers()
    assert mgr._oracle_wanted() is True


def test_park_blocks_until_resumed_and_heartbeats():
    mgr = _manager()
    w = _worker()
    mgr.pause_workers()
    released = threading.Event()

    def run():
        mgr._park_if_paused(w)
        released.set()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    time.sleep(0.5)
    assert not released.is_set(), "must still be parked while paused"
    assert w["status"] == "paused"
    assert w["last_heartbeat_at"] is not None, "a parked worker must heartbeat"

    mgr.resume_workers()
    assert released.wait(5), "must resume promptly"
    assert w["status"] == "running", "status must be restored, not left paused"


def test_park_returns_immediately_when_not_paused():
    mgr = _manager()
    w = _worker()
    t0 = time.time()
    mgr._park_if_paused(w)
    assert time.time() - t0 < 0.5
    assert w["status"] == "running"


def test_stop_releases_a_parked_worker():
    """Otherwise a paused fleet could never be stopped without resuming first."""
    mgr = _manager()
    w = _worker()
    mgr.pause_workers()
    released = threading.Event()
    threading.Thread(target=lambda: (mgr._park_if_paused(w), released.set()),
                     daemon=True).start()
    time.sleep(0.3)
    assert not released.is_set()
    w["stop_flag"].set()
    assert released.wait(5), "stop must break the park"
    assert w["status"] == "paused", "a stopped worker is not silently 'running' again"

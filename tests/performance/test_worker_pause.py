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
    mgr._pause_source = None
    mgr._emit_status = lambda *a, **k: None
    mgr._persist_active_workers = lambda: None
    mgr._persist_pause_state = lambda: None
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


# ---------------------------------------------- pause across a restart ------

class _FakeQueue:
    def __init__(self): self.data = {}
    def load(self):
        import copy; return copy.deepcopy(self.data)
    def save(self, q):
        import copy; self.data = copy.deepcopy(q)


def _mgr_with_store(store):
    import web
    mgr = object.__new__(web.WorkerManager)
    mgr._workers = {}
    mgr._lock = threading.RLock()
    mgr._paused = threading.Event()
    mgr._pause_reason = None
    mgr._pause_source = None
    mgr._emit_status = lambda *a, **k: None
    mgr._load_queue = store.load
    mgr._save_queue = store.save
    mgr._session_id = "s1"
    return mgr


def test_pause_survives_a_restart():
    """THE point: pause -> restart -> still paused, so the fleet comes back
    parked instead of immediately spending tokens."""
    store = _FakeQueue()
    a = _mgr_with_store(store)
    a.pause_workers("dashboard redeploy")

    b = _mgr_with_store(store)          # a "new process"
    st = b.load_pause_state()
    assert st and st["reason"] == "dashboard redeploy"
    assert st["source"] == "operator"


def test_resume_clears_the_persisted_pause():
    store = _FakeQueue()
    a = _mgr_with_store(store)
    a.pause_workers("temporary")
    a.resume_workers()
    assert _mgr_with_store(store).load_pause_state() is None, \
        "a resumed fleet must not come back paused"


def test_pause_snapshots_the_roster():
    """pause->restart never goes through the stop path, so without capturing
    here the fleet you paused is the fleet you cannot get back."""
    import web
    store = _FakeQueue()
    mgr = _mgr_with_store(store)
    mgr._workers = {"w1": {"provider": "minimax", "count": 12, "continuous": True,
                           "model": None, "binary": "/b/x.dll", "mode": "port",
                           "addresses": None, "status": "running",
                           "restore_on_restart": True}}
    mgr.pause_workers("redeploy")
    assert store.data["meta"][web.WorkerManager.RESTORE_META_KEY], "roster must be captured at pause"


def test_drained_is_false_until_workers_actually_park():
    mgr = _manager()
    w = _worker()
    mgr._workers = {"w1": w}
    mgr._paused.set()
    assert mgr.pause_drained() is False, "still running == not drained"
    w["status"] = "paused"
    assert mgr.pause_drained() is True


def test_not_drained_when_not_paused():
    mgr = _manager()
    mgr._workers = {"w1": _worker()}
    assert mgr.pause_drained() is False


# ------------------------------------------- dependency pause/resume --------

class _FakeGhidra:
    def __init__(self, **st): self.st = st
    def get_state(self): return self.st


def test_ghidra_outage_parks_the_fleet_and_recovery_lifts_it():
    mgr = _manager()
    mgr._ghidra_monitor = _FakeGhidra(reachable=False, consecutive_down=3)
    mgr._sync_dependency_pause()
    assert mgr.is_paused() and mgr.pause_state()["source"] == "dependency"

    mgr._ghidra_monitor = _FakeGhidra(reachable=True, consecutive_down=0)
    mgr._sync_dependency_pause()
    assert not mgr.is_paused(), "a dependency pause must lift itself"


def test_dependency_recovery_never_resumes_an_operator_pause():
    """Otherwise an operator pause silently un-pauses itself."""
    mgr = _manager()
    mgr.pause_workers("closing the game", source="operator")
    mgr._ghidra_monitor = _FakeGhidra(reachable=True, consecutive_down=0)
    mgr._sync_dependency_pause()
    assert mgr.is_paused(), "operator pause must survive a healthy dependency"


def test_brief_ghidra_blip_does_not_park_the_fleet():
    mgr = _manager()
    mgr._ghidra_monitor = _FakeGhidra(reachable=False, consecutive_down=1)
    mgr._sync_dependency_pause()
    assert not mgr.is_paused()


def test_unprobed_ghidra_is_not_an_outage():
    """reachable=None means 'not probed yet', never a reason to park."""
    mgr = _manager()
    mgr._ghidra_monitor = _FakeGhidra(reachable=None, consecutive_down=0)
    mgr._sync_dependency_pause()
    assert not mgr.is_paused()

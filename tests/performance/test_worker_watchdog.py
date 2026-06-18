"""
Regression tests for the WorkerManager heartbeat + stall watchdog.

Background: on 2026-04-24 we discovered eight workers stuck for 67+
minutes with no automated recovery — the only signs of life in
`events.jsonl` were `worker.started` and `worker.run_begin`, and the
provider watchdog that was supposed to fire after 900s never did. There
was no periodic heartbeat to prove the worker thread was alive, and no
higher-level watchdog to unstick a wedged thread.

This suite locks in the fix:

  * Periodic `worker.heartbeat` events are written to events.jsonl
    at the configured cadence for every live worker, so events.jsonl
    never has a gap longer than the cadence while a worker is alive.

  * When `last_heartbeat_at` falls past the stall threshold, the
    watchdog flips `stop_flag`, calls `kill_worker_subprocesses`,
    emits `worker.stalled_kill` to the durable log, and marks
    `stall_kill_fired` so the kill fires at most once.

The tests bypass real worker setup (which needs Ghidra + state.json +
queue). They construct a WorkerManager, hand-insert a synthetic worker
dict with a controllable `last_heartbeat_at`, and watch the watchdog
react.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"


@pytest.fixture
def fast_watchdog_env(monkeypatch, tmp_path):
    """Reload web with aggressive heartbeat + stall thresholds for test speed.

    Also redirects the events.jsonl file into tmp_path so tests can
    inspect emitted heartbeats without polluting the real log.
    """
    monkeypatch.setenv("FUNDOC_HEARTBEAT_INTERVAL_SEC", "1")
    monkeypatch.setenv("FUNDOC_STALL_KILL_THRESHOLD_SEC", "2")
    if str(FUN_DOC_DIR) not in sys.path:
        sys.path.insert(0, str(FUN_DOC_DIR))

    # Isolate from the real state.db / Postgres: force the legacy in-memory
    # path so reloading web doesn't try to materialize the live SQL backend.
    monkeypatch.setenv("FUN_DOC_DB_URL", f"sqlite:///{tmp_path}/test_state.db")
    import fun_doc
    monkeypatch.setattr(fun_doc, "_storage_repo", None, raising=False)
    monkeypatch.setattr(fun_doc, "_storage_repo_failed", True, raising=False)
    monkeypatch.setattr(fun_doc, "STATE_FILE", tmp_path / "state.json", raising=False)

    # Redirect events.jsonl for this test run by patching event_log's
    # module-level constant. This is safer than touching the real file.
    import event_log
    original_path = event_log._EVENT_LOG_FILE
    test_log = tmp_path / "events.jsonl"
    event_log._EVENT_LOG_FILE = test_log

    # Reload web with the test env vars in place so the module-level
    # constants pick up the fast cadence.
    import importlib
    import web
    importlib.reload(web)

    yield web, test_log

    event_log._EVENT_LOG_FILE = original_path


def _make_mgr(web_module):
    """Build a WorkerManager wired to mocks so we never touch real I/O."""
    bus = MagicMock()
    socketio = MagicMock()
    load_queue = MagicMock(return_value={"config": {}, "meta": {}})
    save_queue = MagicMock()

    mgr = web_module.WorkerManager(
        state_file=Path("/tmp/nonexistent-state.json"),
        bus=bus,
        socketio=socketio,
        load_queue=load_queue,
        save_queue=save_queue,
    )
    return mgr, bus, socketio


def _read_events(path):
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def test_watchdog_emits_periodic_heartbeats(fast_watchdog_env):
    """The watchdog must emit a heartbeat for every live worker each tick.

    After the H25 fix the worker loop — not the watchdog — writes
    last_heartbeat_at.  We simulate that here with a background thread
    that advances the field every 0.4s (faster than the 1s watchdog
    cadence), keeping stale_sec well below the 2s kill threshold so the
    watchdog only emits heartbeat events and never fires a kill.
    """
    web, test_log = fast_watchdog_env
    mgr, bus, _ = _make_mgr(web)
    stop_sim = threading.Event()
    try:
        now_iso = datetime.now().isoformat()
        worker_dict = {
            "id": "test-hb",
            "provider": "mock",
            "count": 1,
            "continuous": False,
            "model": None,
            "binary": None,
            "thread": None,
            "stop_flag": threading.Event(),
            "started_at": now_iso,
            "status": "running",
            "timeout_count": 0,
            "last_alert": None,
            "phase": "process_function",
            "phase_since": now_iso,
            "stall_kill_fired": False,
            "last_heartbeat_at": now_iso,
            "progress": {"completed": 0, "skipped": 0, "failed": 0, "current": None},
        }
        with mgr._lock:
            mgr._workers["test-hb"] = worker_dict

        # Simulate the worker loop: update last_heartbeat_at every 0.4s
        # so stale_sec stays below the 2s kill threshold (H25: only the
        # worker loop may write this field — the watchdog only reads it).
        def _sim_worker_loop():
            while not stop_sim.wait(0.4):
                with mgr._lock:
                    worker_dict["last_heartbeat_at"] = datetime.now().isoformat()

        sim_thread = threading.Thread(target=_sim_worker_loop, daemon=True)
        sim_thread.start()

        # Wait long enough for at least 2 heartbeat cycles at 1s cadence.
        time.sleep(2.6)

        events = _read_events(test_log)
        heartbeats = [
            e for e in events
            if e.get("event") == "worker.heartbeat" and e.get("worker_id") == "test-hb"
        ]
        assert len(heartbeats) >= 2, (
            f"Expected >=2 heartbeats at 1s cadence over 2.6s; got {len(heartbeats)}. "
            f"Events: {events}"
        )
        # Each heartbeat carries phase info so the dashboard can render it.
        for hb in heartbeats:
            assert hb["phase"] == "process_function"
            assert hb["provider"] == "mock"
            assert hb["status"] == "running"
            assert "stale_sec" in hb
    finally:
        stop_sim.set()
        mgr._watchdog_stop.set()


def test_watchdog_fires_stall_kill_once(fast_watchdog_env, monkeypatch):
    """A worker whose heartbeat is older than threshold must be killed exactly once."""
    web, test_log = fast_watchdog_env
    mgr, bus, _ = _make_mgr(web)

    kill_calls = []

    def fake_kill(worker_id):
        kill_calls.append(worker_id)
        return 1  # pretend we killed 1 subprocess

    import fun_doc
    monkeypatch.setattr(fun_doc, "kill_worker_subprocesses", fake_kill)

    try:
        # Seed a worker with last_heartbeat_at older than the 2s threshold.
        ancient = (datetime.now() - timedelta(seconds=30)).isoformat()
        phase_ancient = (datetime.now() - timedelta(seconds=30)).isoformat()
        stop_flag = threading.Event()
        with mgr._lock:
            mgr._workers["test-kill"] = {
                "id": "test-kill",
                "provider": "mock",
                "count": 1,
                "continuous": False,
                "model": None,
                "binary": None,
                "thread": None,
                "stop_flag": stop_flag,
                "started_at": ancient,
                "status": "running",
                "timeout_count": 0,
                "last_alert": None,
                "phase": "process_function",
                "phase_since": phase_ancient,
                "stall_kill_fired": False,
                "last_heartbeat_at": ancient,
                "progress": {"completed": 0, "skipped": 0, "failed": 0, "current": None},
            }

        # Give the watchdog time to notice and fire twice.
        time.sleep(2.8)

        # kill_worker_subprocesses must have been called exactly once —
        # the stall_kill_fired latch prevents repeat firing.
        assert kill_calls == ["test-kill"], (
            f"Expected kill to fire exactly once for 'test-kill'; got {kill_calls}"
        )

        # stop_flag must have been set so the worker loop unwinds.
        assert stop_flag.is_set(), "stop_flag must be set after stall kill"

        # The worker must be marked stall_kill_fired.
        with mgr._lock:
            assert mgr._workers["test-kill"]["stall_kill_fired"] is True
            assert mgr._workers["test-kill"]["last_alert"]["type"] == "stalled_kill"

        # A durable `worker.stalled_kill` event must be in events.jsonl so
        # post-mortems don't require reconstructing state from memory.
        events = _read_events(test_log)
        kill_events = [
            e for e in events
            if e.get("event") == "worker.stalled_kill" and e.get("worker_id") == "test-kill"
        ]
        assert len(kill_events) == 1, (
            f"Expected exactly one worker.stalled_kill for 'test-kill'; "
            f"got {len(kill_events)}. Events: {kill_events}"
        )
        assert kill_events[0]["subprocesses_killed"] == 1
        assert kill_events[0]["phase"] == "process_function"
        assert kill_events[0]["threshold_sec"] == 2
    finally:
        mgr._watchdog_stop.set()


def test_get_status_exposes_phase_and_stall_kill_fired(fast_watchdog_env):
    """The dashboard reads these fields off get_status(); contract must hold."""
    web, _ = fast_watchdog_env
    mgr, _, _ = _make_mgr(web)
    try:
        now_iso = datetime.now().isoformat()
        with mgr._lock:
            mgr._workers["test-status"] = {
                "id": "test-status",
                "provider": "mock",
                "count": 1,
                "continuous": False,
                "model": None,
                "binary": None,
                "thread": None,
                "stop_flag": threading.Event(),
                "started_at": now_iso,
                "status": "running",
                "timeout_count": 0,
                "last_alert": None,
                "phase": "pre_refresh",
                "phase_since": now_iso,
                "stall_kill_fired": False,
                "last_heartbeat_at": now_iso,
                "progress": {"completed": 0, "skipped": 0, "failed": 0, "current": None},
            }
        rows = mgr.get_status()
        row = next(r for r in rows if r["id"] == "test-status")
        assert row["phase"] == "pre_refresh"
        assert row["stall_kill_fired"] is False
        assert "phase_age_sec" in row
        assert "is_stale" in row
    finally:
        mgr._watchdog_stop.set()


def test_subprocess_registry_tracks_and_kills(monkeypatch):
    """register / unregister / kill must form a coherent lifecycle."""
    if str(FUN_DOC_DIR) not in sys.path:
        sys.path.insert(0, str(FUN_DOC_DIR))
    import fun_doc

    terminated = []
    monkeypatch.setattr(fun_doc, "_terminate_process_tree", lambda pid: terminated.append(pid))

    class FakeProc:
        def __init__(self, pid):
            self.pid = pid
            self._alive = True

        def is_alive(self):
            return self._alive

    p1, p2 = FakeProc(1111), FakeProc(2222)
    fun_doc.register_worker_subprocess("wX", p1)
    fun_doc.register_worker_subprocess("wX", p2)
    fun_doc.register_worker_subprocess("wY", FakeProc(3333))  # different worker

    killed = fun_doc.kill_worker_subprocesses("wX")
    assert killed == 2
    assert sorted(terminated) == [1111, 2222], (
        "kill must target only the requested worker's subprocesses"
    )

    # Unregister should make subsequent kills no-ops for that pair.
    terminated.clear()
    fun_doc.register_worker_subprocess("wZ", p1)
    fun_doc.unregister_worker_subprocess("wZ", p1)
    killed = fun_doc.kill_worker_subprocesses("wZ")
    assert killed == 0
    assert terminated == []

    # No-op safety: unknown worker id returns 0.
    assert fun_doc.kill_worker_subprocesses("never-registered") == 0
    assert fun_doc.kill_worker_subprocesses(None) == 0


def test_watchdog_does_not_self_heartbeat(fast_watchdog_env):
    """H25: the watchdog must OBSERVE last_heartbeat_at, not write it.
    Before the fix, the watchdog reset last_heartbeat_at = now on every
    non-kill tick, keeping stale_sec permanently ≈ HEARTBEAT_INTERVAL_SEC
    so the kill threshold was unreachable for any initially-healthy worker.

    This test seeds a worker with a fresh heartbeat (not pre-stale) so
    the watchdog must tick ≥2× before the threshold is crossed. With the
    bug, each tick resets the clock, so the kill never fires. After the
    fix, only the worker loop may write last_heartbeat_at, so the clock
    advances and the kill fires once stale_sec > STALL_KILL_THRESHOLD_SEC.
    """
    web, _log = fast_watchdog_env
    mgr, _, _ = _make_mgr(web)
    # Fresh heartbeat — the worker is healthy right now. With the bug the
    # watchdog resets this on every tick so it never goes stale enough
    # (threshold=2s, interval=1s → stale_sec stays ≈1s forever).
    seed = datetime.now().isoformat()
    worker = {
        "id": "w-test",
        "provider": "test",
        "count": 1,
        "continuous": False,
        "model": None,
        "binary": None,
        "thread": None,
        "stop_flag": threading.Event(),
        "started_at": seed,
        "status": "running",
        "timeout_count": 0,
        "last_alert": None,
        "phase": "process_function",
        "phase_since": seed,
        "stall_kill_fired": False,
        "last_heartbeat_at": seed,
        "progress": {"completed": 0, "skipped": 0, "failed": 0, "current": None},
    }
    with mgr._lock:
        mgr._workers["w-test"] = worker
    # Sleep 4.5s — well past the 2s threshold. With the bug, stale_sec
    # stays at ≈1s (reset each tick) and the kill never fires. After the
    # fix, stale_sec grows to >2s and the kill fires after the second tick.
    time.sleep(4.5)
    # The watchdog must NOT have advanced the heartbeat — only the worker
    # loop is allowed to. With STALL_KILL_THRESHOLD_SEC=2 and a heartbeat
    # frozen at seed, the kill MUST have fired well before now.
    assert worker.get("stall_kill_fired") is True, (
        "watchdog never fired — it is still self-heartbeating "
        f"(last_heartbeat_at={worker.get('last_heartbeat_at')!r}, seed={seed!r})"
    )
    mgr._watchdog_stop.set()

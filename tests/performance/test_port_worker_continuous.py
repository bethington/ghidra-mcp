"""Regression test for the PORT/Prove worker's "All" checkbox (2026-07-25).

The dashboard's "All" checkbox sets worker["continuous"]=True so a lane runs
every candidate instead of stopping at the `count` field's value. The globals
worker correctly forwards this into run_globals_worker_pass, but
WorkerManager._run_worker_port never forwarded it to run_port_worker_pass --
that call always used the function's continuous=False default, so the Prove
lane silently stopped after `count` completions (the UI's default count=12)
even with "All" checked. Confirmed live: a user-visible "12 iterations then
exits" report traced straight to this missing kwarg.
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

import fun_doc  # noqa: E402


def _make_mgr():
    import web

    bus = MagicMock()
    socketio = MagicMock()
    load_queue = MagicMock(return_value={"config": {}, "meta": {}})
    save_queue = MagicMock()
    return web.WorkerManager(
        state_file=Path("/tmp/none.json"),
        bus=bus,
        socketio=socketio,
        load_queue=load_queue,
        save_queue=save_queue,
    )


def _seed_port_worker(mgr, worker_id, *, continuous):
    mgr._workers[worker_id] = {
        "id": worker_id,
        "mode": "port",
        "provider": "minimax",
        "count": 12,
        "continuous": continuous,
        "model": None,
        "binary": "/Mods/PD2-S12/D2Client.dll",
        "thread": None,
        "stop_flag": threading.Event(),
        "started_at": "2026-07-25T00:00:00",
        "status": "starting",
        "restored": False,
        "progress": {},
        "restore_on_restart": True,
    }
    return mgr._workers[worker_id]


@pytest.mark.parametrize("continuous", [True, False])
def test_run_worker_port_forwards_continuous(monkeypatch, continuous):
    mgr = _make_mgr()
    worker_id = "w1"
    _seed_port_worker(mgr, worker_id, continuous=continuous)

    captured = {}

    def _fake_pass(**kwargs):
        captured.update(kwargs)
        return {"processed": 0, "totals": {}, "stopped_reason": "no_candidates"}

    monkeypatch.setattr(fun_doc, "run_port_worker_pass", _fake_pass)
    monkeypatch.setattr(
        "port_live_prove.check_oracle_alive", lambda: False, raising=False
    )

    mgr._run_worker_port(worker_id)

    assert "continuous" in captured, (
        "run_port_worker_pass was called without a continuous kwarg -- "
        "the 'All' checkbox has no effect on the Prove/Port lane"
    )
    assert captured["continuous"] is continuous

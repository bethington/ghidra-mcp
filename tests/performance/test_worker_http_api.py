"""Offline tests for the HTTP worker-control API and program-scope injection.

Covers the two features added 2026-07-20/21:

  * `/api/worker/start` + `/api/worker/stop` + `/api/worker/status` — HTTP
    twins of the socket.io worker handlers (backlog #12), so autonomous
    launchers can drive workers without holding a socket.io session.
    WorkerManager methods are stubbed at the class level; no real worker
    threads or provider calls happen here.
  * `fun_doc._apply_program_scope` — defaults the `program` argument on a
    model tool call from the session's debug context, so multi-binary
    worker rotation can't reroute an implicit-ACTIVE-program call (or
    write) to the wrong binary.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))

import fun_doc  # noqa: E402


# ---------- _apply_program_scope ----------


def test_program_scope_injects_when_model_omits_program():
    out = fun_doc._apply_program_scope(
        {"address": "0x6faf1950"}, {"address", "program"}, "/Mods/PD2-S12/D2Client.dll"
    )
    assert out["program"] == "/Mods/PD2-S12/D2Client.dll"
    assert out["address"] == "0x6faf1950"


def test_program_scope_never_overrides_explicit_program():
    args = {"address": "0x1000", "program": "/Mods/PD2-S12/D2Common.dll"}
    out = fun_doc._apply_program_scope(
        args, {"address", "program"}, "/Mods/PD2-S12/D2Client.dll"
    )
    assert out["program"] == "/Mods/PD2-S12/D2Common.dll"


def test_program_scope_skips_tools_without_program_param():
    args = {"query": "foo"}
    out = fun_doc._apply_program_scope(args, {"query"}, "/Mods/PD2-S12/D2Client.dll")
    assert "program" not in out


def test_program_scope_noop_without_context_program():
    args = {"address": "0x1000"}
    out = fun_doc._apply_program_scope(args, {"address", "program"}, None)
    assert "program" not in out


def test_program_scope_does_not_mutate_caller_dict():
    args = {"address": "0x1000"}
    out = fun_doc._apply_program_scope(
        args, {"address", "program"}, "/Mods/PD2-S12/D2Client.dll"
    )
    assert "program" not in args, "helper must copy-on-inject, not mutate"
    assert out is not args


# ---------- HTTP worker routes ----------


@pytest.fixture
def dashboard_client(monkeypatch, tmp_path):
    """Dashboard Flask test client with stubbed WorkerManager methods.

    Mirrors test_context_meta_writes.dashboard_client: tmp priority queue
    with background machinery disabled BEFORE create_app, tmp SQLite repo,
    and Thread.start suppressed during create_app so no daemon threads
    outlive the fixture. WorkerManager.start/stop are patched at the CLASS
    level so the instance closed over by the routes uses the stubs — the
    routes must never launch a real provider worker from a test."""
    from storage import StorageConfig, make_engine
    from storage.repository import Repository

    import event_bus
    import web

    queue_file = tmp_path / "priority_queue.json"
    queue_file.write_text(
        json.dumps(
            {
                "config": {
                    "inventory_enabled": False,
                    "global_inventory_enabled": False,
                    "pre_refresh_on_start": False,
                },
                "meta": {},
                "pinned": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(fun_doc, "PRIORITY_QUEUE_FILE", queue_file)

    cfg = StorageConfig(
        backend="sqlite", url=f"sqlite:///{tmp_path / 'worker_api.db'}", schema=None
    )
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    repo.bootstrap_schema()
    monkeypatch.setattr(fun_doc, "_storage_repo", repo)
    monkeypatch.setattr(fun_doc, "_storage_repo_failed", False)
    monkeypatch.setattr(fun_doc, "STATE_FILE", tmp_path / "state.json")

    calls = {"start": [], "stop": []}

    def _stub_start(self, provider="minimax", count=5, model=None, binary=None,
                    continuous=False, restored=False, mode="functions", **kw):
        calls["start"].append(
            {"provider": provider, "count": count, "model": model,
             "binary": binary, "continuous": continuous, "mode": mode}
        )
        if binary == "/locked.dll":
            raise ValueError("a worker is already running on /locked.dll")
        return "wid-test-1"

    def _stub_stop(self, worker_id):
        calls["stop"].append(worker_id)

    monkeypatch.setattr(web.WorkerManager, "start_worker", _stub_start)
    monkeypatch.setattr(web.WorkerManager, "stop_worker", _stub_stop)
    monkeypatch.setattr(web.WorkerManager, "get_status", lambda self: [])

    bus = event_bus.EventBus()
    import threading as _threading

    _orig_start = _threading.Thread.start
    _threading.Thread.start = lambda self: None
    try:
        app, _socketio = web.create_app(tmp_path / "state.json", event_bus=bus)
    finally:
        _threading.Thread.start = _orig_start
    yield app.test_client(), calls
    engine.dispose()


def test_http_worker_status_shape(dashboard_client):
    client, _calls = dashboard_client
    resp = client.get("/api/worker/status")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["workers"] == []


def test_http_worker_start_passes_args_and_returns_id(dashboard_client):
    client, calls = dashboard_client
    resp = client.post(
        "/api/worker/start",
        json={"provider": "minimax", "count": 12, "binary": "/Mods/PD2-S12/D2Client.dll",
              "continuous": True, "mode": "functions"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body == {"ok": True, "worker_id": "wid-test-1", "mode": "functions"}
    assert calls["start"] == [
        {"provider": "minimax", "count": 12, "model": None,
         "binary": "/Mods/PD2-S12/D2Client.dll", "continuous": True,
         "mode": "functions"}
    ]


def test_http_worker_start_normalizes_mode_aliases(dashboard_client):
    client, calls = dashboard_client
    for alias in ("document", "doc", "functions"):
        resp = client.post("/api/worker/start", json={"mode": alias})
        assert resp.status_code == 200
        assert resp.get_json()["mode"] == "functions"
    resp = client.post("/api/worker/start", json={"mode": "globals"})
    assert resp.status_code == 200
    assert resp.get_json()["mode"] == "globals"
    assert [c["mode"] for c in calls["start"]] == [
        "functions", "functions", "functions", "globals"
    ]


def test_http_worker_start_clamps_count(dashboard_client):
    client, calls = dashboard_client
    client.post("/api/worker/start", json={"count": 100000})
    client.post("/api/worker/start", json={"count": 0})
    assert [c["count"] for c in calls["start"]] == [500, 1]


def test_http_worker_start_conflict_is_409_with_reason(dashboard_client):
    client, _calls = dashboard_client
    resp = client.post("/api/worker/start", json={"binary": "/locked.dll"})
    assert resp.status_code == 409
    body = resp.get_json()
    assert body["ok"] is False
    assert "already running" in body["error"]


def test_http_worker_stop_requires_worker_id(dashboard_client):
    client, calls = dashboard_client
    resp = client.post("/api/worker/stop", json={})
    assert resp.status_code == 400
    assert calls["stop"] == []


def test_http_worker_stop_routes_to_manager(dashboard_client):
    client, calls = dashboard_client
    resp = client.post("/api/worker/stop", json={"worker_id": "wid-test-1"})
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True, "worker_id": "wid-test-1"}
    assert calls["stop"] == ["wid-test-1"]

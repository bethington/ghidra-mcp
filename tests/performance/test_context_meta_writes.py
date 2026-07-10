"""Regression tests for the dashboard's meta-only context writes.

Background (2026-07-09): switching binaries in the dashboard took ~60 s.
POST /api/context/binary did ``load_state()`` + ``save_state()`` — i.e. it
materialized all ~62K functions_workflow rows and then bulk-upserted every
one of them back — just to flip the ``active_binary`` pointer on the meta
singleton. The fix routes context switches through ``fun_doc.set_state_meta``
(one UPDATE on the meta row) and adds a ``binary_name`` filter to
``load_state`` so read paths can materialize a single binary.

These tests pin:
  * set_state_meta writes the meta row and NEVER touches functions_workflow
  * the /api/context/binary and /api/context/folder routes use that path
  * load_state(binary_name=...) filters in SQL but keeps the state shape
  * get_state_meta / list_scanned_binaries return without materializing
  * the legacy state.json fallback for set_state_meta still works
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))


def _seed_functions(repo):
    """Two binaries, three functions. Returns the seeded row snapshots."""
    for addr, binary in (
        ("00401000", "D2Common.dll"),
        ("00402000", "D2Common.dll"),
        ("00401000", "D2Game.dll"),
    ):
        repo.upsert_function(
            {
                "program_path": f"/Mods/PD2-S12/{binary}",
                "binary_name": binary,
                "address": addr,
                "name": f"Fn_{binary}_{addr}",
                "score": 50,
                "queue_status": "queued",
                "is_thunk": False,
                "is_external": False,
            }
        )
    return {
        (r["program_path"], r["address"]): r for r in repo.list_functions()
    }


@pytest.fixture
def sqlite_fun_doc(monkeypatch, tmp_path):
    """fun_doc wired to a fresh tmp SQLite repo (SQL path, not legacy)."""
    from storage import StorageConfig, make_engine
    from storage.repository import Repository

    import fun_doc

    cfg = StorageConfig(
        backend="sqlite", url=f"sqlite:///{tmp_path / 'meta_test.db'}", schema=None
    )
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    repo.bootstrap_schema()
    monkeypatch.setattr(fun_doc, "_storage_repo", repo)
    monkeypatch.setattr(fun_doc, "_storage_repo_failed", False)
    yield fun_doc, repo
    engine.dispose()


def test_set_state_meta_updates_meta_without_touching_functions(sqlite_fun_doc):
    fun_doc, repo = sqlite_fun_doc
    before = _seed_functions(repo)

    fun_doc.set_state_meta(active_binary="D2Common.dll")
    fun_doc.set_state_meta(project_folder="/Mods/PD2-S12")

    meta = repo.get_meta()
    assert meta["active_binary"] == "D2Common.dll"
    assert meta["project_folder"] == "/Mods/PD2-S12"
    # The whole point: not one functions_workflow row may change (the old
    # save_state path rewrote every row, including updated_at).
    after = {(r["program_path"], r["address"]): r for r in repo.list_functions()}
    assert after == before

    # Clearing with None nulls the pointer.
    fun_doc.set_state_meta(active_binary=None)
    assert repo.get_meta()["active_binary"] is None


def test_set_state_meta_rejects_unknown_fields(sqlite_fun_doc):
    fun_doc, _repo = sqlite_fun_doc
    with pytest.raises(ValueError, match="unsupported field"):
        fun_doc.set_state_meta(functions={})
    with pytest.raises(ValueError, match="unsupported field"):
        fun_doc.set_state_meta(active_binary="x.dll", score=100)


def test_get_state_meta_shape(sqlite_fun_doc):
    fun_doc, repo = sqlite_fun_doc
    _seed_functions(repo)
    fun_doc.set_state_meta(active_binary="D2Game.dll")
    meta = fun_doc.get_state_meta()
    assert meta["active_binary"] == "D2Game.dll"
    assert "project_folder" in meta and "last_scan" in meta
    # Meta-only contract: no functions payload.
    assert "functions" not in meta


def test_load_state_binary_filter(sqlite_fun_doc):
    fun_doc, repo = sqlite_fun_doc
    _seed_functions(repo)

    full = fun_doc.load_state()
    assert len(full["functions"]) == 3

    filtered = fun_doc.load_state(binary_name="D2Common.dll")
    assert len(filtered["functions"]) == 2
    assert all(
        f["program_name"] == "D2Common.dll"
        for f in filtered["functions"].values()
    )
    # Top-level shape unchanged — meta pointers still present.
    for key in ("project_folder", "last_scan", "active_binary", "sessions"):
        assert key in filtered


def test_list_scanned_binaries(sqlite_fun_doc):
    fun_doc, repo = sqlite_fun_doc
    _seed_functions(repo)
    assert fun_doc.list_scanned_binaries() == ["D2Common.dll", "D2Game.dll"]


def test_set_state_meta_legacy_fallback(monkeypatch, tmp_path):
    """With the repo unavailable (test-only scaffolding), set_state_meta
    round-trips through state.json without dropping the functions dict."""
    import fun_doc

    fake_state = tmp_path / "state.json"
    fake_state.write_text(
        json.dumps(
            {
                "project_folder": "/old",
                "functions": {"p::a": {"program_name": "p", "address": "a"}},
                "sessions": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(fun_doc, "STATE_FILE", fake_state)
    monkeypatch.setattr(fun_doc, "_storage_repo", None)
    monkeypatch.setattr(fun_doc, "_storage_repo_failed", True)

    fun_doc.set_state_meta(active_binary="p.dll", project_folder="/new")
    on_disk = json.loads(fake_state.read_text(encoding="utf-8"))
    assert on_disk["active_binary"] == "p.dll"
    assert on_disk["project_folder"] == "/new"
    assert on_disk["functions"] == {"p::a": {"program_name": "p", "address": "a"}}

    fun_doc.set_state_meta(active_binary=None)
    on_disk = json.loads(fake_state.read_text(encoding="utf-8"))
    assert "active_binary" not in on_disk


@pytest.fixture
def dashboard_client(monkeypatch, tmp_path):
    """Dashboard Flask test client wired to a tmp SQLite repo.

    PRIORITY_QUEUE_FILE is redirected to a tmp queue with the background
    machinery disabled BEFORE create_app runs. Without this, create_app
    reads the REAL priority_queue.json: it restores persisted workers and
    starts the inventory scorers if the user's config enables them — and
    those daemon threads outlive the monkeypatch, writing to the real
    state.db (observed live 2026-07-09: a fixture-started scorer scored
    two real D2Launch.dll rows after teardown restored the real repo).
    """
    from storage import StorageConfig, make_engine
    from storage.repository import Repository

    import event_bus
    import fun_doc
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
        backend="sqlite", url=f"sqlite:///{tmp_path / 'route_test.db'}", schema=None
    )
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    repo.bootstrap_schema()
    monkeypatch.setattr(fun_doc, "_storage_repo", repo)
    monkeypatch.setattr(fun_doc, "_storage_repo_failed", False)
    monkeypatch.setattr(fun_doc, "STATE_FILE", tmp_path / "state.json")

    bus = event_bus.EventBus()
    state_file = tmp_path / "state.json"
    # Suppress create_app's background daemon threads (WorkerManager
    # watchdog + `_prewarm`). The route tests are fully synchronous through
    # the Flask test client, so they need no threads — and a leftover daemon
    # thread from create_app concurrently touching sys.modules is what raced
    # with a sibling fixture's del-and-reimport of `event_bus`, tripping an
    # intermittent KeyError under full-suite collection order.
    import threading as _threading

    _orig_start = _threading.Thread.start
    _threading.Thread.start = lambda self: None
    try:
        app, _socketio = web.create_app(state_file, event_bus=bus)
    finally:
        _threading.Thread.start = _orig_start
    yield app.test_client(), repo
    engine.dispose()


def test_context_binary_route_is_meta_only(dashboard_client):
    """POST /api/context/binary must not rewrite functions_workflow rows.

    This is the regression that made binary switching take ~60 s: the route
    used to round-trip the entire functions table through save_state().
    """
    client, repo = dashboard_client
    before = _seed_functions(repo)

    r = client.post("/api/context/binary", json={"binary": "D2Common.dll"})
    assert r.status_code == 200
    assert r.get_json() == {"ok": True, "active_binary": "D2Common.dll"}
    assert repo.get_meta()["active_binary"] == "D2Common.dll"

    after = {(r_["program_path"], r_["address"]): r_ for r_ in repo.list_functions()}
    assert after == before, "context switch must never touch function rows"

    # Clearing the filter ("" from the dropdown) nulls the pointer.
    r = client.post("/api/context/binary", json={"binary": ""})
    assert r.status_code == 200
    assert repo.get_meta()["active_binary"] is None


def test_context_folder_route_is_meta_only(dashboard_client):
    client, repo = dashboard_client
    before = _seed_functions(repo)

    r = client.post("/api/context/folder", json={"folder": "/Mods/PD2-S12"})
    assert r.status_code == 200
    assert repo.get_meta()["project_folder"] == "/Mods/PD2-S12"
    after = {(r_["program_path"], r_["address"]): r_ for r_ in repo.list_functions()}
    assert after == before

    # Missing folder still 400s.
    r = client.post("/api/context/folder", json={})
    assert r.status_code == 400

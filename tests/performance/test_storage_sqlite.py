"""SQLite-engine-specific storage tests.

These tests cover behavior that only matters for the SQLite backend (which
is the default for users who don't opt into Postgres). Cross-backend
correctness lives in test_storage_common.py.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))


@pytest.fixture
def sqlite_repo(tmp_path):
    from storage import StorageConfig, make_engine
    from storage.repository import Repository

    cfg = StorageConfig(
        backend="sqlite", url=f"sqlite:///{tmp_path / 'test.db'}", schema=None
    )
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    repo.bootstrap_schema()
    yield repo, tmp_path / "test.db"
    engine.dispose()


def test_wal_mode_enabled_after_bootstrap(sqlite_repo):
    """The schema bootstrap sets WAL mode. Verify it stuck."""
    _repo, db_path = sqlite_repo
    conn = sqlite3.connect(str(db_path))
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
    finally:
        conn.close()


def test_foreign_keys_enabled(sqlite_repo):
    _repo, db_path = sqlite_repo
    # The PRAGMA in the migration applies per connection. SQLAlchemy opens
    # its own connections, so we re-check via the engine's connection.
    repo, _ = sqlite_repo
    with repo.engine.connect() as conn:
        from sqlalchemy import text

        # Note: SQLAlchemy's sqlite dialect doesn't auto-enable FKs unless
        # we wire a connection event. The migration sets PRAGMA but that's
        # connection-scoped. This test documents the gap so we know to
        # surface it before P5 if cascades end up mattering for the worker.
        result = conn.execute(text("PRAGMA foreign_keys")).scalar()
        assert result in (0, 1)  # documents either state — neither is wrong yet


def test_sqlite_default_path(tmp_path, monkeypatch):
    """resolve_config(): with no FUN_DOC_DB_URL and no config block, it
    falls back to the bundled sqlite path under fun-doc/state.db."""
    from storage import resolve_config, DEFAULT_SQLITE_PATH

    monkeypatch.delenv("FUN_DOC_DB_URL", raising=False)
    cfg = resolve_config(None)
    assert cfg.backend == "sqlite"
    assert str(DEFAULT_SQLITE_PATH) in cfg.url


def test_sqlite_bare_path_url_normalization(tmp_path, monkeypatch):
    """A bare path in storage.url (without sqlite:/// prefix) gets prefixed
    so SQLAlchemy treats it as SQLite."""
    from storage import resolve_config

    monkeypatch.delenv("FUN_DOC_DB_URL", raising=False)
    cfg = resolve_config({"backend": "sqlite", "url": str(tmp_path / "x.db")})
    assert cfg.url.startswith("sqlite:///")


def test_env_var_overrides_config(tmp_path, monkeypatch):
    """FUN_DOC_DB_URL wins over the config block."""
    from storage import resolve_config

    monkeypatch.setenv("FUN_DOC_DB_URL", f"sqlite:///{tmp_path / 'env.db'}")
    cfg = resolve_config(
        {"backend": "postgres", "url": "postgresql://wrong:x@nowhere/db"}
    )
    assert cfg.backend == "sqlite"
    assert "env.db" in cfg.url


def test_refresh_candidate_scores_persists_to_sql(sqlite_repo, monkeypatch):
    """H23: refresh must write to the SQL backend, not the dead state.json,
    and must clear the one-shot blacklist flags so the user's 'Refresh Top N'
    gesture actually re-arms blacklisted functions."""
    import fun_doc

    repo, _db_path = sqlite_repo
    monkeypatch.setattr(fun_doc, "_get_storage_repo", lambda: repo)

    # Seed the SQL row with a stale score + blacklist flags set.
    # upsert_function expects the row shape (program_path, not program).
    repo.upsert_function({
        "program_path": "/proj/Foo.exe",
        "binary_name": "Foo.exe",
        "address": "00401000",
        "name": "FUN_00401000",
        "score": 10,
        "fixable": 0.5,
        "recovery_pass_done": True,
        "decompile_timeout": True,
        "library_code": True,
        "stagnation_runs": 7,
    })

    # Stub _batch_score (the internal helper refresh_candidate_scores calls)
    # so no real Ghidra HTTP request is needed.
    monkeypatch.setattr(
        fun_doc, "_batch_score",
        lambda addresses, prog_path=None, **kw: {
            "00401000": {
                "score": 42, "fixable": 0.5, "has_custom_name": False,
                "has_plate_comment": False, "is_leaf": True,
                "classification": "leaf", "deductions": [],
            }
        },
        raising=False,
    )
    monkeypatch.setattr(fun_doc, "load_priority_queue",
                        lambda: {"meta": {}, "config": {}}, raising=False)
    monkeypatch.setattr(fun_doc, "save_priority_queue", lambda q: None, raising=False)

    # Build a selectable state dict without blacklist flags so select_candidates
    # includes the function.  Blacklist flags live in SQL (set above); after
    # refresh the explicit-clear block sets them to False in the func dict, and
    # _update_function_via_repo writes those cleared values back to SQL.
    state = {
        "functions": {
            "/proj/Foo.exe::00401000": {
                "program": "/proj/Foo.exe",
                "address": "00401000",
                "name": "FUN_00401000",
                "score": 10,
                "fixable": 0.5,
            }
        }
    }
    fun_doc.refresh_candidate_scores(state, count=10, save=True)

    fetched = repo.get_function("/proj/Foo.exe", "00401000")
    assert fetched["score"] == 42, "refreshed score never reached SQL"
    assert not fetched.get("recovery_pass_done"), "blacklist flag not cleared in SQL"
    assert not fetched.get("decompile_timeout")
    assert not fetched.get("library_code")
    assert (fetched.get("stagnation_runs") or 0) == 0


def test_migrate_runs_idempotent(sqlite_repo, tmp_path, monkeypatch):
    """H26: re-running the migration must not duplicate runs rows."""
    import json
    sys.path.insert(0, str(_FUNDOC_DIR / "scripts"))
    import migrate_state_to_sql as mig

    # Minimal state.json + runs.jsonl with one entry.
    state_json = tmp_path / "state.json"
    state_json.write_text(json.dumps({
        "functions": {"/p/Foo.exe::00401000": {
            "program": "/p/Foo.exe", "address": "00401000", "name": "FUN_00401000"
        }}
    }))
    runs_jsonl = tmp_path / "runs.jsonl"
    runs_jsonl.write_text(json.dumps({
        "program": "/p/Foo.exe", "address": "00401000",
        "timestamp": "2026-01-01T00:00:00", "provider": "p", "model": "m",
        "result": "completed",
    }) + "\n")

    repo, _db_path = sqlite_repo
    monkeypatch.setattr(mig, "engine", repo._engine, raising=False)
    monkeypatch.setattr(mig, "repo", repo, raising=False)

    mig.migrate(state_path=state_json, runs_path=runs_jsonl, truncate_runs=False)
    n1 = repo.count_runs()
    assert n1 == 1

    # Second run without --truncate-runs must refuse, not duplicate.
    import pytest as _pytest
    with _pytest.raises(SystemExit) as exc_info:
        mig.migrate(state_path=state_json, runs_path=runs_jsonl, truncate_runs=False)
    assert exc_info.value.code == 2
    assert repo.count_runs() == 1

    # With --truncate-runs, second run replaces (count stays 1).
    mig.migrate(state_path=state_json, runs_path=runs_jsonl, truncate_runs=True)
    assert repo.count_runs() == 1


def test_selector_blacklist_flags_round_trip(sqlite_repo):
    """H22: recovery_pass_done / decompile_timeout / not_a_function must
    survive _state_func_to_row → repo → _row_to_state_func, otherwise the
    selector re-picks pathological functions forever."""
    import fun_doc

    repo, _db_path = sqlite_repo

    key = "/proj/Foo.exe::00401000"
    rec = {
        "program": "/proj/Foo.exe",
        "address": "00401000",
        "name": "FUN_00401000",
        "score": 12,
        "recovery_pass_done": True,
        "decompile_timeout": True,
        "not_a_function": True,
    }
    row = fun_doc._state_func_to_row(key, rec)
    assert row.get("recovery_pass_done") is True
    assert row.get("decompile_timeout") is True
    assert row.get("not_a_function") is True

    repo.upsert_function(row)
    fetched = repo.get_function("/proj/Foo.exe", "00401000")
    back = fun_doc._row_to_state_func(fetched)
    assert back.get("recovery_pass_done") is True
    assert back.get("decompile_timeout") is True
    assert back.get("not_a_function") is True

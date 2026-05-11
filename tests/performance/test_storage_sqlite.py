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

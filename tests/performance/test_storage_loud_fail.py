"""Regression tests for the v5.9.1+ loud-fail guard in fun-doc's storage
backend opener.

Background
==========

v5.9.0 release day surfaced a silent-fallback pattern: when fun-doc could
not open its SQL backend it printed a one-line WARNING and quietly
reverted to legacy state.json. The user's worker output then accumulated
in state.json while the dashboard read state.db — invisible drift.

v5.9.1 added an import-time guard that exits cleanly when ``sqlalchemy``
is missing, but the post-import failure modes (Postgres unreachable, bad
URL, schema-bootstrap broken, SQLite path unwritable) still degraded
silently. This file regresses each of those: the storage opener must
``sys.exit(1)`` with an actionable diagnostic, never return ``None`` and
let load_state fall back.

These tests don't touch the user's real state.db — they monkeypatch
fun_doc._storage_repo / _storage_repo_failed to fresh state inside each
test and patch the storage entry points to raise on demand.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


@pytest.fixture
def fun_doc_module(monkeypatch):
    """Import fun_doc with a clean storage-repo cache."""
    funcdoc_dir = Path(__file__).resolve().parent.parent.parent / "fun-doc"
    if str(funcdoc_dir) not in sys.path:
        sys.path.insert(0, str(funcdoc_dir))
    import fun_doc

    # The autouse fixture in conftest.py already wipes these, but reset
    # again so this test is self-contained if the conftest changes.
    monkeypatch.setattr(fun_doc, "_storage_repo", None, raising=False)
    monkeypatch.setattr(fun_doc, "_storage_repo_failed", False, raising=False)
    return fun_doc


def _patch_make_repository_to_raise(monkeypatch, exc: Exception) -> None:
    """Replace ``storage.make_repository`` with one that raises ``exc``."""
    import storage

    def _boom(*_args, **_kwargs):
        raise exc

    monkeypatch.setattr(storage, "make_repository", _boom)


# ---------------------------------------------------------------------------
# Loud-fail: bad URL / connection refused
# ---------------------------------------------------------------------------

def test_get_storage_repo_exits_when_postgres_unreachable(fun_doc_module, monkeypatch, capsys):
    """Connection-refused from make_repository must surface, not silently fall back."""
    _patch_make_repository_to_raise(
        monkeypatch,
        ConnectionRefusedError("connection to localhost:5432 refused"),
    )

    with pytest.raises(SystemExit) as exc_info:
        fun_doc_module._get_storage_repo()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "fun-doc storage backend failed to open" in captured.err
    assert "ConnectionRefusedError" in captured.err
    assert "localhost:5432" in captured.err
    # Must point the operator at the diagnostic next step.
    assert "FUN_DOC_DB_URL" in captured.err or "priority_queue.json" in captured.err


def test_get_storage_repo_exits_when_bootstrap_schema_fails(fun_doc_module, monkeypatch, capsys):
    """Schema migration explosion must propagate to a clean exit."""
    import storage

    class _FakeRepo:
        def bootstrap_schema(self):
            raise RuntimeError("migration 0002_library_code.sql: column already exists")

    monkeypatch.setattr(storage, "make_repository", lambda *a, **kw: _FakeRepo())

    with pytest.raises(SystemExit) as exc_info:
        fun_doc_module._get_storage_repo()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "RuntimeError" in captured.err
    assert "migration 0002_library_code.sql" in captured.err
    assert "migrate_state_to_sql.py" in captured.err


def test_get_storage_repo_exits_when_sqlite_path_unwritable(fun_doc_module, monkeypatch, capsys):
    """OperationalError from a read-only SQLite path must loud-fail."""
    _patch_make_repository_to_raise(
        monkeypatch,
        OSError("[Errno 13] Permission denied: 'fun-doc/state.db'"),
    )

    with pytest.raises(SystemExit) as exc_info:
        fun_doc_module._get_storage_repo()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Permission denied" in captured.err
    # Caller should be pointed at filesystem permission diagnostics.
    assert "filesystem permissions" in captured.err or "state.db" in captured.err


# ---------------------------------------------------------------------------
# Test-fixture path: _storage_repo_failed = True must still return None
# ---------------------------------------------------------------------------

def test_test_fixture_override_still_returns_none(fun_doc_module, monkeypatch):
    """The legacy-state.json test path (test_state_atomicity.py) sets
    ``_storage_repo_failed = True`` explicitly to bypass the SQL backend.
    The loud-fail guard must not break that override -- it should only
    apply when the opener actually runs.
    """
    monkeypatch.setattr(fun_doc_module, "_storage_repo_failed", True)
    monkeypatch.setattr(fun_doc_module, "_storage_repo", None)

    # No exit, no exception -- just None for the legacy fallback to handle.
    assert fun_doc_module._get_storage_repo() is None


# ---------------------------------------------------------------------------
# Happy path stays happy
# ---------------------------------------------------------------------------

def test_get_storage_repo_returns_cached_repo(fun_doc_module, monkeypatch):
    """If a repo is already cached, return it without re-opening."""
    sentinel = object()
    monkeypatch.setattr(fun_doc_module, "_storage_repo", sentinel)
    monkeypatch.setattr(fun_doc_module, "_storage_repo_failed", False)

    assert fun_doc_module._get_storage_repo() is sentinel

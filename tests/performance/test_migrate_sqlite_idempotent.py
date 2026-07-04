"""Regression: SQLite migration runner makes ALTER TABLE ADD COLUMN idempotent.

Copilot review #4 on the v5.9.0 PR: the SQLite-dialect migration files
issue plain ``ALTER TABLE ... ADD COLUMN`` (SQLite doesn't accept the
``IF NOT EXISTS`` form). If the runner crashed between
``executescript`` and the ``schema_versions`` row commit — process kill,
power loss, SIGINT during deploy — the column landed but the version
didn't, so the next migrate run tried to add it again and failed with
``duplicate column name``, requiring manual recovery.

``db/migrate.py``'s ``_SqliteConnAdapter.executescript`` now inspects
``PRAGMA table_info(<table>)`` before each ADD COLUMN and rewrites the
statement to a comment when the column is already present. These tests
pin that behavior:

* A second run of the exact same script is a no-op (the original bug).
* Only the duplicate ADD COLUMN is suppressed; non-duplicate statements
  in the same script still execute.
* A statement targeting an unrelated table is untouched.
* Non-ALTER statements (CREATE INDEX, etc.) pass through unchanged.
"""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_MIGRATE_PY = _REPO_ROOT / "fun-doc" / "db" / "migrate.py"


@pytest.fixture
def migrate_module(monkeypatch):
    """Load fun-doc/db/migrate.py without importing it as a package
    (it imports relative siblings; isolating via importlib avoids
    polluting sys.modules between tests)."""
    monkeypatch.syspath_prepend(str(_MIGRATE_PY.parent))
    spec = importlib.util.spec_from_file_location("fun_doc_migrate_under_test", _MIGRATE_PY)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fun_doc_migrate_under_test"] = mod
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pytest.skip("migrate.py raised SystemExit during import (missing optional dep)")
    yield mod
    sys.modules.pop("fun_doc_migrate_under_test", None)


def _make_adapter(migrate_module, tmp_path: Path):
    """Build the SQLite adapter against a fresh on-disk DB with the
    functions_workflow table the migrations target."""
    conn = sqlite3.connect(str(tmp_path / "state.db"))
    conn.isolation_level = None
    conn.execute(
        "CREATE TABLE functions_workflow ("
        "id INTEGER PRIMARY KEY, "
        "address TEXT NOT NULL"
        ")"
    )
    return migrate_module._SqliteConnAdapter(conn), conn


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def test_add_column_then_replay_does_not_raise(migrate_module, tmp_path):
    """The whole reason this fix exists: re-applying the same migration
    SQL must not fail with 'duplicate column name'."""
    adapter, conn = _make_adapter(migrate_module, tmp_path)
    try:
        sql = "ALTER TABLE functions_workflow ADD COLUMN library_code INTEGER DEFAULT 0;"
        adapter.executescript(sql)
        adapter.executescript(sql)   # second run is the regression case
        assert "library_code" in _columns(conn, "functions_workflow")
    finally:
        conn.close()


def test_multi_column_partial_replay_completes_missing_columns(
    migrate_module, tmp_path
):
    """Realistic partial-apply: column 1 landed on the first run before a
    crash; column 2 didn't. The replay must skip column 1 (already there)
    but still add column 2."""
    adapter, conn = _make_adapter(migrate_module, tmp_path)
    try:
        # Simulate partial application — column 1 is already in the schema.
        conn.execute("ALTER TABLE functions_workflow ADD COLUMN library_code INTEGER DEFAULT 0")
        before = _columns(conn, "functions_workflow")
        assert "library_code" in before
        assert "library_code_at" not in before

        adapter.executescript(
            "ALTER TABLE functions_workflow ADD COLUMN library_code INTEGER DEFAULT 0;\n"
            "ALTER TABLE functions_workflow ADD COLUMN library_code_at TEXT;\n"
        )
        after = _columns(conn, "functions_workflow")
        assert "library_code" in after
        assert "library_code_at" in after, (
            "second column must be added even though the first was a no-op skip"
        )
    finally:
        conn.close()


def test_unrelated_table_alter_passes_through(migrate_module, tmp_path):
    """The pre-flight skip is scoped per-(table, column). A statement
    against a different table whose schema we don't know yet should NOT
    be suppressed — let SQLite raise the real error if it's malformed,
    but if the table happens to exist with a missing column, run it."""
    adapter, conn = _make_adapter(migrate_module, tmp_path)
    try:
        # Build a second table with its own column already present.
        conn.execute("CREATE TABLE schema_versions (version INTEGER, applied_at TEXT)")
        adapter.executescript(
            "ALTER TABLE schema_versions ADD COLUMN extra_field TEXT;"
        )
        assert "extra_field" in _columns(conn, "schema_versions")
    finally:
        conn.close()


def test_non_alter_statements_unaffected(migrate_module, tmp_path):
    """CREATE INDEX (and other non-ALTER statements) must pass through
    the filter unchanged. The filter is intentionally narrow — it only
    knows how to suppress duplicate ADD COLUMN, nothing else."""
    adapter, conn = _make_adapter(migrate_module, tmp_path)
    try:
        adapter.executescript(
            "ALTER TABLE functions_workflow ADD COLUMN name_source TEXT;\n"
            "CREATE INDEX IF NOT EXISTS ix_name_source "
            "ON functions_workflow (name_source);\n"
        )
        idx_rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='ix_name_source'"
        ).fetchall()
        assert idx_rows, "CREATE INDEX statement was not executed"
    finally:
        conn.close()


def test_record_applied_duplicate_version_is_tolerant(migrate_module, tmp_path):
    """Regression: two migrators racing the read-versions -> apply -> record
    window (e.g. two threads bootstrapping the same fresh SQLite) used to
    blow up with `UNIQUE constraint failed: schema_versions.version` when
    the loser recorded a version the winner already inserted. INSERT OR
    IGNORE makes the loser a no-op."""
    conn = sqlite3.connect(str(tmp_path / "state.db"))
    conn.isolation_level = None
    adapter = migrate_module._SqliteConnAdapter(conn)
    try:
        migrate_module._ensure_versions_table(adapter, "sqlite")
        migrate_module._record_applied(adapter, "sqlite", 1, "initial")
        migrate_module._record_applied(adapter, "sqlite", 1, "initial")  # loser of the race
        rows = conn.execute("SELECT version FROM schema_versions").fetchall()
        assert [r[0] for r in rows] == [1]
    finally:
        conn.close()


def test_concurrent_migrate_same_db_no_unique_failure(migrate_module, tmp_path):
    """Full-stack version of the race: two threads run migrate() against the
    same fresh SQLite simultaneously. Both must finish without raising, and
    schema_versions must hold each version exactly once."""
    import threading

    db_path = str(tmp_path / "race.db")
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def run():
        try:
            barrier.wait(timeout=10)
            migrate_module.migrate("sqlite", db_path)
        except BaseException as e:  # noqa: BLE001 — collect for assertion
            errors.append(e)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"concurrent migrate raised: {errors!r}"
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT version, COUNT(*) FROM schema_versions GROUP BY version HAVING COUNT(*) > 1"
        ).fetchall()
        assert rows == [], f"duplicate schema_versions rows: {rows}"
    finally:
        conn.close()


def test_get_storage_repo_singleton_is_threadsafe(tmp_path, monkeypatch):
    """Regression for the in-process half of the race: _get_storage_repo()
    was an unlocked check-then-build singleton, so a worker/watchdog thread
    and the main thread could both bootstrap the same SQLite. All concurrent
    callers must now get the SAME repository instance with no error."""
    import threading

    fundoc_dir = _REPO_ROOT / "fun-doc"
    if str(fundoc_dir) not in sys.path:
        sys.path.insert(0, str(fundoc_dir))
    import fun_doc as fd

    monkeypatch.setenv("FUN_DOC_DB_URL", f"sqlite:///{tmp_path / 'singleton_race.db'}")
    fd._storage_repo = None
    fd._storage_repo_failed = False

    n = 8
    barrier = threading.Barrier(n)
    results: list[object] = []
    errors: list[BaseException] = []

    def grab():
        try:
            barrier.wait(timeout=10)
            results.append(fd._get_storage_repo())
        except BaseException as e:  # noqa: BLE001 — collect for assertion
            errors.append(e)

    threads = [threading.Thread(target=grab) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    try:
        assert not errors, f"_get_storage_repo raised under concurrency: {errors!r}"
        assert len(results) == n
        assert len({id(r) for r in results}) == 1, "threads got different repo instances"
        assert results[0] is not None
    finally:
        if fd._storage_repo is not None:
            try:
                fd._storage_repo.engine.dispose()
            except Exception:
                pass
            fd._storage_repo = None


def test_strip_helper_in_isolation(migrate_module, tmp_path):
    """The regex helper rewrites a duplicate ADD COLUMN to a comment;
    pin that behavior so a future regex tweak can't silently regress."""
    adapter, conn = _make_adapter(migrate_module, tmp_path)
    try:
        # Pre-populate column 'library_code'.
        conn.execute("ALTER TABLE functions_workflow ADD COLUMN library_code INTEGER")
        sql = (
            "ALTER TABLE functions_workflow ADD COLUMN library_code INTEGER DEFAULT 0;\n"
            "ALTER TABLE functions_workflow ADD COLUMN library_code_at TEXT;\n"
        )
        rewritten = migrate_module._strip_existing_alter_add_column_sqlite(adapter, sql)
        # First (duplicate) statement → comment; second (new) → unchanged
        assert "-- [migrate] skipped:" in rewritten
        assert "library_code_at TEXT" in rewritten
    finally:
        conn.close()

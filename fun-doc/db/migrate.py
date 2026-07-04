"""Schema migration runner for fun-doc.

Reads the SQL files in ``fun-doc/db/migrations/`` and applies any that
haven't run yet, tracked in ``fun_doc.schema_versions`` (PG) or
``schema_versions`` (SQLite). Idempotent: running twice is a no-op.

Usage:

    # Bring up a fresh SQLite DB at the default path
    python -m fun_doc.db.migrate --backend sqlite

    # Bring up Postgres using FUN_DOC_DB_URL env var
    python -m fun_doc.db.migrate --backend postgres

    # Override the connection URL on the command line
    python -m fun_doc.db.migrate --url postgresql://user:pw@host/db

The runner is intentionally minimal — no schema versioning library, no
checksum verification, no down-migrations. fun-doc is single-tenant; if a
migration is wrong, you fix the file and recreate the DB. For a real
multi-tenant deployment we'd reach for Alembic, but it's overkill here.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import threading
from pathlib import Path
from typing import Optional


MIGRATIONS_DIR = Path(__file__).parent / "migrations"
DEFAULT_SQLITE_PATH = Path(__file__).parent.parent / "state.db"


def _migration_files(backend: str) -> list[tuple[int, str, Path]]:
    """Return [(version, name, path), ...] for migrations matching the backend.

    Filenames look like ``0001_initial.sql`` (PG) or
    ``0001_initial.sqlite.sql`` (SQLite). The numeric prefix is the version;
    the suffix decides which backend the file applies to.
    """
    suffix = ".sqlite.sql" if backend == "sqlite" else ".sql"
    out: list[tuple[int, str, Path]] = []
    for path in sorted(MIGRATIONS_DIR.glob("[0-9]*")):
        name = path.name
        if backend == "postgres" and name.endswith(".sqlite.sql"):
            continue
        if backend == "sqlite" and not name.endswith(".sqlite.sql"):
            continue
        m = re.match(r"^(\d+)_(.+?)" + re.escape(suffix) + r"$", name)
        if not m:
            continue
        version = int(m.group(1))
        out.append((version, m.group(2), path))
    out.sort(key=lambda t: t[0])
    return out


def _ensure_versions_table(conn, backend: str) -> None:
    if backend == "postgres":
        conn.execute(
            "CREATE SCHEMA IF NOT EXISTS fun_doc; "
            "CREATE TABLE IF NOT EXISTS fun_doc.schema_versions ("
            "  version INTEGER PRIMARY KEY,"
            "  name TEXT NOT NULL,"
            "  applied_at TIMESTAMPTZ DEFAULT now()"
            ")"
        )
    else:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_versions ("
            "  version INTEGER PRIMARY KEY,"
            "  name TEXT NOT NULL,"
            "  applied_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"
            ")"
        )


def _applied_versions(conn, backend: str) -> set[int]:
    table = "fun_doc.schema_versions" if backend == "postgres" else "schema_versions"
    rows = conn.execute(f"SELECT version FROM {table}").fetchall()
    return {r[0] for r in rows}


def _record_applied(conn, backend: str, version: int, name: str) -> None:
    # Conflict-tolerant on purpose: two migrators can race the
    # read-versions -> apply -> record window (e.g. two threads
    # bootstrapping the same fresh SQLite). The migration SQL itself is
    # idempotent by design (CREATE TABLE IF NOT EXISTS + the ALTER ADD
    # COLUMN rewrite below), so the loser of the race just skips the
    # duplicate version row instead of blowing up with a UNIQUE failure.
    table = "fun_doc.schema_versions" if backend == "postgres" else "schema_versions"
    if backend == "postgres":
        conn.execute(
            f"INSERT INTO {table} (version, name) VALUES (%s, %s) "
            "ON CONFLICT (version) DO NOTHING",
            (version, name),
        )
    else:
        conn.execute(
            f"INSERT OR IGNORE INTO {table} (version, name) VALUES (?, ?)",
            (version, name),
        )


def _connect(backend: str, url: Optional[str]):
    if backend == "sqlite":
        import sqlite3

        path = url if url else str(DEFAULT_SQLITE_PATH)
        # Allow file: URLs and bare paths; strip the prefix.
        if path.startswith("sqlite:///"):
            path = path[len("sqlite:///") :]
        # Make sure the parent directory exists.
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        conn.isolation_level = None  # autocommit-ish; we manage txns explicitly
        # Wrap so .execute returns a cursor with .fetchall like psycopg.
        return _SqliteConnAdapter(conn), path
    elif backend == "postgres":
        try:
            import psycopg
        except ImportError as e:
            raise SystemExit(
                "Postgres backend requires the 'psycopg' package. "
                "Install with: pip install 'psycopg[binary]>=3.1'"
            ) from e
        url = url or os.environ.get("FUN_DOC_DB_URL")
        if not url:
            raise SystemExit(
                "No Postgres URL provided. Set FUN_DOC_DB_URL or pass --url."
            )
        conn = psycopg.connect(url, autocommit=False)
        return _PgConnAdapter(conn), url
    raise SystemExit(f"Unknown backend: {backend!r}")


_ALTER_ADD_COLUMN_RE = re.compile(
    r"""ALTER\s+TABLE\s+                        # ALTER TABLE
        (?P<table>[A-Za-z_][\w.]*)\s+           # qualified table name
        ADD\s+COLUMN\s+                          # ADD COLUMN
        (?P<column>[A-Za-z_]\w*)                # column identifier (must be word-bounded)
        \b                                       # …no embedded suffix
        [^;]*;                                   # type + defaults + closing semicolon
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)


def _existing_columns_sqlite(conn, table: str) -> set[str]:
    """Lower-cased column names already on ``table`` (empty if missing)."""
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return {row[1].lower() for row in cur.fetchall()}
    except Exception:
        # Table doesn't exist yet (the migration creating it hasn't run);
        # let the script run and surface the real error naturally.
        return set()


def _strip_existing_alter_add_column_sqlite(conn, sql: str) -> str:
    """SQLite ALTER TABLE ADD COLUMN has no IF NOT EXISTS form. Without
    pre-flight skipping, re-running a migration whose schema_versions
    entry didn't commit (process crashed between executescript and
    commit) raises "duplicate column name" and forces manual recovery.

    This helper inspects each ALTER TABLE ADD COLUMN statement against
    PRAGMA table_info(<table>); if the column is already present it
    rewrites the statement to a SQL comment so the rest of the script
    still runs. Postgres migrations are unaffected — they use ADD
    COLUMN IF NOT EXISTS natively.

    Bare-string scanning is sufficient because the migration files are
    hand-authored, one-statement-per-line, no embedded `;` inside types.
    A more elaborate parser would be overkill for this controlled input.
    """
    def _maybe_strip(match: re.Match) -> str:
        table = match.group("table").lower()
        column = match.group("column").lower()
        if column in _existing_columns_sqlite(conn, table):
            return (
                f"-- [migrate] skipped: column {column!r} already present on "
                f"{table!r} (idempotent ADD COLUMN)"
            )
        return match.group(0)

    return _ALTER_ADD_COLUMN_RE.sub(_maybe_strip, sql)


class _SqliteConnAdapter:
    """Thin wrapper so SQLite and psycopg connections share a tiny interface."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        cur = self._conn.cursor()
        if params is None:
            cur.execute(sql)
        else:
            cur.execute(sql, params)
        return cur

    def executescript(self, sql):
        # Make ALTER TABLE ADD COLUMN idempotent so a crashed-mid-migration
        # retry doesn't fail with "duplicate column name". The check
        # consults PRAGMA table_info before each statement runs.
        filtered = _strip_existing_alter_add_column_sqlite(self, sql)
        self._conn.executescript(filtered)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


class _PgConnAdapter:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        cur = self._conn.cursor()
        if params is None:
            cur.execute(sql)
        else:
            cur.execute(sql, params)
        return cur

    def executescript(self, sql):
        # psycopg3 accepts multi-statement SQL when sent via execute; no need
        # for a separate executescript path.
        self._conn.cursor().execute(sql)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


# Serializes concurrent migrate() calls within a process. The PRAGMA-based
# ADD COLUMN skip and INSERT-OR-IGNORE version record make a *retry* idempotent,
# but they cannot win a cross-connection TOCTOU race: two threads that both read
# an empty schema race the same `ALTER TABLE ADD COLUMN`, and the loser dies with
# "duplicate column name". fun-doc migrates in-process (main + worker/watchdog
# threads), so serializing here lets the second caller observe the first's
# committed schema and no-op instead of colliding.
_migrate_lock = threading.Lock()


def migrate(backend: str, url: Optional[str] = None) -> int:
    """Apply all unapplied migrations for ``backend``. Returns count applied."""
    with _migrate_lock:
        conn, target = _connect(backend, url)
        applied_count = 0
        try:
            _ensure_versions_table(conn, backend)
            already = _applied_versions(conn, backend)
            for version, name, path in _migration_files(backend):
                if version in already:
                    continue
                sql = path.read_text(encoding="utf-8")
                conn.executescript(sql)
                _record_applied(conn, backend, version, name)
                applied_count += 1
                print(f"[migrate] applied {version:04d}_{name} ({backend}) at {target}")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    if applied_count == 0:
        print(f"[migrate] {backend} schema already up to date at {target}")
    return applied_count


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Apply fun-doc schema migrations.", prog="fun_doc.db.migrate"
    )
    parser.add_argument(
        "--backend",
        choices=["sqlite", "postgres"],
        default="sqlite",
        help="Storage backend to migrate.",
    )
    parser.add_argument(
        "--url",
        default=None,
        help=(
            "Override the connection URL. For SQLite, this is a path or "
            "sqlite:/// URL. For Postgres, an RFC-3986 URL "
            "(postgresql://user:pw@host/db). Defaults to FUN_DOC_DB_URL "
            "for postgres or the bundled state.db for sqlite."
        ),
    )
    args = parser.parse_args(argv)
    migrate(args.backend, args.url)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Postgres-engine-specific storage tests.

Skipped automatically if neither ``FUN_DOC_TEST_PG_URL`` is set nor
testcontainers + Docker are available. Set ``FUN_DOC_TEST_PG_URL`` to point
at a disposable PG instance to run these without Docker.

Cross-backend correctness lives in test_storage_common.py — anything in
this file is genuinely PG-specific (JSONB operators, schema namespacing,
behaviors SQLite can't reproduce).
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))


def _explicit_pg_url() -> str | None:
    return os.environ.get("FUN_DOC_TEST_PG_URL")


def _docker_available() -> bool:
    """Probe whether Docker is usable from this process — daemon, not just CLI."""
    try:
        import subprocess

        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() != ""
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    _explicit_pg_url() is None and not _docker_available(),
    reason="No FUN_DOC_TEST_PG_URL and no Docker for testcontainers",
)


@pytest.fixture
def pg_repo(request):
    from sqlalchemy import text

    from storage import StorageConfig, make_engine
    from storage.repository import Repository

    pg_url = _explicit_pg_url()
    container = None
    if pg_url is None:
        try:
            from testcontainers.postgres import PostgresContainer
        except ImportError:
            pytest.skip("testcontainers not installed; pip install testcontainers")
        container = PostgresContainer("postgres:16")
        container.start()
        pg_url = container.get_connection_url()

    schema = f"fun_doc_test_{os.getpid()}_{id(request) & 0xFFFF:x}"
    cfg = StorageConfig(backend="postgres", url=pg_url, schema=schema)
    engine = make_engine(cfg)
    with engine.begin() as conn:
        conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))

    sql_path = _FUNDOC_DIR / "db" / "migrations" / "0001_initial.sql"
    sql = sql_path.read_text(encoding="utf-8").replace("fun_doc.", f'"{schema}".')
    sql = sql.replace(
        "CREATE SCHEMA IF NOT EXISTS fun_doc;",
        f'CREATE SCHEMA IF NOT EXISTS "{schema}";',
    )
    with engine.begin() as conn:
        conn.execute(text(sql))

    repo = Repository(engine, cfg)
    yield repo
    with engine.begin() as conn:
        conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    engine.dispose()
    if container is not None:
        container.stop()


def test_jsonb_columns_are_native_jsonb(pg_repo):
    """deductions and callees should be stored as JSONB in PG, not TEXT.
    This matters because future queries (audit drains, propagation) will
    want jsonb_array_elements / @> operators."""
    from sqlalchemy import text

    repo = pg_repo
    schema = repo.config.schema
    with repo.engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = :schema AND table_name = 'functions_workflow' "
                "AND column_name IN ('deductions', 'callees')"
            ),
            {"schema": schema},
        ).fetchall()
    types = {r[0]: r[1] for r in rows}
    assert types == {"deductions": "jsonb", "callees": "jsonb"}


def test_jsonb_query_via_operator(pg_repo):
    """Verify JSONB operators work end-to-end against a stored row."""
    from sqlalchemy import text

    repo = pg_repo
    repo.upsert_function(
        {
            "program_path": "/test/foo.dll",
            "binary_name": "foo.dll",
            "version": "v1",
            "address": "00400000",
            "deductions": [{"category": "plate", "points": 5}],
            "callees": ["00400100"],
        }
    )
    schema = repo.config.schema
    with repo.engine.connect() as conn:
        row = conn.execute(
            text(
                f'SELECT name, deductions->0->>\'category\' AS first_cat '
                f'FROM "{schema}".functions_workflow '
                f"WHERE program_path = '/test/foo.dll'"
            )
        ).first()
    assert row[1] == "plate"


def test_schema_namespacing(pg_repo):
    """Two repositories on different schemas must not see each other's data."""
    from sqlalchemy import text

    from storage import StorageConfig, make_engine
    from storage.repository import Repository

    repo_a = pg_repo
    schema_b = repo_a.config.schema + "_b"
    cfg_b = StorageConfig(
        backend="postgres", url=repo_a.config.url, schema=schema_b
    )
    engine_b = make_engine(cfg_b)
    sql_path = _FUNDOC_DIR / "db" / "migrations" / "0001_initial.sql"
    sql = sql_path.read_text(encoding="utf-8").replace("fun_doc.", f'"{schema_b}".')
    sql = sql.replace(
        "CREATE SCHEMA IF NOT EXISTS fun_doc;",
        f'CREATE SCHEMA IF NOT EXISTS "{schema_b}";',
    )
    with engine_b.begin() as conn:
        conn.execute(text(sql))
    repo_b = Repository(engine_b, cfg_b)

    repo_a.upsert_function(
        {
            "program_path": "/test/foo.dll",
            "binary_name": "foo.dll",
            "version": "v1",
            "address": "00400000",
            "name": "FromA",
        }
    )
    assert repo_a.get_function("/test/foo.dll", "00400000")["name"] == "FromA"
    assert repo_b.get_function("/test/foo.dll", "00400000") is None

    with engine_b.begin() as conn:
        conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema_b}" CASCADE'))
    engine_b.dispose()


def test_on_conflict_do_update_for_inventory(pg_repo):
    """Verify the dialect-aware upsert path uses ON CONFLICT semantics on PG."""
    repo = pg_repo
    repo.upsert_inventory(
        {
            "program_path": "/test/foo.dll",
            "binary_name": "foo.dll",
            "version": "v1",
            "total_documentable": 100,
            "scored": 50,
        }
    )
    repo.upsert_inventory(
        {
            "program_path": "/test/foo.dll",
            "binary_name": "foo.dll",
            "version": "v1",
            "total_documentable": 100,
            "scored": 90,
        }
    )
    inv = repo.get_inventory("/test/foo.dll")
    assert len(inv) == 1
    assert inv[0]["scored"] == 90

"""Cross-backend storage tests.

These tests run against both backends — SQLite by default (always available),
Postgres when ``FUN_DOC_TEST_PG_URL`` is set or testcontainers is installed.
The fixture ``storage_repo`` parametrizes over whatever backends are
available; the SQLite path always runs, the PG path is gated.

The point of this module is correctness of the abstraction: any test here
that passes on SQLite but fails on PG (or vice versa) reveals a leaky
abstraction we'd otherwise discover only in production. Engine-specific
behavior (WAL mode, JSONB operators, advisory locks) lives in the per-engine
test files.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))


def _docker_available() -> bool:
    """Probe whether Docker is usable from this process.

    The CLI being on PATH isn't enough — the daemon also has to be
    reachable. Without the daemon, testcontainers raises DockerException
    inside the fixture and the test errors instead of skipping. Catching
    that case here keeps the SQLite path running cleanly.
    """
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


def _explicit_pg_url() -> str | None:
    return os.environ.get("FUN_DOC_TEST_PG_URL")


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgres",
            marks=pytest.mark.skipif(
                _explicit_pg_url() is None and not _docker_available(),
                reason="No FUN_DOC_TEST_PG_URL and Docker unavailable for testcontainers",
            ),
        ),
    ]
)
def storage_repo(request, tmp_path):
    """Yield a fresh Repository against the parametrized backend.

    SQLite uses a tmp_path-rooted file. Postgres uses ``FUN_DOC_TEST_PG_URL``
    when set, otherwise spins up a testcontainer. Schema is dropped + applied
    fresh per test for isolation.
    """
    from storage import StorageConfig, make_engine
    from storage.repository import Repository

    backend = request.param
    if backend == "sqlite":
        url = f"sqlite:///{tmp_path / 'test.db'}"
        cfg = StorageConfig(backend="sqlite", url=url, schema=None)
        engine = make_engine(cfg)
        repo = Repository(engine, cfg)
        repo.bootstrap_schema()
        yield repo
        engine.dispose()
        return

    # Postgres path
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
    # Wipe and recreate the schema for isolation.
    with engine.begin() as conn:
        from sqlalchemy import text

        conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    repo = Repository(engine, cfg)
    # bootstrap_schema applies migrations against schema=fun_doc — for
    # isolation we want them in the per-test schema. Apply by hand.
    _apply_pg_migrations(engine, schema)
    yield repo
    with engine.begin() as conn:
        from sqlalchemy import text

        conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    engine.dispose()
    if container is not None:
        container.stop()


def _apply_pg_migrations(engine, schema: str) -> None:
    """Apply the PG migration into ``schema`` instead of the hardcoded fun_doc.

    Reads the SQL file and rewrites the schema name in-place. Crude, but
    fine for a 120-line bootstrap that only references one schema.
    """
    from sqlalchemy import text

    sql_path = _FUNDOC_DIR / "db" / "migrations" / "0001_initial.sql"
    sql = sql_path.read_text(encoding="utf-8").replace("fun_doc.", f'"{schema}".')
    sql = sql.replace(
        "CREATE SCHEMA IF NOT EXISTS fun_doc;",
        f'CREATE SCHEMA IF NOT EXISTS "{schema}";',
    )
    with engine.begin() as conn:
        conn.execute(text(sql))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _sample_function(addr="00400000", name="TestFn", score=80) -> dict:
    return {
        "program_path": "/test/foo.dll",
        "binary_name": "foo.dll",
        "version": "v1",
        "address": addr,
        "name": name,
        "score": score,
        "effective_score": score,
        "fixable": 5.0,
        "has_custom_name": True,
        "has_plate_comment": True,
        "classification": "wrapper",
        "queue_status": "done",
        "deductions": [{"category": "plate", "points": 5.0, "fixable": True}],
        "callees": ["00400100", "00400200"],
        "is_thunk": False,
        "is_external": False,
    }


def test_upsert_and_get(storage_repo):
    repo = storage_repo
    fid = repo.upsert_function(_sample_function())
    assert isinstance(fid, int) and fid > 0
    got = repo.get_function("/test/foo.dll", "00400000")
    assert got is not None
    assert got["name"] == "TestFn"
    assert got["score"] == 80
    assert got["deductions"] == [
        {"category": "plate", "points": 5.0, "fixable": True}
    ]
    assert got["callees"] == ["00400100", "00400200"]


def test_upsert_is_merge_not_replace(storage_repo):
    """An UPSERT with a partial record must not null-out columns from the
    original. This is the canonical bug we're protecting against."""
    repo = storage_repo
    repo.upsert_function(_sample_function())
    # Update with a partial — only score and queue_status. classification
    # MUST survive.
    fid_after = repo.upsert_function(
        {
            "program_path": "/test/foo.dll",
            "binary_name": "foo.dll",
            "version": "v1",
            "address": "00400000",
            "score": 95,
            "queue_status": "in_progress",
        }
    )
    got = repo.get_function("/test/foo.dll", "00400000")
    assert got["score"] == 95
    assert got["queue_status"] == "in_progress"
    # Note: upsert_function's INSERT-or-UPDATE patches with whatever the
    # caller passed, so columns omitted from the second call retain the
    # values written by the first call.
    assert got["classification"] == "wrapper"
    assert got["name"] == "TestFn"


def test_get_returns_none_for_missing(storage_repo):
    assert storage_repo.get_function("/nope/no.dll", "00000000") is None


def test_update_function_fields_whitelist(storage_repo):
    repo = storage_repo
    repo.upsert_function(_sample_function())
    # Try to set both a whitelisted field and a denorm field (run_count).
    # The whitelisted field updates; the denorm field is silently dropped.
    ok = repo.update_function_fields(
        "/test/foo.dll", "00400000", score=99, run_count=100
    )
    assert ok is True
    got = repo.get_function("/test/foo.dll", "00400000")
    assert got["score"] == 99
    assert got["run_count"] == 0  # not 100 — whitelist rejected it


def test_update_function_fields_returns_false_on_missing(storage_repo):
    ok = storage_repo.update_function_fields(
        "/missing/nope.dll", "00000000", score=10
    )
    assert ok is False


def test_record_run_doc_kind_bumps_run_counters(storage_repo):
    repo = storage_repo
    repo.upsert_function(_sample_function())
    rid = repo.record_run(
        "/test/foo.dll",
        "00400000",
        {
            "run_kind": "doc",
            "provider": "claude",
            "model": "sonnet",
            "score_before": 80,
            "score_after": 90,
            "delta": 10,
            "outcome": "improved",
        },
    )
    assert isinstance(rid, int) and rid > 0
    got = repo.get_function("/test/foo.dll", "00400000")
    assert got["run_count"] == 1
    assert got["last_run_provider"] == "claude"
    assert got["last_run_model"] == "sonnet"
    assert got["last_run_delta"] == 10
    assert got["last_run_at"] is not None
    # Audit + escalation counters untouched
    assert got["audit_count"] == 0
    assert got["escalation_count"] == 0


def test_record_run_audit_kind_bumps_audit_counters(storage_repo):
    repo = storage_repo
    repo.upsert_function(_sample_function())
    repo.record_run(
        "/test/foo.dll",
        "00400000",
        {
            "run_kind": "audit",
            "provider": "gemini",
            "model": "gemini-pro",
            "score_before": 90,
            "score_after": 95,
            "delta": 5,
            "outcome": "improved",
        },
    )
    got = repo.get_function("/test/foo.dll", "00400000")
    assert got["audit_count"] == 1
    assert got["last_audit_provider"] == "gemini"
    assert got["last_audit_delta"] == 5
    assert got["last_audited_at"] is not None
    # Doc counters untouched
    assert got["run_count"] == 0
    assert got["last_run_provider"] is None


def test_record_run_escalation_kind_bumps_escalation_counters(storage_repo):
    repo = storage_repo
    repo.upsert_function(_sample_function())
    repo.record_run(
        "/test/foo.dll",
        "00400000",
        {
            "run_kind": "escalation",
            "provider": "opus",
            "model": "opus-4-7",
            "score_before": 50,
            "score_after": 80,
            "delta": 30,
            "outcome": "improved",
            "notes": "sonnet",
        },
    )
    got = repo.get_function("/test/foo.dll", "00400000")
    assert got["escalation_count"] == 1
    assert got["last_escalated_at"] is not None
    assert got["last_escalation_from"] == "sonnet"


def test_record_run_raises_when_function_missing(storage_repo):
    with pytest.raises(LookupError):
        storage_repo.record_run(
            "/missing/foo.dll",
            "00400000",
            {"provider": "claude", "model": "sonnet", "run_kind": "doc"},
        )


def test_get_recent_runs_orders_descending(storage_repo):
    repo = storage_repo
    repo.upsert_function(_sample_function())
    for delta in (5, 10, 15):
        repo.record_run(
            "/test/foo.dll",
            "00400000",
            {
                "run_kind": "doc",
                "provider": "claude",
                "model": "sonnet",
                "delta": delta,
            },
        )
    runs = repo.get_recent_runs("/test/foo.dll", "00400000", limit=10)
    assert [r["delta"] for r in runs] == [15, 10, 5]


def test_list_and_count_functions(storage_repo):
    repo = storage_repo
    for i in range(5):
        rec = _sample_function(addr=f"0040{i:04x}", name=f"Fn{i}")
        if i % 2 == 0:
            rec["queue_status"] = "queued"
        repo.upsert_function(rec)
    assert repo.count_functions(program_path="/test/foo.dll") == 5
    assert repo.count_functions(program_path="/test/foo.dll", queue_status="queued") == 3
    listed = repo.list_functions(program_path="/test/foo.dll", limit=2, offset=0)
    assert len(listed) == 2
    listed2 = repo.list_functions(program_path="/test/foo.dll", limit=2, offset=2)
    assert listed[0]["address"] != listed2[0]["address"]


def test_inventory_upsert_and_get(storage_repo):
    repo = storage_repo
    repo.upsert_inventory(
        {
            "program_path": "/test/foo.dll",
            "binary_name": "foo.dll",
            "version": "v1",
            "total_documentable": 100,
            "scored": 50,
            "last_scan": datetime(2026, 4, 25, 12, 0, 0, tzinfo=timezone.utc),
        }
    )
    inv = repo.get_inventory("/test/foo.dll")
    assert len(inv) == 1
    assert inv[0]["total_documentable"] == 100
    assert inv[0]["scored"] == 50
    # Update — verify it overwrites cleanly
    repo.upsert_inventory(
        {
            "program_path": "/test/foo.dll",
            "binary_name": "foo.dll",
            "version": "v1",
            "total_documentable": 100,
            "scored": 75,
        }
    )
    inv2 = repo.get_inventory("/test/foo.dll")
    assert inv2[0]["scored"] == 75


def test_global_inventory_upsert_and_get(storage_repo):
    repo = storage_repo
    repo.upsert_global_inventory(
        {
            "program_path": "/test/foo.dll",
            "binary_name": "foo.dll",
            "version": "v1",
            "total_documentable": 50,
            "fully_documented": 10,
        }
    )
    inv = repo.get_global_inventory("/test/foo.dll")
    assert len(inv) == 1
    assert inv[0]["fully_documented"] == 10


def test_meta_singleton(storage_repo):
    repo = storage_repo
    repo.set_meta(project_folder="F:/GhidraProjects/diablo2", active_binary="D2Common.dll")
    m = repo.get_meta()
    assert m["project_folder"] == "F:/GhidraProjects/diablo2"
    assert m["active_binary"] == "D2Common.dll"
    # Update one field; the other survives
    repo.set_meta(active_binary="D2Game.dll")
    m2 = repo.get_meta()
    assert m2["project_folder"] == "F:/GhidraProjects/diablo2"
    assert m2["active_binary"] == "D2Game.dll"


def test_session_upsert_and_get(storage_repo):
    repo = storage_repo
    repo.upsert_session(
        "session-2026-04-25",
        started_at=datetime(2026, 4, 25, 12, 0, 0, tzinfo=timezone.utc),
        payload={"worker_count": 4, "binaries": ["foo.dll", "bar.dll"]},
    )
    s = repo.get_session("session-2026-04-25")
    assert s is not None
    assert s["payload"] == {"worker_count": 4, "binaries": ["foo.dll", "bar.dll"]}


def test_bulk_upsert_functions(storage_repo):
    """Migration path uses bulk_upsert_functions for the 27 MB state.json
    load; verify INSERT and UPDATE both work in the same call."""
    repo = storage_repo
    # First call: all inserts.
    initial = [
        _sample_function(addr=f"0050{i:04x}", name=f"Init{i}") for i in range(10)
    ]
    n = repo.bulk_upsert_functions(initial)
    assert n == 10
    assert repo.count_functions(program_path="/test/foo.dll") == 10

    # Second call: 5 updates + 5 inserts mixed together.
    mixed = []
    for i in range(5):  # updates
        rec = _sample_function(addr=f"0050{i:04x}", name=f"Updated{i}", score=99)
        mixed.append(rec)
    for i in range(10, 15):  # inserts
        mixed.append(_sample_function(addr=f"0050{i:04x}", name=f"New{i}"))
    n2 = repo.bulk_upsert_functions(mixed)
    assert n2 == 10
    assert repo.count_functions(program_path="/test/foo.dll") == 15
    # Verify an updated row took the new name + score
    got = repo.get_function("/test/foo.dll", "00500000")
    assert got["name"] == "Updated0"
    assert got["score"] == 99


def test_count_runs_filters(storage_repo):
    repo = storage_repo
    repo.upsert_function(_sample_function())
    repo.record_run(
        "/test/foo.dll", "00400000",
        {"run_kind": "doc", "provider": "claude", "model": "sonnet"},
    )
    repo.record_run(
        "/test/foo.dll", "00400000",
        {"run_kind": "audit", "provider": "gemini", "model": "gemini-pro"},
    )
    assert repo.count_runs() == 2
    assert repo.count_runs(provider="claude") == 1
    assert repo.count_runs(provider="gemini") == 1
    assert repo.count_runs(program_path="/nope/missing.dll") == 0

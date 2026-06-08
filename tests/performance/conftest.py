"""Test isolation for fun-doc performance tests.

The storage layer (PR1) lazily initializes a SQLAlchemy engine pointing at
``fun-doc/state.db`` by default. Tests that exercise the legacy
state.json fallback need to make sure the storage repo *isn't* sitting
around from a previous test, because if it is, calls to fun_doc.load_state
will silently use the SQL backend instead of the legacy file path the test
is trying to validate.

This conftest provides an autouse fixture that:
  * Resets the cached storage repo on the fun_doc module so the next
    test that calls _get_storage_repo() re-runs init logic.

Tests that explicitly want the SQL backend (test_storage_*.py) construct
their own Repository against a tmp_path SQLite or testcontainers PG, so
this autouse cleanup doesn't interfere with them.

DESTRUCTIVE-FIXTURE GUARD (v5.9.1)
==================================
Previous versions of this conftest also unconditionally deleted
``fun-doc/state.db`` before AND after every test. That was correct in a
clean-repo / CI context where the file is purely a leftover test
artifact — but in a developer environment the file holds the LIVE
fun-doc database (workflow state, run history, library_code flags).
Running ``pytest tests/performance/`` on a working repo wiped the
user's database to 0 bytes (real incident: 65 library_code flags and
36k+ runs lost; recoverable only by re-running
scripts/migrate_state_to_sql.py against state.json).

We now check the size of state.db before deleting and refuse to remove
files that look populated. A populated database is preserved; only
truly-empty (0-byte) leftover files get cleaned. Tests that genuinely
need a fresh SQL backend create their own under tmp_path.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
_DEFAULT_STATE_DB = _FUNDOC_DIR / "state.db"
# Anything larger than this is treated as a real user database, not a
# stray test artifact. A fresh-bootstrap schema-only SQLite file is
# typically ~50-150 KB; we use 512 KB as a comfortable threshold.
_USER_DB_SIZE_THRESHOLD_BYTES = 512 * 1024


def _safe_clean_state_db() -> None:
    """Delete ``fun-doc/state.db`` only if it's empty or trivially small.

    Refuses to delete user data. Tests that need a guaranteed fresh DB
    should construct one under ``tmp_path`` instead of relying on this.
    """
    if not _DEFAULT_STATE_DB.exists():
        return
    try:
        size = _DEFAULT_STATE_DB.stat().st_size
    except OSError:
        return
    if size > _USER_DB_SIZE_THRESHOLD_BYTES:
        # Looks like the user's live database — leave it alone.
        return
    try:
        _DEFAULT_STATE_DB.unlink()
    except OSError:
        pass


@pytest.fixture(autouse=True)
def _isolate_storage_repo(tmp_path, monkeypatch):
    """Isolate every perf test from the real fun-doc database.

    Two layers:

    1. Force ``FUN_DOC_DB_URL`` to a per-test throwaway SQLite. ``resolve_config``
       checks this env var first, so any call to ``_get_storage_repo()`` (including
       from a freshly importlib-loaded ``fun_doc`` module, e.g. the state-lock test)
       resolves to an empty isolated DB instead of the repo's real ``state.db``.

       Without this, the size-guard below correctly REFUSES to delete a populated
       real ``state.db`` (data-safety), so on a developer machine ``load_state()``
       would fall back to the real, multi-thousand-row database. That produced
       slow real-data queries and SQLite write-lock contention when the suite runs
       in one process — surfacing as the spurious "_state_lock deadlock has
       regressed" timeout and atomicity flakiness. Each file passed in isolation
       and in clean CI (no real data), masking the cause. Forcing the env var makes
       the tests hermetic regardless of the developer's real DB.

       Tests that specifically assert the no-env fallback (test_sqlite_default_path)
       ``monkeypatch.delenv`` it themselves; tests that build explicit repositories
       pass an explicit config and ignore the env. So this override is safe.

    2. Reset the cached repo singleton before/after each test so the next
       ``_get_storage_repo()`` re-initializes against the isolated DB.
    """
    monkeypatch.setenv("FUN_DOC_DB_URL", f"sqlite:///{tmp_path / 'isolated_state.db'}")

    _safe_clean_state_db()
    # Pre-test: drop the cached repo so the next call re-initializes.
    if "fun_doc" in sys.modules:
        fd = sys.modules["fun_doc"]
        fd._storage_repo = None
        fd._storage_repo_failed = False

    yield

    # Post-test: same cleanup so the next test starts fresh.
    if "fun_doc" in sys.modules:
        fd = sys.modules["fun_doc"]
        if getattr(fd, "_storage_repo", None) is not None:
            try:
                fd._storage_repo.engine.dispose()
            except Exception:
                pass
            fd._storage_repo = None
        fd._storage_repo_failed = False
    _safe_clean_state_db()

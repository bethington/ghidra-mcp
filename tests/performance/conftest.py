"""Test isolation for fun-doc performance tests.

The storage layer (PR1) lazily initializes a SQLAlchemy engine pointing at
``fun-doc/state.db`` by default. Tests that exercise the legacy
state.json fallback need to make sure the storage repo *isn't* sitting
around from a previous test, because if it is, calls to fun_doc.load_state
will silently use the SQL backend instead of the legacy file path the test
is trying to validate.

This conftest provides an autouse fixture that:
  * Removes any stray ``fun-doc/state.db`` left over from prior tests.
  * Resets the cached storage repo on the fun_doc module so the next
    test that calls _get_storage_repo() re-runs init logic.

Tests that explicitly want the SQL backend (test_storage_*.py) construct
their own Repository against a tmp_path SQLite or testcontainers PG, so
this autouse cleanup doesn't interfere with them.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
_DEFAULT_STATE_DB = _FUNDOC_DIR / "state.db"


@pytest.fixture(autouse=True)
def _isolate_storage_repo():
    """Reset the fun_doc storage repo singleton + clean stray state.db."""
    # Pre-test: clear any leftover default state.db from prior runs.
    if _DEFAULT_STATE_DB.exists():
        try:
            _DEFAULT_STATE_DB.unlink()
        except OSError:
            pass
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
    if _DEFAULT_STATE_DB.exists():
        try:
            _DEFAULT_STATE_DB.unlink()
        except OSError:
            pass

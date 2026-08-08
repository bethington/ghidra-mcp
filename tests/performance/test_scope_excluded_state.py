"""`scope_excluded` state plumbing: migration 0008 through to the selector.

Three layers, and the middle one is where this class of change historically dies:

  1. SQL round-trip -- the columns survive `upsert_function` and
     `update_function_fields` (the both-lists trap: a field missing from
     `_UPDATABLE_WORKFLOW_FIELDS` is dropped with NO exception, which silently
     no-op'd `port_status` in 0005 and `audit_tool_calls` in 0007).
  2. fun_doc's state<->row converters, including the timestamp.
  3. The selector actually skipping on the flag -- because a column nothing reads
     is the same as no column at all.

Offline: SQL is a tmp sqlite file, no Ghidra, no network.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

fd = pytest.importorskip("fun_doc")


@pytest.fixture
def sqlite_repo(tmp_path):
    from storage import StorageConfig, make_engine
    from storage.repository import Repository

    cfg = StorageConfig(backend="sqlite",
                        url=f"sqlite:///{tmp_path / 'test.db'}", schema=None)
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    repo.bootstrap_schema()
    yield repo
    engine.dispose()


# --------------------------------------------------------------------------
# 1. SQL
# --------------------------------------------------------------------------

def test_columns_exist_after_bootstrap(sqlite_repo):
    """models.py and the migration SQL must agree -- models mirrors the
    migrations by hand, on purpose, so a hand-edit can leave them apart."""
    from sqlalchemy import inspect as sa_inspect
    cols = {c["name"] for c in
            sa_inspect(sqlite_repo.engine).get_columns("functions_workflow")}
    assert {"scope_excluded", "scope_excluded_at",
            "scope_excluded_reasons"} <= cols


def test_fields_survive_upsert(sqlite_repo):
    from datetime import datetime, timezone

    ts = datetime(2026, 8, 7, 9, 30, tzinfo=timezone.utc)
    sqlite_repo.upsert_function({
        "program_path": "/Mods/PD2-S12/PD2_EXT.dll",
        "binary_name": "PD2_EXT.dll",
        "address": "10001000",
        "scope_excluded": True,
        "scope_excluded_at": ts,
        "scope_excluded_reasons": ["all 3 referrer(s) are library code"],
    })
    row = sqlite_repo.get_function("/Mods/PD2-S12/PD2_EXT.dll", "10001000")
    assert row["scope_excluded"] in (True, 1)
    assert row["scope_excluded_reasons"][0].startswith("all 3 referrer")
    assert row["scope_excluded_at"] is not None


def test_fields_survive_update_function_fields(sqlite_repo):
    """The both-lists trap. `changed` being falsy here is precisely how
    port_status and audit_tool_calls were lost: no error, no write."""
    sqlite_repo.upsert_function({
        "program_path": "/p", "binary_name": "p", "address": "1000"})
    changed = sqlite_repo.update_function_fields(
        "/p", "1000", scope_excluded=True,
        scope_excluded_reasons=["referrers are library"])
    assert changed, "fields were silently filtered out of the update"
    row = sqlite_repo.get_function("/p", "1000")
    assert row["scope_excluded"] in (True, 1)
    assert row["scope_excluded_reasons"] == ["referrers are library"]


def test_the_flag_is_independent_of_library_code(sqlite_repo):
    """The reason there are two columns: an inference must be recordable without
    asserting the function IS library code, and correctable without touching the
    other verdict."""
    sqlite_repo.upsert_function({
        "program_path": "/p", "binary_name": "p", "address": "2000",
        "scope_excluded": True, "library_code": False})
    row = sqlite_repo.get_function("/p", "2000")
    assert row["scope_excluded"] in (True, 1)
    assert row["library_code"] in (False, 0, None)

    sqlite_repo.update_function_fields("/p", "2000", scope_excluded=False)
    row = sqlite_repo.get_function("/p", "2000")
    assert row["scope_excluded"] in (False, 0)
    assert row["library_code"] in (False, 0, None)


# --------------------------------------------------------------------------
# 2. converters
# --------------------------------------------------------------------------

def test_state_row_converters_carry_the_fields():
    rec = {
        "program": "/Mods/PD2-S12/PD2_EXT.dll",
        "program_name": "PD2_EXT.dll",
        "address": "10001000",
        "scope_excluded": True,
        "scope_excluded_at": "2026-08-07T09:30:00",
        "scope_excluded_reasons": ["all 3 referrer(s) are library code"],
    }
    row = fd._state_func_to_row("/Mods/PD2-S12/PD2_EXT.dll::10001000", rec)
    assert row["scope_excluded"] is True
    assert row["scope_excluded_reasons"][0].startswith("all 3 referrer")
    assert hasattr(row["scope_excluded_at"], "isoformat"), \
        "timestamps must cross the boundary as datetimes, not strings"

    back = fd._row_to_state_func(row)
    assert back["scope_excluded"] is True
    assert back["scope_excluded_at"].startswith("2026-08-07T09:30:00")
    assert back["scope_excluded_reasons"][0].startswith("all 3 referrer")


def test_field_is_listed_in_both_gates():
    """Belt and braces on top of the round-trip: name the two lists explicitly so
    a failure says WHICH gate is missing the field, not just 'it vanished'."""
    from storage.repository import _UPDATABLE_WORKFLOW_FIELDS
    assert "scope_excluded" in fd._STATE_DIRECT_FIELDS
    for f in ("scope_excluded", "scope_excluded_at", "scope_excluded_reasons"):
        assert f in _UPDATABLE_WORKFLOW_FIELDS, f


# --------------------------------------------------------------------------
# 3. the selector
# --------------------------------------------------------------------------

def _func(addr="1000", **kw):
    f = {"program": "/Mods/PD2-S12/PD2_EXT.dll", "program_name": "PD2_EXT.dll",
         "address": addr, "name": f"FUNC_{addr}", "score": 40,
         "fixable": True, "classification": "documented"}
    f.update(kw)
    return f


def _keys(picked):
    out = []
    for p in picked or []:
        if isinstance(p, dict):
            out.append(p.get("address") or p.get("key"))
        elif isinstance(p, (tuple, list)) and p:
            out.append(p[0])
        else:
            out.append(p)
    return out


def test_selector_skips_a_scope_excluded_function():
    """A column nothing reads is the same as no column. This is the assertion
    that makes the whole lane real."""
    funcs = {
        "/Mods/PD2-S12/PD2_EXT.dll::1000": _func("1000"),
        "/Mods/PD2-S12/PD2_EXT.dll::2000": _func("2000", scope_excluded=True),
    }
    picked = fd.select_candidates(funcs, queue={"config": {}, "pinned": []})
    keys = " ".join(str(x) for x in _keys(picked))
    assert "1000" in keys
    assert "2000" not in keys, "scope_excluded function was offered to a worker"


def test_pinning_bypasses_the_skip():
    """The escape hatch for the one case the graph provably cannot judge: an
    authored entry point whose only referrer is the CRT's DllMain."""
    key = "/Mods/PD2-S12/PD2_EXT.dll::2000"
    funcs = {key: _func("2000", scope_excluded=True)}
    picked = fd.select_candidates(funcs, queue={"config": {}, "pinned": [key]})
    assert "2000" in " ".join(str(x) for x in _keys(picked)), \
        "a pinned function must stay selectable despite the flag"


def test_library_code_and_scope_excluded_are_separate_skips():
    """Both retire a function; neither implies the other."""
    funcs = {
        "/Mods/PD2-S12/PD2_EXT.dll::1000": _func("1000", library_code=True),
        "/Mods/PD2-S12/PD2_EXT.dll::2000": _func("2000", scope_excluded=True),
        "/Mods/PD2-S12/PD2_EXT.dll::3000": _func("3000"),
    }
    keys = " ".join(str(x) for x in
                    _keys(fd.select_candidates(funcs, queue={"config": {}, "pinned": []})))
    assert "3000" in keys and "1000" not in keys and "2000" not in keys

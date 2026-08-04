"""Regression tests for scripts/backfill_library_code.py.

`library_code` in functions_workflow is a DENORMALIZED CACHE of Ghidra's
durable LIB_* function tags, and the selector's `skip_library_code` reads the
COLUMN, not the tag. `refresh_candidate_scores` re-syncs it, but only for
functions a refresh pass actually visits -- so a binary tagged AFTER its last
scan keeps a stale column indefinitely.

Measured 2026-08-04: Ghidra held 271 LIB_CRT tags on PD2_EXT.dll while all 463
SQL rows said library_code = 0, so ~430 of that binary's 469 functions were
documented as though they were mod code. Corpus-wide the backfill set 2,626.

These tests are offline: the Ghidra tag reader is stubbed, the store is an
in-memory sqlite.
"""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))

_SCRIPT = FUN_DOC_DIR / "scripts" / "backfill_library_code.py"


@pytest.fixture(scope="module")
def backfill():
    spec = importlib.util.spec_from_file_location("backfill_library_code", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.execute("""create table functions_workflow (
                    program_path text, address text, name text, library_code integer,
                    library_code_at text, library_code_reasons text)""")
    return c


def _seed(conn, program, rows):
    conn.executemany(
        "insert into functions_workflow (program_path, address, name, library_code)"
        " values (?,?,?,?)",
        [(program, a, n, f) for a, n, f in rows])
    conn.commit()


def test_tagged_but_unflagged_rows_are_the_work(backfill, conn, monkeypatch):
    import fun_doc as fd
    P = "/Mods/PD2-S12/PD2_EXT.dll"
    _seed(conn, P, [("10001000", "CRT_Init", 0),
                    ("10001050", "PD2EXT_Hook", 0)])
    monkeypatch.setattr(fd, "_lib_tagged_addrs", lambda p: {"0x10001000"})

    plan = backfill.plan_for_program(conn, P)
    assert [a for a, _ in plan["to_set"]] == ["10001000"]
    assert plan["ghidra_tags"] == 1
    assert plan["sql_rows"] == 2


def test_address_normalisation_bridges_the_two_formats(backfill, conn, monkeypatch):
    """SQL stores bare lowercase hex ('10001000'); the tag readers return
    '0x'-prefixed. Getting this wrong makes the whole backfill a silent no-op --
    every row looks untagged and nothing is ever written."""
    import fun_doc as fd
    P = "/p"
    _seed(conn, P, [("6fd51bb0", "_qsort", 0)])
    monkeypatch.setattr(fd, "_lib_tagged_addrs", lambda p: {"0x6fd51bb0"})

    plan = backfill.plan_for_program(conn, P)
    assert [a for a, _ in plan["to_set"]] == ["6fd51bb0"], (
        "0x-prefixed tag failed to match the bare-hex SQL address")


def test_already_correct_rows_are_not_rewritten(backfill, conn, monkeypatch):
    import fun_doc as fd
    P = "/p"
    _seed(conn, P, [("aaa", "CRT_A", 1), ("bbb", "ModCode", 0)])
    monkeypatch.setattr(fd, "_lib_tagged_addrs", lambda p: {"0xaaa"})

    plan = backfill.plan_for_program(conn, P)
    assert plan["to_set"] == []
    assert plan["already_correct"] == 2


def test_flagged_without_a_tag_is_reported_but_never_cleared(backfill, conn, monkeypatch):
    """The safety property. The NAME-based detector also writes this column, so
    clearing a flag this script cannot see evidence for would silently re-open
    functions that were excluded on evidence it does not have."""
    import fun_doc as fd
    P = "/p"
    _seed(conn, P, [("aaa", "DetectedByName", 1)])
    monkeypatch.setattr(fd, "_lib_tagged_addrs", lambda p: set())

    plan = backfill.plan_for_program(conn, P)
    assert [a for a, _ in plan["untagged_but_flagged"]] == ["aaa"]
    assert plan["to_set"] == []
    # and nothing in the plan ever asks for a clear
    assert "to_clear" not in plan


def test_tags_for_unscanned_functions_are_surfaced_not_dropped(backfill, conn, monkeypatch):
    """789 corpus-wide: tagged in Ghidra, absent from SQL because the binary was
    never scanned. Reporting them explains an otherwise confusing tag/row gap."""
    import fun_doc as fd
    P = "/p"
    _seed(conn, P, [("aaa", "CRT_A", 0)])
    monkeypatch.setattr(fd, "_lib_tagged_addrs", lambda p: {"0xaaa", "0xbbb"})

    plan = backfill.plan_for_program(conn, P)
    assert plan["tagged_not_in_sql"] == ["bbb"]
    assert [a for a, _ in plan["to_set"]] == ["aaa"]


def test_plan_is_read_only(backfill, conn, monkeypatch):
    """Dry-run default: planning must not touch the store."""
    import fun_doc as fd
    P = "/p"
    _seed(conn, P, [("aaa", "CRT_A", 0)])
    monkeypatch.setattr(fd, "_lib_tagged_addrs", lambda p: {"0xaaa"})

    backfill.plan_for_program(conn, P)
    assert conn.execute("select library_code from functions_workflow").fetchone()[0] == 0

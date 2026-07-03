"""Tests for the state.json → SQL migration script.

End-to-end round trip: build a synthetic state.json + runs.jsonl + inventory
files, run the migration into a fresh SQLite DB, run the verifier — assert
zero diff. Plus targeted tests for the per-record transformation
(``function_record_to_row``) and the inline-attempts → runs splitter.

The migration is also smoke-tested against the real 27 MB state.json by
hand at PR-prep time; this module covers the synthetic round-trip so the
contract is enforced in CI without depending on a live state file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))


# ---------------------------------------------------------------------------
# Unit tests for function_record_to_row
# ---------------------------------------------------------------------------


def test_function_record_to_row_minimal():
    from scripts.migrate_state_to_sql import function_record_to_row

    rec = {"program": "/Vanilla/1.13d/D2Common.dll", "address": "6fdaef40"}
    row = function_record_to_row(rec)
    assert row["program_path"] == "/Vanilla/1.13d/D2Common.dll"
    assert row["binary_name"] == "D2Common.dll"
    assert row["version"] == "1.13d"
    assert row["address"] == "6fdaef40"
    assert row["queue_status"] == "queued"  # no last_result → default to queued


def test_function_record_to_row_completed():
    from scripts.migrate_state_to_sql import function_record_to_row

    rec = {
        "program": "/Mods/PD2-S12/D2Game.dll",
        "address": "6fc21000",
        "name": "SafeDelete",
        "score": 85,
        "classification": "wrapper",
        "last_result": "completed",
        "deductions": [{"category": "plate", "points": 8.0}],
        "callees": ["6fc2a27a"],
        "is_thunk": False,
        "caller_count": 12,
    }
    row = function_record_to_row(rec)
    assert row["queue_status"] == "done"
    assert row["score"] == 85
    assert row["deductions"] == [{"category": "plate", "points": 8.0}]
    assert row["callees"] == ["6fc2a27a"]
    assert row["caller_count"] == 12


def test_function_record_to_row_inline_attempts_become_count_and_hot_pointers():
    from scripts.migrate_state_to_sql import function_record_to_row

    inline = [
        {"ts": "2026-04-25T14:24:21.633727", "provider": "minimax",
         "model": "minimax-m1", "delta": 40},
        {"ts": "2026-04-25T15:00:00", "provider": "claude",
         "model": "sonnet", "delta": 5},
    ]
    rec = {
        "program": "/x/foo.dll",
        "address": "00400000",
        "attempts": inline,
        "last_result": "completed",
    }
    row = function_record_to_row(rec)
    assert row["attempts"] == 2          # int count, not the list
    assert row["run_count"] == 2
    assert row["last_run_provider"] == "claude"  # from last entry
    assert row["last_run_model"] == "sonnet"
    assert row["last_run_delta"] == 5
    # The list itself does not appear in the row dict — workflow column
    # would reject it.
    assert "attempts" in row and not isinstance(row["attempts"], list)


def test_function_record_to_row_preserves_failed_status():
    from scripts.migrate_state_to_sql import function_record_to_row

    rec = {
        "program": "/x/foo.dll",
        "address": "00400000",
        "last_result": "decompile_timeout",
    }
    row = function_record_to_row(rec)
    assert row["queue_status"] == "decompile_timeout"


# ---------------------------------------------------------------------------
# End-to-end migration + verify round trip
# ---------------------------------------------------------------------------


def _write_state(tmp_path: Path, *, n_functions: int = 5) -> dict:
    """Build a small but realistic state.json + runs.jsonl + inventory."""
    state_path = tmp_path / "state.json"
    runs_path = tmp_path / "logs" / "runs.jsonl"
    inv_path = tmp_path / "inventory.json"
    ginv_path = tmp_path / "global_inventory.json"
    runs_path.parent.mkdir(parents=True, exist_ok=True)

    functions = {}
    for i in range(n_functions):
        addr = f"00400{i:03x}"
        functions[f"/Vanilla/1.13d/D2Common.dll::{addr}"] = {
            "program": "/Vanilla/1.13d/D2Common.dll",
            "program_name": "D2Common.dll",
            "address": addr,
            "name": f"FuncTest{i}",
            "score": 50 + i,
            "classification": "wrapper" if i % 2 == 0 else "leaf",
            "has_custom_name": True,
            "has_plate_comment": i % 2 == 0,
            "is_thunk": False,
            "is_external": False,
            "is_leaf": i % 3 == 0,
            "caller_count": i,
            "deductions": [{"category": "plate", "points": 5.0}] if i > 0 else [],
            "callees": [f"00500{i:03x}"],
            "last_result": "completed" if i % 2 == 0 else "scanned",
            "last_processed": f"2026-04-25T12:0{i}:00",
            "consecutive_fails": 0,
            # Inline attempt — exercises the runs-table side migration.
            "attempts": [
                {
                    "ts": f"2026-04-25T12:0{i}:30",
                    "provider": "minimax",
                    "model": "minimax-m1",
                    "mode": "FULL:comments",
                    "result": "completed" if i % 2 == 0 else "needs_redo",
                    "score_before": 30 + i,
                    "score_after": 50 + i,
                    "delta": 20,
                    "tool_calls": 12,
                }
            ] if i > 0 else [],
        }

    state = {
        "project_folder": "F:/GhidraProjects/diablo2",
        "last_scan": "2026-04-25T16:00:00",
        "active_binary": "D2Common.dll",
        "current_session": None,
        "functions": functions,
        "sessions": [
            {
                "started": "2026-04-25T10:00:00",
                "ended": "2026-04-25T11:30:00",
                "completed": 3,
                "skipped": 0,
                "failed": 1,
                "partial": 1,
                "functions": ["a", "b", "c"],
                "date": "2026-04-25",
            }
        ],
    }
    state_path.write_text(json.dumps(state), encoding="utf-8")

    # runs.jsonl: one entry per function — half match, half are orphans
    # (so we exercise the skipped-count path).
    with runs_path.open("w", encoding="utf-8") as f:
        for i in range(n_functions):
            addr = f"00400{i:03x}"
            f.write(json.dumps({
                "timestamp": f"2026-04-25T13:0{i}:00",
                "program": "/Vanilla/1.13d/D2Common.dll",
                "address": addr,
                "function": f"FuncTest{i}",
                "mode": "FIX",
                "model": "sonnet",
                "provider": "claude",
                "score_before": 40 + i,
                "score_after": 50 + i,
                "tool_calls": 5,
                "result": "completed",
                "output": f"Did the thing #{i}",
            }) + "\n")
        # one orphan
        f.write(json.dumps({
            "timestamp": "2026-04-25T14:00:00",
            "program": "/Vanilla/1.13d/D2Common.dll",
            "address": "deadbeef",
            "function": "Orphan",
            "mode": "FULL",
            "model": "opus",
            "provider": "claude",
            "score_before": 0,
            "score_after": 0,
            "result": "completed",
            "output": "",
        }) + "\n")

    inv_path.write_text(json.dumps({
        "version": 1,
        "binaries": {
            "/Vanilla/1.13d/D2Common.dll": {
                "name": "D2Common.dll",
                "total_documentable": 100,
                "scored": n_functions,
                "last_scan": "2026-04-25T16:00:00",
            }
        }
    }), encoding="utf-8")
    ginv_path.write_text(json.dumps({
        "version": 1,
        "binaries": {
            "/Vanilla/1.13d/D2Common.dll": {
                "name": "D2Common.dll",
                "total_documentable": 30,
                "fully_documented": 5,
                "last_scan": "2026-04-25T16:00:00",
            }
        }
    }), encoding="utf-8")

    return {
        "state": state_path,
        "runs": runs_path,
        "inventory": inv_path,
        "global_inventory": ginv_path,
    }


def test_round_trip_synthetic(tmp_path):
    paths = _write_state(tmp_path, n_functions=5)
    db_url = f"sqlite:///{tmp_path / 'out.db'}"

    from scripts.migrate_state_to_sql import migrate
    from scripts.verify_migration import verify

    summary = migrate(
        state_path=paths["state"],
        runs_path=paths["runs"],
        inventory_path=paths["inventory"],
        global_inventory_path=paths["global_inventory"],
        backend="sqlite",
        url=db_url,
    )
    assert summary["functions"] == 5
    # 5 jsonl entries (one matches every function) + 4 inline attempts
    # (function 0 has no inline) = 9 total, minus the orphan jsonl entry = 9.
    # Actually 5 jsonl matched + 4 inline = 9 written, 1 jsonl orphan skipped.
    assert summary["runs"] == 9
    assert summary["runs_skipped"] == 1
    assert summary["inventory"] == 1
    assert summary["global_inventory"] == 1
    assert summary["sessions"] == 1

    ok, mismatches = verify(
        state_path=paths["state"],
        runs_path=paths["runs"],
        inventory_path=paths["inventory"],
        global_inventory_path=paths["global_inventory"],
        backend="sqlite",
        url=db_url,
        sample_size=5,
    )
    assert ok, f"verifier failed: {mismatches}"


def test_round_trip_idempotent(tmp_path):
    """Re-running the migration against a populated DB requires --truncate-runs (H26)."""
    paths = _write_state(tmp_path, n_functions=3)
    db_url = f"sqlite:///{tmp_path / 'out.db'}"

    from scripts.migrate_state_to_sql import migrate

    s1 = migrate(
        state_path=paths["state"], runs_path=paths["runs"],
        inventory_path=paths["inventory"],
        global_inventory_path=paths["global_inventory"],
        backend="sqlite", url=db_url,
    )
    # The runs table has only an autoincrement PK and no natural unique key,
    # so a bare re-run would duplicate every row (H26). migrate() refuses
    # unless truncate_runs=True; without it this second call raises SystemExit.
    with pytest.raises(SystemExit):
        migrate(
            state_path=paths["state"], runs_path=paths["runs"],
            inventory_path=paths["inventory"],
            global_inventory_path=paths["global_inventory"],
            backend="sqlite", url=db_url,
        )
    # With truncate_runs=True the runs table is wiped and reloaded from the
    # same source files, so the reload is idempotent in row count.
    s2 = migrate(
        state_path=paths["state"], runs_path=paths["runs"],
        inventory_path=paths["inventory"],
        global_inventory_path=paths["global_inventory"],
        backend="sqlite", url=db_url,
        truncate_runs=True,
    )
    assert s1["functions"] == s2["functions"]
    assert s1["inventory"] == s2["inventory"]
    assert s2["runs"] == s1["runs"]  # Same source files → same count per pass


def test_dry_run_writes_nothing(tmp_path):
    paths = _write_state(tmp_path, n_functions=2)
    db_url = f"sqlite:///{tmp_path / 'out.db'}"

    from scripts.migrate_state_to_sql import migrate

    summary = migrate(
        state_path=paths["state"], runs_path=paths["runs"],
        inventory_path=paths["inventory"],
        global_inventory_path=paths["global_inventory"],
        backend="sqlite", url=db_url, dry_run=True,
    )
    assert summary["functions"] == 2
    # The DB file should not exist — dry-run never opened a connection.
    assert not (tmp_path / "out.db").exists()

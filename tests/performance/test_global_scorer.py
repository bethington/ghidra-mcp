"""Offline regression tests for the bulk global-variable scorer.

`global_scorer.py` mirrors `inventory_scorer.py`'s shape: pure helpers
(`status_for`, `pick_next_binary`, `load_inventory`, `save_inventory`)
are testable without threads, and the `GlobalScorer` class takes
injected callables so the threaded execution can be exercised with
mocked I/O.

Locked design (Q1-Q8 conversation 2026-04-25 — same shape as the
function inventory scorer, separate module per Q8):

  Q1  four-axis "documented global" bar
  Q2  binary-wide bulk scope (this module)
  Q4  naming + reject auto-gen patterns
  Q5  bytes formatting rules
  Q6  ≥4-word plate-comment rule
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest


FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import global_scorer as gs  # noqa: E402


# ---------- pick_next_binary ----------


def test_pick_next_binary_picks_most_with_issues_first():
    inv = {
        "/AA": {"name": "AA", "total_documentable": 100, "fully_documented": 99, "last_scan": "x"},
        "/BB": {"name": "BB", "total_documentable": 100, "fully_documented": 50, "last_scan": "x"},
        "/CC": {"name": "CC", "total_documentable": 100, "fully_documented": 80, "last_scan": "x"},
    }
    picked = gs.pick_next_binary(inv, ["/AA", "/BB", "/CC"], blacklist=set())
    assert picked == "/BB"  # 50 with-issues — most


def test_pick_next_binary_reverse_alpha_tiebreak():
    inv = {
        "/AA": {"name": "AA", "total_documentable": 100, "fully_documented": 50, "last_scan": "x"},
        "/BB": {"name": "BB", "total_documentable": 100, "fully_documented": 50, "last_scan": "x"},
        "/CC": {"name": "CC", "total_documentable": 100, "fully_documented": 50, "last_scan": "x"},
    }
    picked = gs.pick_next_binary(inv, ["/AA", "/BB", "/CC"], blacklist=set())
    assert picked == "/CC"


def test_pick_next_binary_skips_complete():
    inv = {
        "/done": {"name": "done", "total_documentable": 100, "fully_documented": 100, "last_scan": "x"},
        "/wip": {"name": "wip", "total_documentable": 100, "fully_documented": 5, "last_scan": "x"},
    }
    assert gs.pick_next_binary(inv, ["/done", "/wip"], blacklist=set()) == "/wip"


def test_pick_next_binary_respects_blacklist():
    inv = {
        "/big": {"name": "big", "total_documentable": 100, "fully_documented": 0, "last_scan": "x"},
        "/small": {"name": "small", "total_documentable": 100, "fully_documented": 80, "last_scan": "x"},
    }
    assert gs.pick_next_binary(inv, ["/big", "/small"], blacklist={"/big"}) == "/small"


def test_pick_next_binary_returns_none_when_all_complete_or_blacklisted():
    inv = {
        "/done": {"name": "done", "total_documentable": 5, "fully_documented": 5, "last_scan": "x"},
    }
    assert gs.pick_next_binary(inv, ["/done"], blacklist=set()) is None
    assert gs.pick_next_binary({}, [], blacklist=set()) is None


def test_pick_next_binary_unfetched_sentinel():
    """A binary the scorer has never walked (total=0, last_scan=None)
    should still be picked over fully-complete binaries via the unfetched
    sentinel — same pattern as inventory_scorer."""
    inv = {
        "/done": {"name": "done", "total_documentable": 100, "fully_documented": 100, "last_scan": "x"},
        "/new": {"name": "new", "total_documentable": 0, "fully_documented": 0, "last_scan": None},
    }
    assert gs.pick_next_binary(inv, ["/done", "/new"], blacklist=set()) == "/new"


# ---------- status_for ----------


def test_status_for_complete_when_all_fully_documented():
    assert gs.status_for({"total_documentable": 10, "fully_documented": 10, "last_scan": "x"}) == "complete"
    assert gs.status_for({"total_documentable": 10, "fully_documented": 12, "last_scan": "x"}) == "complete"


def test_status_for_in_progress_partial():
    assert gs.status_for({"total_documentable": 10, "fully_documented": 4, "last_scan": "x"}) == "in_progress"


def test_status_for_untouched_when_never_scanned():
    assert gs.status_for({"total_documentable": 0, "fully_documented": 0, "last_scan": None}) == "untouched"
    assert gs.status_for({"total_documentable": 10, "fully_documented": 0, "last_scan": None}) == "untouched"


# ---------- inventory.json round-trip ----------


def test_save_load_inventory_round_trip(tmp_path):
    payload = {
        "binaries": {
            "/Vanilla/1.13d/D2Common.dll": {
                "name": "D2Common.dll",
                "total_documentable": 84,
                "fully_documented": 84,
                "last_scan": "2026-04-25T12:00:00",
            },
        }
    }
    gs.save_inventory(tmp_path, payload)
    loaded = gs.load_inventory(tmp_path)
    assert loaded["version"] == gs.GLOBAL_INVENTORY_FILE_VERSION
    assert loaded["binaries"] == payload["binaries"]


def test_load_inventory_missing_file_returns_skeleton(tmp_path):
    loaded = gs.load_inventory(tmp_path)
    assert loaded == {"version": gs.GLOBAL_INVENTORY_FILE_VERSION, "binaries": {}}


def test_load_inventory_corrupt_returns_skeleton(tmp_path):
    (tmp_path / "global_inventory.json").write_text("{not valid json")
    loaded = gs.load_inventory(tmp_path)
    assert loaded == {"version": gs.GLOBAL_INVENTORY_FILE_VERSION, "binaries": {}}


def test_save_atomic_no_tmp_left(tmp_path):
    gs.save_inventory(tmp_path, {"binaries": {"/a": {"name": "a"}}})
    assert (tmp_path / "global_inventory.json").exists()
    assert not (tmp_path / "global_inventory.json.tmp").exists()


# ---------- threaded scorer (mocked I/O) ----------


class _FakeWM:
    def __init__(self, active=False):
        self.active = active

    def has_active_workers(self):
        return self.active


def _make_scorer(
    *,
    wm=None,
    programs=None,
    list_globals_returns=None,
    audit_returns=None,
    state_dir=None,
    fail_strikes=3,
):
    scorer = gs.GlobalScorer(
        worker_manager=wm or _FakeWM(),
        project_folder_getter=lambda: "/proj",
        state_dir=state_dir or Path("."),
        fetch_programs=lambda folder: programs or [],
        list_globals_for_program=lambda path: (list_globals_returns or {}).get(path, []),
        audit_global=lambda path, addr: (audit_returns or {}).get((path, addr)),
        on_status_change=None,
        fail_strikes=fail_strikes,
    )
    return scorer


def test_audit_one_binary_writes_inventory(tmp_path):
    """Happy path: scorer audits each global, tallies fully_documented vs
    total_documentable, persists to global_inventory.json."""
    list_globals_returns = {
        "/a": [
            {"address": "0x1000"},
            {"address": "0x2000"},
            {"address": "0x3000"},
        ]
    }
    audit_returns = {
        ("/a", "0x1000"): {"issues": []},  # fully documented
        ("/a", "0x2000"): {"issues": ["untyped", "missing_plate_comment"]},
        ("/a", "0x3000"): {"issues": []},  # fully documented
    }
    scorer = _make_scorer(
        programs=[{"path": "/a", "name": "a.dll"}],
        list_globals_returns=list_globals_returns,
        audit_returns=audit_returns,
        state_dir=tmp_path,
    )
    scorer._audit_one_binary("/a")

    persisted = gs.load_inventory(tmp_path)
    assert persisted["binaries"]["/a"]["total_documentable"] == 3
    assert persisted["binaries"]["/a"]["fully_documented"] == 2
    assert persisted["binaries"]["/a"]["last_scan"] is not None


def test_audit_one_binary_pauses_when_workers_active(tmp_path):
    """Q7-style cooperative pause: at the start of a chunk (here, each
    global), if workers are active, scorer yields without writing
    inventory."""
    list_globals_returns = {
        "/a": [{"address": f"0x{i:04x}"} for i in range(10)]
    }
    wm = _FakeWM(active=False)

    audit_calls = {"count": 0}

    def _audit(path, addr):
        audit_calls["count"] += 1
        if audit_calls["count"] >= 2:
            wm.active = True
        return {"issues": []}

    scorer = gs.GlobalScorer(
        worker_manager=wm,
        project_folder_getter=lambda: "/proj",
        state_dir=tmp_path,
        fetch_programs=lambda folder: [{"path": "/a", "name": "a.dll"}],
        list_globals_for_program=lambda p: list_globals_returns[p],
        audit_global=_audit,
        on_status_change=None,
    )
    scorer._audit_one_binary("/a")
    # First two calls happened, then yielded without persisting.
    assert audit_calls["count"] == 2
    persisted = gs.load_inventory(tmp_path)
    assert "/a" not in persisted.get("binaries", {})


def test_record_failure_blacklists_after_three_strikes(tmp_path):
    scorer = _make_scorer(state_dir=tmp_path, fail_strikes=3)
    scorer._record_failure("/bad", "test1")
    assert "/bad" not in scorer.get_status()["blacklisted"]
    scorer._record_failure("/bad", "test2")
    assert "/bad" not in scorer.get_status()["blacklisted"]
    scorer._record_failure("/bad", "test3")
    assert "/bad" in scorer.get_status()["blacklisted"]


def test_clear_blacklist_unblocks(tmp_path):
    scorer = _make_scorer(state_dir=tmp_path, fail_strikes=2)
    scorer._record_failure("/bad", "x")
    scorer._record_failure("/bad", "y")
    assert "/bad" in scorer.get_status()["blacklisted"]
    scorer.clear_blacklist("/bad")
    assert scorer.get_status()["blacklisted"] == []


def test_audit_one_binary_handles_list_globals_failure(tmp_path):
    """list_globals returning None counts as a failure strike."""
    scorer = _make_scorer(
        list_globals_returns={"/a": None},
        state_dir=tmp_path,
        fail_strikes=3,
    )
    scorer._audit_one_binary("/a")
    assert scorer._fail_streak["/a"] == 1


def test_set_enabled_idempotent(tmp_path):
    scorer = _make_scorer(state_dir=tmp_path)
    scorer.set_enabled(True)
    t1 = scorer._thread
    scorer.set_enabled(True)  # no-op
    assert scorer._thread is t1
    scorer.set_enabled(False)
    for _ in range(50):
        if not (scorer._thread and scorer._thread.is_alive()):
            break
        time.sleep(0.05)
    scorer.set_enabled(True)
    assert scorer._thread is not None
    scorer.set_enabled(False)

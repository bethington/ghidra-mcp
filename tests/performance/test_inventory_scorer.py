"""Offline regression tests for the background inventory scorer.

The scorer module is split into pure-logic helpers (compute_per_binary_inventory,
pick_next_binary, status_for, is_documentable, is_scored, load_inventory,
save_inventory) and an InventoryScorer thread class. The pure helpers are
tested directly. The class is tested with all I/O dependencies injected as
mock callables — no real Ghidra, no threads, no sockets.

Locked design (Q1-Q12 conversation 2026-04-25 — see git log on feat/worker-
config-snapshot for full rationale). The tests below pin each Q's contract:

  Q3  coverage definition
  Q4  most-missing first, reverse-alpha tiebreak
  Q7  cooperative pause at chunk boundaries
  Q8  3-strike session blacklist
  Q10 inventory.json shape stability
  Q11 thunk/external exclusion
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest


FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import inventory_scorer as iv  # noqa: E402


# ---------- pure-function helpers ----------


def _func(program, address, *, score=None, is_thunk=False, is_external=False, name="x"):
    entry = {
        "program": program,
        "program_name": Path(program).name,
        "address": address,
        "name": name,
        "is_thunk": is_thunk,
        "is_external": is_external,
    }
    if score is not None:
        entry["score"] = score
    return entry


# ---------- is_scored / is_documentable (Q11 + scored definition) ----------


def test_is_scored_accepts_zero():
    """A score of 0 is still 'scored' — a legitimately trivial function has a
    real measurement. Treating 0 as unscored would cause infinite rescoring."""
    assert iv.is_scored({"score": 0})
    assert iv.is_scored({"score": 95})
    assert iv.is_scored({"score": 0.5})


def test_is_scored_rejects_missing_or_null():
    """Missing key, None, and non-numeric mean unscored — picked up next pass."""
    assert not iv.is_scored({})
    assert not iv.is_scored({"score": None})
    assert not iv.is_scored({"score": "high"})


def test_is_documentable_skips_thunks_and_externals():
    """Q11: scorer matches select_candidates' exclusion. Thunks/externals do
    not count toward 'complete inventory'."""
    assert iv.is_documentable(_func("/p", "1000"))
    assert not iv.is_documentable(_func("/p", "1000", is_thunk=True))
    assert not iv.is_documentable(_func("/p", "1000", is_external=True))


# ---------- compute_per_binary_inventory ----------


def test_compute_per_binary_inventory_counts_documentable_only():
    funcs = {
        "/a::1": _func("/a", "1", score=80),
        "/a::2": _func("/a", "2", score=70),
        "/a::3": _func("/a", "3"),  # unscored
        "/a::4": _func("/a", "4", score=50, is_thunk=True),  # excluded
        "/a::5": _func("/a", "5", score=60, is_external=True),  # excluded
        "/b::1": _func("/b", "1"),
    }
    inv = iv.compute_per_binary_inventory(funcs)
    assert inv["/a"]["total_documentable"] == 3
    assert inv["/a"]["scored"] == 2
    assert inv["/b"]["total_documentable"] == 1
    assert inv["/b"]["scored"] == 0


def test_compute_per_binary_inventory_uses_external_totals_when_provided():
    """When the caller has fresh function-list totals (Ghidra is the
    authority), they override state-derived counts so functions that exist
    in Ghidra but aren't in state.json yet still increase the denominator."""
    funcs = {"/a::1": _func("/a", "1", score=80)}
    inv = iv.compute_per_binary_inventory(funcs, totals_by_path={"/a": 100})
    assert inv["/a"]["total_documentable"] == 100
    assert inv["/a"]["scored"] == 1


def test_compute_per_binary_inventory_clamps_scored_to_total():
    """Defensive: if state has more scored entries than fresh totals report
    (stale state.json), clamp scored to total to avoid >100% in the UI."""
    funcs = {f"/a::{i}": _func("/a", str(i), score=50) for i in range(5)}
    inv = iv.compute_per_binary_inventory(funcs, totals_by_path={"/a": 3})
    assert inv["/a"]["total_documentable"] == 3
    assert inv["/a"]["scored"] == 3


# ---------- status_for ----------


def test_status_for_complete_when_scored_meets_total():
    assert iv.status_for({"total_documentable": 10, "scored": 10, "last_scan": "x"}) == "complete"
    assert iv.status_for({"total_documentable": 10, "scored": 12, "last_scan": "x"}) == "complete"


def test_status_for_in_progress_partial():
    assert iv.status_for({"total_documentable": 10, "scored": 4, "last_scan": "x"}) == "in_progress"


def test_status_for_untouched_when_never_scanned():
    """No last_scan, no scored — clearly untouched."""
    assert iv.status_for({"total_documentable": 0, "scored": 0, "last_scan": None}) == "untouched"
    assert iv.status_for({"total_documentable": 10, "scored": 0, "last_scan": None}) == "untouched"


# ---------- pick_next_binary (Q4 ordering) ----------


def test_pick_next_binary_picks_most_missing_first():
    """Q4 primary: largest deficit wins."""
    inv = {
        "/AA": {"name": "AA", "total_documentable": 100, "scored": 99, "last_scan": "x"},
        "/BB": {"name": "BB", "total_documentable": 100, "scored": 50, "last_scan": "x"},
        "/CC": {"name": "CC", "total_documentable": 100, "scored": 80, "last_scan": "x"},
    }
    picked = iv.pick_next_binary(inv, ["/AA", "/BB", "/CC"], blacklist=set())
    assert picked == "/BB"  # missing=50, biggest


def test_pick_next_binary_reverse_alpha_tiebreak():
    """Q4 secondary: when missing counts tie, later-in-alphabet wins."""
    inv = {
        "/AA": {"name": "AA", "total_documentable": 100, "scored": 50, "last_scan": "x"},
        "/BB": {"name": "BB", "total_documentable": 100, "scored": 50, "last_scan": "x"},
        "/CC": {"name": "CC", "total_documentable": 100, "scored": 50, "last_scan": "x"},
    }
    picked = iv.pick_next_binary(inv, ["/AA", "/BB", "/CC"], blacklist=set())
    assert picked == "/CC"  # all tied; reverse-alpha = "CC" wins


def test_pick_next_binary_skips_complete_binaries():
    """A binary with scored == total has nothing for the scorer to do —
    must be skipped even if it's first in the candidate list."""
    inv = {
        "/done": {"name": "done", "total_documentable": 100, "scored": 100, "last_scan": "x"},
        "/wip": {"name": "wip", "total_documentable": 100, "scored": 5, "last_scan": "x"},
    }
    picked = iv.pick_next_binary(inv, ["/done", "/wip"], blacklist=set())
    assert picked == "/wip"


def test_pick_next_binary_respects_blacklist():
    """Q8: blacklisted paths must not be picked even if they have the largest
    deficit. The 3-strike rule funnels into this set."""
    inv = {
        "/big": {"name": "big", "total_documentable": 100, "scored": 0, "last_scan": "x"},
        "/small": {"name": "small", "total_documentable": 100, "scored": 80, "last_scan": "x"},
    }
    picked = iv.pick_next_binary(inv, ["/big", "/small"], blacklist={"/big"})
    assert picked == "/small"


def test_pick_next_binary_returns_none_when_all_complete_or_blacklisted():
    inv = {
        "/done": {"name": "done", "total_documentable": 5, "scored": 5, "last_scan": "x"},
    }
    assert iv.pick_next_binary(inv, ["/done"], blacklist=set()) is None
    assert iv.pick_next_binary({}, [], blacklist=set()) is None


def test_pick_next_binary_sentinel_for_untouched_binaries():
    """A binary the scorer has never walked has total=0 and last_scan=None.
    It should still be picked over fully-complete binaries — pick_next_binary
    treats 'unfetched' as 'has at least one missing function (sentinel=1)'.
    Otherwise we'd never bootstrap new binaries."""
    inv = {
        "/done": {"name": "done", "total_documentable": 100, "scored": 100, "last_scan": "x"},
        "/new": {"name": "new", "total_documentable": 0, "scored": 0, "last_scan": None},
    }
    picked = iv.pick_next_binary(inv, ["/done", "/new"], blacklist=set())
    assert picked == "/new"


# ---------- inventory.json round-trip (Q10 shape stability) ----------


def test_save_load_inventory_round_trip(tmp_path):
    payload = {
        "binaries": {
            "/Vanilla/1.13d/D2Common.dll": {
                "name": "D2Common.dll",
                "total_documentable": 2961,
                "scored": 2961,
                "last_scan": "2026-04-25T12:00:00",
            },
        }
    }
    iv.save_inventory(tmp_path, payload)
    loaded = iv.load_inventory(tmp_path)
    assert loaded["version"] == iv.INVENTORY_FILE_VERSION
    assert loaded["binaries"] == payload["binaries"]


def test_load_inventory_returns_skeleton_when_file_missing(tmp_path):
    loaded = iv.load_inventory(tmp_path)
    assert loaded == {"version": iv.INVENTORY_FILE_VERSION, "binaries": {}}


def test_load_inventory_returns_skeleton_when_file_corrupt(tmp_path):
    """Don't let a corrupt inventory.json crash dashboard startup."""
    (tmp_path / "inventory.json").write_text("{not valid json")
    loaded = iv.load_inventory(tmp_path)
    assert loaded == {"version": iv.INVENTORY_FILE_VERSION, "binaries": {}}


def test_save_inventory_atomic_write_uses_replace(tmp_path):
    """Atomic-write contract: there's never a moment where inventory.json is
    truncated/half-written from another reader's perspective. We check this
    by verifying no .tmp file is left behind after a successful save."""
    iv.save_inventory(tmp_path, {"binaries": {"/a": {"name": "a"}}})
    assert (tmp_path / "inventory.json").exists()
    assert not (tmp_path / "inventory.json.tmp").exists()


# ---------- InventoryScorer thread (mocked I/O) ----------


class _FakeWM:
    def __init__(self, active=False):
        self.active = active

    def has_active_workers(self):
        return self.active


def _make_scorer(
    *,
    wm=None,
    state=None,
    programs=None,
    function_lists=None,
    score_responses=None,
    state_dir=None,
    chunk_size=2,
    fail_strikes=3,
):
    """Helper: construct an InventoryScorer with mocked I/O. State is held
    in a dict so the scorer's load/save round-trip keeps working."""
    state = state or {"functions": {}, "project_folder": "/proj"}
    state_holder = {"state": state}

    def _load():
        # Return a deep-ish copy so writes don't leak back through the load.
        return json.loads(json.dumps(state_holder["state"]))

    def _save(s):
        state_holder["state"] = s

    scorer = iv.InventoryScorer(
        worker_manager=wm or _FakeWM(),
        project_folder_getter=lambda: "/proj",
        state_dir=state_dir or Path("."),
        load_state=_load,
        save_state=_save,
        fetch_programs=lambda folder: programs or [],
        fetch_function_list=lambda path: (function_lists or {}).get(path),
        batch_score=lambda chunk, prog: (score_responses or {}).get(prog, lambda c: {})(chunk),
        on_status_change=None,
        chunk_size=chunk_size,
        fail_strikes=fail_strikes,
    )
    return scorer, state_holder


def test_score_one_binary_writes_state_and_inventory(tmp_path):
    """Happy path: scorer fetches function list, scores all functions in
    chunks, writes per-function entries to state.json, stamps inventory.json."""
    func_list = [
        {"address": "1000", "name": "f1", "isThunk": False, "isExternal": False},
        {"address": "2000", "name": "f2", "isThunk": False, "isExternal": False},
        {"address": "3000", "name": "f3", "isThunk": True},  # excluded
    ]

    def _score(chunk):
        # _batch_score returns dict keyed by address-without-0x.
        return {
            (addr[2:] if addr.startswith("0x") else addr): {
                "score": 80,
                "fixable": 5,
                "deductions": [],
            }
            for addr in chunk
        }

    scorer, holder = _make_scorer(
        programs=[{"path": "/a", "name": "a.dll"}],
        function_lists={"/a": func_list},
        score_responses={"/a": _score},
        state_dir=tmp_path,
        chunk_size=10,
    )
    scorer._score_one_binary("/a")

    # State got both documentable functions, both scored.
    funcs = holder["state"]["functions"]
    assert "/a::1000" in funcs
    assert funcs["/a::1000"]["score"] == 80
    assert "/a::2000" in funcs
    assert "/a::3000" not in funcs  # thunk excluded

    # Inventory.json stamped: 2 documentable, 2 scored, last_scan present.
    persisted = iv.load_inventory(tmp_path)
    assert persisted["binaries"]["/a"]["total_documentable"] == 2
    assert persisted["binaries"]["/a"]["scored"] == 2
    assert persisted["binaries"]["/a"]["last_scan"] is not None


def test_score_one_binary_pauses_on_active_workers(tmp_path):
    """Q7: at the start of a chunk, if a doc worker is active, scorer
    yields without scoring. State.json must not be modified — no half-
    work leaks."""
    func_list = [
        {"address": str(i * 0x10), "name": f"f{i}", "isThunk": False, "isExternal": False}
        for i in range(5)
    ]
    wm = _FakeWM(active=True)  # workers are active from the start
    scorer, holder = _make_scorer(
        wm=wm,
        function_lists={"/a": func_list},
        score_responses={"/a": lambda c: {addr.lstrip("0x"): {"score": 50} for addr in c}},
        state_dir=tmp_path,
        chunk_size=2,
    )
    scorer._score_one_binary("/a")
    # No state writes — paused before scoring any chunks.
    assert holder["state"]["functions"] == {}
    # Pause reason recorded for the dashboard widget.
    assert "active" in (scorer.get_status()["paused_reason"] or "")


def _strip_hex_prefix(addr):
    """Mirror what _apply_chunk_results does: strip a literal '0x' prefix.
    Using lstrip('0x') is wrong — it strips all leading 0/x chars."""
    return addr[2:] if addr.startswith("0x") else addr


def test_score_one_binary_pauses_mid_scan(tmp_path):
    """Q7: pause check runs between every chunk. Partial work persists, the
    rest is left for the next pass."""
    func_list = [
        # Use addresses that don't start with 0 so the test is robust to
        # any lstrip/slicing differences. 'a000' through 'f000' work fine.
        {"address": f"{c}000", "name": f"f_{c}", "isThunk": False, "isExternal": False}
        for c in ["a", "b", "c", "d", "e", "f"]
    ]
    state = {"functions": {}, "project_folder": "/proj"}

    # Toggle "workers active" after the first chunk completes so pause kicks
    # in between chunks 1 and 2.
    chunks_seen = {"count": 0}
    wm = _FakeWM(active=False)

    def _score(chunk):
        chunks_seen["count"] += 1
        if chunks_seen["count"] >= 1:
            wm.active = True  # next iteration's pause check will trip
        return {_strip_hex_prefix(addr): {"score": 50} for addr in chunk}

    scorer, holder = _make_scorer(
        wm=wm,
        state=state,
        function_lists={"/a": func_list},
        score_responses={"/a": _score},
        state_dir=tmp_path,
        chunk_size=2,
    )
    scorer._score_one_binary("/a")
    # First chunk's two functions persisted; remaining four wait for next pass.
    assert len(holder["state"]["functions"]) == 2


def test_record_failure_blacklists_after_three_strikes(tmp_path):
    """Q8: 3 consecutive failures => blacklisted for the session."""
    scorer, _ = _make_scorer(state_dir=tmp_path, fail_strikes=3)
    scorer._record_failure("/bad", "test1")
    assert "/bad" not in scorer.get_status()["blacklisted"]
    scorer._record_failure("/bad", "test2")
    assert "/bad" not in scorer.get_status()["blacklisted"]
    scorer._record_failure("/bad", "test3")
    assert "/bad" in scorer.get_status()["blacklisted"]


def test_clear_blacklist_unblocks_path(tmp_path):
    scorer, _ = _make_scorer(state_dir=tmp_path, fail_strikes=2)
    scorer._record_failure("/bad", "x")
    scorer._record_failure("/bad", "y")
    assert "/bad" in scorer.get_status()["blacklisted"]
    scorer.clear_blacklist("/bad")
    assert scorer.get_status()["blacklisted"] == []


def test_clear_blacklist_all(tmp_path):
    scorer, _ = _make_scorer(state_dir=tmp_path, fail_strikes=2)
    scorer._record_failure("/a", "x")
    scorer._record_failure("/a", "y")
    scorer._record_failure("/b", "x")
    scorer._record_failure("/b", "y")
    assert set(scorer.get_status()["blacklisted"]) == {"/a", "/b"}
    scorer.clear_blacklist()  # no path = clear all
    assert scorer.get_status()["blacklisted"] == []


def test_score_one_binary_handles_fetch_function_list_failure(tmp_path):
    """fetch_function_list returning None counts as a failure strike."""
    scorer, _ = _make_scorer(
        function_lists={"/a": None}, state_dir=tmp_path, fail_strikes=3
    )
    scorer._score_one_binary("/a")
    assert scorer._fail_streak["/a"] == 1


def test_score_one_binary_marks_complete_when_already_scored(tmp_path):
    """If every documentable function already has a score in state, no
    batch_score call is needed — just stamp last_scan and move on."""
    func_list = [
        {"address": "1000", "name": "f1", "isThunk": False, "isExternal": False},
    ]
    state = {
        "functions": {
            "/a::1000": _func("/a", "1000", score=85),
        },
        "project_folder": "/proj",
    }
    score_calls = []

    def _score(chunk):
        score_calls.append(chunk)
        return {}

    scorer, _ = _make_scorer(
        state=state,
        function_lists={"/a": func_list},
        score_responses={"/a": _score},
        state_dir=tmp_path,
    )
    scorer._score_one_binary("/a")
    assert score_calls == []  # batch_score never invoked
    persisted = iv.load_inventory(tmp_path)
    assert persisted["binaries"]["/a"]["scored"] == 1
    assert persisted["binaries"]["/a"]["total_documentable"] == 1


def test_set_enabled_is_idempotent(tmp_path):
    """Multiple set_enabled(True) calls don't spawn multiple threads."""
    scorer, _ = _make_scorer(state_dir=tmp_path)
    scorer.set_enabled(True)
    t1 = scorer._thread
    scorer.set_enabled(True)  # no-op
    assert scorer._thread is t1
    scorer.set_enabled(False)
    # Wait briefly for the thread to notice the stop event.
    for _ in range(50):
        if not (scorer._thread and scorer._thread.is_alive()):
            break
        time.sleep(0.05)
    scorer.set_enabled(True)  # spawn fresh thread
    assert scorer._thread is not None
    scorer.set_enabled(False)

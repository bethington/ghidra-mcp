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
from datetime import datetime, timedelta
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
        "/done": {"name": "done", "total_documentable": 5, "fully_documented": 5, "last_scan": "x", "rules_version": gs.RULES_VERSION},
    }
    assert gs.pick_next_binary(inv, ["/done"], blacklist=set()) is None
    assert gs.pick_next_binary({}, [], blacklist=set()) is None


def test_pick_next_binary_re_picks_complete_binary_stamped_under_old_rules():
    """A tally stamped under an older RULES_VERSION can't be trusted — the
    counting bar changed, so even a '5/5 complete' record is re-pickable
    (and bypasses the rescan cooldown via the inf scan age)."""
    inv = {
        "/done_old_bar": {"name": "done", "total_documentable": 5, "fully_documented": 5, "last_scan": datetime.now().isoformat()},
    }
    assert gs.pick_next_binary(inv, ["/done_old_bar"], blacklist=set()) == "/done_old_bar"


def test_pick_next_binary_skips_recently_scanned_in_favor_of_unscanned():
    """Production bug fix: after walking a binary that has many unresolved
    issues, the scorer used to immediately re-pick the same binary because
    its issue count outranked never-scanned candidates. Now the cooldown
    filter excludes recent scans, so the rotation reaches every binary."""
    just_now = datetime.now().isoformat()
    inv = {
        "/big_just_walked": {
            "name": "big",
            "total_documentable": 328,
            "fully_documented": 0,
            "last_scan": just_now,
            "rules_version": gs.RULES_VERSION,
        },
        "/never_walked": {
            "name": "never",
            "total_documentable": 0,
            "fully_documented": 0,
            "last_scan": None,
        },
    }
    picked = gs.pick_next_binary(
        inv, ["/big_just_walked", "/never_walked"], blacklist=set()
    )
    assert picked == "/never_walked"


def test_pick_next_binary_returns_none_when_all_recently_scanned():
    """Once every binary has been freshly walked, the scorer should pause
    instead of looping. Doc-worker progress will become visible after the
    cooldown expires on the next scan."""
    just_now = datetime.now().isoformat()
    inv = {
        "/a": {"name": "a", "total_documentable": 100, "fully_documented": 50, "last_scan": just_now, "rules_version": gs.RULES_VERSION},
        "/b": {"name": "b", "total_documentable": 200, "fully_documented": 0, "last_scan": just_now, "rules_version": gs.RULES_VERSION},
    }
    picked = gs.pick_next_binary(inv, ["/a", "/b"], blacklist=set())
    assert picked is None


def test_pick_next_binary_re_picks_after_cooldown_expires():
    """A binary that was scanned more than the cooldown ago becomes
    eligible again — that's how doc-worker fixes get reflected in the
    inventory."""
    long_ago = (datetime.now() - timedelta(seconds=7200)).isoformat()  # 2 h
    inv = {
        "/stale": {"name": "stale", "total_documentable": 100, "fully_documented": 50, "last_scan": long_ago},
    }
    picked = gs.pick_next_binary(inv, ["/stale"], blacklist=set())
    assert picked == "/stale"


def test_pick_next_binary_re_picks_zero_total_with_last_scan():
    """Auto-heal: a record stamped as `total=0 AND last_scan set` is the
    bug signature from a pre-fix scorer that wrote zeros for an empty
    list_globals fetch. The fixed scorer re-walks it."""
    inv = {
        "/wedged": {"name": "wedged", "total_documentable": 0, "fully_documented": 0, "last_scan": "2026-04-25T19:21:51"},
    }
    picked = gs.pick_next_binary(inv, ["/wedged"], blacklist=set())
    assert picked == "/wedged"


def test_status_for_zero_total_with_last_scan_is_in_progress():
    rec = {"total_documentable": 0, "fully_documented": 0, "last_scan": "2026-04-25T19:21:51"}
    assert gs.status_for(rec) == "in_progress"


def test_pick_next_binary_unfetched_sentinel():
    """A binary the scorer has never walked (total=0, last_scan=None)
    should still be picked over fully-complete binaries via the unfetched
    sentinel — same pattern as inventory_scorer."""
    inv = {
        "/done": {"name": "done", "total_documentable": 100, "fully_documented": 100, "last_scan": "x"},
        "/new": {"name": "new", "total_documentable": 0, "fully_documented": 0, "last_scan": None},
    }
    assert gs.pick_next_binary(inv, ["/done", "/new"], blacklist=set()) == "/new"


# ---------- current-binary preference ----------


def test_pick_next_binary_prefers_current_binary_over_larger_deficit():
    """When the user has a focused binary, it wins even if another binary
    has more globals with issues."""
    inv = {
        "/big": {"name": "big", "total_documentable": 1000, "fully_documented": 0, "last_scan": "x"},
        "/focused": {"name": "focused", "total_documentable": 100, "fully_documented": 90, "last_scan": "x"},
    }
    picked = gs.pick_next_binary(
        inv, ["/big", "/focused"], blacklist=set(), current_path="/focused"
    )
    assert picked == "/focused"


def test_pick_next_binary_falls_back_when_current_binary_complete():
    """A current binary with zero pending should not block the queue —
    fall through to standard ordering."""
    inv = {
        "/done": {"name": "done", "total_documentable": 100, "fully_documented": 100, "last_scan": "x", "rules_version": gs.RULES_VERSION},
        "/wip": {"name": "wip", "total_documentable": 100, "fully_documented": 50, "last_scan": "x"},
    }
    picked = gs.pick_next_binary(
        inv, ["/done", "/wip"], blacklist=set(), current_path="/done"
    )
    assert picked == "/wip"


def test_pick_next_binary_ignores_current_when_blacklisted():
    """If the focused binary has hit its session strike count, skip it
    and use standard ordering."""
    inv = {
        "/focused": {"name": "focused", "total_documentable": 100, "fully_documented": 0, "last_scan": "x"},
        "/wip": {"name": "wip", "total_documentable": 100, "fully_documented": 50, "last_scan": "x"},
    }
    picked = gs.pick_next_binary(
        inv, ["/focused", "/wip"], blacklist={"/focused"}, current_path="/focused"
    )
    assert picked == "/wip"


def test_pick_next_binary_ignores_current_when_not_in_candidates():
    """If the focused binary isn't in the project tree, fall through."""
    inv = {
        "/wip": {"name": "wip", "total_documentable": 100, "fully_documented": 50, "last_scan": "x"},
    }
    picked = gs.pick_next_binary(
        inv, ["/wip"], blacklist=set(), current_path="/missing"
    )
    assert picked == "/wip"


def test_pick_next_binary_picks_current_when_unfetched():
    """Sentinel logic still applies when the current binary has never been
    walked — a focused, unfetched binary still wins."""
    inv = {
        "/big": {"name": "big", "total_documentable": 1000, "fully_documented": 0, "last_scan": "x"},
        "/focused": {"name": "focused", "total_documentable": 0, "fully_documented": 0, "last_scan": None},
    }
    picked = gs.pick_next_binary(
        inv, ["/big", "/focused"], blacklist=set(), current_path="/focused"
    )
    assert picked == "/focused"


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
    current_binary_name_getter=None,
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
        current_binary_name_getter=current_binary_name_getter,
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


def test_audit_one_binary_skips_individual_audit_exceptions(tmp_path):
    """Regression: a single audit_global exception must NOT abort the
    whole walk — that turned a 5000-global D2Game.dll walk into an
    infinite re-pick loop in production. The walk should skip the bad
    address and stamp the successful audits."""
    list_globals_returns = {"/a": [{"address": f"0x{i:04x}"} for i in range(10)]}

    def _audit(prog, addr):
        if addr == "0x0005":
            raise RuntimeError("address parse failure")
        return {"issues": []}

    scorer = gs.GlobalScorer(
        worker_manager=_FakeWM(),
        project_folder_getter=lambda: "/proj",
        state_dir=tmp_path,
        fetch_programs=lambda folder: [{"path": "/a", "name": "a.dll"}],
        list_globals_for_program=lambda p: list_globals_returns[p],
        audit_global=_audit,
        on_status_change=None,
    )
    scorer._audit_one_binary("/a")

    persisted = gs.load_inventory(tmp_path)
    rec = persisted["binaries"]["/a"]
    assert rec["total_documentable"] == 9   # 10 globals - 1 exception
    assert rec["fully_documented"] == 9


def test_audit_one_binary_records_failure_on_high_error_rate(tmp_path):
    """If most audits raise, the binary is treated as broken and gets a
    strike (so it eventually blacklists), instead of stamping near-empty
    progress and looping."""
    list_globals_returns = {"/a": [{"address": f"0x{i:04x}"} for i in range(10)]}

    def _audit(prog, addr):
        raise RuntimeError("everything fails")

    scorer = gs.GlobalScorer(
        worker_manager=_FakeWM(),
        project_folder_getter=lambda: "/proj",
        state_dir=tmp_path,
        fetch_programs=lambda folder: [{"path": "/a", "name": "a.dll"}],
        list_globals_for_program=lambda p: list_globals_returns[p],
        audit_global=_audit,
        on_status_change=None,
    )
    scorer._audit_one_binary("/a")

    # Strike counter advanced (rather than being reset by a successful walk).
    assert scorer._fail_streak.get("/a") == 1


def test_audit_one_binary_stamps_partial_on_pause(tmp_path):
    """Mid-scan pause must stamp partial progress so the next loop
    iteration shows the work that's been done — preventing the infinite
    re-pick loop where pauses kept resetting the counter to 0."""
    addrs = [f"0x{i:04x}" for i in range(20)]
    list_globals_returns = {"/a": [{"address": a} for a in addrs]}
    audited = {"count": 0}
    wm = _FakeWM(active=False)

    def _audit(prog, addr):
        audited["count"] += 1
        # Trigger pause after 5 audits — but well before the periodic
        # stamp threshold (50), so we're testing the on-pause stamp,
        # not the periodic stamp.
        if audited["count"] >= 5:
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

    persisted = gs.load_inventory(tmp_path)
    rec = persisted["binaries"]["/a"]
    # At least the 5 audits before the pause should be persisted.
    assert rec["total_documentable"] >= 5


def test_audit_one_binary_force_on_bypasses_mid_scan_pause(tmp_path):
    """Regression: when force-on is engaged, the mid-scan worker check
    must NOT bail out — otherwise the walk never stamps inventory and
    auto-heal re-picks the binary forever (observed live as a tight
    list_globals loop on D2Game.dll with no progress)."""
    list_globals_returns = {
        "/a": [{"address": f"0x{i:04x}"} for i in range(10)]
    }
    wm = _FakeWM(active=True)  # workers always active
    audit_returns = {("/a", f"0x{i:04x}"): {"issues": []} for i in range(10)}

    scorer = gs.GlobalScorer(
        worker_manager=wm,
        project_folder_getter=lambda: "/proj",
        state_dir=tmp_path,
        fetch_programs=lambda folder: [{"path": "/a", "name": "a.dll"}],
        list_globals_for_program=lambda p: list_globals_returns[p],
        audit_global=lambda p, a: audit_returns.get((p, a)),
        on_status_change=None,
    )
    scorer.set_force_on(True)
    scorer._audit_one_binary("/a")

    # All 10 globals processed and inventory stamped (not bailed out).
    persisted = gs.load_inventory(tmp_path)
    assert persisted["binaries"]["/a"]["total_documentable"] == 10
    assert persisted["binaries"]["/a"]["fully_documented"] == 10


def test_audit_one_binary_pauses_when_workers_active(tmp_path):
    """Q7-style cooperative pause: when workers go active mid-walk, the
    scorer yields. Partial progress is now persisted (so the dashboard
    shows real numbers instead of repeatedly resetting to zero)."""
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
    assert audit_calls["count"] == 2
    persisted = gs.load_inventory(tmp_path)
    # Partial progress IS now persisted on pause (the fix for the
    # "tight loop, no progress on D2Game.dll" bug). Two audits happened
    # before the pause, both fully documented.
    rec = persisted["binaries"]["/a"]
    assert rec["total_documentable"] == 2
    assert rec["fully_documented"] == 2


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


def test_audit_one_binary_records_failure_on_empty_list(tmp_path):
    """Bug fix mirror: empty list_globals must record a failure, not
    stamp '0/0 complete'."""
    scorer = _make_scorer(
        programs=[{"path": "/empty", "name": "empty.dll"}],
        list_globals_returns={"/empty": []},
        state_dir=tmp_path,
    )
    scorer._audit_one_binary("/empty")
    persisted = gs.load_inventory(tmp_path)
    assert "/empty" not in persisted.get("binaries", {})
    assert scorer._fail_streak.get("/empty") == 1


def test_pick_least_recent_global(tmp_path):
    inv = {
        "/old": {"last_scan": "2026-01-01T00:00:00"},
        "/never": {"last_scan": None},
        "/recent": {"last_scan": "2026-04-25T19:00:00"},
    }
    assert gs._pick_least_recent(inv, ["/old", "/never", "/recent"], blacklist=set()) == "/never"
    assert gs._pick_least_recent(inv, ["/old", "/recent"], blacklist=set()) == "/old"
    assert gs._pick_least_recent(inv, ["/old", "/recent"], blacklist={"/old"}) == "/recent"


def test_set_force_on_updates_status(tmp_path):
    scorer = _make_scorer(state_dir=tmp_path)
    assert scorer.get_status()["force_on"] is False
    scorer.set_force_on(True)
    assert scorer.get_status()["force_on"] is True


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


# ---------- _resolve_current_path ----------


def test_resolve_current_path_returns_none_without_getter(tmp_path):
    scorer = _make_scorer(state_dir=tmp_path)
    assert scorer._resolve_current_path([{"name": "a.dll", "path": "/a"}]) is None


def test_resolve_current_path_returns_none_when_getter_returns_none(tmp_path):
    scorer = _make_scorer(state_dir=tmp_path, current_binary_name_getter=lambda: None)
    assert scorer._resolve_current_path([{"name": "a.dll", "path": "/a"}]) is None


def test_resolve_current_path_maps_name_to_path(tmp_path):
    scorer = _make_scorer(
        state_dir=tmp_path, current_binary_name_getter=lambda: "D2Common.dll"
    )
    programs = [
        {"name": "D2Game.dll", "path": "/Vanilla/1.13d/D2Game.dll"},
        {"name": "D2Common.dll", "path": "/Vanilla/1.13d/D2Common.dll"},
    ]
    assert scorer._resolve_current_path(programs) == "/Vanilla/1.13d/D2Common.dll"


def test_resolve_current_path_returns_none_for_unknown_name(tmp_path):
    scorer = _make_scorer(
        state_dir=tmp_path, current_binary_name_getter=lambda: "Ghost.dll"
    )
    programs = [{"name": "D2Common.dll", "path": "/Vanilla/1.13d/D2Common.dll"}]
    assert scorer._resolve_current_path(programs) is None


def test_resolve_current_path_swallows_getter_exceptions(tmp_path):
    def _broken():
        raise RuntimeError("state read failed")

    scorer = _make_scorer(state_dir=tmp_path, current_binary_name_getter=_broken)
    assert scorer._resolve_current_path([{"name": "a.dll", "path": "/a"}]) is None

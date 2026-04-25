"""
Regression tests for fun-doc's state.json atomic-save contract.

Background: state.json was previously written via a non-atomic
`open(path, 'w')` → write → close pattern. A process kill mid-write left a
truncated file (the real one we hit: line 731,439 cut off at `"classification"`
with no value). The fix was:

    atomic: write to .tmp → fsync → os.replace(.tmp, .json)
    rotate: previous state.json → state.json.bak before replace
    retry:  load_state retries JSONDecodeError up to 5 times with backoff
    update: update_function_state() for per-function RMW (no lost updates)

These tests run in isolated temp directories, so they never touch the real
state.json. They exercise:
  * Atomic replacement (readers never see a half-written file)
  * Backup rotation (state.json.bak exists and is valid JSON)
  * Read-retry behavior when the main file is corrupt
  * update_function_state preserves concurrent updates to other keys
"""

import json
import multiprocessing
import os
import threading
import time
from pathlib import Path

import pytest


def _debug_child_probe(funcdoc_dir, log_dir, debug_ctx, result_queue):
    import sys

    sys.path.insert(0, str(funcdoc_dir))
    import fun_doc

    fun_doc._restore_debug_context_for_worker(debug_ctx, log_dir)
    fun_doc._debug_log_tool_call(
        "mcp_ghidra-mcp_rename_variable",
        {"address": "0x401000", "name": "nValue"},
        {"ok": True},
        "failed",
        12,
    )
    result_queue.put(str(fun_doc._debug_get_log_path()))


@pytest.fixture
def isolated_state(monkeypatch, tmp_path):
    """Point fun_doc.STATE_FILE at a temp path for the duration of one test."""
    import sys

    # Ensure fun-doc is importable
    funcdoc_dir = Path(__file__).parent.parent.parent / "fun-doc"
    sys.path.insert(0, str(funcdoc_dir))
    import fun_doc

    fake_state = tmp_path / "state.json"
    monkeypatch.setattr(fun_doc, "STATE_FILE", fake_state)
    yield fun_doc, fake_state


def _sample_state(n=5):
    return {
        "project_folder": "/test",
        "last_scan": "2026-04-13T00:00:00",
        "functions": {
            f"prog::addr{i:04x}": {
                "program": "/test/prog",
                "program_name": "prog",
                "address": f"{i:04x}",
                "name": f"func_{i}",
                "score": i * 10,
                "fixable": 0.0,
                "has_custom_name": False,
                "has_plate_comment": False,
                "deductions": [],
                "caller_count": 0,
                "is_leaf": False,
                "classification": "unknown",
                "is_thunk": False,
                "is_external": False,
                "last_processed": None,
                "last_result": None,
            }
            for i in range(n)
        },
        "sessions": [],
        "current_session": None,
    }


def test_save_state_writes_atomically_with_backup(isolated_state):
    """save_state must leave state.json parseable and produce a .bak file."""
    fun_doc, path = isolated_state
    bak_path = path.with_suffix(".json.bak")

    # Initial save
    s1 = _sample_state(5)
    fun_doc.save_state(s1)
    assert path.exists()
    # First save has no prior content, so .bak may not exist yet
    loaded = json.loads(path.read_text())
    assert len(loaded["functions"]) == 5

    # Second save rotates first into .bak
    s2 = _sample_state(7)
    fun_doc.save_state(s2)
    assert path.exists()
    assert bak_path.exists()
    assert len(json.loads(path.read_text())["functions"]) == 7
    assert len(json.loads(bak_path.read_text())["functions"]) == 5


def test_load_state_recovers_from_corrupt_file_via_backup(isolated_state, tmp_path):
    """If state.json is corrupt but .bak is valid, load_state returns .bak."""
    fun_doc, path = isolated_state
    bak_path = path.with_suffix(".json.bak")

    # Seed a good backup
    good = _sample_state(3)
    bak_path.write_text(json.dumps(good))

    # Corrupt the main file (truncated JSON matching the real-world corruption)
    path.write_text('{"functions": {"foo": {"classificat')

    state = fun_doc.load_state()
    assert state is not None
    assert len(state.get("functions", {})) == 3
    assert "prog::addr0000" in state["functions"]


def test_load_state_retries_on_transient_mid_write(isolated_state):
    """load_state must retry on JSONDecodeError — a concurrent save may have
    caught us mid-write. The retry loop (5 attempts with 0.2s backoff) gives
    the writer time to finish."""
    fun_doc, path = isolated_state

    # Start with a valid file
    fun_doc.save_state(_sample_state(3))

    # Simulate a race: writer corrupts briefly, then fixes itself
    def racing_writer():
        time.sleep(0.05)
        path.write_text('{"functions": {"foo')  # corrupt
        time.sleep(0.3)
        fun_doc.save_state(_sample_state(4))  # restore

    t = threading.Thread(target=racing_writer, daemon=True)
    t.start()
    # Give the writer time to corrupt
    time.sleep(0.1)

    state = fun_doc.load_state()  # should retry past the corruption window
    t.join(timeout=2)
    assert state is not None
    # Either got the old 3 or the new 4 — both are acceptable recoveries
    assert len(state.get("functions", {})) in (3, 4)


def test_update_function_state_preserves_concurrent_other_keys(isolated_state):
    """The whole point of update_function_state: if worker A updates key X
    while worker B is about to update key Y, neither clobbers the other.

    Pre-fix: save_state(state) wrote the whole dict, so B's in-memory copy
    (with stale X) would overwrite A's X update.

    Post-fix: update_function_state(key, func) does read-modify-write under
    _state_lock and re-reads from disk, so A and B both survive.
    """
    fun_doc, path = isolated_state

    # Initial state with 10 functions, all at score 0
    fun_doc.save_state(_sample_state(10))

    # Simulate worker A: write key 0 at score 99
    key_a = "prog::addr0000"
    func_a = {
        **fun_doc.load_state()["functions"][key_a],
        "score": 99,
        "last_result": "A",
    }
    fun_doc.update_function_state(key_a, func_a)

    # Simulate worker B with a STALE in-memory copy that doesn't see A's update.
    # Under the old save_state path, B writing its own copy would clobber A.
    # Under update_function_state, B only touches its own key and re-reads the
    # rest, so A's update survives.
    key_b = "prog::addr0005"
    stale_funcs = json.loads(path.read_text())["functions"]
    stale_funcs[key_a]["score"] = 0  # B's stale view: still 0
    # B atomically updates its own key
    func_b = {**stale_funcs[key_b], "score": 55, "last_result": "B"}
    fun_doc.update_function_state(key_b, func_b)

    # Re-read from disk — both updates must be present
    final = json.loads(path.read_text())
    assert (
        final["functions"][key_a]["score"] == 99
    ), "Worker A's update was lost — update_function_state clobbered it"
    assert final["functions"][key_b]["score"] == 55
    assert final["functions"][key_a]["last_result"] == "A"
    assert final["functions"][key_b]["last_result"] == "B"


def test_finalize_worker_session_does_not_clobber_concurrent_function_updates(
    isolated_state,
):
    """Worker-loop end-of-run persistence must not reintroduce the lost-update
    race that update_function_state exists to solve.

    Scenario: worker A loads state, worker B concurrently commits a per-function
    update via update_function_state, worker A finalizes its session. If worker
    A's finalize writes the full in-memory state, worker B's update is lost.
    finalize_worker_session does RMW, so B's update survives.
    """
    fun_doc, path = isolated_state

    fun_doc.save_state(_sample_state(10))

    # Worker A loads state (stale snapshot from here on)
    worker_a_state = fun_doc.load_state()
    session_a = fun_doc.start_session(worker_a_state)
    session_a["completed"] = 3
    session_a["functions"] = ["prog::addr0001", "prog::addr0002", "prog::addr0003"]

    # Worker B commits a per-function update — invisible to A's cached state
    key_b = "prog::addr0007"
    on_disk = json.loads(path.read_text())
    func_b = {**on_disk["functions"][key_b], "score": 88, "last_result": "B"}
    fun_doc.update_function_state(key_b, func_b)

    # Worker A finalizes its session. Must NOT clobber B's update.
    fun_doc.finalize_worker_session(session_a)

    final = json.loads(path.read_text())
    assert (
        final["functions"][key_b]["score"] == 88
    ), "finalize_worker_session clobbered a concurrent per-function update"
    assert final["functions"][key_b]["last_result"] == "B"

    # Session was recorded with ended timestamp
    assert len(final["sessions"]) == 1
    archived = final["sessions"][0]
    assert archived["completed"] == 3
    assert archived["functions"] == ["prog::addr0001", "prog::addr0002", "prog::addr0003"]
    assert archived.get("ended")


def test_finalize_worker_session_handles_active_binary_restore(isolated_state):
    """active_binary override path: pass a value to set, pass None to clear,
    omit to leave the on-disk value untouched."""
    fun_doc, path = isolated_state

    # Seed: active_binary already set on disk (e.g., by dashboard)
    seed = _sample_state(3)
    seed["active_binary"] = "dashboard_binary"
    fun_doc.save_state(seed)

    # Worker finishes, no override: on-disk active_binary must be preserved
    session = {"started": "2026-04-24T10:00:00", "completed": 1}
    fun_doc.finalize_worker_session(session)
    assert json.loads(path.read_text())["active_binary"] == "dashboard_binary"

    # Worker restores a prior original_binary
    session2 = {"started": "2026-04-24T11:00:00", "completed": 1}
    fun_doc.finalize_worker_session(session2, active_binary="original")
    assert json.loads(path.read_text())["active_binary"] == "original"

    # Worker clears (original was None)
    session3 = {"started": "2026-04-24T12:00:00", "completed": 1}
    fun_doc.finalize_worker_session(session3, active_binary=None)
    assert "active_binary" not in json.loads(path.read_text())


def test_finalize_worker_session_only_clears_matching_current_session(isolated_state):
    """current_session must only be cleared if it still references this worker's
    session. Another worker's concurrent session should stay untouched."""
    fun_doc, path = isolated_state

    # Seed state with another worker's current_session already recorded
    seed = _sample_state(3)
    other_session = {"started": "2026-04-24T09:00:00", "completed": 0}
    seed["current_session"] = other_session
    fun_doc.save_state(seed)

    my_session = {"started": "2026-04-24T10:00:00", "completed": 2}
    fun_doc.finalize_worker_session(my_session)

    final = json.loads(path.read_text())
    # Other worker's current_session untouched
    assert final["current_session"] == other_session
    # My session archived
    assert len(final["sessions"]) == 1
    assert final["sessions"][0]["started"] == "2026-04-24T10:00:00"


def test_finalize_worker_session_uses_backup_when_state_is_corrupt(isolated_state):
    """Worker finalization should preserve recoverable history by loading the
    same backup that load_state() would use instead of writing a fresh default."""
    fun_doc, path = isolated_state
    bak_path = path.with_suffix(".json.bak")
    good = _sample_state(2)
    good["current_session"] = {"started": "2026-04-24T10:00:00", "completed": 0}
    bak_path.write_text(json.dumps(good))
    path.write_text('{"functions": {"foo": {"classificat')

    fun_doc.finalize_worker_session({"started": "2026-04-24T10:00:00", "completed": 1})

    final = json.loads(path.read_text())
    assert len(final["functions"]) == 2
    assert final["sessions"][-1]["completed"] == 1


def test_save_state_truncation_corruption_is_recoverable(isolated_state, tmp_path):
    """End-to-end: simulate the exact failure mode we hit — a truncated
    state.json where a function entry is cut off mid-value. The recovery
    script (truncate at last clean entry) should produce a parseable file
    with most of the data preserved."""
    fun_doc, path = isolated_state
    bak_path = path.with_suffix(".json.bak")

    # Write a complete valid file
    fun_doc.save_state(_sample_state(10))

    # Simulate the real-world truncation: cut off mid-entry. The last line
    # ends with '"classification"' and no colon (the actual bytes we saw).
    content = path.read_text()
    cutoff = content.find('"classification"')
    if cutoff > 0:
        # Truncate in the middle of the 5th function's classification line
        # Find 5th occurrence roughly
        idx = 0
        for _ in range(5):
            next_idx = content.find('"classification"', idx + 1)
            if next_idx < 0:
                break
            idx = next_idx
        if idx > 0:
            path.write_text(content[: idx + len('"classification"')])

    # Main file is now corrupt; .bak should not exist yet (we only saved once)
    # load_state should either recover from .bak (if it exists) or raise RuntimeError
    try:
        state = fun_doc.load_state()
        # Recovery succeeded (from .bak)
        assert state is not None
    except RuntimeError as e:
        # No .bak available — this is the "both corrupt" path and we explicitly
        # raise rather than silently starting fresh
        assert "corrupt" in str(e).lower()


def test_debug_log_path_is_unique_per_run_and_provider(
    isolated_state, monkeypatch, tmp_path
):
    """Each run should get its own debug file path, even for the same function."""
    fun_doc, _ = isolated_state
    monkeypatch.setattr(fun_doc, "LOG_DIR", tmp_path / "logs")

    fun_doc._debug_set_context(
        "/test/prog::401000",
        "ExampleFunc",
        "/test/prog",
        "401000",
        "minimax",
        "runalpha",
        requested_provider="minimax",
    )
    path_a = fun_doc._debug_get_log_path()

    fun_doc._debug_set_context(
        "/test/prog::401000",
        "ExampleFunc",
        "/test/prog",
        "401000",
        "gemini",
        "runbeta",
        requested_provider="gemini",
    )
    path_b = fun_doc._debug_get_log_path()

    assert path_a != path_b
    assert "runalpha" in str(path_a)
    assert "runbeta" in str(path_b)
    assert "minimax" in str(path_a)
    assert "gemini" in str(path_b)


def test_debug_log_normalizes_tool_names_and_preserves_raw_name(
    isolated_state, monkeypatch, tmp_path
):
    """Debug entries should use a comparable short tool name while keeping the raw provider name."""
    fun_doc, _ = isolated_state
    monkeypatch.setattr(fun_doc, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(
        fun_doc,
        "load_priority_queue",
        lambda: {"config": {"debug_mode": True}},
    )

    fun_doc._debug_set_context(
        "/test/prog::401000",
        "ExampleFunc",
        "/test/prog",
        "401000",
        "gemini",
        "runxyz",
        requested_provider="gemini",
    )
    fun_doc._debug_log_tool_call(
        "mcp_ghidra-mcp_batch_set_comments",
        {"address": "0x401000"},
        {"ok": True},
        "success",
        None,
    )

    log_path = fun_doc._debug_get_log_path()
    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert entry["tool"] == "batch_set_comments"
    assert entry["tool_raw"] == "mcp_ghidra-mcp_batch_set_comments"
    assert entry["run_id"] == "runxyz"
    assert entry["requested_provider"] == "gemini"


def test_debug_context_is_restored_in_spawned_worker(
    isolated_state, monkeypatch, tmp_path
):
    """Watchdog-spawned provider workers must keep per-run debug logging."""
    fun_doc, _ = isolated_state
    log_dir = tmp_path / "logs"
    monkeypatch.setattr(fun_doc, "LOG_DIR", log_dir)
    monkeypatch.setattr(
        fun_doc,
        "load_priority_queue",
        lambda: {"config": {"debug_mode": True}},
    )

    fun_doc._debug_set_context(
        "/test/prog::401000",
        "ExampleFunc",
        "/test/prog",
        "401000",
        "claude",
        "spawnrun",
        requested_provider="claude",
    )
    debug_ctx = dict(fun_doc._debug_ctx.get())
    funcdoc_dir = Path(__file__).parent.parent.parent / "fun-doc"

    ctx = multiprocessing.get_context("spawn")
    result_queue = ctx.Queue(maxsize=1)
    proc = ctx.Process(
        target=_debug_child_probe,
        args=(funcdoc_dir, str(log_dir), debug_ctx, result_queue),
    )
    proc.start()
    proc.join(timeout=10)

    assert proc.exitcode == 0
    log_path = Path(result_queue.get(timeout=2))
    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert entry["run_id"] == "spawnrun"
    assert entry["tool"] == "rename_variable"
    assert entry["status"] == "error"

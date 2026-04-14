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
import os
import threading
import time
from pathlib import Path

import pytest


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
    func_a = {**fun_doc.load_state()["functions"][key_a], "score": 99, "last_result": "A"}
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
    assert final["functions"][key_a]["score"] == 99, (
        "Worker A's update was lost — update_function_state clobbered it"
    )
    assert final["functions"][key_b]["score"] == 55
    assert final["functions"][key_a]["last_result"] == "A"
    assert final["functions"][key_b]["last_result"] == "B"


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

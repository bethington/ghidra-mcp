"""Regression test for the _state_lock reentrant-acquire deadlock.

Motivation: on 2026-04-24 four workers wedged for 28+ minutes in
refresh_candidate_scores. py-spy showed one thread holding _state_lock
at fun_doc.py:2124 while calling load_state(), which itself does
`with _state_lock: ...` at fun_doc.py:582. threading.Lock is
non-reentrant — the self-acquire deadlocked the holding thread, and
every other worker queued up behind it indefinitely.

The fix converts _state_lock (and _queue_lock, same pattern) to
threading.RLock. This test locks the deadlock-free behavior in: hold
the lock, call load_state, assert the call returns within a tight
timeout.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
from pathlib import Path

import pytest


FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc" / "fun_doc.py"


@pytest.fixture
def fun_doc_module(tmp_path, monkeypatch):
    """Load fun_doc.py with a throwaway state file to avoid touching
    the repo's live state. fun_doc uses sibling-module imports
    (`from event_bus import ...`) so we prepend fun-doc/ to sys.path
    before import and pop it after.
    """
    state_file = tmp_path / "state.json"
    state_file.write_text('{"functions": {}}')

    monkeypatch.setenv("FUNDOC_STATE_FILE", str(state_file))
    monkeypatch.setenv("FUNDOC_DASHBOARD", "false")

    fun_doc_dir = str(FUN_DOC.parent)
    monkeypatch.syspath_prepend(fun_doc_dir)

    spec = importlib.util.spec_from_file_location("fun_doc_under_test", FUN_DOC)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fun_doc_under_test"] = mod
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pytest.skip("fun_doc.py raised SystemExit during import")
    # Redirect STATE_FILE module-global to our temp path so load_state
    # / _atomic_write_state don't touch the repo's live state.
    mod.STATE_FILE = state_file
    yield mod
    sys.modules.pop("fun_doc_under_test", None)


def test_load_state_inside_state_lock_does_not_deadlock(fun_doc_module):
    """Hold _state_lock, then call load_state() — must not deadlock.

    This is the exact pattern refresh_candidate_scores uses around
    its merge + write step. With a plain threading.Lock this call
    would block forever; with RLock it returns immediately.
    """
    mod = fun_doc_module

    result_ready = threading.Event()
    done = threading.Event()

    def _probe():
        with mod._state_lock:
            mod.load_state()
            result_ready.set()
        done.set()

    t = threading.Thread(target=_probe, daemon=True)
    t.start()
    # 5s is orders of magnitude more than a healthy load_state needs
    # (the file is tiny in this test), but short enough that a real
    # deadlock fails the test promptly.
    assert result_ready.wait(timeout=5.0), (
        "load_state() hung while _state_lock was held by the same thread — "
        "the non-reentrant Lock deadlock has regressed."
    )
    assert done.wait(timeout=1.0)
    t.join(timeout=1.0)


def test_queue_lock_reentrant(fun_doc_module):
    """Same contract for _queue_lock: re-entering from the same thread
    must not deadlock. save_priority_queue holds the lock and some
    call paths historically re-read the queue under it.
    """
    mod = fun_doc_module

    done = threading.Event()

    def _probe():
        with mod._queue_lock:
            with mod._queue_lock:
                pass
        done.set()

    t = threading.Thread(target=_probe, daemon=True)
    t.start()
    assert done.wait(timeout=5.0), (
        "_queue_lock self-acquire deadlocked — must be an RLock."
    )
    t.join(timeout=1.0)

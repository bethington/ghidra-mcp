"""
Regression tests for fun-doc's cross-process event-bus drain.

Background: workers invoke the AI provider in a `multiprocessing.spawn`
subprocess (hang-timeout protection). Inside that subprocess, `bus_emit`
is wired to push each event onto a cross-process `multiprocessing.Queue`.
A drain thread in the parent reads from the queue and re-emits events
on the parent's bus, where the dashboard's Flask-SocketIO bridge
forwards them to connected clients.

The drain loop used to call `get_bus().emit(event_type, data)` while
`get_bus` was never imported at the fun_doc module scope. Every emit
raised `NameError`, which was swallowed by the drain's broad
`except Exception: pass`. Result: subprocess-originated events
(tool_call, tool_result, model_text, etc.) silently disappeared while
parent-thread-emitted events (worker_started, function_started, etc.)
kept flowing. The dashboard looked dead even though workers ran.

These tests lock in:
  * fun_doc re-exports `get_bus` at module scope (lint-level guard).
  * End-to-end: a subprocess with `set_cross_process_queue` pushes
    events that the parent's bus subscribers actually observe.
"""

from __future__ import annotations

import importlib.util
import multiprocessing as mp
import sys
import threading
import time
from pathlib import Path

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"


@pytest.fixture(scope="module")
def fun_doc_on_path():
    """Make fun-doc/ importable without polluting the test process's
    sys.modules beyond the fixture scope. fun_doc.py imports state.json
    on load so we want the path addition even for the lint test.
    """
    path_str = str(FUN_DOC_DIR)
    added = False
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
        added = True
    try:
        yield
    finally:
        if added:
            try:
                sys.path.remove(path_str)
            except ValueError:
                pass


def test_event_bus_module_exposes_expected_api(fun_doc_on_path):
    """event_bus.py must expose the full public API the drain loop needs."""
    import event_bus

    for name in ("emit", "get_bus", "get_worker_id", "set_worker_id",
                 "set_cross_process_queue"):
        assert hasattr(event_bus, name), f"event_bus missing `{name}`"
    assert callable(event_bus.get_bus)


def test_fun_doc_imports_get_bus_at_module_scope(fun_doc_on_path):
    """Guard against the silent NameError regression.

    The drain thread in `_invoke_provider_with_watchdog` calls
    `get_bus()` inside a nested function whose only reachable binding
    is the fun_doc module global. Local/function-scoped imports of
    `get_bus` elsewhere in the file DO NOT satisfy this — Python name
    resolution for the drain thread uses LEGB and the enclosing
    function doesn't import get_bus. So parse the AST and check for
    `get_bus` specifically in a module-level `from event_bus import`.
    """
    import ast

    source_path = FUN_DOC_DIR / "fun_doc.py"
    source = source_path.read_text(encoding="utf-8")

    # Sanity: the drain loop still uses get_bus (if refactored, update test).
    assert "get_bus()" in source, (
        "drain loop no longer references get_bus — update this test or "
        "ensure the replacement event-routing path is covered"
    )

    tree = ast.parse(source, filename=str(source_path))
    module_level_imports = (
        node for node in tree.body if isinstance(node, ast.ImportFrom)
    )
    imported_names: set[str] = set()
    for node in module_level_imports:
        if node.module != "event_bus":
            continue
        for alias in node.names:
            imported_names.add(alias.asname or alias.name)

    assert "get_bus" in imported_names, (
        "fun_doc.py references get_bus() at module scope (from the drain "
        "thread nested inside _invoke_provider_with_watchdog) but never "
        "imports it from event_bus at module level. Drain thread will "
        "raise NameError on every event and the dashboard bridge will "
        "never see subprocess-emitted tool_call/tool_result. "
        f"Found module-level event_bus imports: {sorted(imported_names)}"
    )


def _subprocess_emitter(queue_to_parent, parent_worker_id, events_to_emit):
    """Child process body. Installs the cross-process queue and emits.

    Mirrors what `_provider_worker_entry` does before calling the
    provider: grab the queue, pin the worker_id, then let bus_emit
    flow events back to the parent via the queue.
    """
    path_str = str(FUN_DOC_DIR)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
    from event_bus import emit as bus_emit, set_cross_process_queue

    set_cross_process_queue(queue_to_parent, worker_id=parent_worker_id)
    for event_type, data in events_to_emit:
        bus_emit(event_type, data)


def test_subprocess_events_reach_parent_bus(fun_doc_on_path):
    """End-to-end: subprocess emit → queue → parent drain → parent bus subs."""
    import event_bus

    ctx = mp.get_context("spawn")
    q = ctx.Queue(maxsize=100)

    # Parent-side bus: subscribe on the same singleton the drain will
    # emit on. This is what the dashboard bridge does in create_app().
    received: list[tuple[str, dict]] = []
    received_lock = threading.Lock()

    def capture(event_type):
        def handler(data):
            with received_lock:
                received.append((event_type, data))
        return handler

    bus = event_bus.get_bus()
    bus.on("tool_call", capture("tool_call"))
    bus.on("tool_result", capture("tool_result"))

    # Spin up the parent's drain thread — same shape as in fun_doc.py.
    stop = threading.Event()

    def drain():
        import queue as _q
        while not stop.is_set():
            try:
                evt = q.get(timeout=0.2)
            except _q.Empty:
                continue
            try:
                event_type, data = evt
                event_bus.get_bus().emit(event_type, data)
            except Exception:
                pass

    drain_thread = threading.Thread(target=drain, daemon=True)
    drain_thread.start()

    # Kick off a subprocess that emits a deterministic sequence.
    events_to_emit = [
        ("tool_call",   {"tool": "decompile_function", "status": "calling"}),
        ("tool_result", {"tool": "decompile_function", "status": "success"}),
        ("tool_call",   {"tool": "rename_function",    "status": "calling"}),
        ("tool_result", {"tool": "rename_function",    "status": "success"}),
    ]
    parent_worker_id = "test-worker-abc123"
    proc = ctx.Process(
        target=_subprocess_emitter,
        args=(q, parent_worker_id, events_to_emit),
    )
    proc.start()
    proc.join(timeout=10)
    assert proc.exitcode == 0, f"emitter subprocess failed (exit={proc.exitcode})"

    # Wait up to 2s for the drain thread to flush. In practice it takes
    # tens of ms; the generous bound tolerates slow CI.
    deadline = time.time() + 2.0
    while time.time() < deadline:
        with received_lock:
            if len(received) >= len(events_to_emit):
                break
        time.sleep(0.02)

    stop.set()
    drain_thread.join(timeout=2)

    with received_lock:
        captured = list(received)

    assert len(captured) == len(events_to_emit), (
        f"expected {len(events_to_emit)} events on the parent bus, "
        f"got {len(captured)}: {captured}"
    )

    # Every event must carry worker_id (pinned on the subprocess via
    # set_cross_process_queue). The dashboard routes by worker_id; an
    # event without it goes to an unnamed pane and is effectively lost.
    for event_type, data in captured:
        assert data.get("worker_id") == parent_worker_id, (
            f"event {event_type!r} lost worker_id tag: {data}"
        )

    # Order must be preserved — a Codex/minimax tool call and its
    # corresponding tool_result need to land in sequence so the pane
    # renders `calling` then `success`, not the reverse.
    assert [e[0] for e in captured] == [e[0] for e in events_to_emit]

"""
Thread-safe publish-subscribe event bus for fun-doc.

Used to bridge CLI events (scan progress, tool calls, score updates)
to the WebSocket dashboard without coupling core logic to Flask.

Usage:
    from event_bus import emit as bus_emit
    bus_emit("tool_call", {"tool": "rename_function", "status": "calling"})

The emit() convenience function is a no-op when the bus hasn't been
initialized (CLI-only mode without dashboard), so it's safe to call
everywhere with zero overhead.

Cross-process propagation:
    Provider calls are run inside spawned subprocesses by
    _invoke_provider_with_watchdog (for hang-timeout protection). A
    subprocess has its own Python interpreter, its own sys.modules,
    its own EventBus instance — so `emit("tool_call", ...)` inside the
    subprocess never reaches the parent's subscribers by default.

    The fix: the parent gives the subprocess a multiprocessing.Queue
    via `set_cross_process_queue()`. When set, `emit()` also puts each
    event onto the queue. A drain thread in the parent reads from the
    queue and re-emits on the parent's bus, where the dashboard bridge
    picks it up. Events stay live-delivered (microsecond IPC, not file
    polling) while audit events still flow to events.jsonl through the
    separate event_log module.
"""

import sys
import threading
import types
from collections import defaultdict

# Thread-local storage for worker context
_thread_local = threading.local()

# IMPORTANT: this module gets loaded multiple times in a single Python
# process (confirmed: the subprocess spawn reloads it fresh). Using a
# module-level `_bus = None` default caused workers to emit on a bus the
# dashboard hadn't subscribed on. `sys.modules` is process-wide, so we
# stash a tiny holder module in there and attach the real bus to it.
# Within a process this gives us a true singleton; across processes,
# each subprocess has its own sys.modules and its own bus — that's what
# the cross-process queue below bridges.
_HOLDER_KEY = "__fun_doc_event_bus_holder__"


class EventBus:
    """Thread-safe publish-subscribe event bus."""

    def __init__(self):
        self._subscribers = defaultdict(list)
        self._lock = threading.Lock()

    def on(self, event_type, callback):
        """Subscribe to an event type. Returns an unsubscribe function."""
        with self._lock:
            self._subscribers[event_type].append(callback)

        def unsub():
            with self._lock:
                self._subscribers[event_type] = [
                    cb for cb in self._subscribers[event_type] if cb is not callback
                ]

        return unsub

    def emit(self, event_type, data=None):
        """Emit an event to all subscribers. Non-blocking, errors are swallowed."""
        with self._lock:
            callbacks = list(self._subscribers[event_type])
        for cb in callbacks:
            try:
                cb(data)
            except Exception:
                pass  # Never let a subscriber crash the emitter


def get_bus():
    """Get the process-wide EventBus, creating it lazily.

    Stored as a fake holder module in sys.modules — the only storage
    location guaranteed shared across all module-copy contexts within
    a single process.
    """
    holder = sys.modules.get(_HOLDER_KEY)
    if holder is None:
        holder = types.ModuleType(_HOLDER_KEY)
        holder.bus = EventBus()
        sys.modules[_HOLDER_KEY] = holder
    return holder.bus


def set_worker_id(worker_id):
    """Set the current thread's worker_id (attached to all emitted events)."""
    _thread_local.worker_id = worker_id


def get_worker_id():
    """Get the current thread's worker_id, or None."""
    return getattr(_thread_local, "worker_id", None)


def set_cross_process_queue(q, worker_id=None):
    """Install a multiprocessing.Queue for cross-process event propagation.

    Called by provider subprocess entry points with the queue their
    parent watchdog created. Once set, every emit() in this process
    will also push the event onto the queue (best-effort, dropped on
    full) so the parent can re-emit it on its own bus.

    worker_id is pinned here (as a process-wide default) so subprocess
    threads that don't have thread-local worker_id still get events
    tagged correctly.
    """
    holder = sys.modules.get(_HOLDER_KEY)
    if holder is None:
        holder = types.ModuleType(_HOLDER_KEY)
        holder.bus = EventBus()
        sys.modules[_HOLDER_KEY] = holder
    holder.cross_process_queue = q
    holder.cross_process_worker_id = worker_id


def _get_cross_process_queue():
    holder = sys.modules.get(_HOLDER_KEY)
    if holder is None:
        return None, None
    return (
        getattr(holder, "cross_process_queue", None),
        getattr(holder, "cross_process_worker_id", None),
    )


def emit(event_type, data=None):
    """Convenience: emit on the process-wide bus. Auto-attaches worker_id.

    When a cross-process queue is installed (we're in a provider
    subprocess), also push the event to the parent. Local subscribers
    still fire — useful for subprocess-internal logging like
    event_log.log_event.
    """
    bus = get_bus()

    # Attach worker_id. Prefer thread-local (set by worker thread in parent)
    # but fall back to the cross-process queue's stored worker_id so
    # subprocess emissions get tagged without per-thread setup.
    worker_id = getattr(_thread_local, "worker_id", None)
    cross_q, cross_wid = _get_cross_process_queue()
    if not worker_id and cross_wid:
        worker_id = cross_wid
    if worker_id and isinstance(data, dict):
        data = {**data, "worker_id": worker_id}
    elif worker_id and data is None:
        data = {"worker_id": worker_id}

    # Forward to the parent if we're in a subprocess. Must be best-effort:
    # if the queue is full or the parent has gone away, we drop rather than
    # block the provider call.
    if cross_q is not None:
        try:
            cross_q.put_nowait((event_type, data))
        except Exception:
            pass  # full queue, dead parent, pickling failure — all non-fatal

    bus.emit(event_type, data)

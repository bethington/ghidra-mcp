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
"""

import threading
from collections import defaultdict


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


# Module-level singleton. None until explicitly initialized.
_bus = None


def get_bus():
    """Get the global EventBus, creating it lazily."""
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


def emit(event_type, data=None):
    """Convenience: emit on the global bus. No-op if bus not initialized."""
    if _bus is not None:
        _bus.emit(event_type, data)

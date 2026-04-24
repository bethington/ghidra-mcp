"""
Structured event log for fun-doc.

Writes a single JSONL file at logs/events.jsonl containing a durable,
tail-filterable audit trail of worker lifecycle, tool calls, ghidra
health, provider errors, and config changes.

Motivation:
    runs.jsonl captures completed runs. The dashboard console captures
    everything else but is ephemeral and can crash on encoding errors —
    today a 'charmap' encoding crash silently dropped 3 of 5 completed
    runs. Structured events survive encoding crashes (UTF-8 enforced
    with errors='replace') and are replayable for post-mortem analysis.

Usage:
    from event_log import log_event
    log_event("worker.run_begin", worker_id=wid, function=name, mode=mode)
    log_event("ghidra.slow_response", latency_ms=1234, path="/decompile")
    log_event("config.changed", source="dashboard_ui", key="debug_mode",
              old=False, new=True)

Event schema conventions:
    - `event` is dotted path: namespace.action (worker.started, ghidra.offline)
    - `ts` is ISO-8601 with microseconds
    - Fields are flat JSON-serializable values
    - Large payloads (tool results, tracebacks) should be truncated
      to 2kB before passing in

The writer is append-only, thread-safe, and tolerates parallel workers
without a separate lock file. Failures are non-fatal — a failed event
write prints a warning but never blocks the caller.
"""

import json
import threading
from datetime import datetime
from pathlib import Path

_EVENT_LOG_FILE = Path(__file__).parent / "logs" / "events.jsonl"
_event_lock = threading.Lock()

# Counters help detect silent data loss — exposed via get_counters() so a
# dashboard health endpoint can surface divergence (e.g. 50 runs produced
# but only 47 logged means three log writes failed).
_counters = {
    "events_produced": 0,
    "events_logged": 0,
    "events_failed": 0,
}
_counter_lock = threading.Lock()


def log_event(event, **fields):
    """Append a structured event to events.jsonl. Thread-safe, UTF-8.

    Args:
        event: Dotted event name (e.g. "worker.started", "ghidra.offline").
        **fields: Extra fields to include in the JSON record.

    Returns nothing. Failures are logged to stderr but never raised.
    """
    with _counter_lock:
        _counters["events_produced"] += 1

    entry = {
        "ts": datetime.now().isoformat(),
        "event": event,
        **fields,
    }
    try:
        _EVENT_LOG_FILE.parent.mkdir(exist_ok=True)
        with _event_lock:
            # errors='replace' ensures a stray non-UTF-8 char never
            # crashes the writer — unlike the console print that took
            # down workers earlier today.
            with open(_EVENT_LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
                f.write(json.dumps(entry, default=str, ensure_ascii=False) + "\n")
        with _counter_lock:
            _counters["events_logged"] += 1
    except Exception as e:
        with _counter_lock:
            _counters["events_failed"] += 1
        # Print to stderr via a safe path — no newline inside the f-string
        # to avoid the charmap crash pattern.
        try:
            print(f"  WARNING: event_log write failed: {type(e).__name__}", flush=True)
        except Exception:
            pass


def get_counters():
    """Return a snapshot of event production vs logging counters.

    Divergence between produced and logged indicates silent write failures.
    """
    with _counter_lock:
        return dict(_counters)


def get_log_file():
    """Path to the events JSONL file (for tail/monitor consumers)."""
    return _EVENT_LOG_FILE

"""Regression test for the /api/_diag_bridge endpoint.

The audit rule `bridge_counter_stall` (fun-doc/audit/rules.yaml) polls
this endpoint to track whether tool_call / tool_result / model_text
events are flowing from workers to the dashboard. Before v5.11.3 the
endpoint did not exist — the audit fetcher caught the 404, returned
``{}``, and every counter read as 0 forever. Result: 24 false-positive
fires between 2026-04-25 and 2026-05-21, one per day, exactly at the
30-minute stall threshold the rule was configured for.

These tests pin the contract that the endpoint exists, returns the
shape the audit fetcher expects, and increments on each bus event.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"


@pytest.fixture
def app_with_bus(monkeypatch, tmp_path):
    """Build a fresh dashboard Flask app + its EventBus.

    Mirrors the dashboard's create_app() call shape; the test issues
    events on the bus then hits the diag endpoint with Flask's test
    client to assert the counters advanced.
    """
    monkeypatch.setenv("FUNDOC_DASHBOARD", "false")
    monkeypatch.syspath_prepend(str(FUN_DOC_DIR))
    if "web" in sys.modules:
        del sys.modules["web"]
    if "event_bus" in sys.modules:
        del sys.modules["event_bus"]
    import event_bus  # noqa: WPS433
    import web        # noqa: WPS433

    bus = event_bus.EventBus()
    state_file = tmp_path / "state.json"
    state_file.write_text("{\"functions\": {}}", encoding="utf-8")
    app, _socketio = web.create_app(state_file, event_bus=bus)
    client = app.test_client()
    yield client, bus

    sys.modules.pop("web", None)
    sys.modules.pop("event_bus", None)


def test_diag_bridge_endpoint_exists_and_returns_expected_shape(app_with_bus):
    """The audit fetcher reads ``(r.json() or {}).get('bridge_counters')``
    — pin the wrapping key + initial zeros."""
    client, _bus = app_with_bus
    r = client.get("/api/_diag_bridge")
    assert r.status_code == 200, "endpoint must exist (previously 404)"
    payload = r.get_json()
    assert isinstance(payload, dict)
    assert "bridge_counters" in payload, (
        "audit fetcher reads .get('bridge_counters') — top-level key required"
    )
    counters = payload["bridge_counters"]
    # The three event_types referenced by rules.yaml.
    for event_type in ("tool_call", "tool_result", "model_text"):
        assert event_type in counters, (
            f"counter {event_type} must be present (rule "
            "bridge_counter_stall references it)"
        )
        assert counters[event_type] == 0, "fresh dashboard starts at zero"


def test_counters_increment_on_each_bus_event(app_with_bus):
    """Emitting bus events with the matching name advances the
    corresponding counter — the audit rule's whole premise is that
    these counters track actual bridge activity."""
    client, bus = app_with_bus

    bus.emit("tool_call", {"tool": "decompile_function"})
    bus.emit("tool_call", {"tool": "rename_function"})
    bus.emit("tool_result", {"ok": True})
    bus.emit("model_text", {"chunk": "..."})
    bus.emit("model_text", {"chunk": "..."})
    bus.emit("model_text", {"chunk": "..."})

    counters = client.get("/api/_diag_bridge").get_json()["bridge_counters"]
    assert counters["tool_call"] == 2
    assert counters["tool_result"] == 1
    assert counters["model_text"] == 3


def test_unrelated_events_do_not_advance_counters(app_with_bus):
    """Only the three audit-tracked event_types should advance. A
    drive-by event like worker_started must NOT trip the counters or
    the rule's signal-to-noise gets worse."""
    client, bus = app_with_bus

    bus.emit("worker_started", {"worker_id": "abc12345"})
    bus.emit("worker_progress", {"worker_id": "abc12345"})
    bus.emit("scan_progress", {"index": 1, "total": 100})

    counters = client.get("/api/_diag_bridge").get_json()["bridge_counters"]
    assert counters["tool_call"] == 0
    assert counters["tool_result"] == 0
    assert counters["model_text"] == 0


def test_counters_are_monotonic(app_with_bus):
    """Counters must only increase — the rule's evaluator compares to
    zero and a transient reset would falsely trip 'stall' state."""
    client, bus = app_with_bus

    for _ in range(5):
        bus.emit("tool_call", {})
    first = client.get("/api/_diag_bridge").get_json()["bridge_counters"]["tool_call"]

    for _ in range(3):
        bus.emit("tool_call", {})
    second = client.get("/api/_diag_bridge").get_json()["bridge_counters"]["tool_call"]

    assert second == first + 3
    assert second > first

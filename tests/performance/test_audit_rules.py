"""
Tests for fun-doc/audit/watcher.py rule evaluation.

Each rule kind has (a) a positive case showing it fires when it should,
(b) at least one near-miss case showing it does NOT fire when the
condition is almost-but-not-quite met, and (c) where applicable a dedup
check verifying the registry short-circuit keeps the second fire out.

Design: the watcher takes every external as a constructor arg (bus,
registry, rules, bridge_counters_fetcher, now_fn, log_event_fn), so these
tests never touch real Flask, real event_log, or real wall clocks.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"


@pytest.fixture(scope="module", autouse=True)
def fun_doc_on_path():
    path_str = str(FUN_DOC_DIR)
    added = False
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
        added = True
    yield
    if added:
        try:
            sys.path.remove(path_str)
        except ValueError:
            pass


# -- fakes ----------------------------------------------------------------


class FakeBus:
    """Bare EventBus that matches the public surface used by the watcher."""

    def __init__(self):
        self._subs = defaultdict(list)

    def on(self, event_type, callback):
        self._subs[event_type].append(callback)

        def unsub():
            try:
                self._subs[event_type].remove(callback)
            except ValueError:
                pass

        return unsub

    def emit(self, event_type, data=None):
        for cb in list(self._subs[event_type]):
            cb(data)


class Clock:
    """Controllable clock for deterministic timestamps."""

    def __init__(self, start: datetime):
        self._now = start

    def __call__(self) -> datetime:
        return self._now

    def advance(self, **kwargs) -> None:
        self._now = self._now + timedelta(**kwargs)

    def set(self, dt: datetime) -> None:
        self._now = dt


class EventLogSink:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, event: str, **fields) -> None:
        self.calls.append((event, fields))

    def of_type(self, event: str) -> list[dict]:
        return [fields for ev, fields in self.calls if ev == event]


# -- helpers --------------------------------------------------------------


def _t(h: int = 0, m: int = 0, s: int = 0) -> datetime:
    return datetime(2026, 4, 24, h, m, s, tzinfo=timezone.utc)


def _load_seed_rules() -> list[dict]:
    from audit.watcher import load_rules_from_yaml

    rules_path = FUN_DOC_DIR / "audit" / "rules.yaml"
    return load_rules_from_yaml(rules_path)


def _rule_by_id(rules: list[dict], rule_id: str) -> dict:
    for r in rules:
        if r.get("id") == rule_id:
            return r
    raise KeyError(f"rule {rule_id!r} not in rules.yaml")


def _make_watcher(
    tmp_path,
    *,
    rules,
    bridge_counters=None,
    clock=None,
    bus=None,
):
    from audit.registry import AuditRegistry
    from audit.watcher import AuditWatcher

    counters = dict(bridge_counters or {})
    clock = clock or Clock(_t(0))
    registry = AuditRegistry(tmp_path / "registry.json")
    sink = EventLogSink()
    watcher = AuditWatcher(
        bus=bus or FakeBus(),
        registry=registry,
        rules=rules,
        queue_path=tmp_path / "queue.jsonl",
        bridge_counters_fetcher=lambda: dict(counters),
        eval_interval_seconds=9999,  # we never start the thread in tests
        now_fn=clock,
        log_event_fn=sink,
    )
    return watcher, registry, sink, counters


def _queue_entries(tmp_path) -> list[dict]:
    path = tmp_path / "queue.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


# -- rules.yaml sanity ----------------------------------------------------


def test_seed_rules_all_report_mode():
    """Phase 1 contract: no rule graduates above `report` yet."""
    rules = _load_seed_rules()
    assert len(rules) == 5
    for rule in rules:
        assert rule.get("mode") == "report", f"{rule['id']} is not at report mode"


def test_seed_rules_have_required_fields():
    rules = _load_seed_rules()
    for rule in rules:
        for required in ("id", "kind", "mode", "signature", "condition"):
            assert required in rule, f"{rule.get('id')} missing {required!r}"


# -- bridge_counter_stall -------------------------------------------------


def test_bridge_counter_stall_fires_after_duration(tmp_path):
    rules = [_rule_by_id(_load_seed_rules(), "bridge_counter_stall")]
    clock = Clock(_t(0))
    watcher, _reg, sink, counters = _make_watcher(
        tmp_path, rules=rules, clock=clock
    )
    # Subscribe the watcher to its bus so worker events land in state.
    watcher._subscribe()

    # Worker active; tool_call counter at zero.
    watcher._bus.emit("worker_started", {"worker_id": "w1"})
    counters.update({"tool_call": 0, "tool_result": 0, "model_text": 0})

    # Tick at t=0 — records stall start, does NOT fire yet.
    watcher._tick()
    assert _queue_entries(tmp_path) == []

    # Advance past duration_seconds (30 min from seed rule).
    clock.advance(minutes=31)
    watcher._tick()

    entries = _queue_entries(tmp_path)
    # One fire per event_type that stalled. Seed rule has 3 event types
    # but the first fire trips cooldown for its signature only; the
    # others share the evaluation loop and fire independently.
    assert len(entries) >= 1
    assert all(e["rule_id"] == "bridge_counter_stall" for e in entries)
    fired_event_types = {e["context"]["event_type"] for e in entries}
    assert fired_event_types & {"tool_call", "tool_result", "model_text"}

    # audit.triggered event emitted
    assert sink.of_type("audit.triggered"), "expected an audit.triggered event"


def test_bridge_counter_stall_does_not_fire_when_no_workers(tmp_path):
    """Stall timer should only run while workers are active."""
    rules = [_rule_by_id(_load_seed_rules(), "bridge_counter_stall")]
    clock = Clock(_t(0))
    watcher, _reg, _sink, counters = _make_watcher(
        tmp_path, rules=rules, clock=clock
    )
    watcher._subscribe()

    # No workers.
    counters.update({"tool_call": 0, "tool_result": 0, "model_text": 0})
    watcher._tick()
    clock.advance(hours=2)
    watcher._tick()
    assert _queue_entries(tmp_path) == []


def test_bridge_counter_stall_resets_when_counter_moves(tmp_path):
    """A counter incrementing to non-zero must clear the stall timer."""
    rules = [_rule_by_id(_load_seed_rules(), "bridge_counter_stall")]
    clock = Clock(_t(0))
    watcher, _reg, _sink, counters = _make_watcher(
        tmp_path, rules=rules, clock=clock
    )
    watcher._subscribe()
    watcher._bus.emit("worker_started", {"worker_id": "w1"})

    counters.update({"tool_call": 0, "tool_result": 0, "model_text": 0})
    watcher._tick()  # seeds stall start
    clock.advance(minutes=29)  # still inside window
    counters["tool_call"] = 5
    counters["tool_result"] = 5
    counters["model_text"] = 5
    watcher._tick()  # stall cleared; timers reset

    clock.advance(minutes=5)  # original 30min boundary would fire, but timer was reset
    counters.update({"tool_call": 0, "tool_result": 0, "model_text": 0})
    watcher._tick()
    assert _queue_entries(tmp_path) == []


# -- worker_crashed -------------------------------------------------------


def test_worker_crashed_fires_on_unexpected_reason(tmp_path):
    rules = [_rule_by_id(_load_seed_rules(), "worker_crashed")]
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules)
    watcher._subscribe()

    watcher._bus.emit("worker_started", {"worker_id": "w1"})
    watcher._bus.emit(
        "worker_stopped",
        {"worker_id": "w1", "reason": "crashed", "progress": {"completed": 3}},
    )

    entries = _queue_entries(tmp_path)
    assert len(entries) == 1
    assert entries[0]["rule_id"] == "worker_crashed"
    assert entries[0]["context"]["reason"] == "crashed"
    assert entries[0]["context"]["worker_id"] == "w1"
    assert entries[0]["context"]["progress"] == {"completed": 3}


@pytest.mark.parametrize("reason", ["finished", "stopped_by_user", "stopped"])
def test_worker_crashed_does_not_fire_on_acceptable_reasons(tmp_path, reason):
    rules = [_rule_by_id(_load_seed_rules(), "worker_crashed")]
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules)
    watcher._subscribe()

    watcher._bus.emit("worker_started", {"worker_id": "w1"})
    watcher._bus.emit("worker_stopped", {"worker_id": "w1", "reason": reason})

    assert _queue_entries(tmp_path) == []


def test_worker_crashed_signature_slugs_weird_reasons(tmp_path):
    """Weird reason strings must produce a signature safe for filesystems."""
    rules = [_rule_by_id(_load_seed_rules(), "worker_crashed")]
    watcher, reg, _sink, _c = _make_watcher(tmp_path, rules=rules)
    watcher._subscribe()

    watcher._bus.emit("worker_started", {"worker_id": "w1"})
    watcher._bus.emit(
        "worker_stopped",
        {"worker_id": "w1", "reason": "killed: OOM (memory < 512MB)"},
    )
    entries = _queue_entries(tmp_path)
    assert len(entries) == 1
    sig = entries[0]["signature"]
    # Signature template is "worker_crash:{reason}" — slug keeps alnum/underscore
    assert sig.startswith("worker_crash:")
    assert all(
        ch.isalnum() or ch in ":_-" for ch in sig
    ), f"signature {sig!r} has unsafe chars"


# -- ghidra_offline_sustained --------------------------------------------


def test_ghidra_offline_sustained_fires_after_duration(tmp_path):
    rules = [_rule_by_id(_load_seed_rules(), "ghidra_offline_sustained")]
    clock = Clock(_t(0))
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules, clock=clock)
    watcher._subscribe()

    watcher._bus.emit("ghidra_health", {"new": "offline"})
    watcher._tick()
    assert _queue_entries(tmp_path) == []

    clock.advance(minutes=6)  # past 5m threshold
    watcher._tick()
    entries = _queue_entries(tmp_path)
    assert len(entries) == 1
    assert entries[0]["context"]["status"] == "offline"


def test_ghidra_offline_sustained_does_not_fire_when_recovers(tmp_path):
    rules = [_rule_by_id(_load_seed_rules(), "ghidra_offline_sustained")]
    clock = Clock(_t(0))
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules, clock=clock)
    watcher._subscribe()

    watcher._bus.emit("ghidra_health", {"new": "offline"})
    clock.advance(minutes=3)
    watcher._bus.emit("ghidra_health", {"new": "healthy"})
    clock.advance(minutes=10)
    watcher._tick()
    assert _queue_entries(tmp_path) == []


# -- provider_timeout_cluster --------------------------------------------


def test_provider_timeout_cluster_fires_after_three_in_window(tmp_path):
    rules = [_rule_by_id(_load_seed_rules(), "provider_timeout_cluster")]
    clock = Clock(_t(0))
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules, clock=clock)
    watcher._subscribe()

    for i in range(3):
        clock.advance(minutes=5)
        watcher._bus.emit("provider_timeout", {"provider": "minimax"})

    watcher._tick()
    entries = _queue_entries(tmp_path)
    assert len(entries) == 1
    assert entries[0]["context"]["count"] == 3
    assert entries[0]["context"]["provider"] == "minimax"
    assert entries[0]["signature"] == "provider_timeout_cluster:minimax"


def test_provider_timeout_cluster_groups_by_provider(tmp_path):
    """Two providers, each with N timeouts, should fire separate signatures."""
    rules = [_rule_by_id(_load_seed_rules(), "provider_timeout_cluster")]
    clock = Clock(_t(0))
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules, clock=clock)
    watcher._subscribe()

    for _ in range(3):
        clock.advance(minutes=2)
        watcher._bus.emit("provider_timeout", {"provider": "minimax"})
    for _ in range(3):
        clock.advance(minutes=2)
        watcher._bus.emit("provider_timeout", {"provider": "claude"})

    watcher._tick()
    entries = _queue_entries(tmp_path)
    providers = {e["context"]["provider"] for e in entries}
    assert providers == {"minimax", "claude"}


def test_provider_timeout_cluster_does_not_fire_below_threshold(tmp_path):
    rules = [_rule_by_id(_load_seed_rules(), "provider_timeout_cluster")]
    clock = Clock(_t(0))
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules, clock=clock)
    watcher._subscribe()

    for _ in range(2):
        clock.advance(minutes=5)
        watcher._bus.emit("provider_timeout", {"provider": "minimax"})

    watcher._tick()
    assert _queue_entries(tmp_path) == []


def test_provider_timeout_cluster_respects_window(tmp_path):
    """Timeouts outside the 1h window shouldn't count toward the threshold."""
    rules = [_rule_by_id(_load_seed_rules(), "provider_timeout_cluster")]
    clock = Clock(_t(0))
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules, clock=clock)
    watcher._subscribe()

    # Two very old timeouts (~2h before now)
    for _ in range(2):
        watcher._bus.emit("provider_timeout", {"provider": "minimax"})
    clock.advance(hours=2)

    # One fresh timeout — total 3, but 2 are outside the 1h window.
    watcher._bus.emit("provider_timeout", {"provider": "minimax"})

    watcher._tick()
    assert _queue_entries(tmp_path) == []


# -- run_failure_rate_spike ----------------------------------------------


def test_run_failure_rate_fires_when_threshold_exceeded(tmp_path):
    rules = [_rule_by_id(_load_seed_rules(), "run_failure_rate_spike")]
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules)
    watcher._subscribe()

    # Seed 30 runs, 20 failed (rate = 66.7%).
    for _ in range(20):
        watcher._bus.emit("run_logged", {"result": "failed"})
    for _ in range(10):
        watcher._bus.emit("run_logged", {"result": "completed"})

    watcher._tick()
    entries = _queue_entries(tmp_path)
    assert len(entries) == 1
    assert entries[0]["rule_id"] == "run_failure_rate_spike"
    assert entries[0]["context"]["failure_rate"] >= 0.6


def test_run_failure_rate_does_not_fire_with_fewer_than_window(tmp_path):
    """Refuse to fire until we have a full window — noise on small samples."""
    rules = [_rule_by_id(_load_seed_rules(), "run_failure_rate_spike")]
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules)
    watcher._subscribe()

    for _ in range(5):
        watcher._bus.emit("run_logged", {"result": "failed"})

    watcher._tick()
    assert _queue_entries(tmp_path) == []


def test_run_failure_rate_does_not_fire_below_threshold(tmp_path):
    rules = [_rule_by_id(_load_seed_rules(), "run_failure_rate_spike")]
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules)
    watcher._subscribe()

    # 40% failure rate — below the 60% threshold.
    for _ in range(12):
        watcher._bus.emit("run_logged", {"result": "failed"})
    for _ in range(18):
        watcher._bus.emit("run_logged", {"result": "completed"})

    watcher._tick()
    assert _queue_entries(tmp_path) == []


def test_run_failure_rate_counts_ghidra_offline_as_failure(tmp_path):
    """ghidra_offline results should count toward the failure rate."""
    rules = [_rule_by_id(_load_seed_rules(), "run_failure_rate_spike")]
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules)
    watcher._subscribe()

    for _ in range(22):
        watcher._bus.emit("run_logged", {"result": "ghidra_offline"})
    for _ in range(8):
        watcher._bus.emit("run_logged", {"result": "completed"})

    watcher._tick()
    entries = _queue_entries(tmp_path)
    assert len(entries) == 1


# -- dedup integration ---------------------------------------------------


def test_second_fire_of_same_signature_hits_cooldown(tmp_path):
    """Same signature in back-to-back ticks shouldn't double-land."""
    rules = [_rule_by_id(_load_seed_rules(), "worker_crashed")]
    watcher, _reg, sink, _c = _make_watcher(tmp_path, rules=rules)
    watcher._subscribe()

    watcher._bus.emit("worker_started", {"worker_id": "w1"})
    watcher._bus.emit("worker_stopped", {"worker_id": "w1", "reason": "crashed"})
    watcher._bus.emit("worker_started", {"worker_id": "w2"})
    watcher._bus.emit("worker_stopped", {"worker_id": "w2", "reason": "crashed"})

    entries = _queue_entries(tmp_path)
    assert len(entries) == 1, "second identical signature must be deduped"
    # audit.skipped event recorded the suppression.
    skipped = sink.of_type("audit.skipped")
    assert any(s.get("reason") == "skip_cooldown" for s in skipped)


def test_different_signatures_not_deduped(tmp_path):
    """Different reasons → different sigs → both fire."""
    rules = [_rule_by_id(_load_seed_rules(), "worker_crashed")]
    watcher, _reg, _sink, _c = _make_watcher(tmp_path, rules=rules)
    watcher._subscribe()

    watcher._bus.emit("worker_stopped", {"worker_id": "w1", "reason": "crashed"})
    watcher._bus.emit("worker_stopped", {"worker_id": "w2", "reason": "timeout"})

    entries = _queue_entries(tmp_path)
    assert len(entries) == 2
    sigs = {e["signature"] for e in entries}
    assert len(sigs) == 2

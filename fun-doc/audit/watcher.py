"""
Audit watcher — in-process event-bus tap + periodic rule evaluator.

Phase 1 walking skeleton. The watcher subscribes to the shared event bus
(the same one the dashboard bridges to SocketIO) and maintains small
ring buffers of recent events. Every `eval_interval_seconds` it walks
the rules loaded from audit/rules.yaml, evaluates each against the
current buffers + bridge counters + worker status, and on match consults
the AuditRegistry to decide whether to fire, skip (cooldown), or skip
(circuit breaker tripped).

Fire path emits:
    audit.triggered  — rule matched AND decision == fire
    audit.queued     — trigger appended to audit/queue.jsonl
    audit.skipped    — rule matched but dedup/CB suppressed it
    audit.circuit_breaker_tripped — the fire that caused CB to trip

No agent is attached in Phase 1. The queue file just accumulates. Phase 3
wires the queue to a /schedule'd drain agent.

Thread model:
    One background thread runs the periodic tick. Bus subscribers may
    run on any thread (the bus emits synchronously on the caller's
    thread). A single module-level lock guards the watcher state so
    subscribers and the tick thread can safely interleave.

Testability:
    The watcher takes all externals as constructor args: bus, registry,
    rules (as a list), queue_path, bridge_counters_fetcher, now_fn. Tests
    drive bus.emit() + call watcher._tick() directly with a controllable
    clock, then assert on queue file contents + registry state.
"""

from __future__ import annotations

import json
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from .registry import AuditRegistry, FireDecision


# Event types the watcher subscribes to on the bus. Buffered for rules
# that need windowed history; other events only drive state transitions.
BUS_SUBSCRIPTIONS = (
    "ghidra_health",
    "worker_started",
    "worker_stopped",
    "provider_timeout",
    "run_logged",
)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class _WatcherState:
    """Mutable buffers. All access goes through AuditWatcher._lock."""

    active_workers: set[str] = field(default_factory=set)
    ghidra_status: Optional[str] = None            # "healthy" | "slow" | "offline" | None
    ghidra_status_since: Optional[datetime] = None

    # Ring buffers of recent events. Capped so long-running watchers
    # don't leak memory; bounds far exceed any rule's evaluation window.
    provider_timeouts: deque = field(default_factory=lambda: deque(maxlen=500))
    recent_runs: deque = field(default_factory=lambda: deque(maxlen=500))

    # Per (rule_id, event_type) — when did the bridge_counter_stall
    # condition start holding continuously? Cleared when condition breaks.
    stall_started_at: dict[tuple[str, str], datetime] = field(default_factory=dict)


class AuditWatcher:
    def __init__(
        self,
        *,
        bus,
        registry: AuditRegistry,
        rules: list[dict[str, Any]],
        queue_path: Path,
        bridge_counters_fetcher: Callable[[], dict[str, int]],
        eval_interval_seconds: float = 30.0,
        now_fn: Callable[[], datetime] = _now_utc,
        log_event_fn: Optional[Callable[..., None]] = None,
    ):
        self._bus = bus
        self._registry = registry
        self._rules = list(rules)
        self._queue_path = Path(queue_path)
        self._fetch_bridge_counters = bridge_counters_fetcher
        self._eval_interval = float(eval_interval_seconds)
        self._now = now_fn

        self._state = _WatcherState()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._unsubs: list[Callable[[], None]] = []

        self._log_event = log_event_fn or _default_log_event

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        self._subscribe()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="audit-watcher",
        )
        self._thread.start()

    def stop(self, join_timeout: float = 2.0) -> None:
        self._stop.set()
        for unsub in self._unsubs:
            try:
                unsub()
            except Exception:
                pass
        self._unsubs.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)

    # -- subscription -----------------------------------------------------

    def _subscribe(self) -> None:
        handlers = {
            "ghidra_health": self._on_ghidra_health,
            "worker_started": self._on_worker_started,
            "worker_stopped": self._on_worker_stopped,
            "provider_timeout": self._on_provider_timeout,
            "run_logged": self._on_run_logged,
        }
        for evt in BUS_SUBSCRIPTIONS:
            unsub = self._bus.on(evt, handlers[evt])
            if unsub:
                self._unsubs.append(unsub)

    def _on_ghidra_health(self, data: Optional[dict[str, Any]]) -> None:
        data = data or {}
        new = data.get("new") or data.get("status")
        if not new:
            return
        with self._lock:
            if self._state.ghidra_status != new:
                self._state.ghidra_status_since = self._now()
            self._state.ghidra_status = new

    def _on_worker_started(self, data: Optional[dict[str, Any]]) -> None:
        data = data or {}
        wid = data.get("worker_id")
        if not wid:
            return
        with self._lock:
            self._state.active_workers.add(wid)

    def _on_worker_stopped(self, data: Optional[dict[str, Any]]) -> None:
        data = data or {}
        wid = data.get("worker_id")
        reason = (data.get("reason") or "").strip()
        with self._lock:
            if wid:
                self._state.active_workers.discard(wid)
        # Immediate event-driven rule: worker crashed.
        self._check_worker_crashed(reason, wid, data)

    def _on_provider_timeout(self, data: Optional[dict[str, Any]]) -> None:
        data = data or {}
        with self._lock:
            self._state.provider_timeouts.append(
                {"ts": self._now(), "provider": data.get("provider", "?")}
            )

    def _on_run_logged(self, data: Optional[dict[str, Any]]) -> None:
        data = data or {}
        with self._lock:
            self._state.recent_runs.append(
                {"ts": self._now(), "result": data.get("result")}
            )

    # -- periodic tick ----------------------------------------------------

    def _run_loop(self) -> None:
        while not self._stop.wait(self._eval_interval):
            try:
                self._tick()
            except Exception as exc:  # never let a bad tick kill the loop
                print(
                    f"  [audit_watcher] tick error: {type(exc).__name__}: {exc}",
                    flush=True,
                )

    def _tick(self) -> None:
        """Public-ish for tests: evaluate all rules once, synchronously."""
        try:
            counters = self._fetch_bridge_counters() or {}
        except Exception:
            counters = {}

        for rule in self._rules:
            kind = rule.get("kind")
            try:
                if kind == "bridge_counter_stall":
                    self._eval_bridge_counter_stall(rule, counters)
                elif kind == "ghidra_offline_sustained":
                    self._eval_ghidra_offline_sustained(rule)
                elif kind == "event_count_in_window":
                    self._eval_event_count_in_window(rule)
                elif kind == "run_failure_rate":
                    self._eval_run_failure_rate(rule)
                elif kind == "worker_stopped_unexpectedly":
                    # Event-driven; handled in _on_worker_stopped.
                    pass
                # Unknown kinds are silently ignored — adding a new kind
                # should land in this dispatch + its own evaluator method.
            except Exception as exc:
                print(
                    f"  [audit_watcher] rule {rule.get('id')!r} eval error: "
                    f"{type(exc).__name__}: {exc}",
                    flush=True,
                )

    # -- rule evaluators --------------------------------------------------

    def _eval_bridge_counter_stall(
        self, rule: dict[str, Any], bridge_counters: dict[str, int]
    ) -> None:
        cond = rule.get("condition") or {}
        event_types = list(cond.get("event_types") or [])
        duration = float(cond.get("duration_seconds", 1800))
        workers_min = int(cond.get("workers_active_min", 1))
        target = int(cond.get("value", 0))

        now = self._now()
        with self._lock:
            workers_active = len(self._state.active_workers)

            if workers_active < workers_min:
                # Guard not met — reset any in-flight stall timers for this rule.
                for et in event_types:
                    self._state.stall_started_at.pop((rule["id"], et), None)
                return

            for event_type in event_types:
                counter = int(bridge_counters.get(event_type, 0))
                key = (rule["id"], event_type)
                if counter <= target:
                    start = self._state.stall_started_at.get(key)
                    if start is None:
                        self._state.stall_started_at[key] = now
                        continue
                    elapsed = (now - start).total_seconds()
                    if elapsed >= duration:
                        signature = rule["signature"].format(event_type=event_type)
                        context = {
                            "event_type": event_type,
                            "counter_value": counter,
                            "workers_active": workers_active,
                            "stall_duration_seconds": round(elapsed, 1),
                        }
                        # Fire can re-arm the stall start so we don't
                        # re-fire every tick — the cooldown handles that,
                        # but clearing the start also protects against
                        # registry loss.
                        self._state.stall_started_at.pop(key, None)
                        # Drop the lock before calling _fire (which also
                        # locks via registry). Keep the local variables.
                        self._fire_release_lock(rule, signature, context)
                        return
                else:
                    self._state.stall_started_at.pop(key, None)

    def _eval_ghidra_offline_sustained(self, rule: dict[str, Any]) -> None:
        cond = rule.get("condition") or {}
        duration = float(cond.get("duration_seconds", 300))
        now = self._now()

        with self._lock:
            status = self._state.ghidra_status
            since = self._state.ghidra_status_since

        if status != "offline" or since is None:
            return
        elapsed = (now - since).total_seconds()
        if elapsed < duration:
            return
        self._fire(
            rule,
            rule["signature"],
            {"status": "offline", "elapsed_seconds": round(elapsed, 1)},
        )

    def _eval_event_count_in_window(self, rule: dict[str, Any]) -> None:
        cond = rule.get("condition") or {}
        event_name = cond.get("event")
        count_min = int(cond.get("count_min", 3))
        window = float(cond.get("window_seconds", 3600))
        group_field = cond.get("group_by_field")

        now = self._now()
        cutoff = now - timedelta(seconds=window)

        with self._lock:
            if event_name == "provider_timeout":
                recent = [e for e in self._state.provider_timeouts if e["ts"] >= cutoff]
            else:
                return  # unsupported — extend here when adding more rules

        if group_field:
            groups: dict[str, list] = defaultdict(list)
            for e in recent:
                groups[e.get(group_field, "?")].append(e)
            for group_value, items in groups.items():
                if len(items) >= count_min:
                    signature = rule["signature"].format(**{group_field: group_value})
                    context = {
                        "count": len(items),
                        "window_seconds": window,
                        group_field: group_value,
                    }
                    self._fire(rule, signature, context)
        else:
            if len(recent) >= count_min:
                self._fire(
                    rule,
                    rule["signature"],
                    {"count": len(recent), "window_seconds": window},
                )

    def _eval_run_failure_rate(self, rule: dict[str, Any]) -> None:
        cond = rule.get("condition") or {}
        window_runs = int(cond.get("window_runs", 30))
        threshold = float(cond.get("threshold", 0.6))
        failure_results = {"failed", "error", "ghidra_offline"}

        with self._lock:
            runs = list(self._state.recent_runs)[-window_runs:]

        if len(runs) < window_runs:
            return  # need a full window before firing
        failed = sum(1 for r in runs if r.get("result") in failure_results)
        rate = failed / len(runs)
        if rate < threshold:
            return
        self._fire(
            rule,
            rule["signature"],
            {
                "failure_rate": round(rate, 3),
                "window_runs": window_runs,
                "failed_count": failed,
            },
        )

    def _check_worker_crashed(
        self,
        reason: str,
        worker_id: Optional[str],
        data: dict[str, Any],
    ) -> None:
        if not reason:
            return
        for rule in self._rules:
            if rule.get("kind") != "worker_stopped_unexpectedly":
                continue
            cond = rule.get("condition") or {}
            acceptable = set(cond.get("acceptable_reasons") or [])
            if reason in acceptable:
                return
            signature = rule["signature"].format(reason=_slug(reason))
            context = {"reason": reason, "worker_id": worker_id}
            if "progress" in data:
                context["progress"] = data["progress"]
            self._fire(rule, signature, context)
            return

    # -- fire -------------------------------------------------------------

    def _fire_release_lock(
        self, rule: dict[str, Any], signature: str, context: dict[str, Any]
    ) -> None:
        # Helper used when we've just released self._lock and want to fire
        # without re-acquiring. _fire itself doesn't take self._lock; this
        # is just a rename for readability at call sites that had to drop
        # the lock first.
        self._fire(rule, signature, context)

    def _fire(
        self, rule: dict[str, Any], signature: str, context: dict[str, Any]
    ) -> None:
        decision: FireDecision = self._registry.check_and_record_fire(signature)
        rule_id = rule.get("id", "<unknown>")
        mode = rule.get("mode", "report")
        base = {
            "rule_id": rule_id,
            "signature": signature,
            "mode": mode,
            "context": context,
        }

        if decision.action == "fire":
            self._append_queue(
                {
                    "ts": self._now().isoformat(),
                    "rule_id": rule_id,
                    "signature": signature,
                    "mode": mode,
                    "context": context,
                }
            )
            self._log_event("audit.triggered", **base)
            self._log_event(
                "audit.queued", rule_id=rule_id, signature=signature, mode=mode
            )
            if decision.circuit_breaker_tripped_this_fire:
                cb = self._registry.get_circuit_breaker_state()
                self._log_event(
                    "audit.circuit_breaker_tripped",
                    fires_window_size=len(cb.get("fires_window") or []),
                    halt_until=cb.get("halt_until"),
                )
        else:
            self._log_event(
                "audit.skipped",
                reason=decision.action,
                cooldown_expires_at=(
                    decision.cooldown_expires_at.isoformat()
                    if decision.cooldown_expires_at
                    else None
                ),
                circuit_breaker_halt_until=(
                    decision.circuit_breaker_halt_until.isoformat()
                    if decision.circuit_breaker_halt_until
                    else None
                ),
                **base,
            )

    def _append_queue(self, entry: dict[str, Any]) -> None:
        self._queue_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._queue_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    # -- introspection ----------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Used by dashboard panel (Phase 2)."""
        with self._lock:
            return {
                "active_workers": len(self._state.active_workers),
                "ghidra_status": self._state.ghidra_status,
                "ghidra_status_since": (
                    self._state.ghidra_status_since.isoformat()
                    if self._state.ghidra_status_since
                    else None
                ),
                "recent_provider_timeouts": len(self._state.provider_timeouts),
                "recent_runs": len(self._state.recent_runs),
                "stall_started_at": {
                    f"{rid}:{et}": ts.isoformat()
                    for (rid, et), ts in self._state.stall_started_at.items()
                },
            }


# -- public loader --------------------------------------------------------


def load_rules_from_yaml(path: Path) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    rules = data.get("rules") or []
    if not isinstance(rules, list):
        raise ValueError(f"{path}: 'rules' must be a list")
    return rules


# -- defaults -------------------------------------------------------------


def _default_log_event(event: str, **fields: Any) -> None:
    """Import lazily so tests can inject a fake without pulling event_log."""
    try:
        from event_log import log_event  # type: ignore
    except ImportError:
        return
    log_event(event, **fields)


def _slug(s: str, maxlen: int = 48) -> str:
    """Produce a safe signature fragment from an arbitrary reason string."""
    cleaned = "".join(ch if (ch.isalnum() or ch in "_-") else "_" for ch in s)
    return cleaned[:maxlen] or "unknown"

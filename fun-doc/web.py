"""
Fun-Doc Web Dashboard: Real-time control panel for RE documentation progress.

Features:
- WebSocket push updates via Flask-SocketIO (no page reloading)
- Live activity feed: tool calls, model text, score updates streaming
- Deduction breakdown: where are the points hiding?
- ROI-ranked work queue with pin/skip controls
- Scan triggers: rescan all or per-binary from the dashboard
- Run log stats: model performance, stuck functions
"""

import json
import os
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit as sio_emit

from event_bus import get_bus

import uuid

# Shared across workers so adaptive-refresh trigger fires once per stale run
# even with multiple concurrent workers hitting the threshold simultaneously.
_adaptive_refresh_lock = threading.Lock()

HEARTBEAT_INTERVAL_SEC = float(os.environ.get("FUNDOC_HEARTBEAT_INTERVAL_SEC", "30"))
STALL_KILL_THRESHOLD_SEC = float(os.environ.get("FUNDOC_STALL_KILL_THRESHOLD_SEC", "900"))


class WorkerManager:
    """Manages concurrent documentation worker threads (max 3)."""

    MAX_WORKERS = 12
    RESTORE_META_KEY = "dashboard_active_workers"

    def __init__(self, state_file, bus, socketio, load_queue, save_queue):
        self._workers = {}
        self._lock = threading.Lock()
        self._state_file = state_file
        self._bus = bus
        self._socketio = socketio
        self._in_progress_keys = set()
        self._load_queue = load_queue
        self._save_queue = save_queue
        self._bus.on("provider_timeout", self._handle_provider_timeout)
        self._watchdog_stop = threading.Event()
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            name="fun-doc-worker-watchdog",
            daemon=True,
        )
        self._watchdog_thread.start()

    def _set_phase(self, worker_id, phase):
        with self._lock:
            worker = self._workers.get(worker_id)
            if not worker:
                return
            worker["phase"] = phase
            worker["phase_since"] = datetime.now().isoformat()

    def _watchdog_loop(self):
        from event_log import log_event

        while not self._watchdog_stop.wait(HEARTBEAT_INTERVAL_SEC):
            now = datetime.now()
            heartbeats = []
            kill_requests = []
            with self._lock:
                for worker_id, worker in self._workers.items():
                    if worker.get("status") not in ("starting", "running", "stopping", "quota_paused"):
                        continue
                    last_raw = worker.get("last_heartbeat_at") or worker.get("started_at")
                    try:
                        last_dt = datetime.fromisoformat(last_raw)
                    except (TypeError, ValueError):
                        last_dt = now
                    stale_sec = max(0.0, (now - last_dt).total_seconds())
                    phase = worker.get("phase", "unknown")
                    if stale_sec > STALL_KILL_THRESHOLD_SEC and not worker.get("stall_kill_fired", False):
                        worker["stall_kill_fired"] = True
                        worker["stop_flag"].set()
                        worker["status"] = "stopping"
                        worker["restore_on_restart"] = False
                        worker["last_alert"] = {
                            "type": "stalled_kill",
                            "message": f"Worker stalled for {int(stale_sec)}s in phase {phase}",
                            "phase": phase,
                            "stale_sec": stale_sec,
                            "at": now.isoformat(),
                        }
                        kill_requests.append((worker_id, phase, stale_sec))
                        continue
                    worker["last_heartbeat_at"] = now.isoformat()
                    heartbeats.append({
                        "worker_id": worker_id,
                        "provider": worker.get("provider"),
                        "status": worker.get("status"),
                        "phase": phase,
                        "stale_sec": stale_sec,
                    })

            for hb in heartbeats:
                log_event("worker.heartbeat", **hb)

            for worker_id, phase, stale_sec in kill_requests:
                subprocesses_killed = 0
                try:
                    from fun_doc import kill_worker_subprocesses
                    subprocesses_killed = kill_worker_subprocesses(worker_id)
                except Exception:
                    subprocesses_killed = 0
                log_event(
                    "worker.stalled_kill",
                    worker_id=worker_id,
                    phase=phase,
                    stale_sec=stale_sec,
                    threshold_sec=int(STALL_KILL_THRESHOLD_SEC),
                    subprocesses_killed=subprocesses_killed,
                )

            if heartbeats or kill_requests:
                self._emit_status()

    def _serialize_worker(self, worker):
        return {
            "provider": worker["provider"],
            "count": worker["count"],
            "continuous": bool(worker.get("continuous", False)),
            "model": worker.get("model"),
            "binary": worker.get("binary"),
        }

    def _persist_active_workers(self):
        try:
            queue = self._load_queue()
            meta = dict(queue.get("meta") or {})
            meta[self.RESTORE_META_KEY] = [
                self._serialize_worker(w)
                for w in self._workers.values()
                if w.get("restore_on_restart", True)
                and w["status"] in ("starting", "running")
            ]
            queue["meta"] = meta
            self._save_queue(queue)
        except Exception as e:
            print(f"  Worker restore-state persist failed: {e}")

    def restore_workers(self):
        try:
            queue = self._load_queue()
            specs = list((queue.get("meta") or {}).get(self.RESTORE_META_KEY) or [])
        except Exception as e:
            print(f"  Worker restore-state load failed: {e}")
            return []

        restored = []
        for spec in specs[: self.MAX_WORKERS]:
            try:
                restored.append(
                    self.start_worker(
                        provider=spec.get("provider", "minimax"),
                        count=spec.get("count", 5),
                        model=spec.get("model"),
                        binary=spec.get("binary"),
                        continuous=bool(spec.get("continuous", False)),
                        restored=True,
                    )
                )
            except Exception as e:
                print(f"  Worker restore skipped: {e}")
        return restored

    def _handle_provider_timeout(self, data):
        if not isinstance(data, dict):
            return
        worker_id = data.get("worker_id")
        if not worker_id:
            return

        with self._lock:
            worker = self._workers.get(worker_id)
            if not worker:
                return
            worker["timeout_count"] = worker.get("timeout_count", 0) + 1
            worker["last_alert"] = {
                "type": "provider_timeout",
                "provider": data.get("provider"),
                "timeout_secs": data.get("timeout_secs"),
                "message": data.get("message") or "Provider timeout",
                "at": datetime.now().isoformat(),
            }
        self._emit_status()

    def start_worker(
        self,
        provider="minimax",
        count=5,
        model=None,
        binary=None,
        continuous=False,
        restored=False,
    ):
        with self._lock:
            active = {
                wid: w
                for wid, w in self._workers.items()
                if w["status"] in ("starting", "running", "stopping")
            }
            if len(active) >= self.MAX_WORKERS:
                active_info = ", ".join(
                    f"{w['provider']}#{wid}({w['status']})" for wid, w in active.items()
                )
                raise ValueError(
                    f"Maximum {self.MAX_WORKERS} workers ({len(active)} active: {active_info})"
                )

            worker_id = str(uuid.uuid4())[:8]
            stop_flag = threading.Event()

            # Capture a frozen snapshot of every queue.config field that
            # should remain constant for this worker's lifetime. See
            # fun_doc.build_worker_config_snapshot for the schema. The
            # snapshot is opaque to WorkerManager — _run_worker passes
            # it through to process_function on every iteration. Nothing
            # mutates the snapshot after this point; live config edits via
            # the dashboard apply only to workers started AFTER the edit.
            try:
                from fun_doc import build_worker_config_snapshot, load_priority_queue
                config_snapshot = build_worker_config_snapshot(
                    load_priority_queue(), provider
                )
            except Exception as e:
                # Snapshot is best-effort. If we can't build one (rare —
                # corrupt queue file etc.), fall back to None and the
                # worker will use live config reads, matching pre-snapshot
                # behavior.
                print(f"  WARNING: config snapshot build failed: {e}")
                config_snapshot = None

            worker = {
                "id": worker_id,
                "provider": provider,
                "count": count,
                "continuous": continuous,
                "model": model,
                "binary": binary,
                "thread": None,
                "stop_flag": stop_flag,
                "started_at": datetime.now().isoformat(),
                "status": "starting",
                "restored": bool(restored),
                "restore_on_restart": True,
                "timeout_count": 0,
                "last_alert": None,
                "config_snapshot": config_snapshot,
                "phase": "starting",
                "phase_since": datetime.now().isoformat(),
                "stall_kill_fired": False,
                "last_heartbeat_at": datetime.now().isoformat(),
                "progress": {
                    "completed": 0,
                    "skipped": 0,
                    "failed": 0,
                    "current": None,
                },
            }
            self._workers[worker_id] = worker
            self._persist_active_workers()

        thread = threading.Thread(
            target=self._run_worker, args=(worker_id,), daemon=True
        )
        worker["thread"] = thread
        thread.start()
        self._emit_status()
        return worker_id

    def stop_worker(self, worker_id):
        with self._lock:
            worker = self._workers.get(worker_id)
            if not worker:
                raise ValueError(f"Unknown worker: {worker_id}")
            worker["stop_flag"].set()
            worker["status"] = "stopping"
            worker["restore_on_restart"] = False
            self._persist_active_workers()
        self._emit_status()

    def has_active_workers(self):
        """True if any doc worker is starting/running/stopping. Used by the
        background InventoryScorer to yield MCP bandwidth (Q1 idle-time backfill,
        Q7 cooperative pause)."""
        with self._lock:
            return any(
                w["status"] in ("starting", "running", "stopping")
                for w in self._workers.values()
            )

    def get_status(self):
        with self._lock:
            # Prune workers finished > 5 minutes ago
            now = datetime.now()
            stale = [
                wid
                for wid, w in self._workers.items()
                if w["status"] in ("finished", "stopped")
                and (
                    now - datetime.fromisoformat(w.get("finished_at", w["started_at"]))
                ).total_seconds()
                > 300
            ]
            for wid in stale:
                del self._workers[wid]

            rows = []
            for w in self._workers.values():
                try:
                    phase_since_dt = (
                        datetime.fromisoformat(w["phase_since"])
                        if w.get("phase_since")
                        else None
                    )
                except (TypeError, ValueError):
                    phase_since_dt = None
                try:
                    heartbeat_dt = datetime.fromisoformat(
                        w.get("last_heartbeat_at") or w.get("started_at")
                    )
                    heartbeat_age = (now - heartbeat_dt).total_seconds()
                except (TypeError, ValueError):
                    heartbeat_age = 0.0
                rows.append(
                    {
                    "id": w["id"],
                    "provider": w["provider"],
                    "count": w["count"],
                    "continuous": w.get("continuous", False),
                    "model": w["model"],
                    "binary": w["binary"],
                    "status": w["status"],
                    "restored": bool(w.get("restored", False)),
                    "timeout_count": int(w.get("timeout_count", 0) or 0),
                    "last_alert": (
                        dict(w["last_alert"]) if w.get("last_alert") else None
                    ),
                    "progress": dict(w["progress"]),
                    "started_at": w["started_at"],
                    # Snapshot is what the dashboard renders in the per-worker
                    # config sub-line. Unconditionally emitted so the dashboard
                    # can detect drift vs current live config and show the
                    # save-time toast (Q5). None for legacy/CLI workers; the
                    # dashboard renders no sub-line in that case.
                    "config_snapshot": w.get("config_snapshot"),
                    # Quota-pause fields populated when status == "quota_paused".
                    "paused_until": w.get("paused_until"),
                    "paused_reason": w.get("paused_reason"),
                    "phase": w.get("phase"),
                    "phase_since": w.get("phase_since"),
                    "phase_age_sec": (
                        max(0.0, (now - phase_since_dt).total_seconds())
                        if phase_since_dt
                        else None
                    ),
                    "last_heartbeat_at": w.get("last_heartbeat_at"),
                    "stall_kill_fired": bool(w.get("stall_kill_fired", False)),
                    "is_stale": heartbeat_age > STALL_KILL_THRESHOLD_SEC,
                    }
                )
            return rows

    def _run_worker(self, worker_id):
        """Worker loop — fetches one function at a time to avoid conflicts with other workers."""
        from event_bus import set_worker_id

        set_worker_id(worker_id)  # Tag all events from this thread

        worker = self._workers[worker_id]
        current_key = None
        try:
            from fun_doc import (
                load_state,
                get_next_functions,
                start_session,
                finalize_worker_session,
                process_function,
                refresh_candidate_scores,
                load_priority_queue,
                reset_handoff_counter,
                _bump_handoff_counter,
                get_auto_escalation_provider,
                update_function_state,
            )

            worker["status"] = "running"
            self._set_phase(worker_id, "starting")
            self._emit_status()
            self._bus.emit(
                "worker_started",
                {
                    "worker_id": worker_id,
                    "provider": worker["provider"],
                    "count": worker["count"],
                    "continuous": worker.get("continuous", False),
                    "restored": worker.get("restored", False),
                },
            )

            # Persist worker.started to events.jsonl with the frozen config
            # snapshot. This is the durable record that lets a future analysis
            # of runs.jsonl join on worker_id to see the exact config under
            # which each function was processed. Snapshot is None on workers
            # that started before the snapshot field existed (legacy/CLI),
            # which is fine — the field is just absent in those records.
            try:
                from event_log import log_event as _log_event
                _log_event(
                    "worker.started",
                    worker_id=worker_id,
                    provider=worker["provider"],
                    count=worker["count"],
                    continuous=bool(worker.get("continuous", False)),
                    binary=worker.get("binary"),
                    model=worker.get("model"),
                    restored=bool(worker.get("restored", False)),
                    config_snapshot=worker.get("config_snapshot"),
                )
            except Exception:
                # Event-log failures must not abort worker startup; the worker
                # is still functional, just less observable.
                pass

            state = load_state()
            original_binary = state.get("active_binary")
            if worker["binary"]:
                state["active_binary"] = worker["binary"]

            # Reset the per-session handoff counter so the dashboard indicator
            # reflects this run, not stale counts from a previous session.
            try:
                reset_handoff_counter()
            except Exception:
                pass

            # Pre-refresh: batch-rescore the top 20 ROI candidates before the loop.
            # Multiple gates prevent this from blocking worker startup under load:
            #   1. Config flag (pre_refresh_on_start) can disable entirely
            #   2. Freshness gate: skip if another worker refreshed < N minutes ago
            #   3. Binary gate: require active_binary (avoid cross-binary cascade)
            #   4. Short timeout (60s) + no individual fallback — fail fast
            #   5. Count clamped to 20 (was 50)
            try:
                self._set_phase(worker_id, "pre_refresh")
                pre_queue = load_priority_queue()
                pre_cfg = pre_queue.get("config") or {}
                pre_meta = pre_queue.get("meta") or {}
                pre_enabled = pre_cfg.get("pre_refresh_on_start", True)
                freshness_min = int(pre_cfg.get("pre_refresh_freshness_min", 5) or 5)
                worker_binary = worker.get("binary")

                skip_reason = None
                if not pre_enabled:
                    skip_reason = "disabled in config"
                elif not worker_binary:
                    skip_reason = "no active_binary selected (would touch every binary)"
                else:
                    # Freshness gate
                    last_refresh_at = pre_meta.get("last_refresh_at")
                    if last_refresh_at:
                        try:
                            last_dt = datetime.fromisoformat(last_refresh_at)
                            age_sec = (datetime.now() - last_dt).total_seconds()
                            if age_sec < freshness_min * 60:
                                skip_reason = (
                                    f"last refresh was {int(age_sec)}s ago "
                                    f"(freshness window {freshness_min}m)"
                                )
                        except (ValueError, TypeError):
                            pass

                if skip_reason:
                    print(f"  Pre-refresh: skipped ({skip_reason})")
                else:
                    print(
                        f"  Pre-refresh: scoring top 20 candidates for {worker_binary}..."
                    )
                    result = refresh_candidate_scores(
                        state,
                        active_binary=worker_binary,
                        count=20,
                        fallback=False,  # don't amplify failure into 25min block
                        first_batch_timeout=60,  # fail fast when Ghidra is unresponsive
                    )
                    print(
                        f"  Pre-refresh: {result['refreshed']} scored, "
                        f"{result['stale']} drifted >= 5pts"
                    )
                    self._bus.emit(
                        "queue_changed",
                        {
                            "action": "pre_refresh",
                            "refreshed": result["refreshed"],
                            "stale": result["stale"],
                        },
                    )
                    state = load_state()  # Pick up the saved refresh
                    if worker_binary:
                        state["active_binary"] = worker_binary
            except Exception as e:
                print(f"  Pre-refresh failed (continuing with stale state): {e}")

            self._set_phase(worker_id, "session_start")
            session = start_session(state)
            processed = 0
            # Threshold for adaptive refresh — this worker reads the shared
            # counter in queue.meta.stale_skips_since_refresh (bumped from
            # process_function) and triggers refresh when it crosses this.
            STALE_STREAK_THRESHOLD = 3

            # Load good_enough threshold for auto-escalation decisions
            good_enough = (
                load_priority_queue().get("config", {}).get("good_enough_score", 80)
            )

            # Resolve the worker's primary FULL model from the frozen snapshot.
            # The quota-pause gate keys on (provider, model); we check the
            # FULL-mode model since that's the dominant call on most functions.
            # Audit/handoff models on the same provider get their own pause
            # treatment via the Q10 skip-silently path inside process_function.
            def _worker_primary_model():
                snap = worker.get("config_snapshot") or {}
                providers = snap.get("providers") or {}
                p_entry = providers.get(worker["provider"]) or {}
                return (
                    (p_entry.get("models") or {}).get("FULL")
                    or worker.get("model")
                )

            def _yield_for_quota_pause():
                """If our (provider, FULL-model) is walled, set status to
                quota_paused and sleep until the pause clears or stop fires.
                Returns True if we yielded (caller should `continue` the loop)."""
                from provider_pause import get_default_manager as _get_pm

                primary_model = _worker_primary_model()
                if not primary_model:
                    return False
                pm = _get_pm()
                paused_until = pm.wait_until(worker["provider"], primary_model)
                if paused_until is None:
                    return False
                # Enter quota_paused state and sleep with periodic re-check.
                worker["status"] = "quota_paused"
                worker["paused_until"] = paused_until.isoformat()
                worker["paused_reason"] = (
                    pm.reason(worker["provider"], primary_model) or "quota wall"
                )
                self._emit_status()
                while not worker["stop_flag"].is_set():
                    now = datetime.now()
                    remaining = (paused_until - now).total_seconds()
                    if remaining <= 0:
                        break
                    # Re-check pause status every 30s so manual clears and
                    # external pause-set mutations get picked up promptly.
                    if worker["stop_flag"].wait(timeout=min(remaining, 30.0)):
                        break  # stop requested mid-pause
                    paused_until = pm.wait_until(worker["provider"], primary_model)
                    if paused_until is None:
                        break
                if not worker["stop_flag"].is_set():
                    worker["status"] = "running"
                    worker.pop("paused_until", None)
                    worker.pop("paused_reason", None)
                    self._emit_status()
                return True

            # Q8: manual start during a pause — yield immediately at loop entry
            # so the worker enters quota_paused without burning a redundant API
            # call to discover the wall.
            _yield_for_quota_pause()

            while not worker["stop_flag"].is_set() and (
                worker["continuous"] or processed < worker["count"]
            ):
                # Per-iteration pause check (Q1): another worker may have
                # discovered the wall while we were idle/processing. Yield
                # before picking the next function.
                if _yield_for_quota_pause():
                    if worker["stop_flag"].is_set():
                        break
                    continue

                # Reload state each iteration to get fresh scores/queue
                self._set_phase(worker_id, "select_function")
                state = load_state()
                if worker["binary"]:
                    state["active_binary"] = worker["binary"]

                # Get next function, skipping ones already in progress.
                # Fetch more candidates than needed so concurrent workers
                # don't all contend over the same small set.
                candidates = get_next_functions(state, count=50)
                target = None
                with self._lock:
                    for k, f in candidates:
                        if k not in self._in_progress_keys:
                            self._in_progress_keys.add(k)
                            target = (k, f)
                            current_key = k
                            break

                if target is None:
                    break  # No more work available

                key, func = target
                worker["progress"]["current"] = {
                    "key": key,
                    "name": func.get("name", "?"),
                    "address": func.get("address", "?"),
                }
                self._emit_status()
                self._bus.emit(
                    "worker_progress",
                    {
                        "worker_id": worker_id,
                        "current": worker["progress"]["current"],
                        "completed": worker["progress"]["completed"],
                        "total": worker["count"],
                    },
                )

                self._set_phase(worker_id, "process_function")
                result = process_function(
                    key,
                    func,
                    state,
                    model=worker["model"],
                    provider=worker["provider"],
                    stop_flag=worker["stop_flag"],
                    config_snapshot=worker.get("config_snapshot"),
                )

                # Optional immediate retry: only use an explicitly configured
                # provider. Do not silently fall back to a stronger provider.
                if (
                    result in ("completed", "partial", "failed", "needs_redo")
                    and not worker["stop_flag"].is_set()
                ):
                    # Re-read the function's current score from state
                    fresh = load_state()
                    fresh_func = fresh.get("functions", {}).get(key)
                    if fresh_func:
                        current_score = fresh_func.get("score", 0)
                        escalate_to = get_auto_escalation_provider(
                            worker["provider"], queue=load_priority_queue()
                        )
                        if (
                            current_score < good_enough
                            and current_score > 0
                            and escalate_to
                        ):
                            reason = (
                                "failed"
                                if result in ("failed", "needs_redo")
                                else f"score {current_score}%"
                            )
                            escalation_count = _bump_handoff_counter()
                            print(
                                f"\n  AUTO-ESCALATE #{escalation_count}: {worker['provider']} → {escalate_to} "
                                f"({reason}, below {good_enough}%)",
                                flush=True,
                            )
                            # Stamp per-function escalation tracking
                            from datetime import datetime as _dt

                            fresh_func["escalation_count"] = (
                                fresh_func.get("escalation_count", 0) + 1
                            )
                            fresh_func["last_escalated"] = _dt.now().isoformat()
                            fresh_func["last_escalation_from"] = worker["provider"]
                            fresh_func["last_escalation_to"] = escalate_to
                            update_function_state(key, fresh_func)
                            self._set_phase(worker_id, "auto_escalate")
                            escalate_result = process_function(
                                key,
                                fresh_func,
                                fresh,
                                model=None,  # auto-select for the escalation provider
                                provider=escalate_to,
                                stop_flag=worker["stop_flag"],
                                config_snapshot=worker.get("config_snapshot"),
                            )
                            # Use the escalation result for stats
                            if escalate_result in ("completed", "partial"):
                                result = escalate_result

                # Release the key immediately after processing
                with self._lock:
                    self._in_progress_keys.discard(key)
                    current_key = None

                processed += 1
                if result in ("quit", "stopped"):
                    break
                elif result == "rate_limited":
                    worker["progress"]["failed"] += 1
                    session["failed"] += 1
                    # Exponential backoff: 30s, 60s, 120s. After 3 consecutive
                    # rate-limited results, stop the worker.
                    rate_limit_streak = worker.get("_rate_limit_streak", 0) + 1
                    worker["_rate_limit_streak"] = rate_limit_streak
                    if rate_limit_streak >= 3:
                        self._bus.emit(
                            "worker_stopped",
                            {
                                "worker_id": worker_id,
                                "reason": "rate_limited (3 consecutive)",
                                "progress": dict(worker["progress"]),
                            },
                        )
                        break
                    backoff = 30 * (2 ** (rate_limit_streak - 1))  # 30s, 60s
                    print(
                        f"  Rate limited — backing off {backoff}s before retry "
                        f"(attempt {rate_limit_streak}/3)...",
                        flush=True,
                    )
                    worker["stop_flag"].wait(backoff)
                    if worker["stop_flag"].is_set():
                        break
                    continue  # retry with next function
                elif result in ("completed", "partial"):
                    worker["progress"]["completed"] += 1
                    session["completed"] += 1
                    session["functions"].append(key)
                    worker["_rate_limit_streak"] = 0  # reset on success
                elif result in ("skipped", "decompile_timeout"):
                    worker["progress"]["skipped"] += 1
                    session["skipped"] += 1
                elif result in ("failed", "blocked", "needs_redo"):
                    worker["progress"]["failed"] += 1
                    session["failed"] += 1
                else:
                    # Catch-all for any unhandled result type
                    worker["progress"]["completed"] += 1
                    session["completed"] += 1

                # Push updated progress to dashboard so the ok/fail
                # counters in the worker pane header update in real time
                self._emit_status()

                # Adaptive refresh: check the SHARED stale-skip counter in
                # queue.meta (bumped by process_function when it detects a
                # truly-stale skip). Multiple workers share one counter, and
                # the lock ensures only one worker actually runs the refresh
                # even if several cross the threshold at the same instant.
                # The 30s cooldown via last_refresh_at prevents rapid re-fires.
                if (
                    result == "skipped"
                    and func.get("last_result") == "skipped_above_threshold"
                ):
                    if _adaptive_refresh_lock.acquire(blocking=False):
                        try:
                            q = load_priority_queue()
                            meta = q.get("meta") or {}
                            count = int(meta.get("stale_skips_since_refresh", 0) or 0)
                            last_at = meta.get("last_refresh_at")
                            cooldown_ok = True
                            if last_at:
                                try:
                                    age = (
                                        datetime.now() - datetime.fromisoformat(last_at)
                                    ).total_seconds()
                                    if age < 30:
                                        cooldown_ok = False
                                except (ValueError, TypeError):
                                    pass
                            if count >= STALE_STREAK_THRESHOLD and cooldown_ok:
                                self._set_phase(worker_id, "adaptive_refresh")
                                print(
                                    f"  Detected {count} stale skips — batch refreshing..."
                                )
                                try:
                                    r = refresh_candidate_scores(
                                        state,
                                        active_binary=worker.get("binary"),
                                        count=50,
                                    )
                                    print(
                                        f"  Refresh: {r['refreshed']} scored, {r['stale']} drifted"
                                    )
                                    self._bus.emit(
                                        "queue_changed",
                                        {
                                            "action": "adaptive_refresh",
                                            "refreshed": r["refreshed"],
                                            "stale": r["stale"],
                                        },
                                    )
                                except Exception as e:
                                    print(f"  Adaptive refresh failed: {e}")
                        finally:
                            _adaptive_refresh_lock.release()

                self._emit_status()

            # Persist session + optional active_binary restore via a
            # read-modify-write that leaves state["functions"] alone. A
            # full-state save here would write the functions snapshot this
            # worker loaded, clobbering per-function updates written
            # concurrently by other workers via update_function_state().
            self._set_phase(worker_id, "finalize_session")
            if worker["binary"] and original_binary != worker["binary"]:
                finalize_worker_session(session, active_binary=original_binary)
            else:
                finalize_worker_session(session)

        except Exception as e:
            self._bus.emit(
                "worker_stopped", {"worker_id": worker_id, "reason": f"error: {e}"}
            )
        finally:
            worker["status"] = (
                "finished" if not worker["stop_flag"].is_set() else "stopped"
            )
            worker["restore_on_restart"] = False
            worker["finished_at"] = datetime.now().isoformat()
            worker["progress"]["current"] = None
            with self._lock:
                if current_key:
                    self._in_progress_keys.discard(current_key)
                self._persist_active_workers()
            self._emit_status()
            self._bus.emit(
                "worker_stopped",
                {
                    "worker_id": worker_id,
                    "reason": worker["status"],
                    "progress": dict(worker["progress"]),
                },
            )

    def _emit_status(self):
        self._socketio.emit("worker_status", self.get_status())


def create_app(state_file, event_bus=None):
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["STATE_FILE"] = Path(state_file)
    app.config["LOG_FILE"] = Path(__file__).parent / "logs" / "runs.jsonl"
    app.config["QUEUE_FILE"] = Path(__file__).parent / "priority_queue.json"

    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

    # Wire EventBus -> SocketIO bridge
    bus = event_bus or get_bus()

    def bridge(event_type):
        """Forward EventBus events to all WebSocket clients."""

        def handler(data):
            socketio.emit(event_type, data or {})

        return handler

    for evt in [
        "scan_started",
        "scan_progress",
        "scan_complete",
        "function_started",
        "function_mode",
        "function_complete",
        "tool_call",
        "tool_result",
        "model_text",
        "score_update",
        "state_changed",
        "run_logged",
        "queue_changed",
        "worker_started",
        "worker_progress",
        "worker_stopped",
        "provider_timeout",
    ]:
        bus.on(evt, bridge(evt))

    # --- Data loading helpers ---

    def load_state():
        sf = app.config["STATE_FILE"]
        if not sf.exists():
            return {
                "functions": {},
                "sessions": [],
                "project_folder": "unknown",
                "last_scan": None,
            }
        # Retry on partial read (race with concurrent save_state)
        for attempt in range(3):
            try:
                with open(sf, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, ValueError):
                if attempt < 2:
                    import time

                    time.sleep(0.1)
        return {
            "functions": {},
            "sessions": [],
            "project_folder": "unknown",
            "last_scan": None,
        }

    def _save_state_inline(state):
        """Save state from web.py context — uses fun_doc's lock if available."""
        sf = app.config["STATE_FILE"]
        try:
            from fun_doc import _state_lock

            with _state_lock:
                with open(sf, "w") as f:
                    json.dump(state, f, indent=2, default=str)
        except ImportError:
            with open(sf, "w") as f:
                json.dump(state, f, indent=2, default=str)

    def load_queue():
        from fun_doc import load_priority_queue

        return load_priority_queue()

    def save_queue(queue):
        from fun_doc import save_priority_queue

        save_priority_queue(queue)

    def load_run_logs(max_lines=500):
        lf = app.config["LOG_FILE"]
        if not lf.exists():
            return []
        lines = []
        try:
            with open(lf, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            lines.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            return lines[-max_lines:]
        except Exception:
            return []

    def count_run_totals():
        """Fast line-counting for today_runs and total_runs without parsing
        every JSON entry. Only parses enough to check the date prefix."""
        lf = app.config["LOG_FILE"]
        if not lf.exists():
            return 0, 0
        today = datetime.now().date().isoformat()
        total = 0
        today_count = 0
        try:
            with open(lf, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    total += 1
                    # Fast date check: timestamp is always the first field
                    # in the JSON: {"timestamp": "2026-04-17T...
                    if f'"timestamp": "{today}' in line:
                        today_count += 1
        except Exception:
            pass
        return total, today_count

    # --- Compute functions ---

    def compute_deduction_breakdown(funcs):
        cats = defaultdict(lambda: {"count": 0, "total_pts": 0.0, "functions": 0})
        for f in funcs.values():
            seen = set()
            for d in f.get("deductions", []):
                cat = d.get("category", "unknown")
                if not d.get("fixable", False):
                    continue
                cats[cat]["count"] += d.get("count", 1)
                cats[cat]["total_pts"] += d.get("points", 0)
                if cat not in seen:
                    cats[cat]["functions"] += 1
                    seen.add(cat)
        return sorted(
            [{"category": k, **v} for k, v in cats.items()],
            key=lambda x: x["total_pts"],
            reverse=True,
        )

    def compute_roi_queue(funcs, queue, active_binary=None):
        from fun_doc import select_candidates

        candidates = select_candidates(funcs, queue, active_binary=active_binary)
        good_enough = queue.get("config", {}).get("good_enough_score", 80)
        result = []
        for c in candidates:
            f = c["func"]
            # Count undocumented callees (deps remaining)
            callees = f.get("callees", [])
            if not callees:
                deps_remaining = 0
            else:
                prog = f.get("program")
                deps_remaining = 0
                for ca in callees:
                    ck = f"{prog}::{ca}"
                    cf = funcs.get(ck)
                    if cf and cf.get("score", 0) < good_enough:
                        deps_remaining += 1
            result.append(
                {
                    "key": c["key"],
                    "name": f["name"],
                    "address": f["address"],
                    "program": f.get("program_name", ""),
                    "score": f.get("score", 0),
                    "fixable": round(f.get("fixable", 0), 1),
                    "callers": f.get("caller_count", 0),
                    "roi": round(c["roi"], 1),
                    "readiness": round(c.get("readiness", 1.0), 2),
                    "deps_remaining": deps_remaining,
                    "is_leaf": f.get("is_leaf", False),
                    "call_graph_layer": c.get("call_graph_layer"),
                    "last_result": f.get("last_result"),
                    "pinned": c["pinned"],
                    "needs_scoring": c["needs_scoring"],
                    "classification": f.get("classification", ""),
                }
            )
        return result

    def compute_run_stats(logs, total_override=None, today_override=None):
        empty = {
            "total_runs": total_override or 0,
            "today_runs": today_override or 0,
            "avg_delta": 0,
            "success_rate": 0,
            "by_provider": {},
            "handoffs": {"total": 0, "top_pairs": [], "top_chains": []},
            "stuck_functions": [],
            "failure_modes": {},
            "regressions": 0,
            "zero_delta": 0,
            "audit": {
                "ran": 0,
                "improved": 0,
                "regressed": 0,
                "no_change": 0,
                "skipped_good": 0,
                "skipped_delta": 0,
                "today_ran": 0,
                "today_improved": 0,
                "today_skipped_good": 0,
                "today_skipped_delta": 0,
            },
            "today": {"runs": 0, "success_rate": 0, "avg_delta": 0, "by_provider": {}},
        }
        if not logs:
            return empty

        today = datetime.now().date().isoformat()
        today_logs = [l for l in logs if l.get("timestamp", "").startswith(today)]

        deltas = []
        success = 0
        regressions = 0
        zero_delta = 0
        failure_modes = defaultdict(int)
        by_provider = defaultdict(
            lambda: {
                "runs": 0,
                "deltas": [],
                "success": 0,
                "failed": 0,
                "known_tool_calls": [],
                "unknown_tool_runs": 0,
                "today_runs": 0,
                "today_deltas": [],
                "today_success": 0,
            }
        )
        func_results = defaultdict(lambda: {"fails": 0, "name": "", "address": ""})
        handoff_pairs = defaultdict(int)
        handoff_chains = defaultdict(int)

        # Audit tracking
        audit_ran = 0
        audit_improved = 0
        audit_regressed = 0
        audit_no_change = 0
        audit_skipped_good = 0
        audit_skipped_delta = 0
        # Today-specific audit tracking
        today_audit_ran = 0
        today_audit_improved = 0
        today_audit_skipped_good = 0
        today_audit_skipped_delta = 0

        is_today = {}  # cache per-log today check

        for l in logs:
            before = l.get("score_before")
            after = l.get("score_after")
            result = l.get("result", "")
            provider = l.get("provider", "unknown")
            requested_provider = l.get("requested_provider") or provider
            provider_chain = l.get("provider_chain") or [requested_provider]
            delta = l.get("score_delta")
            tc = l.get("tool_calls")
            tc_known = bool(l.get("tool_calls_known", tc is not None and tc >= 0))
            l_today = l.get("timestamp", "").startswith(today)

            bp = by_provider[provider]

            if not isinstance(provider_chain, list) or not provider_chain:
                provider_chain = (
                    [requested_provider, provider]
                    if requested_provider != provider
                    else [provider]
                )
            chain_label = " -> ".join(str(x) for x in provider_chain)
            if requested_provider != provider or len(provider_chain) > 1:
                handoff_chains[chain_label] += 1
                handoff_pairs[f"{requested_provider} -> {provider}"] += 1

            if before is not None and after is not None:
                d = delta if delta is not None else (after - before)
                deltas.append(d)
                bp["deltas"].append(d)
                if d < 0:
                    regressions += 1
                elif d == 0 and result == "completed":
                    zero_delta += 1
                if l_today:
                    bp["today_deltas"].append(d)

            bp["runs"] += 1
            if l_today:
                bp["today_runs"] += 1

            if tc_known and isinstance(tc, (int, float)) and tc >= 0:
                bp["known_tool_calls"].append(tc)
            else:
                bp["unknown_tool_runs"] += 1

            if result == "completed":
                success += 1
                bp["success"] += 1
                if l_today:
                    bp["today_success"] += 1
            elif result in ("failed", "needs_redo", "blocked", "rate_limited"):
                bp["failed"] += 1
                failure_modes[result] += 1

            # Audit outcome
            ao = l.get("audit_outcome")
            if ao == "ran":
                audit_ran += 1
                if l_today:
                    today_audit_ran += 1
                ab = l.get("audit_score_before")
                aa = l.get("audit_score_after")
                if ab is not None and aa is not None:
                    if aa > ab:
                        audit_improved += 1
                        if l_today:
                            today_audit_improved += 1
                    elif aa < ab:
                        audit_regressed += 1
                    else:
                        audit_no_change += 1
            elif ao == "skipped_good_enough":
                audit_skipped_good += 1
                if l_today:
                    today_audit_skipped_good += 1
            elif ao == "skipped_delta":
                audit_skipped_delta += 1
                if l_today:
                    today_audit_skipped_delta += 1

            fkey = f"{l.get('program', '')}::{l.get('address', '')}"
            func_results[fkey]["name"] = l.get("function", "")
            func_results[fkey]["address"] = l.get("address", "")
            if result in ("failed", "needs_redo"):
                func_results[fkey]["fails"] += 1

        # Per-provider stats
        provider_stats = {}
        for p, data in sorted(by_provider.items()):
            d = data["deltas"]
            r = data["runs"]
            td = data["today_deltas"]
            tc = data["known_tool_calls"]
            provider_stats[p] = {
                "runs": r,
                "avg_delta": round(sum(d) / len(d), 1) if d else 0,
                "success_rate": round(data["success"] / r * 100, 1) if r else 0,
                "fail_rate": round(data["failed"] / r * 100, 1) if r else 0,
                "avg_tools": round(sum(tc) / len(tc), 1) if tc else 0,
                "known_tool_runs": len(tc),
                "unknown_tool_runs": data["unknown_tool_runs"],
                "today_runs": data["today_runs"],
                "today_avg_delta": round(sum(td) / len(td), 1) if td else 0,
                "today_success_rate": (
                    round(data["today_success"] / data["today_runs"] * 100, 1)
                    if data["today_runs"]
                    else 0
                ),
            }

        stuck = sorted(
            [
                {"name": v["name"], "address": v["address"], "fails": v["fails"]}
                for v in func_results.values()
                if v["fails"] >= 3
            ],
            key=lambda x: x["fails"],
            reverse=True,
        )[:10]

        # Today aggregate
        today_deltas = [
            l.get("score_delta", 0)
            for l in today_logs
            if l.get("score_before") is not None and l.get("score_after") is not None
        ]
        today_success = sum(1 for l in today_logs if l.get("result") == "completed")
        today_stats = {
            "runs": len(today_logs),
            "success_rate": (
                round(today_success / len(today_logs) * 100, 1) if today_logs else 0
            ),
            "avg_delta": (
                round(sum(today_deltas) / len(today_deltas), 1) if today_deltas else 0
            ),
        }

        return {
            "total_runs": total_override if total_override is not None else len(logs),
            "today_runs": (
                today_override if today_override is not None else len(today_logs)
            ),
            "avg_delta": round(sum(deltas) / len(deltas), 1) if deltas else 0,
            "success_rate": round(success / len(logs) * 100, 1) if logs else 0,
            "by_provider": provider_stats,
            "handoffs": {
                "total": sum(handoff_chains.values()),
                "top_pairs": sorted(
                    (
                        {"pair": pair, "count": count}
                        for pair, count in handoff_pairs.items()
                    ),
                    key=lambda x: x["count"],
                    reverse=True,
                )[:5],
                "top_chains": sorted(
                    (
                        {"chain": chain, "count": count}
                        for chain, count in handoff_chains.items()
                    ),
                    key=lambda x: x["count"],
                    reverse=True,
                )[:5],
            },
            "stuck_functions": stuck,
            "failure_modes": dict(failure_modes),
            "regressions": regressions,
            "zero_delta": zero_delta,
            "audit": {
                "ran": audit_ran,
                "improved": audit_improved,
                "regressed": audit_regressed,
                "no_change": audit_no_change,
                "skipped_good": audit_skipped_good,
                "skipped_delta": audit_skipped_delta,
                "today_ran": today_audit_ran,
                "today_improved": today_audit_improved,
                "today_skipped_good": today_audit_skipped_good,
                "today_skipped_delta": today_audit_skipped_delta,
            },
            "today": today_stats,
        }

    def compute_stats(state):
        all_funcs = state.get("functions", {})
        active_binary = state.get("active_binary")
        # Available binaries: merge Ghidra project files + already-scanned
        folder = state.get("project_folder", "/")
        project_binaries = _fetch_project_binaries(folder)
        scanned_binaries = sorted(
            set(f.get("program_name", "unknown") for f in all_funcs.values())
        )
        available_binaries = sorted(set(project_binaries + scanned_binaries))
        # Filter to active binary if set
        if active_binary:
            funcs = {
                k: v
                for k, v in all_funcs.items()
                if v.get("program_name") == active_binary
            }
        else:
            funcs = all_funcs
        total_all = len(funcs)
        # Exclude thunks/externals from all statistics — they're IAT stubs
        # that can't be documented and inflate the score distribution chart
        # with a misleading 0-9% block.
        scoreable = {
            k: v
            for k, v in funcs.items()
            if not v.get("is_thunk") and not v.get("is_external")
        }
        total = len(scoreable)
        queue = load_queue()
        cfg = queue.get("config", {})
        good_enough = cfg.get("good_enough_score", 80)
        queue_meta = queue.get("meta") or {}
        if total == 0:
            return {
                "total": 0,
                "done": 0,
                "fixable": 0,
                "needs_work": 0,
                "pct": 0,
                "audited": 0,
                "escalated": 0,
                "buckets": {},
                "by_program": {},
                "sessions": [],
                "roi_queue": [],
                "all_functions": [],
                "deduction_breakdown": [],
                "run_stats": compute_run_stats([]),
                "project_folder": state.get("project_folder", "unknown"),
                "active_binary": active_binary,
                "available_binaries": available_binaries,
                "available_folders": _fetch_project_folders(),
                "last_scan": state.get("last_scan"),
                "queue_config": cfg,
                "queue_meta": queue_meta,
            }
        fixable_lo = max(good_enough - 20, 0)
        done = sum(1 for f in scoreable.values() if f["score"] >= good_enough)
        fixable_count = sum(
            1 for f in scoreable.values() if fixable_lo <= f["score"] < good_enough
        )
        needs_work = sum(1 for f in scoreable.values() if f["score"] < fixable_lo)
        pct = (done / total * 100) if total > 0 else 0
        audited = sum(1 for f in scoreable.values() if f.get("audit_count", 0) > 0)
        escalated = sum(
            1 for f in scoreable.values() if f.get("escalation_count", 0) > 0
        )
        buckets = {
            "100": 0,
            "90-99": 0,
            "80-89": 0,
            "70-79": 0,
            "60-69": 0,
            "50-59": 0,
            "40-49": 0,
            "30-39": 0,
            "20-29": 0,
            "10-19": 0,
            "0-9": 0,
        }
        for f in scoreable.values():
            s = f["score"]
            if s >= 100:
                buckets["100"] += 1
            elif s >= 90:
                buckets["90-99"] += 1
            elif s >= 80:
                buckets["80-89"] += 1
            elif s >= 70:
                buckets["70-79"] += 1
            elif s >= 60:
                buckets["60-69"] += 1
            elif s >= 50:
                buckets["50-59"] += 1
            elif s >= 40:
                buckets["40-49"] += 1
            elif s >= 30:
                buckets["30-39"] += 1
            elif s >= 20:
                buckets["20-29"] += 1
            elif s >= 10:
                buckets["10-19"] += 1
            else:
                buckets["0-9"] += 1
        by_program = defaultdict(lambda: {"total": 0, "done": 0, "remaining": 0})
        for f in scoreable.values():
            prog = f.get("program_name", "unknown")
            by_program[prog]["total"] += 1
            if f["score"] >= good_enough:
                by_program[prog]["done"] += 1
            else:
                by_program[prog]["remaining"] += 1
        pinned_keys = set(queue.get("pinned", []))
        func_list = []
        for key, func in funcs.items():
            if func.get("is_thunk") or func.get("is_external"):
                continue
            func_list.append(
                {
                    "key": key,
                    "name": func["name"],
                    "address": func["address"],
                    "program": func.get("program_name", ""),
                    "score": func["score"],
                    "fixable": round(func.get("fixable", 0), 1),
                    "callers": func.get("caller_count", 0),
                    "is_leaf": func.get("is_leaf", False),
                    "last_result": func.get("last_result"),
                    "pinned": key in pinned_keys,
                    # True when state.json has never had analyze_function_completeness
                    # run for this entry — score=0 here means "unknown", not "0% done"
                    "unscored": not func.get("last_processed"),
                }
            )
        func_list.sort(key=lambda x: x["score"])
        all_func_total = len(func_list)
        return {
            "total": total,
            "done": done,
            "fixable": fixable_count,
            "needs_work": needs_work,
            "pct": round(pct, 1),
            "audited": audited,
            "escalated": escalated,
            "buckets": buckets,
            "by_program": dict(by_program),
            "sessions": state.get("sessions", [])[-10:],
            "roi_queue": compute_roi_queue(funcs, queue, active_binary=active_binary)[
                :50
            ],
            "all_functions": func_list,
            "all_functions_total": all_func_total,
            "deduction_breakdown": compute_deduction_breakdown(funcs),
            "run_stats": compute_run_stats(load_run_logs(), *count_run_totals()),
            "project_folder": state.get("project_folder", "unknown"),
            "active_binary": active_binary,
            "available_binaries": available_binaries,
            "available_folders": _fetch_project_folders(),
            "last_scan": state.get("last_scan"),
            "queue_config": cfg,
            "queue_meta": queue_meta,
        }

    # --- SocketIO event handlers ---

    @socketio.on("connect")
    def handle_connect():
        state = load_state()
        stats = compute_stats(state)
        sio_emit("initial_state", stats)

    _scan_thread = None

    @socketio.on("request_rescan")
    def handle_rescan(data):
        nonlocal _scan_thread
        if _scan_thread and _scan_thread.is_alive():
            sio_emit("scan_error", {"error": "Scan already in progress"})
            return
        refresh = data.get("refresh", False) if data else False
        program_filter = data.get("program") if data else None

        def run_scan():
            try:
                # Delayed import to avoid circular dependency
                from fun_doc import scan_functions, load_state, save_state

                state = load_state()
                folder = state.get("project_folder", "/Mods/PD2-S12")
                scan_functions(
                    state, folder, refresh=refresh, binary_filter=program_filter
                )
            except Exception as e:
                bus.emit("scan_error", {"error": str(e)})

        _scan_thread = threading.Thread(target=run_scan, daemon=True)
        _scan_thread.start()
        sio_emit("scan_acknowledged", {"refresh": refresh, "program": program_filter})

    # --- Worker management ---
    worker_mgr = WorkerManager(
        app.config["STATE_FILE"],
        bus,
        socketio,
        load_queue,
        save_queue,
    )

    # --- Background inventory scorer (Q1-Q12 design, opt-in via config) ---
    from inventory_scorer import (
        InventoryScorer,
        load_inventory,
        save_inventory,
        compute_per_binary_inventory,
        status_for,
    )

    def _project_folder():
        try:
            return load_state().get("project_folder")
        except Exception:
            return None

    def _emit_inventory_status(status: dict):
        """Bridge scorer status changes -> WebSocket so the dashboard widget
        and Inventory panel update without polling."""
        try:
            socketio.emit("inventory_status", status or {})
        except Exception:
            pass

    def _make_scorer():
        from fun_doc import (
            _fetch_programs,
            _fetch_function_list,
            _batch_score,
            load_state as fd_load_state,
            save_state as fd_save_state,
        )

        return InventoryScorer(
            worker_manager=worker_mgr,
            project_folder_getter=_project_folder,
            state_dir=Path(__file__).parent,
            load_state=fd_load_state,
            save_state=fd_save_state,
            fetch_programs=_fetch_programs,
            fetch_function_list=_fetch_function_list,
            batch_score=_batch_score,
            on_status_change=_emit_inventory_status,
        )

    inventory_scorer = _make_scorer()

    # Honor the persisted opt-in flag at startup.
    try:
        if (load_queue().get("config") or {}).get("inventory_enabled"):
            inventory_scorer.set_enabled(True)
    except Exception as _exc:
        print(f"  Inventory scorer auto-start skipped: {_exc}")

    @socketio.on("request_start_worker")
    def handle_start_worker(data):
        try:
            provider = (data or {}).get("provider", "minimax")
            continuous = bool((data or {}).get("continuous", False))
            count = max(1, min(500, int((data or {}).get("count", 5))))
            model = (data or {}).get("model") or None
            binary = (data or {}).get("binary") or None
            worker_id = worker_mgr.start_worker(
                provider=provider,
                count=count,
                model=model,
                binary=binary,
                continuous=continuous,
            )
            sio_emit("worker_started_ack", {"worker_id": worker_id})
        except ValueError as e:
            sio_emit("worker_error", {"error": str(e)})

    @socketio.on("request_stop_worker")
    def handle_stop_worker(data):
        try:
            worker_id = (data or {}).get("worker_id")
            if not worker_id:
                sio_emit("worker_error", {"error": "worker_id required"})
                return
            worker_mgr.stop_worker(worker_id)
            sio_emit("worker_stop_ack", {"worker_id": worker_id})
        except ValueError as e:
            sio_emit("worker_error", {"error": str(e)})

    @socketio.on("request_worker_status")
    def handle_worker_status(data=None):
        sio_emit("worker_status", worker_mgr.get_status())

    # --- HTTP routes ---

    @app.route("/")
    def dashboard():
        state = load_state()
        stats = compute_stats(state)
        return render_template("dashboard.html", stats=stats)

    @app.route("/api/stats")
    def api_stats():
        state = load_state()
        stats = compute_stats(state)
        stats.pop("all_functions", None)
        return jsonify(stats)

    @app.route("/api/queue", methods=["GET"])
    def get_queue():
        return jsonify(load_queue())

    @app.route("/api/queue/pin", methods=["POST"])
    def pin_function():
        data = request.json
        key = data.get("key")
        if not key:
            return jsonify({"error": "key required"}), 400
        queue = load_queue()
        if key not in queue["pinned"]:
            queue["pinned"].append(key)
        save_queue(queue)

        # Score-on-queue: immediately fetch the live score for this function
        # so the user doesn't queue something that's actually already done.
        # The state.json entry might be stale ("score=0" really meaning unscored).
        # If the live score is above good_enough, auto-dequeue right away and
        # tell the frontend so it can show "already at X%" instead of "queued".
        from fun_doc import (
            save_state as fd_save_state,
            _score_single,
            _sync_func_state,
            auto_dequeue_if_done,
        )

        try:
            # Use the local load_state — it has retry-on-partial-read for the
            # race against concurrent worker writes.
            state = load_state()
            func = state.get("functions", {}).get(key)
            response = {"ok": True, "status": "queued"}
            if func:
                addr = func.get("address")
                program = func.get("program")
                if addr and program:
                    # Capture pre-state BEFORE applying the fresh score, so we
                    # can tell the frontend whether this was a true "score on
                    # demand" hit vs. a refresh of an already-scored entry.
                    old_score = func.get("score", 0)
                    was_unscored_before = not func.get("last_processed")

                    score_info = _score_single(addr, prog_path=program)
                    if score_info:
                        # Apply the fresh score back to the state entry
                        func["score"] = score_info["score"]
                        func["fixable"] = score_info["fixable"]
                        func["has_custom_name"] = score_info["has_custom_name"]
                        func["has_plate_comment"] = score_info["has_plate_comment"]
                        func["is_leaf"] = score_info["is_leaf"]
                        func["classification"] = score_info["classification"]
                        func["deductions"] = score_info["deductions"]
                        func["last_processed"] = (
                            func.get("last_processed") or "scored_on_queue"
                        )
                        fd_save_state(state)

                        new_score = score_info["score"]
                        response["score"] = new_score
                        response["was_unscored"] = was_unscored_before

                        # Check if it's already above good_enough
                        cfg = load_queue().get("config") or {}
                        good_enough = cfg.get("good_enough_score", 80)
                        if new_score >= good_enough:
                            if auto_dequeue_if_done(key, new_score, source="pin_check"):
                                response["status"] = "already_done"
                                response["good_enough"] = good_enough
        except Exception as e:
            response = {"ok": True, "status": "queued", "score_error": str(e)}

        socketio.emit(
            "queue_changed",
            {"action": "pin", "key": key, "status": response.get("status")},
        )
        return jsonify(response)

    @app.route("/api/queue/unpin", methods=["POST"])
    def unpin_function():
        data = request.json
        key = data.get("key")
        if not key:
            return jsonify({"error": "key required"}), 400
        queue = load_queue()
        queue["pinned"] = [k for k in queue["pinned"] if k != key]
        save_queue(queue)
        socketio.emit("queue_changed", {"action": "unpin", "key": key})
        return jsonify({"ok": True})

    @app.route("/api/queue/drain_done", methods=["POST"])
    def drain_done():
        """Batch-score every pinned function and auto-dequeue any that are
        already at or above good_enough_score. Useful for cleaning up stuck
        pins from before score-on-queue / auto-dequeue-on-skip existed."""
        from fun_doc import drain_done_pinned

        try:
            state = load_state()
            result = drain_done_pinned(state)
            socketio.emit("queue_changed", {"action": "drain_done", **result})
            return jsonify({"ok": True, **result})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/queue/refresh", methods=["POST"])
    def refresh_candidates():
        """Manually trigger a batch refresh of the top N ROI candidates."""
        from fun_doc import refresh_candidate_scores

        data = request.json or {}
        try:
            count = max(1, min(200, int(data.get("count", 50))))
        except (TypeError, ValueError):
            count = 50
        state = load_state()
        active_binary = data.get("binary") or state.get("active_binary")

        def run_refresh():
            try:
                result = refresh_candidate_scores(
                    state, active_binary=active_binary, count=count
                )
                socketio.emit(
                    "queue_changed",
                    {
                        "action": "manual_refresh",
                        "refreshed": result["refreshed"],
                        "stale": result["stale"],
                    },
                )
            except Exception as e:
                socketio.emit("scan_error", {"error": f"refresh failed: {e}"})

        threading.Thread(target=run_refresh, daemon=True).start()
        return jsonify({"ok": True, "scheduled": True, "count": count})

    @app.route("/api/queue/config", methods=["GET", "POST"])
    def queue_config():
        from fun_doc import DEFAULT_QUEUE_CONFIG

        supported_providers = ("claude", "codex", "minimax", "gemini")

        queue = load_queue()
        if request.method == "POST":
            data = request.json or {}
            cfg = dict(queue.get("config") or DEFAULT_QUEUE_CONFIG)
            if "good_enough_score" in data:
                try:
                    cfg["good_enough_score"] = max(
                        0, min(100, int(data["good_enough_score"]))
                    )
                except (TypeError, ValueError):
                    return (
                        jsonify({"error": "good_enough_score must be int 0-100"}),
                        400,
                    )
            if "require_scored" in data:
                cfg["require_scored"] = bool(data["require_scored"])
            if "complexity_handoff_provider" in data:
                v = data["complexity_handoff_provider"]
                if v in (None, "", "none", "off"):
                    cfg["complexity_handoff_provider"] = None
                elif v in ("claude", "codex", "minimax", "gemini"):
                    cfg["complexity_handoff_provider"] = v
                else:
                    return (
                        jsonify(
                            {
                                "error": "complexity_handoff_provider must be claude/codex/minimax/gemini/null"
                            }
                        ),
                        400,
                    )
            if "complexity_handoff_max" in data:
                try:
                    cfg["complexity_handoff_max"] = max(
                        0, int(data["complexity_handoff_max"])
                    )
                except (TypeError, ValueError):
                    return (
                        jsonify({"error": "complexity_handoff_max must be int >= 0"}),
                        400,
                    )
            if "debug_mode" in data:
                cfg["debug_mode"] = bool(data["debug_mode"])
            if "audit_provider" in data:
                v = data["audit_provider"]
                if v in (None, "", "none", "off"):
                    cfg["audit_provider"] = None
                elif v in ("claude", "codex", "minimax", "gemini"):
                    cfg["audit_provider"] = v
                else:
                    return (
                        jsonify(
                            {
                                "error": "audit_provider must be claude/codex/minimax/gemini/null"
                            }
                        ),
                        400,
                    )
            if "audit_min_delta" in data:
                try:
                    cfg["audit_min_delta"] = max(
                        0, min(100, int(data["audit_min_delta"]))
                    )
                except (TypeError, ValueError):
                    return (
                        jsonify({"error": "audit_min_delta must be int 0-100"}),
                        400,
                    )
            if "provider_max_turns" in data:
                provider_max_turns = data["provider_max_turns"]
                if not isinstance(provider_max_turns, dict):
                    return (
                        jsonify({"error": "provider_max_turns must be an object"}),
                        400,
                    )

                normalized_turns = {}
                for provider, turn_value in provider_max_turns.items():
                    if provider not in supported_providers:
                        return (
                            jsonify(
                                {
                                    "error": f"unsupported provider in provider_max_turns: {provider}"
                                }
                            ),
                            400,
                        )
                    try:
                        normalized_turns[provider] = max(1, int(turn_value))
                    except (TypeError, ValueError):
                        return (
                            jsonify(
                                {
                                    "error": f"provider_max_turns.{provider} must be int >= 1"
                                }
                            ),
                            400,
                        )

                cfg["provider_max_turns"] = normalized_turns
            if "provider_models" in data:
                provider_models = data["provider_models"]
                if not isinstance(provider_models, dict):
                    return jsonify({"error": "provider_models must be an object"}), 400

                normalized_models = {}
                for provider, mode_map in provider_models.items():
                    if provider not in supported_providers:
                        return (
                            jsonify(
                                {
                                    "error": f"unsupported provider in provider_models: {provider}"
                                }
                            ),
                            400,
                        )
                    if not isinstance(mode_map, dict):
                        return (
                            jsonify(
                                {
                                    "error": f"provider_models.{provider} must be an object"
                                }
                            ),
                            400,
                        )
                    for mode, model_name in mode_map.items():
                        normalized_mode = str(mode).upper()
                        if normalized_mode not in ("FULL", "FIX", "VERIFY"):
                            return (
                                jsonify(
                                    {
                                        "error": f"unsupported mode in provider_models.{provider}: {mode}"
                                    }
                                ),
                                400,
                            )
                        normalized_name = str(model_name or "").strip()
                        if normalized_name:
                            normalized_models.setdefault(provider, {})[
                                normalized_mode
                            ] = normalized_name

                cfg["provider_models"] = normalized_models
            if "inventory_enabled" in data:
                cfg["inventory_enabled"] = bool(data["inventory_enabled"])
                # Reflect immediately on the running scorer instance — the
                # opt-in toggle is the only knob that can flip the daemon
                # on/off without a dashboard restart.
                try:
                    inventory_scorer.set_enabled(cfg["inventory_enabled"])
                except Exception as _exc:
                    print(f"  Inventory scorer toggle failed: {_exc}")
            queue["config"] = cfg
            save_queue(queue)
            socketio.emit("queue_changed", {"action": "config", "config": cfg})
            return jsonify({"ok": True, "config": cfg})
        return jsonify({"config": queue.get("config", dict(DEFAULT_QUEUE_CONFIG))})

    @app.route("/api/inventory/status", methods=["GET"])
    def inventory_status():
        """Combined snapshot: scorer runtime state + per-binary inventory
        records. The dashboard widget reads the scorer state for the live
        line; the Inventory panel reads `binaries` for the table.

        Per-binary records overlay state.json's documentable+scored counts
        on top of inventory.json's persisted (totals + last_scan)."""
        try:
            state = load_state()
            funcs = state.get("functions") or {}
            persisted = load_inventory(Path(__file__).parent).get("binaries", {})
            totals_by_path = {
                path: rec.get("total_documentable", 0)
                for path, rec in persisted.items()
                if rec.get("total_documentable")
            }
            inventory = compute_per_binary_inventory(
                funcs, totals_by_path=totals_by_path
            )
            for path, persisted_rec in persisted.items():
                rec = inventory.setdefault(
                    path,
                    {
                        "name": persisted_rec.get("name") or Path(path).name,
                        "total_documentable": persisted_rec.get(
                            "total_documentable", 0
                        ),
                        "scored": 0,
                        "last_scan": persisted_rec.get("last_scan"),
                    },
                )
                rec["last_scan"] = persisted_rec.get("last_scan")
                rec["name"] = persisted_rec.get("name") or rec.get("name")

            scorer_status = inventory_scorer.get_status()
            blacklist = set(scorer_status.get("blacklisted") or [])

            binaries = []
            for path, rec in inventory.items():
                total = rec.get("total_documentable", 0) or 0
                scored = rec.get("scored", 0) or 0
                missing = max(0, total - scored)
                pct = round(100.0 * scored / total, 1) if total else 0.0
                row_status = status_for(rec)
                if path in blacklist:
                    row_status = "blacklisted"
                binaries.append(
                    {
                        "path": path,
                        "name": rec.get("name") or Path(path).name,
                        "total_documentable": total,
                        "scored": scored,
                        "missing": missing,
                        "percent": pct,
                        "last_scan": rec.get("last_scan"),
                        "status": row_status,
                    }
                )
            # Most-missing first, reverse-alpha tiebreak (Q4). Two stable
            # sorts: secondary key first, primary key last.
            binaries.sort(key=lambda r: r["name"], reverse=True)  # reverse-alpha
            binaries.sort(key=lambda r: r["missing"], reverse=True)  # missing desc
            totals = {
                "total_documentable": sum(r["total_documentable"] for r in binaries),
                "scored": sum(r["scored"] for r in binaries),
                "missing": sum(r["missing"] for r in binaries),
                "binaries_total": len(binaries),
                "binaries_complete": sum(
                    1 for r in binaries if r["status"] == "complete"
                ),
            }
            return jsonify(
                {
                    "scorer": scorer_status,
                    "totals": totals,
                    "binaries": binaries,
                }
            )
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500

    @app.route("/api/inventory/toggle", methods=["POST"])
    def inventory_toggle():
        """Enable/disable the scorer. Persists to priority_queue.json so
        the choice survives dashboard restarts (Q9 opt-in toggle)."""
        data = request.json or {}
        enabled = bool(data.get("enabled"))
        queue = load_queue()
        cfg = dict(queue.get("config") or {})
        cfg["inventory_enabled"] = enabled
        queue["config"] = cfg
        save_queue(queue)
        inventory_scorer.set_enabled(enabled)
        return jsonify({"ok": True, "enabled": enabled})

    @app.route("/api/inventory/clear_blacklist", methods=["POST"])
    def inventory_clear_blacklist():
        """Clear the session blacklist for one path or all paths."""
        data = request.json or {}
        path = data.get("path")
        inventory_scorer.clear_blacklist(path)
        return jsonify({"ok": True})

    # --- Provider quota pauses (Q1-Q11) ---
    from provider_pause import get_default_manager as _get_pause_mgr

    def _emit_provider_pauses(active=None):
        try:
            socketio.emit(
                "provider_pauses",
                {"active": active if active is not None else _get_pause_mgr().all_active()},
            )
        except Exception:
            pass

    _get_pause_mgr().set_on_change(_emit_provider_pauses)

    @app.route("/api/provider_pauses", methods=["GET"])
    def provider_pauses_list():
        """Active per-(provider, model) pauses with paused_until + reason."""
        active = _get_pause_mgr().all_active()
        return jsonify(
            {
                "active": [
                    {
                        "provider": p,
                        "model": m,
                        "paused_until": until,
                        "reason": reason,
                    }
                    for p, m, until, reason in active
                ]
            }
        )

    @app.route("/api/provider_pauses/clear", methods=["POST"])
    def provider_pauses_clear():
        """Manually clear a pause. POST {provider, model} clears one;
        empty body clears all. Use this if the API recovered before the
        parsed reset window (rare but possible)."""
        data = request.json or {}
        provider = data.get("provider")
        model = data.get("model")
        mgr = _get_pause_mgr()
        if provider and model:
            mgr.clear(provider, model)
        else:
            mgr.clear_all()
        return jsonify({"ok": True})

    restored_workers = worker_mgr.restore_workers()
    if restored_workers:
        print(f"  Restored {len(restored_workers)} dashboard worker(s) after restart")

    @app.route("/api/functions/search", methods=["GET"])
    def search_functions():
        """Search across the full state.functions map without the 500-row dashboard cap."""
        q = (request.args.get("q") or "").strip().lower()
        program = request.args.get("program") or None
        layer_filter = request.args.get("layer")  # "0", "1", ..., "cyclic", or None
        try:
            limit = max(1, min(10000, int(request.args.get("limit", 5000))))
        except ValueError:
            limit = 5000
        sort = request.args.get("sort", "score")
        state = load_state()
        all_funcs = state.get("functions", {})
        queue = load_queue()
        good_enough = queue.get("config", {}).get("good_enough_score", 80)
        pinned = set(queue.get("pinned", []))

        results = []
        for key, func in all_funcs.items():
            if func.get("is_thunk") or func.get("is_external"):
                continue
            if program and func.get("program_name") != program:
                continue
            # Layer filter — computed dynamically using the same BFS as
            # /api/call_graph_layers so results match the dashboard exactly.
            # The pre-computed call_graph_layer in state.json can diverge
            # because populate_call_graph includes thunks in the adjacency
            # set while the dashboard excludes them.
            if layer_filter is not None:
                if not hasattr(search_functions, "_layer_cache"):
                    search_functions._layer_cache = {}
                cache_key = (program or state.get("active_binary"), layer_filter)
                if cache_key not in search_functions._layer_cache:
                    # Build layer map matching the dashboard's BFS
                    active_bin = program or state.get("active_binary")
                    bf = {
                        k: v
                        for k, v in all_funcs.items()
                        if v.get("program_name") == active_bin
                        and not v.get("is_thunk")
                        and not v.get("is_external")
                    }
                    sa = set()
                    for v in bf.values():
                        sa.add(v.get("address", ""))
                    co = {}
                    cr = defaultdict(set)
                    for v in bf.values():
                        a = v.get("address", "")
                        ic = set(v.get("callees", [])) & sa
                        co[a] = ic
                        for c in ic:
                            cr[c].add(a)
                    dp = {}
                    cur = {a for a in sa if not co.get(a)}
                    for a in cur:
                        dp[a] = 0
                    ln = 0
                    while cur:
                        nx = set()
                        for a in cur:
                            for ca in cr.get(a, set()):
                                if ca in dp:
                                    continue
                                if all(c in dp for c in co.get(ca, set())):
                                    dp[ca] = ln + 1
                                    nx.add(ca)
                        cur = nx
                        ln += 1
                        if ln > 200:
                            break
                    lm = {}
                    for a in sa:
                        lm[a] = dp.get(a)  # None = cyclic
                    search_functions._layer_cache[cache_key] = lm
                lm = search_functions._layer_cache[cache_key]
                func_layer = lm.get(func.get("address", ""))
                if layer_filter == "cyclic":
                    if func_layer is not None:
                        continue
                else:
                    try:
                        target_layer = int(layer_filter)
                    except ValueError:
                        target_layer = -1
                    if func_layer != target_layer:
                        continue
            if q:
                name = func.get("name", "").lower()
                addr = str(func.get("address", "")).lower()
                if q not in name and q not in addr:
                    continue
            # Compute deps remaining
            callees = func.get("callees", [])
            if not callees:
                deps_remaining = 0
            else:
                prog = func.get("program")
                deps_remaining = sum(
                    1
                    for ca in callees
                    if (cf := all_funcs.get(f"{prog}::{ca}"))
                    and cf.get("score", 0) < good_enough
                )
            results.append(
                {
                    "key": key,
                    "name": func.get("name", ""),
                    "address": func.get("address", ""),
                    "program": func.get("program_name", ""),
                    "score": func.get("score", 0),
                    "fixable": round(func.get("fixable", 0), 1),
                    "callers": func.get("caller_count", 0),
                    "is_leaf": not callees,
                    "call_graph_layer": func.get("call_graph_layer"),
                    "deps_remaining": deps_remaining,
                    "last_result": func.get("last_result"),
                    "pinned": key in pinned,
                    "unscored": not func.get("last_processed"),
                }
            )
        if sort == "name":
            results.sort(key=lambda r: r["name"].lower())
        elif sort == "name_desc":
            results.sort(key=lambda r: r["name"].lower(), reverse=True)
        elif sort == "address":
            results.sort(key=lambda r: r.get("address", ""))
        elif sort == "address_desc":
            results.sort(key=lambda r: r.get("address", ""), reverse=True)
        elif sort == "status":
            # Sort by score bucket: unscored first, then NEW (<70), FIX (70-79), DONE (80+)
            def _status_key(r):
                if r.get("unscored"):
                    return 0
                s = r.get("score", 0)
                if s >= 80:
                    return 3
                if s >= 70:
                    return 2
                return 1

            results.sort(key=_status_key)
        elif sort == "status_desc":

            def _status_key_desc(r):
                if r.get("unscored"):
                    return 0
                s = r.get("score", 0)
                if s >= 80:
                    return 3
                if s >= 70:
                    return 2
                return 1

            results.sort(key=_status_key_desc, reverse=True)
        elif sort == "score_desc":
            results.sort(key=lambda r: -r["score"])
        elif sort == "fixable":
            results.sort(key=lambda r: -r["fixable"])
        elif sort == "fixable_desc":
            results.sort(key=lambda r: r["fixable"])
        elif sort == "deps_asc":
            results.sort(key=lambda r: (r.get("deps_remaining", 0), r["score"]))
        elif sort == "deps_desc":
            results.sort(key=lambda r: (-r.get("deps_remaining", 0), r["score"]))
        elif sort == "layer":
            results.sort(
                key=lambda r: (
                    (
                        r.get("call_graph_layer")
                        if r.get("call_graph_layer") is not None
                        else 999
                    ),
                    r["score"],
                )
            )
        elif sort == "layer_desc":
            results.sort(
                key=lambda r: (
                    -(
                        r.get("call_graph_layer")
                        if r.get("call_graph_layer") is not None
                        else -1
                    ),
                    -r["score"],
                )
            )
        else:  # "score" (default — lowest first)
            results.sort(key=lambda r: r["score"])
        total_match = len(results)
        return jsonify(
            {"total": total_match, "results": results[:limit], "limit": limit}
        )

    # --- Folder / binary selection ---

    def _fetch_project_binaries(folder):
        """Fetch all binaries from Ghidra project via HTTP endpoint."""
        import requests

        try:
            r = requests.get(
                "http://127.0.0.1:8089/list_project_files",
                params={"folder": folder},
                timeout=5,
            )
            r.raise_for_status()
            data = r.json()
            files = data.get("files", [])
            return sorted(
                f["name"]
                for f in files
                if isinstance(f, dict) and f.get("content_type") == "Program"
            )
        except Exception:
            return []

    @app.route("/api/navigate", methods=["POST"])
    def navigate_ghidra():
        """Navigate Ghidra to a specific address."""
        from fun_doc import ghidra_post

        data = request.get_json() or {}
        address = data.get("address", "")
        if not address:
            return jsonify({"error": "address required"}), 400
        ghidra_post("/tool/goto_address", data={"address": f"0x{address}"})
        return jsonify({"ok": True, "address": address})

    @app.route("/api/context", methods=["GET"])
    def get_context():
        state = load_state()
        folder = state.get("project_folder", "/")
        # Merge: project files from Ghidra + any binaries already scanned
        project_binaries = _fetch_project_binaries(folder)
        scanned_binaries = sorted(
            set(
                f.get("program_name", "unknown")
                for f in state.get("functions", {}).values()
            )
        )
        all_binaries = sorted(set(project_binaries + scanned_binaries))
        return jsonify(
            {
                "project_folder": folder,
                "active_binary": state.get("active_binary"),
                "available_binaries": all_binaries,
            }
        )

    @app.route("/api/context/binary", methods=["POST"])
    def set_active_binary():
        data = request.json
        binary = data.get("binary")  # None or "" to clear filter
        state = load_state()
        if binary:
            state["active_binary"] = binary
        else:
            state.pop("active_binary", None)
        _save_state_inline(state)
        socketio.emit("state_changed")
        return jsonify({"ok": True, "active_binary": state.get("active_binary")})

    @app.route("/api/context/folder", methods=["POST"])
    def set_project_folder():
        data = request.json
        folder = data.get("folder")
        if not folder:
            return jsonify({"error": "folder required"}), 400
        state = load_state()
        state["project_folder"] = folder
        _save_state_inline(state)
        socketio.emit("state_changed")
        return jsonify({"ok": True, "project_folder": folder})

    def _fetch_project_folders():
        """Recursively discover all folders with binaries in the Ghidra project."""
        import requests

        folders = []

        def _walk(path):
            try:
                r = requests.get(
                    "http://127.0.0.1:8089/list_project_files",
                    params={"folder": path},
                    timeout=5,
                )
                r.raise_for_status()
                data = r.json()
                subfolders = data.get("folders", [])
                files = data.get("files", [])
                has_programs = any(
                    f.get("content_type") == "Program"
                    for f in files
                    if isinstance(f, dict)
                )
                if has_programs:
                    folders.append(path)
                for sf in subfolders:
                    _walk(f"{path}/{sf}" if path != "/" else f"/{sf}")
            except Exception:
                pass

        _walk("/")
        return sorted(folders)

    @app.route("/api/context/folders", methods=["GET"])
    def get_available_folders():
        return jsonify({"folders": _fetch_project_folders()})

    @app.route("/api/call_graph_layers", methods=["GET"])
    def call_graph_layers():
        """Compute call-graph layer assignment and per-layer completion stats.

        Uses BFS from leaf functions (layer 0) upward through callers.
        Functions in call cycles that can't be reached by BFS are grouped
        into a final "cyclic" bucket and ordered internally by callee
        readiness.
        """
        from fun_doc import _callee_readiness

        state = load_state()
        active_binary = state.get("active_binary")
        all_funcs = state.get("functions", {})
        queue = load_queue()
        good_enough = queue.get("config", {}).get("good_enough_score", 80)

        # Filter to active binary, non-thunk only
        if active_binary:
            funcs = {
                k: v
                for k, v in all_funcs.items()
                if v.get("program_name") == active_binary
                and not v.get("is_thunk")
                and not v.get("is_external")
            }
        else:
            funcs = {
                k: v
                for k, v in all_funcs.items()
                if not v.get("is_thunk") and not v.get("is_external")
            }

        # Build adjacency: address → [callee addresses]
        addr_to_key = {}
        callees_of = {}  # addr → set of callee addrs
        callers_of = defaultdict(set)  # addr → set of caller addrs
        all_addrs = set()

        for key, func in funcs.items():
            addr = func.get("address", "")
            addr_to_key[addr] = key
            all_addrs.add(addr)
            callee_addrs = set(func.get("callees", []))
            # Filter to only callees that are in this binary's function set
            internal_callees = callee_addrs & all_addrs
            callees_of[addr] = internal_callees
            for c in internal_callees:
                callers_of[c].add(addr)

        # BFS layer assignment from leaves
        depth = {}
        current_layer = set()
        for addr in all_addrs:
            if not callees_of.get(addr):
                depth[addr] = 0
                current_layer.add(addr)

        layer_num = 0
        while current_layer:
            next_layer = set()
            for addr in current_layer:
                for caller in callers_of.get(addr, set()):
                    if caller in depth:
                        continue
                    # Assign when ALL callees have a depth
                    if all(c in depth for c in callees_of.get(caller, set())):
                        depth[caller] = layer_num + 1
                        next_layer.add(caller)
            current_layer = next_layer
            layer_num += 1
            if layer_num > 200:
                break

        # Build per-layer stats
        max_depth = max(depth.values()) if depth else 0
        layers = []
        for d in range(max_depth + 1):
            layer_addrs = [a for a, dep in depth.items() if dep == d]
            total = len(layer_addrs)
            done = sum(
                1
                for a in layer_addrs
                if a in addr_to_key
                and funcs[addr_to_key[a]].get("score", 0) >= good_enough
            )
            # "Ready" = callees all documented AND not yet done itself
            ready = 0
            for a in layer_addrs:
                if a not in addr_to_key:
                    continue
                func = funcs[addr_to_key[a]]
                if func.get("score", 0) >= good_enough:
                    continue  # already done
                readiness = _callee_readiness(func, all_funcs, good_enough)
                if readiness >= 1.0:
                    ready += 1
            layers.append(
                {
                    "depth": d,
                    "label": "Leaves" if d == 0 else f"Layer {d}",
                    "total": total,
                    "done": done,
                    "pct": round(100 * done / total, 1) if total > 0 else 0,
                    "ready": ready,
                }
            )

        # Cyclic bucket: everything not assigned a depth
        cyclic_addrs = [a for a in all_addrs if a not in depth]
        if cyclic_addrs:
            done = sum(
                1
                for a in cyclic_addrs
                if a in addr_to_key
                and funcs[addr_to_key[a]].get("score", 0) >= good_enough
            )
            ready = 0
            for a in cyclic_addrs:
                if a not in addr_to_key:
                    continue
                func = funcs[addr_to_key[a]]
                if func.get("score", 0) >= good_enough:
                    continue
                readiness = _callee_readiness(func, all_funcs, good_enough)
                if readiness >= 0.8:
                    ready += 1
            layers.append(
                {
                    "depth": max_depth + 1,
                    "label": "Cyclic",
                    "total": len(cyclic_addrs),
                    "done": done,
                    "pct": (
                        round(100 * done / len(cyclic_addrs), 1) if cyclic_addrs else 0
                    ),
                    "ready": ready,
                }
            )

        return jsonify(
            {
                "layers": layers,
                "total_functions": len(funcs),
                "assigned": len(depth),
                "cyclic": len(all_addrs) - len(depth),
                "max_depth": max_depth,
            }
        )

    @app.route("/api/cross_binary_progress", methods=["GET"])
    def cross_binary_progress():
        """Cross-binary progress summary — all binaries in the current folder."""
        state = load_state()
        all_funcs = state.get("functions", {})
        by_binary = defaultdict(
            lambda: {
                "total": 0,
                "done": 0,
                "fixable": 0,
                "needs_work": 0,
                "avg_score": 0,
                "total_fixable_pts": 0,
            }
        )
        for f in all_funcs.values():
            prog = f.get("program_name", "unknown")
            score = f.get("score", 0)
            by_binary[prog]["total"] += 1
            if score >= 90:
                by_binary[prog]["done"] += 1
            elif score >= 70:
                by_binary[prog]["fixable"] += 1
            else:
                by_binary[prog]["needs_work"] += 1
            by_binary[prog]["avg_score"] += score
            by_binary[prog]["total_fixable_pts"] += f.get("fixable", 0)
        result = []
        for prog, info in sorted(by_binary.items()):
            info["avg_score"] = (
                round(info["avg_score"] / info["total"], 1) if info["total"] > 0 else 0
            )
            info["total_fixable_pts"] = round(info["total_fixable_pts"], 0)
            info["pct_done"] = (
                round(info["done"] / info["total"] * 100, 1) if info["total"] > 0 else 0
            )
            info["name"] = prog
            result.append(info)
        return jsonify({"binaries": result})

    return app, socketio

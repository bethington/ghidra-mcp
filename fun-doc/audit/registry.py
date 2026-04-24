"""
Persistent signature registry with cooldown + circuit-breaker state machine.

Pure state — no threads internal to logic (just a lock for concurrent
callers), no network, no subprocess. Tested end-to-end via controlled
timestamps in tests/performance/test_audit_registry.py.

Persistence: atomic writes to `audit/registry.json`. Single-process write
safety via threading.Lock. Not safe across processes — only one watcher
should write to the same registry file.

Semantics locked in design Q5:
    Cooldown     : once a signature fires, same signature is suppressed for
                   COOLDOWN_SECONDS. Prevents re-firing during deploy
                   propagation or transient symptom re-appearance.
    Short CB     : >= CB_SHORT_THRESHOLD fires within CB_SHORT_WINDOW trip
                   the breaker.
    Long CB      : >= CB_LONG_THRESHOLD fires within CB_LONG_WINDOW also
                   trip the breaker.
    Halt         : tripped breaker suppresses ALL fires for CB_HALT_DURATION,
                   then re-arms automatically.
    Manual reset : force_reset_circuit_breaker() clears tripped state and
                   flushes the fires window.
"""

from __future__ import annotations

import copy
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, Optional

# Thresholds — tuning is a Phase-5+ activity. Locking here keeps them
# visible, greppable, and easy to regression-test.
COOLDOWN_SECONDS = 86400       # 24h per-signature cooldown
CB_SHORT_WINDOW = 3600         # 1h
CB_SHORT_THRESHOLD = 3
CB_LONG_WINDOW = 86400         # 24h
CB_LONG_THRESHOLD = 8
CB_HALT_DURATION = 3600        # 1h halt after trip before auto re-arm
HISTORY_PER_SIG = 50           # per-signature history ring

FireAction = Literal[
    "fire",                    # caller may enqueue this trigger
    "skip_cooldown",           # same signature fired too recently
    "skip_circuit_breaker",    # global rate limit engaged
]


@dataclass
class FireDecision:
    action: FireAction
    signature: str
    cooldown_expires_at: Optional[datetime] = None
    circuit_breaker_halt_until: Optional[datetime] = None
    reason: Optional[str] = None
    circuit_breaker_tripped_this_fire: bool = False


class AuditRegistry:
    """Signature state + circuit-breaker state, persisted to JSON."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._state = self._load()

    # -- persistence ------------------------------------------------------

    def _load(self) -> dict[str, Any]:
        if not self._path.is_file():
            return {
                "signatures": {},
                "circuit_breaker": self._default_cb_state(),
            }
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            data.setdefault("signatures", {})
            data.setdefault("circuit_breaker", self._default_cb_state())
            return data
        except (json.JSONDecodeError, OSError):
            # Corrupt or unreadable — start fresh. History lost, but the
            # registry is a cache of derivable state; events.jsonl retains
            # the canonical audit trail.
            return {
                "signatures": {},
                "circuit_breaker": self._default_cb_state(),
            }

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self._state, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        os.replace(tmp, self._path)

    @staticmethod
    def _default_cb_state() -> dict[str, Any]:
        return {
            "state": "armed",
            "tripped_at": None,
            "halt_until": None,
            "fires_window": [],
        }

    # -- primary API ------------------------------------------------------

    def check_and_record_fire(
        self,
        signature: str,
        ts: Optional[datetime] = None,
    ) -> FireDecision:
        """Consult dedup + circuit-breaker state. If allowed, record the fire."""
        ts = ts or _now()
        with self._lock:
            # 1. Re-arm circuit breaker if the halt window has elapsed.
            cb = self._state["circuit_breaker"]
            if cb["state"] == "tripped":
                halt_until = _parse_iso(cb.get("halt_until"))
                if halt_until and ts >= halt_until:
                    cb["state"] = "armed"
                    cb["tripped_at"] = None
                    cb["halt_until"] = None
                    cb["fires_window"] = []
                else:
                    return FireDecision(
                        action="skip_circuit_breaker",
                        signature=signature,
                        circuit_breaker_halt_until=halt_until,
                        reason="circuit breaker tripped",
                    )

            # 2. Cooldown check (after re-arm so cooldown applies when CB ok).
            sig_state = self._state["signatures"].get(signature)
            if sig_state:
                last_fired = _parse_iso(sig_state.get("last_fired_at"))
                if last_fired:
                    cooldown_end = last_fired + timedelta(seconds=COOLDOWN_SECONDS)
                    if ts < cooldown_end:
                        return FireDecision(
                            action="skip_cooldown",
                            signature=signature,
                            cooldown_expires_at=cooldown_end,
                            reason=f"cooldown until {cooldown_end.isoformat()}",
                        )

            # 3. Fire — update signature state.
            sig_state = sig_state or {
                "fire_count": 0,
                "merged_count": 0,
                "revert_count": 0,
                "history": [],
                "mode": "report",
            }
            sig_state["last_fired_at"] = ts.isoformat()
            sig_state["fire_count"] = sig_state.get("fire_count", 0) + 1
            sig_state["history"] = _append_capped(
                sig_state.get("history", []),
                {"ts": ts.isoformat(), "event": "fire"},
                HISTORY_PER_SIG,
            )
            self._state["signatures"][signature] = sig_state

            # 4. Circuit breaker window.
            cb["fires_window"].append(ts.isoformat())
            keep_after = ts - timedelta(
                seconds=max(CB_SHORT_WINDOW, CB_LONG_WINDOW)
            )
            cb["fires_window"] = _prune_window(cb["fires_window"], keep_after)

            fires_short = _count_after(
                cb["fires_window"], ts - timedelta(seconds=CB_SHORT_WINDOW)
            )
            fires_long = _count_after(
                cb["fires_window"], ts - timedelta(seconds=CB_LONG_WINDOW)
            )

            tripped_now = False
            if fires_short >= CB_SHORT_THRESHOLD or fires_long >= CB_LONG_THRESHOLD:
                cb["state"] = "tripped"
                cb["tripped_at"] = ts.isoformat()
                cb["halt_until"] = (
                    ts + timedelta(seconds=CB_HALT_DURATION)
                ).isoformat()
                tripped_now = True

            self._save()
            return FireDecision(
                action="fire",
                signature=signature,
                circuit_breaker_tripped_this_fire=tripped_now,
            )

    def mark_merged(
        self, signature: str, sha: str, ts: Optional[datetime] = None
    ) -> None:
        """Phase 4+: record that the fix for this signature was auto-merged."""
        ts = ts or _now()
        with self._lock:
            sig_state = self._state["signatures"].get(signature)
            if not sig_state:
                return
            sig_state["merged_count"] = sig_state.get("merged_count", 0) + 1
            sig_state["last_merge_sha"] = sha
            sig_state["history"] = _append_capped(
                sig_state.get("history", []),
                {"ts": ts.isoformat(), "event": "merged", "sha": sha},
                HISTORY_PER_SIG,
            )
            self._save()

    def mark_reverted(
        self,
        signature: str,
        sha: str,
        reason: str,
        ts: Optional[datetime] = None,
    ) -> None:
        """Phase 4+: record auto-revert (symptom didn't resolve in window)."""
        ts = ts or _now()
        with self._lock:
            sig_state = self._state["signatures"].get(signature)
            if not sig_state:
                return
            sig_state["revert_count"] = sig_state.get("revert_count", 0) + 1
            sig_state["history"] = _append_capped(
                sig_state.get("history", []),
                {
                    "ts": ts.isoformat(),
                    "event": "reverted",
                    "sha": sha,
                    "reason": reason,
                },
                HISTORY_PER_SIG,
            )
            self._save()

    # -- introspection ----------------------------------------------------

    def get_signature_state(self, signature: str) -> Optional[dict[str, Any]]:
        with self._lock:
            s = self._state["signatures"].get(signature)
            return copy.deepcopy(s) if s else None

    def get_circuit_breaker_state(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._state["circuit_breaker"])

    def snapshot(self) -> dict[str, Any]:
        """Full state snapshot. Used by dashboard panel (Phase 2)."""
        with self._lock:
            return copy.deepcopy(self._state)

    def force_reset_circuit_breaker(self) -> None:
        """Manual resume path — dashboard toggle or ops intervention."""
        with self._lock:
            self._state["circuit_breaker"] = self._default_cb_state()
            self._save()


# -- module-level helpers -------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        # Py 3.11+ handles 'Z'; earlier Pythons don't. Normalize.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _append_capped(seq: list, item, cap: int) -> list:
    return (list(seq) + [item])[-cap:]


def _prune_window(timestamps: list[str], keep_after: datetime) -> list[str]:
    kept = []
    for t in timestamps:
        parsed = _parse_iso(t)
        if parsed and parsed >= keep_after:
            kept.append(t)
    return kept


def _count_after(timestamps: list[str], threshold: datetime) -> int:
    return sum(
        1
        for t in timestamps
        if (_parse_iso(t) or datetime.min.replace(tzinfo=timezone.utc)) >= threshold
    )

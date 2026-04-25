"""Per-provider quota-wall pause manager.

When a provider's daily quota or hard rate limit hits, fun-doc historically
burned 3 retries x ~30s x every queued function, silently incrementing
consecutive_fails and producing no diagnostic output. This module replaces
that with a duration-aware pause-and-resume mechanism.

Design (Q1-Q11 conversation 2026-04-25 — see git log on
feat/worker-config-snapshot for full rationale):

  Q1  scope = (provider, model). Per-account quotas mean every worker on the
      same model sees the same wall; pause them all together.
  Q2  log run as "quota_paused" outcome — does NOT bump consecutive_fails.
  Q3  parse "Xh Ym Zs" + 30-60s jitter; 1h fallback if parse fails.
  Q4  persist to fun-doc/provider_pauses.json (atomic write, prune-on-boot).
  Q6  all four providers (gemini / claude / codex / minimax).
  Q9  detect on first failure when message is unambiguous; skip retries.
  Q11 5-minute threshold: walls under 5 min stay in retry logic; walls over
      5 min install a pause entry.

Public API:

  detect_quota_wall(provider, error_str, http_status=None) -> ResetInfo | None
      Per-provider wall detector. None = not a recognized wall.

  ProviderPauseManager: install / clear / is_paused / wait_until / reason /
      all_active / prune_expired. Atomic JSON persistence.

  get_default_manager() -> singleton instance scoped to fun-doc/.

Tests inject a deterministic jitter_fn so paused_until calculations are
predictable.
"""

from __future__ import annotations

import json
import os
import random
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# Walls under this duration stay in retry logic (soft rate limits self-heal).
# Walls at or over this duration install a pause entry (Q11).
QUOTA_PAUSE_THRESHOLD_SECONDS = 300  # 5 minutes

# Used when a wall is detected but no reset time can be parsed (Q3 fallback).
DEFAULT_FALLBACK_PAUSE_SECONDS = 3600  # 1 hour

# Random jitter window added to paused_until so workers waking together don't
# all hit the API on the same wall-clock second (Q3 thundering-herd guard).
JITTER_MIN_SECONDS = 30.0
JITTER_MAX_SECONDS = 60.0

PAUSE_FILE_NAME = "provider_pauses.json"
PAUSE_FILE_VERSION = 1


@dataclass
class ResetInfo:
    """A successful quota-wall detection.

    raw_seconds is the parsed duration before jitter — tests need this to
    compute deterministic paused_until values, and the manager's install()
    adds the jitter on top.
    """

    raw_seconds: float
    reason: str  # short message: "gemini: quota exhausted (8h59m24s)"


# ---------- duration parser (Q3) ----------


def _parse_duration(text: str) -> Optional[float]:
    """Extract a duration in seconds from common provider error formats.

    Strategy: try the most explicit forms first (word-suffixed: 'X days',
    'X hours', etc.) so a string like 'retry after 2 hours' isn't misread
    by the compact regex as 'retry-after: 2'. Then compact ('8h59m24s'
    gemini format), then HTTP `retry-after: N`, then bare seconds.

    Returns None if nothing usable found.
    """
    if not text:
        return None

    # 1. Word forms first — most explicit, lowest false-positive risk.
    m = re.search(r"(\d+)\s*(?:days?)\b", text, re.IGNORECASE)
    if m:
        return float(m.group(1)) * 86400

    m = re.search(r"(\d+)\s*(?:hours?|hrs?)\b", text, re.IGNORECASE)
    if m:
        return float(m.group(1)) * 3600

    m = re.search(r"(\d+)\s*(?:minutes?|mins?)\b", text, re.IGNORECASE)
    if m:
        return float(m.group(1)) * 60

    m = re.search(r"(\d+)\s*(?:seconds?|secs?)\b", text, re.IGNORECASE)
    if m:
        return float(m.group(1))

    # 2. Compact 'XhYmZs' / 'XhYm' / 'Xh' (gemini format, no spaces).
    m = re.search(r"(\d+)h(?:(\d+)m)?(?:(\d+)s)?", text, re.IGNORECASE)
    if m and m.group(1):
        h = int(m.group(1))
        mi = int(m.group(2) or 0)
        s = int(m.group(3) or 0)
        total = h * 3600 + mi * 60 + s
        if total > 0:
            return float(total)

    # 3. Mixed without leading hours: 'XmYs' or 'Xm'.
    m = re.search(r"(\d+)m(?:(\d+)s)?", text, re.IGNORECASE)
    if m and m.group(1):
        mi = int(m.group(1))
        s = int(m.group(2) or 0)
        total = mi * 60 + s
        if total > 0:
            return float(total)

    # 4. Bare 'Ns' suffix.
    m = re.search(r"(\d+)s\b", text, re.IGNORECASE)
    if m:
        return float(m.group(1))

    # 5. HTTP retry-after: N (seconds, by spec).
    m = re.search(r"retry[-_ ]after[:\s]+(\d+)", text, re.IGNORECASE)
    if m:
        return float(m.group(1))

    return None


# ---------- per-provider detectors (Q6) ----------


def _truncate_for_reason(text: str, limit: int = 140) -> str:
    """Compress a multi-line error into a single short reason line."""
    one_line = " ".join(text.split())
    return (one_line[: limit - 1] + "…") if len(one_line) > limit else one_line


def _detect_gemini(error_str: str, http_status: Optional[int] = None) -> Optional[ResetInfo]:
    s = (error_str or "").lower()
    # Gemini-cli's quota-exhausted phrasing is unambiguous.
    if "exhausted your capacity" in s or "exhausted your" in s and "quota" in s:
        secs = _parse_duration(error_str) or DEFAULT_FALLBACK_PAUSE_SECONDS
        return ResetInfo(
            raw_seconds=secs,
            reason="gemini: " + _truncate_for_reason(error_str),
        )
    # Generic resource-exhausted from underlying Google API.
    if "resource_exhausted" in s or "rate_limit" in s and "quota" in s:
        secs = _parse_duration(error_str)
        if secs is None:
            return None  # No duration -> let retry logic handle it (soft limit).
        return ResetInfo(raw_seconds=secs, reason="gemini: " + _truncate_for_reason(error_str))
    return None


def _detect_claude(error_str: str, http_status: Optional[int] = None) -> Optional[ResetInfo]:
    s = (error_str or "").lower()
    # Hard wall: account billing exhausted.
    if "credit balance is too low" in s or "billing_credit_low" in s or "insufficient_quota" in s:
        secs = _parse_duration(error_str) or DEFAULT_FALLBACK_PAUSE_SECONDS
        return ResetInfo(raw_seconds=secs, reason="claude: " + _truncate_for_reason(error_str))
    # Soft + hard rate limits: 429 / rate_limit_error. Discriminator is duration.
    if http_status == 429 or "rate_limit_error" in s:
        secs = _parse_duration(error_str)
        if secs is None:
            return None
        return ResetInfo(raw_seconds=secs, reason="claude: " + _truncate_for_reason(error_str))
    return None


def _detect_codex(error_str: str, http_status: Optional[int] = None) -> Optional[ResetInfo]:
    s = (error_str or "").lower()
    if "insufficient_quota" in s or "you exceeded your current quota" in s:
        secs = _parse_duration(error_str) or DEFAULT_FALLBACK_PAUSE_SECONDS
        return ResetInfo(raw_seconds=secs, reason="codex: " + _truncate_for_reason(error_str))
    if http_status == 429 or "rate_limit_exceeded" in s:
        secs = _parse_duration(error_str)
        if secs is None:
            return None
        return ResetInfo(raw_seconds=secs, reason="codex: " + _truncate_for_reason(error_str))
    return None


def _detect_minimax(error_str: str, http_status: Optional[int] = None) -> Optional[ResetInfo]:
    s = (error_str or "").lower()
    if ("quota" in s and "exhausted" in s) or "insufficient_balance" in s:
        secs = _parse_duration(error_str) or DEFAULT_FALLBACK_PAUSE_SECONDS
        return ResetInfo(raw_seconds=secs, reason="minimax: " + _truncate_for_reason(error_str))
    if http_status == 429:
        secs = _parse_duration(error_str)
        if secs is None:
            return None
        return ResetInfo(raw_seconds=secs, reason="minimax: " + _truncate_for_reason(error_str))
    return None


_DETECTORS = {
    "gemini": _detect_gemini,
    "claude": _detect_claude,
    "codex": _detect_codex,
    "minimax": _detect_minimax,
}


def detect_quota_wall(
    provider: str, error_str: str, http_status: Optional[int] = None
) -> Optional[ResetInfo]:
    """Per-provider quota-wall detector dispatch.

    Returns ResetInfo when the error matches a known wall pattern (with a
    parsed or default duration); None otherwise. The 5-minute threshold
    (Q11) is applied by the caller — soft rate limits return ResetInfo
    too, but their raw_seconds < threshold means the caller stays in
    retry mode instead of installing a pause.
    """
    fn = _DETECTORS.get(provider)
    if fn is None:
        return None
    return fn(error_str, http_status)


# ---------- pause manager (Q4) ----------


class ProviderPauseManager:
    """In-memory pause set mirrored to provider_pauses.json.

    Keyed by (provider, model). Workers consult is_paused / wait_until
    before each function. Detectors call install when a wall is
    confirmed. Stale entries (paused_until <= now) are pruned on every
    read so callers never see expired pauses.
    """

    def __init__(
        self,
        state_dir: Path,
        jitter_fn=None,
    ):
        self._state_dir = Path(state_dir)
        self._lock = threading.Lock()
        self._entries: dict = {}  # (provider, model) -> (paused_until, reason)
        self._jitter_fn = jitter_fn or (
            lambda: random.uniform(JITTER_MIN_SECONDS, JITTER_MAX_SECONDS)
        )
        self._on_change = None  # optional callback for dashboard push
        self._load()

    # ---- public API ----

    def set_on_change(self, callback) -> None:
        """Register a callback fired whenever the pause set changes.
        Used by the web layer to push updates to the dashboard via
        WebSocket without polling."""
        self._on_change = callback

    def install(self, provider: str, model: str, info: ResetInfo) -> datetime:
        """Install a pause for (provider, model). raw_seconds + jitter is
        added to now() to compute paused_until. Returns the installed
        paused_until."""
        with self._lock:
            until = datetime.now() + timedelta(
                seconds=info.raw_seconds + self._jitter_fn()
            )
            self._entries[(provider, model)] = (until, info.reason)
            self._save_locked()
        self._notify()
        return until

    def clear(self, provider: str, model: str) -> None:
        with self._lock:
            existed = (provider, model) in self._entries
            self._entries.pop((provider, model), None)
            if existed:
                self._save_locked()
        if existed:
            self._notify()

    def clear_all(self) -> None:
        with self._lock:
            had = bool(self._entries)
            self._entries.clear()
            if had:
                self._save_locked()
        if had:
            self._notify()

    def is_paused(self, provider: str, model: str) -> bool:
        return self.wait_until(provider, model) is not None

    def wait_until(self, provider: str, model: str) -> Optional[datetime]:
        """Return paused_until when the pause is still active, else None.
        Side-effect: prunes the entry if it has expired."""
        now = datetime.now()
        with self._lock:
            entry = self._entries.get((provider, model))
            if entry is None:
                return None
            until, _reason = entry
            if until <= now:
                self._entries.pop((provider, model), None)
                self._save_locked()
                return None
            return until

    def reason(self, provider: str, model: str) -> Optional[str]:
        with self._lock:
            entry = self._entries.get((provider, model))
            return entry[1] if entry else None

    def all_active(self) -> list:
        """Return list of (provider, model, paused_until_iso, reason) for
        every active pause. Used by the dashboard.

        Splits compute-from-state and notify steps so a callback that calls
        back into all_active() doesn't recurse: _compute_active_locked is
        called under the lock and returns a snapshot, _notify is invoked
        once with that snapshot if any entries were pruned.
        """
        snapshot, pruned = self._compute_active_locked()
        if pruned:
            self._notify(snapshot)
        return snapshot

    def prune_expired(self) -> int:
        """Drop any entries whose paused_until is in the past. Returns
        the count pruned. Called on boot and opportunistically."""
        now = datetime.now()
        with self._lock:
            stale = [k for k, (until, _) in self._entries.items() if until <= now]
            for k in stale:
                self._entries.pop(k)
            if stale:
                self._save_locked()
        if stale:
            self._notify()
        return len(stale)

    # ---- persistence ----

    def _path(self) -> Path:
        return self._state_dir / PAUSE_FILE_NAME

    def _load(self) -> None:
        path = self._path()
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return
        entries = (data or {}).get("entries") or {}
        for key, val in entries.items():
            try:
                if not isinstance(val, dict):
                    continue
                provider, model = key.split(":", 1)
                until = datetime.fromisoformat(val["paused_until"])
                reason = val.get("reason", "")
                self._entries[(provider, model)] = (until, reason)
            except (ValueError, KeyError):
                continue
        # Sweep stale entries that survived a long downtime.
        self.prune_expired()

    def _save_locked(self) -> None:
        path = self._path()
        tmp = path.with_suffix(".json.tmp")
        payload = {
            "version": PAUSE_FILE_VERSION,
            "entries": {
                f"{p}:{m}": {
                    "paused_until": until.isoformat(),
                    "reason": reason,
                }
                for (p, m), (until, reason) in self._entries.items()
            },
        }
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            try:
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        tmp.replace(path)

    def _compute_active_locked(self) -> tuple[list, bool]:
        """Return (snapshot, pruned). Acquires the lock once: prunes expired
        entries, persists if any were dropped, and snapshots the surviving
        entries. Used by all_active() and _notify() so callbacks can't cause
        recursion via all_active() -> _notify() -> all_active()."""
        now = datetime.now()
        with self._lock:
            stale = [k for k, (until, _) in self._entries.items() if until <= now]
            for k in stale:
                self._entries.pop(k)
            if stale:
                self._save_locked()
            snapshot = [
                (p, m, until.isoformat(), reason)
                for (p, m), (until, reason) in self._entries.items()
            ]
        return snapshot, bool(stale)

    def _notify(self, snapshot=None) -> None:
        """Fire the on_change callback with a snapshot of active entries.
        When the caller already has a snapshot in hand (e.g., post-install),
        pass it in to avoid a redundant compute. When None, compute fresh
        without re-entering all_active() (which would itself call _notify)."""
        cb = self._on_change
        if cb is None:
            return
        if snapshot is None:
            snapshot, _ = self._compute_active_locked()
        try:
            cb(snapshot)
        except Exception:  # noqa: BLE001 — callbacks must never break the manager
            pass


# ---------- module-level singleton ----------


_default_manager: Optional[ProviderPauseManager] = None
_default_lock = threading.Lock()


def get_default_manager() -> ProviderPauseManager:
    """Module-level singleton scoped to the fun-doc directory.

    Workers, providers, and the web layer share the same instance so
    'install' from one place is visible to all readers.
    """
    global _default_manager
    if _default_manager is None:
        with _default_lock:
            if _default_manager is None:
                _default_manager = ProviderPauseManager(Path(__file__).resolve().parent)
    return _default_manager


def reset_default_manager_for_testing() -> None:
    """Tests use this to drop the singleton between cases."""
    global _default_manager
    with _default_lock:
        _default_manager = None

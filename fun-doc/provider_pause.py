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

import contextlib
import json
import os
import random
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


@contextlib.contextmanager
def _interprocess_lock(lock_path: Path):
    """Best-effort advisory lock serializing provider_pauses.json writes ACROSS processes.

    install() runs inside spawned worker subprocesses (multiprocessing 'spawn'), each with
    its own threading.Lock — which provides no cross-process mutual exclusion. This OS-level
    lock serializes the read/replace critical section so two providers hitting a quota wall
    at once cannot tear the file. It is fail-open: if OS locking is unavailable it proceeds
    unlocked rather than hang or crash.
    """
    f = None
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        f = open(lock_path, "a+")
        if os.name == "nt":
            import msvcrt

            # Non-blocking acquire with bounded retry so a stuck holder can't hang a worker.
            for _ in range(50):
                try:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.1)
        else:
            import fcntl

            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    except Exception:
        pass  # fail open
    try:
        yield
    finally:
        if f is not None:
            try:
                if os.name == "nt":
                    import msvcrt

                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                f.close()
            except Exception:
                pass


# Walls under this duration stay in retry logic (soft rate limits self-heal).
# Walls at or over this duration install a pause entry (Q11).
QUOTA_PAUSE_THRESHOLD_SECONDS = 300  # 5 minutes

# Used when a wall is detected but no reset time can be parsed (Q3 fallback).
DEFAULT_FALLBACK_PAUSE_SECONDS = 3600  # 1 hour

# Fallback for a persistent 429 with no parsable reset time (2026-07-18
# incident: MiniMax returned duration-less 429s for ~25 min; detectors
# returned None so workers marched on stamping malformed_response/no_change).
# Long enough to clear the threshold above, short enough to probe again soon.
RATE_LIMIT_FALLBACK_PAUSE_SECONDS = 600  # 10 minutes

# Applied when a provider fails terminally (dead credentials, retired client
# tier). Nothing self-heals here, so the pause exists to stop churn rather
# than to wait out a reset — an hour is long enough that a fixed credential
# resumes on its own without the operator having to clear the pause by hand.
TERMINAL_ERROR_PAUSE_SECONDS = 3600  # 1 hour

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
    if http_status == 429 or "error code: 429" in s or "rate limit" in s or "rate_limit" in s:
        # This detector only sees TERMINAL errors — _invoke_minimax surfaces
        # provider_error after its own 4-attempt exponential backoff (~35s)
        # is exhausted — so a duration-less 429 here is a persistent wall,
        # not a blip. Pause rather than let workers stamp malformed/no_change.
        secs = _parse_duration(error_str) or RATE_LIMIT_FALLBACK_PAUSE_SECONDS
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


# ---------- terminal (non-retryable) provider errors ----------


@dataclass
class TerminalProviderError:
    """A provider failure that retrying cannot fix.

    Unlike a quota wall — which clears on its own once the reset window
    passes — these need a human: expired or revoked credentials, a retired
    client tier, a plan that no longer covers the model. Workers must stop
    rather than burn queue attempts one function at a time.
    """

    reason: str


# Substrings that mark a permanently-broken provider. Kept deliberately
# specific: a false positive halts a working provider, so anything that can
# plausibly be transient (5xx, timeouts, generic "error") stays out.
_TERMINAL_ERROR_PATTERNS = (
    # Entitlement / tier retirement — e.g. Gemini Code Assist for individuals
    # was retired 2026-07-24 in favour of the Antigravity suite, which turns
    # every gemini-cli call into an IneligibleTierError.
    "ineligibletiererror",
    "no longer supported for",
    "client is no longer supported",
    "please migrate to",
    # Credentials
    "invalid api key",
    "invalid_api_key",
    "api key not valid",
    "api key expired",
    "authentication_error",
    "authentication failed",
    "unauthorized",
    "invalid authentication",
    "account is not authorized",
    "permission_denied",
    "access denied",
)


def detect_terminal_provider_error(
    provider: str, error_str: str, http_status: Optional[int] = None
) -> Optional[TerminalProviderError]:
    """Detect a non-retryable provider failure.

    Returns TerminalProviderError when the provider cannot serve requests
    until a human intervenes, else None. Callers install a long pause and
    stop the worker instead of advancing to the next function — otherwise a
    dead provider quietly converts the whole queue into `failed` runs.
    """
    s = (error_str or "").lower()
    if not s:
        return None
    # A quota wall is retryable by definition; never classify one as terminal
    # even if its text happens to mention permissions.
    if detect_quota_wall(provider, error_str, http_status=http_status) is not None:
        return None
    if http_status == 401:
        return TerminalProviderError(
            reason=f"{provider}: authentication rejected (401) — "
            + _truncate_for_reason(error_str)
        )
    for pattern in _TERMINAL_ERROR_PATTERNS:
        if pattern in s:
            return TerminalProviderError(
                reason=f"{provider}: {_truncate_for_reason(error_str)}"
            )
    return None


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
        # (mtime_ns, size) of the pause file as of our last read/write. Reads
        # compare against the live stamp to pick up installs made by other
        # processes — see _reload_if_changed_locked.
        self._file_stamp_seen = None
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
            self._reload_if_changed_locked()
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
            self._reload_if_changed_locked()
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

    def _file_stamp(self):
        """(mtime_ns, size) of the pause file, or None when it is absent."""
        try:
            st = self._path().stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _read_entries_from_disk(self) -> Optional[dict]:
        """Parse the pause file into an entries dict. None on unreadable /
        malformed file so callers keep whatever they already had."""
        path = self._path()
        if not path.exists():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
        entries = {}
        for key, val in ((data or {}).get("entries") or {}).items():
            try:
                if not isinstance(val, dict):
                    continue
                provider, model = key.split(":", 1)
                entries[(provider, model)] = (
                    datetime.fromisoformat(val["paused_until"]),
                    val.get("reason", ""),
                )
            except (ValueError, KeyError):
                continue
        return entries

    def _reload_if_changed_locked(self) -> None:
        """Re-read the pause file when another process has written it.

        A pause is installed by whichever process made the walled API call.
        For function workers that is a spawned provider subprocess with its
        own manager instance, so without this the dashboard process's set
        stays empty forever and workers never yield to a wall the subprocess
        already discovered — they just re-attempt the same function until
        their budget runs out. The file is the cross-process source of truth;
        an unchanged (mtime, size) stamp means our in-memory copy is current.

        Caller must hold self._lock.
        """
        stamp = self._file_stamp()
        if stamp == self._file_stamp_seen:
            return
        entries = self._read_entries_from_disk()
        if entries is None:  # unreadable/torn write — keep current state
            return
        self._file_stamp_seen = stamp
        self._entries = entries

    def _load(self) -> None:
        with self._lock:
            self._reload_if_changed_locked()
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
        # Serialize across processes: each spawned worker has its own threading.Lock, so the
        # OS-level lock is what actually prevents two writers from tearing the file.
        with _interprocess_lock(path.with_suffix(".json.lock")):
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except (OSError, AttributeError):
                    pass
            # On Windows another process briefly holding the file open makes replace() raise
            # PermissionError; retry like _atomic_write_state in fun_doc.py rather than lose
            # the write.
            for attempt in range(5):
                try:
                    tmp.replace(path)
                    break
                except PermissionError:
                    if attempt == 4:
                        raise
                    time.sleep(0.05 * (attempt + 1))
        # Record the stamp of the file we just wrote so the next read doesn't
        # treat our own write as a foreign change — re-reading it would be
        # wasted work and would discard in-memory edits made since.
        self._file_stamp_seen = self._file_stamp()

    def _compute_active_locked(self) -> tuple[list, bool]:
        """Return (snapshot, pruned). Acquires the lock once: prunes expired
        entries, persists if any were dropped, and snapshots the surviving
        entries. Used by all_active() and _notify() so callbacks can't cause
        recursion via all_active() -> _notify() -> all_active()."""
        now = datetime.now()
        with self._lock:
            self._reload_if_changed_locked()
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

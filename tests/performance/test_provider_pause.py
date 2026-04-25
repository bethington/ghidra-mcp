"""Offline regression tests for provider_pause module.

Locks in the design from the Q1-Q11 conversation 2026-04-25:

  Q1  pause scope = (provider, model)
  Q2  log run as quota_paused, no consecutive_fails bump (tested in
      test_provider_selection.py via integration; here we just verify the
      provider_error metadata signals that)
  Q3  parse Xh Ym Zs + jitter; 1h fallback when parse fails
  Q4  persistence in fun-doc/provider_pauses.json (atomic write, prune-on-boot)
  Q6  all four providers detected: gemini / claude / codex / minimax
  Q9  detect on first failure when message is unambiguous (gemini quota)
  Q11 5-minute threshold: short waits return ResetInfo too, but caller
      doesn't pause when raw_seconds < threshold
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest


FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import provider_pause as pp  # noqa: E402


# ---------- duration parser (Q3) ----------


def test_parse_duration_hms_compact():
    """The exact format gemini-cli emits: '8h59m24s' embedded in error text."""
    assert pp._parse_duration("Your quota will reset after 8h59m24s.") == pytest.approx(
        8 * 3600 + 59 * 60 + 24
    )


def test_parse_duration_hms_partial():
    """gemini occasionally returns just minutes+seconds or just seconds."""
    assert pp._parse_duration("reset after 5m30s") == 330
    assert pp._parse_duration("reset after 45s") == 45
    assert pp._parse_duration("reset after 2h") == 7200


def test_parse_duration_retry_after_header():
    """Standard HTTP retry-after seconds — claude/openai use this."""
    assert pp._parse_duration("HTTP 429 retry-after: 30") == 30
    assert pp._parse_duration("Retry-After: 600 seconds") == 600


def test_parse_duration_word_forms():
    """Less compact phrasings: 'in 5 minutes', 'after 2 hours'."""
    assert pp._parse_duration("try again in 5 minutes") == 300
    assert pp._parse_duration("retry after 2 hours") == 7200
    assert pp._parse_duration("wait 90 seconds") == 90


def test_parse_duration_returns_none_on_garbage():
    """Defensive: no recognizable duration -> None, caller falls back to 1h."""
    assert pp._parse_duration("") is None
    assert pp._parse_duration("something went wrong") is None
    assert pp._parse_duration(None) is None


def test_parse_duration_days_supported():
    """Some hard quota walls quote 'X days' for monthly plans."""
    assert pp._parse_duration("billing period resets in 2 days") == 2 * 86400


# ---------- per-provider detectors (Q6) ----------


def test_detect_gemini_unambiguous_quota_wall():
    """Q9: the actual message from the user's incident."""
    err = "You have exhausted your capacity on this model. Your quota will reset after 8h59m24s."
    info = pp.detect_quota_wall("gemini", err)
    assert info is not None
    assert info.raw_seconds == pytest.approx(8 * 3600 + 59 * 60 + 24)
    assert "gemini:" in info.reason


def test_detect_gemini_ignores_unrelated_errors():
    """Detector must return None for errors that aren't quota walls."""
    assert pp.detect_quota_wall("gemini", "Connection refused") is None
    assert pp.detect_quota_wall("gemini", "Invalid API key") is None
    assert pp.detect_quota_wall("gemini", "Timeout after 60s") is None


def test_detect_gemini_falls_back_to_default_when_no_duration():
    """Quota signal present but no parseable time -> 1h fallback (Q3)."""
    info = pp.detect_quota_wall("gemini", "You have exhausted your capacity on this model.")
    assert info is not None
    assert info.raw_seconds == pp.DEFAULT_FALLBACK_PAUSE_SECONDS


def test_detect_claude_credit_balance():
    """Hard wall: account billing exhausted."""
    err = '{"type":"billing_credit_low","message":"Your credit balance is too low to access this model."}'
    info = pp.detect_quota_wall("claude", err)
    assert info is not None
    assert "claude:" in info.reason


def test_detect_claude_429_with_retry_after():
    """Soft rate limit on claude — duration discriminator handles soft vs hard."""
    info = pp.detect_quota_wall("claude", "rate_limit_error retry-after: 30", http_status=429)
    assert info is not None
    assert info.raw_seconds == 30
    # Caller (5-min threshold check) keeps this in retry mode, not pause mode.
    assert info.raw_seconds < pp.QUOTA_PAUSE_THRESHOLD_SECONDS


def test_detect_claude_429_without_duration_returns_none():
    """A 429 with no parseable duration shouldn't trigger pause — let the
    provider's own retry handle it."""
    info = pp.detect_quota_wall("claude", "rate_limit_error", http_status=429)
    assert info is None


def test_detect_codex_insufficient_quota():
    err = '{"error":{"type":"insufficient_quota","message":"You exceeded your current quota"}}'
    info = pp.detect_quota_wall("codex", err)
    assert info is not None
    assert info.raw_seconds == pp.DEFAULT_FALLBACK_PAUSE_SECONDS


def test_detect_codex_429_short_retry_after():
    info = pp.detect_quota_wall(
        "codex", "rate_limit_exceeded retry-after: 60", http_status=429
    )
    assert info is not None
    assert info.raw_seconds == 60


def test_detect_minimax_quota_exhausted():
    info = pp.detect_quota_wall("minimax", "Your quota is exhausted, please retry tomorrow")
    assert info is not None
    assert info.raw_seconds == pp.DEFAULT_FALLBACK_PAUSE_SECONDS


def test_detect_unknown_provider_returns_none():
    """Defensive: a typo in provider name shouldn't crash."""
    assert pp.detect_quota_wall("not_a_real_provider", "anything") is None


# ---------- 5-minute threshold (Q11) ----------


def test_threshold_constant_is_five_minutes():
    """The Q11 threshold is locked at 300 seconds. Tests downstream rely on
    it. If the constant changes, this fails so we revisit the design."""
    assert pp.QUOTA_PAUSE_THRESHOLD_SECONDS == 300


def test_threshold_separates_soft_from_hard_walls():
    """A 30-second retry-after stays below threshold — caller retries instead
    of pausing. A 9-hour wall sits well above — caller pauses."""
    soft = pp.detect_quota_wall("claude", "retry-after: 30", http_status=429)
    hard = pp.detect_quota_wall(
        "gemini",
        "exhausted your capacity ... reset after 8h59m24s",
    )
    assert soft.raw_seconds < pp.QUOTA_PAUSE_THRESHOLD_SECONDS
    assert hard.raw_seconds >= pp.QUOTA_PAUSE_THRESHOLD_SECONDS


# ---------- ProviderPauseManager: install / is_paused / clear ----------


def _no_jitter():
    """Deterministic jitter for tests — paused_until = now + raw_seconds."""
    return 0.0


def _make_mgr(tmp_path):
    pp.reset_default_manager_for_testing()
    return pp.ProviderPauseManager(tmp_path, jitter_fn=_no_jitter)


def test_install_creates_active_pause(tmp_path):
    mgr = _make_mgr(tmp_path)
    info = pp.ResetInfo(raw_seconds=600.0, reason="test")
    until = mgr.install("gemini", "gemini-2.5-pro", info)
    assert mgr.is_paused("gemini", "gemini-2.5-pro")
    assert mgr.wait_until("gemini", "gemini-2.5-pro") == until
    assert mgr.reason("gemini", "gemini-2.5-pro") == "test"


def test_unrelated_provider_model_not_affected(tmp_path):
    """Q1: pause is keyed on (provider, model). Pausing gemini-2.5-pro must
    not affect gemini-2.5-flash or claude-anything."""
    mgr = _make_mgr(tmp_path)
    mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(600.0, "test"))
    assert mgr.is_paused("gemini", "gemini-2.5-pro")
    assert not mgr.is_paused("gemini", "gemini-2.5-flash")
    assert not mgr.is_paused("claude", "claude-sonnet-4-6")


def test_expired_entries_pruned_on_read(tmp_path):
    """A pause whose paused_until has passed should evaporate on next read."""
    mgr = _make_mgr(tmp_path)
    # Install a pause that's already in the past.
    info = pp.ResetInfo(raw_seconds=-10.0, reason="ancient")
    mgr.install("gemini", "gemini-2.5-pro", info)
    # is_paused triggers a wait_until check which prunes expired entries.
    assert not mgr.is_paused("gemini", "gemini-2.5-pro")


def test_clear_specific_pause(tmp_path):
    mgr = _make_mgr(tmp_path)
    mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(600.0, "x"))
    mgr.install("claude", "claude-sonnet-4-6", pp.ResetInfo(600.0, "y"))
    mgr.clear("gemini", "gemini-2.5-pro")
    assert not mgr.is_paused("gemini", "gemini-2.5-pro")
    assert mgr.is_paused("claude", "claude-sonnet-4-6")


def test_clear_all_pauses(tmp_path):
    mgr = _make_mgr(tmp_path)
    mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(600.0, "x"))
    mgr.install("claude", "claude-sonnet-4-6", pp.ResetInfo(600.0, "y"))
    mgr.clear_all()
    assert not mgr.is_paused("gemini", "gemini-2.5-pro")
    assert not mgr.is_paused("claude", "claude-sonnet-4-6")


def test_all_active_returns_only_unexpired(tmp_path):
    mgr = _make_mgr(tmp_path)
    mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(600.0, "future"))
    mgr.install("claude", "claude-sonnet-4-6", pp.ResetInfo(-10.0, "past"))
    active = mgr.all_active()
    keys = {(p, m) for (p, m, _u, _r) in active}
    assert ("gemini", "gemini-2.5-pro") in keys
    assert ("claude", "claude-sonnet-4-6") not in keys


def test_install_with_jitter_extends_paused_until(tmp_path):
    """Jitter pushes paused_until later than raw_seconds — Q3."""
    pp.reset_default_manager_for_testing()
    fixed_jitter = 45.0
    mgr = pp.ProviderPauseManager(tmp_path, jitter_fn=lambda: fixed_jitter)
    before = datetime.now()
    until = mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(60.0, "test"))
    elapsed = (until - before).total_seconds()
    # Should be approximately 60 + 45 = 105 seconds from now (tolerate 1s clock skew).
    assert 104 <= elapsed <= 106


def test_install_replaces_existing(tmp_path):
    """A second install on the same key overwrites the first."""
    mgr = _make_mgr(tmp_path)
    mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(60.0, "first"))
    mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(600.0, "second"))
    assert mgr.reason("gemini", "gemini-2.5-pro") == "second"


# ---------- persistence (Q4) ----------


def test_save_load_round_trip(tmp_path):
    """Pause set persists across manager restarts via provider_pauses.json."""
    mgr1 = _make_mgr(tmp_path)
    mgr1.install("gemini", "gemini-2.5-pro", pp.ResetInfo(3600.0, "test"))

    # Simulate a fresh boot: drop the singleton and create a new manager.
    pp.reset_default_manager_for_testing()
    mgr2 = pp.ProviderPauseManager(tmp_path, jitter_fn=_no_jitter)
    assert mgr2.is_paused("gemini", "gemini-2.5-pro")
    assert mgr2.reason("gemini", "gemini-2.5-pro") == "test"


def test_load_prunes_expired_on_boot(tmp_path):
    """A pause that expired during downtime must be dropped on startup."""
    # Manually write a stale entry to disk.
    payload = {
        "version": pp.PAUSE_FILE_VERSION,
        "entries": {
            "gemini:gemini-2.5-pro": {
                "paused_until": (datetime.now() - timedelta(hours=1)).isoformat(),
                "reason": "ancient",
            }
        },
    }
    (tmp_path / pp.PAUSE_FILE_NAME).write_text(json.dumps(payload))
    pp.reset_default_manager_for_testing()
    mgr = pp.ProviderPauseManager(tmp_path, jitter_fn=_no_jitter)
    assert not mgr.is_paused("gemini", "gemini-2.5-pro")
    assert mgr.all_active() == []


def test_load_handles_missing_file(tmp_path):
    """Fresh install — provider_pauses.json doesn't exist yet."""
    pp.reset_default_manager_for_testing()
    mgr = pp.ProviderPauseManager(tmp_path, jitter_fn=_no_jitter)
    assert mgr.all_active() == []


def test_load_handles_corrupt_file(tmp_path):
    """Don't crash dashboard startup on malformed pause file."""
    (tmp_path / pp.PAUSE_FILE_NAME).write_text("{not valid json")
    pp.reset_default_manager_for_testing()
    mgr = pp.ProviderPauseManager(tmp_path, jitter_fn=_no_jitter)
    assert mgr.all_active() == []


def test_save_atomic_no_tmp_file_left(tmp_path):
    """Atomic write contract — no .tmp file left behind after install."""
    mgr = _make_mgr(tmp_path)
    mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(60.0, "x"))
    assert (tmp_path / pp.PAUSE_FILE_NAME).exists()
    assert not (tmp_path / (pp.PAUSE_FILE_NAME + ".tmp")).exists()


# ---------- on_change callback (used by web layer to push to dashboard) ----------


def test_on_change_fires_on_install_and_clear(tmp_path):
    """The web layer registers a callback that pushes provider_pauses
    over WebSocket on every change."""
    mgr = _make_mgr(tmp_path)
    calls = []
    mgr.set_on_change(lambda active: calls.append(len(active)))
    mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(60.0, "x"))
    assert calls == [1]
    mgr.clear("gemini", "gemini-2.5-pro")
    assert calls == [1, 0]


def test_on_change_does_not_fire_when_clearing_nothing(tmp_path):
    """Idempotent clears don't generate spurious events."""
    mgr = _make_mgr(tmp_path)
    calls = []
    mgr.set_on_change(lambda active: calls.append(active))
    mgr.clear("gemini", "gemini-2.5-pro")  # no entry exists
    assert calls == []


def test_on_change_callback_exception_does_not_break_install(tmp_path):
    """Callback errors must not break the manager."""
    mgr = _make_mgr(tmp_path)
    mgr.set_on_change(lambda active: 1 / 0)
    # Should not raise.
    mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(60.0, "x"))
    assert mgr.is_paused("gemini", "gemini-2.5-pro")


def test_callback_calling_all_active_does_not_recurse(tmp_path):
    """Copilot review feedback (PR #168 / provider_pause.py:339): a callback
    that itself calls back into all_active() must NOT trigger a second
    notify cycle. Pre-fix: all_active() -> _notify() -> cb(all_active())
    -> all_active() -> _notify() -> ... — duplicate work and possible
    recursion. Post-fix: _compute_active_locked separates compute from
    notify so a callback that re-queries the manager is just one extra
    read with no notify side-effect."""
    mgr = _make_mgr(tmp_path)
    notify_count = {"n": 0}

    def cb(active):
        notify_count["n"] += 1
        # Callback re-queries the manager — should NOT trigger another notify.
        mgr.all_active()
        mgr.is_paused("gemini", "gemini-2.5-pro")

    # Install a valid future pause first (set_on_change is None at this
    # point, so no notify fires for the install).
    mgr.install("gemini", "gemini-2.5-pro", pp.ResetInfo(60.0, "test"))
    # Now expire the entry by directly mutating its paused_until. This is
    # the deterministic way to land in the "stale entry to be pruned" branch
    # of _compute_active_locked without sleeping or relying on jitter.
    with mgr._lock:
        until, reason = mgr._entries[("gemini", "gemini-2.5-pro")]
        mgr._entries[("gemini", "gemini-2.5-pro")] = (
            until - timedelta(seconds=120), reason
        )

    mgr.set_on_change(cb)

    # all_active prunes the stale entry and fires _notify once. The cb
    # then calls all_active and is_paused — both must be no-op for notify.
    snapshot = mgr.all_active()
    assert snapshot == []
    assert notify_count["n"] == 1, (
        "Expected exactly one notify; pre-fix would have produced 2+ via the "
        "all_active <-> _notify recursion."
    )

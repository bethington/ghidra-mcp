"""Coverage for unattended oracle recovery: the dead-game path and the
retry budget.

Context (2026-07-30). Six prove workers were running when the D2Debugger
oracle died. Measured 70 minutes later:

    consecutive_down: 94      game_running: false
    relaunch_stage:   null    relaunch_error: null   <-- ZERO attempts made

Three correct-in-isolation decisions deadlocked:

1. `_maybe_auto_recover` was reachable only via `game_wedged`, which requires
   `running and not reachable`. A game that fully EXITED had no unattended
   path back at all.
2. The need-predicate was "a port worker is running". A dead oracle makes port
   workers drain into `oracle_unavailable` and exit, so once the last one went
   the predicate went false and recovery refused with "nothing needs the
   oracle right now".
3. Even reached, recovery gave up permanently after 3 attempts.

These tests pin all three fixes. They are pure unit tests: the monitor is
driven with injected probes, and nothing here launches a game or touches
:8790.
"""

import itertools
import sys
import time
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

oracle_health = pytest.importorskip("oracle_health")


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, payload):
        self.events.append((name, payload))


def _monitor(monkeypatch, *, reachable, game_running, needed=True,
             relaunch_ok=False, bus=None):
    """An OracleHealthMonitor with every external probe stubbed.

    `reachable` / `game_running` are callables so a test can flip them
    mid-sequence (e.g. "the relaunch worked").
    """
    monkeypatch.setattr(oracle_health, "check_oracle_alive", reachable)
    monkeypatch.setattr(oracle_health, "is_game_running", game_running)
    m = oracle_health.OracleHealthMonitor(
        bus=bus, auto_recover=True,
        auto_recover_needed=(needed if callable(needed) else (lambda: needed)),
    )
    calls = []

    def _fake_relaunch(**kwargs):
        calls.append(kwargs)
        return {"ok": relaunch_ok() if callable(relaunch_ok) else relaunch_ok,
                "error": None if relaunch_ok else "launcher failed"}

    monkeypatch.setattr(m, "relaunch", _fake_relaunch)
    m.relaunch_calls = calls

    # The frame probe is an EXTERNAL call too -- it HTTPs :8790 -- and leaving
    # it unstubbed broke this module's "nothing here touches :8790" contract
    # the moment FROZEN detection landed. On a CI runner the read fails, so it
    # returns None and the tests pass; on a developer box with the game
    # actually running it returns a real counter, and back-to-back check_once()
    # calls read it flat and declared a healthy oracle FROZEN. A climbing
    # counter is the honest default for a monitor these tests are calling
    # healthy. Tests about freezing live in test_frozen_game.py.
    frames = itertools.count(1000, 500)
    monkeypatch.setattr(oracle_health, "_present_count", lambda: next(frames))
    return m


# ---------------------------------------------------------------- shapes ----

def test_dead_game_triggers_recovery(monkeypatch):
    """THE regression. Oracle down + no process => game_dead, and recovery
    fires. Before the fix this state had no path to _maybe_auto_recover at
    all, which is how 70 minutes passed with zero attempts."""
    m = _monitor(monkeypatch, reachable=lambda *a, **k: False,
                 game_running=lambda: False)
    # AUTO_RECOVER_AFTER_DOWN polls of hard evidence before acting.
    for _ in range(oracle_health.AUTO_RECOVER_AFTER_DOWN):
        snap = m.check_once()
    assert snap["game_dead"] is True
    assert snap["game_wedged"] is False
    assert m.relaunch_calls, "a dead game must be relaunched, not ignored"


def test_wedged_game_still_triggers_recovery(monkeypatch):
    """The pre-existing path must keep working -- and must still pass
    force=True, since a wedged game has a corpse to close first."""
    m = _monitor(monkeypatch, reachable=lambda *a, **k: False,
                 game_running=lambda: True)
    for _ in range(oracle_health.AUTO_RECOVER_AFTER_DOWN):
        snap = m.check_once()
    assert snap["game_wedged"] is True
    assert snap["game_dead"] is False
    assert m.relaunch_calls and m.relaunch_calls[0].get("force") is True


def test_brief_outage_does_not_trigger_recovery(monkeypatch):
    """One slow poll is not an outage. Acting on it would kill a game over
    a hiccup."""
    m = _monitor(monkeypatch, reachable=lambda *a, **k: False,
                 game_running=lambda: False)
    snap = m.check_once()
    assert snap["game_dead"] is False
    assert not m.relaunch_calls


def test_healthy_oracle_never_recovers(monkeypatch):
    m = _monitor(monkeypatch, reachable=lambda *a, **k: True,
                 game_running=lambda: True)
    for _ in range(6):
        snap = m.check_once()
    assert snap["reachable"] is True
    assert not m.relaunch_calls


# ------------------------------------------------------------ predicate ----

def test_need_predicate_false_blocks_recovery(monkeypatch):
    """The gate is still real: with nothing wanting the oracle we must not
    launch a game on spec."""
    m = _monitor(monkeypatch, reachable=lambda *a, **k: False,
                 game_running=lambda: False, needed=False)
    for _ in range(oracle_health.AUTO_RECOVER_AFTER_DOWN):
        m.check_once()
    assert not m.relaunch_calls


def test_missing_need_predicate_blocks_recovery(monkeypatch):
    """A bare monitor (scripts, tests) must never auto-launch."""
    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda *a, **k: False)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: False)
    m = oracle_health.OracleHealthMonitor(auto_recover=True)
    calls = []
    monkeypatch.setattr(m, "relaunch",
                        lambda **kw: calls.append(kw) or {"ok": True})
    for _ in range(oracle_health.AUTO_RECOVER_AFTER_DOWN + 2):
        m.check_once()
    assert not calls


# --------------------------------------------------------- retry budget ----

def test_cooldown_is_flat_during_the_burst():
    m = oracle_health.OracleHealthMonitor(auto_recover=False)
    for n in range(oracle_health.AUTO_RECOVER_BURST):
        assert m._cooldown_for_attempt(n) == oracle_health.AUTO_RECOVER_COOLDOWN_SEC


def test_cooldown_backs_off_past_the_burst_and_is_capped():
    m = oracle_health.OracleHealthMonitor(auto_recover=False)
    burst = oracle_health.AUTO_RECOVER_BURST
    first_slow = m._cooldown_for_attempt(burst)
    assert first_slow > oracle_health.AUTO_RECOVER_COOLDOWN_SEC
    # Monotonic, and never past the ceiling -- that ceiling is what makes
    # retrying forever safe rather than a kill/launch loop.
    prev = 0.0
    for n in range(burst, burst + 25):
        cd = m._cooldown_for_attempt(n)
        assert cd >= prev
        assert cd <= oracle_health.AUTO_RECOVER_MAX_COOLDOWN_SEC
        prev = cd
    assert m._cooldown_for_attempt(burst + 25) == oracle_health.AUTO_RECOVER_MAX_COOLDOWN_SEC


def test_recovery_never_permanently_gives_up(monkeypatch):
    """THE regression for the overnight stall. Past the burst, attempts must
    keep happening -- just further apart. Previously this returned
    'gave up after N attempt(s)' forever."""
    m = _monitor(monkeypatch, reachable=lambda *a, **k: False,
                 game_running=lambda: False, relaunch_ok=False)
    snap = {"game_wedged": False, "game_dead": True, "relaunching": False}
    attempts_over_a_long_time = 0
    fake_now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: fake_now[0])
    for _ in range(40):
        # Jump past whatever cooldown currently applies.
        fake_now[0] += oracle_health.AUTO_RECOVER_MAX_COOLDOWN_SEC + 1
        before = len(m.relaunch_calls)
        m._maybe_auto_recover(snap)
        if len(m.relaunch_calls) > before:
            attempts_over_a_long_time += 1
    assert attempts_over_a_long_time == 40, (
        "recovery must keep retrying indefinitely once past the burst"
    )


def test_cooldown_blocks_a_tight_loop(monkeypatch):
    """The other half: it must not hammer. Without advancing the clock, the
    second attempt is refused."""
    m = _monitor(monkeypatch, reachable=lambda *a, **k: False,
                 game_running=lambda: False, relaunch_ok=False)
    snap = {"game_wedged": False, "game_dead": True, "relaunching": False}
    m._maybe_auto_recover(snap)
    m._maybe_auto_recover(snap)
    assert len(m.relaunch_calls) == 1
    reason = m._auto_recover_blocked_reason(snap)
    assert reason and "cooling down" in reason


def test_degraded_flag_raised_past_the_burst(monkeypatch):
    m = _monitor(monkeypatch, reachable=lambda *a, **k: False,
                 game_running=lambda: False, relaunch_ok=False)
    snap = {"game_wedged": False, "game_dead": True, "relaunching": False}
    fake_now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: fake_now[0])
    for _ in range(oracle_health.AUTO_RECOVER_BURST):
        fake_now[0] += oracle_health.AUTO_RECOVER_MAX_COOLDOWN_SEC + 1
        m._maybe_auto_recover(snap)
    assert m.get_state()["recovery_degraded"] is True
    assert m.get_state()["recover_attempts"] >= oracle_health.AUTO_RECOVER_BURST


def test_success_rearms_the_burst(monkeypatch):
    """Three failures spread across a day must not leave the monitor stuck in
    slow-retry once the oracle has been healthy since."""
    alive = [False]
    m = _monitor(monkeypatch, reachable=lambda *a, **k: alive[0],
                 game_running=lambda: False, relaunch_ok=False)
    snap = {"game_wedged": False, "game_dead": True, "relaunching": False}
    fake_now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: fake_now[0])
    for _ in range(oracle_health.AUTO_RECOVER_BURST):
        fake_now[0] += oracle_health.AUTO_RECOVER_MAX_COOLDOWN_SEC + 1
        m._maybe_auto_recover(snap)
    assert m.get_state()["recovery_degraded"] is True

    alive[0] = True
    m.check_once()
    st = m.get_state()
    assert st["recovery_degraded"] is False
    assert st["recover_attempts"] == 0
    assert m._auto_recover_attempts == 0


def test_disabled_auto_recover_is_respected(monkeypatch):
    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda *a, **k: False)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: False)
    m = oracle_health.OracleHealthMonitor(auto_recover=False,
                                          auto_recover_needed=lambda: True)
    calls = []
    monkeypatch.setattr(m, "relaunch", lambda **kw: calls.append(kw) or {"ok": True})
    for _ in range(oracle_health.AUTO_RECOVER_AFTER_DOWN + 2):
        m.check_once()
    assert not calls


# ------------------------------------------------------------- env gate ----

def test_env_gate_follows_reachability(monkeypatch):
    """FUNDOC_LIVE_PROVE must track CURRENT reachability -- every
    process_port_candidate gate reads it fresh."""
    import os

    alive = [True]
    m = _monitor(monkeypatch, reachable=lambda *a, **k: alive[0],
                 game_running=lambda: True)
    m.check_once()
    assert os.environ.get("FUNDOC_LIVE_PROVE") == "1"
    alive[0] = False
    m.check_once()
    assert "FUNDOC_LIVE_PROVE" not in os.environ
    alive[0] = True
    m.check_once()
    assert os.environ.get("FUNDOC_LIVE_PROVE") == "1"


def test_next_retry_countdown_is_exposed(monkeypatch):
    """The banner renders a countdown; a pending recovery with no visible
    timer is indistinguishable from a hung dashboard."""
    m = _monitor(monkeypatch, reachable=lambda *a, **k: False,
                 game_running=lambda: False, relaunch_ok=False)
    for _ in range(oracle_health.AUTO_RECOVER_AFTER_DOWN):
        m.check_once()
    snap = m.check_once()
    assert snap["next_retry_in"] is None or snap["next_retry_in"] > 0


# ---------------------------------------------------- launcher windowing ----

def test_launch_is_windowless_when_already_elevated(monkeypatch):
    """LaunchPD2-Oracle.bat ends with `endlocal` and no `exit`, so whatever
    console it runs in sits at a prompt forever. `start` gives it such a
    console -- which is only worth paying for when the .bat has to self-elevate
    and surface a UAC prompt.

    An elevated dashboard makes the .bat's `net session` check pass, so it
    never elevates and that window buys nothing. Two orphaned "Administrator:"
    consoles were found on the desktop 2026-07-31, one per auto-recovery.
    """
    monkeypatch.setattr(oracle_health, "is_elevated", lambda: True)
    monkeypatch.setattr(oracle_health.os.path, "exists", lambda p: True)
    spawned = []
    monkeypatch.setattr(oracle_health.subprocess, "Popen",
                        lambda cmd, **kw: spawned.append((cmd, kw)) or None)

    m = oracle_health.OracleHealthMonitor(auto_recover=False)
    assert m._launch_game() is None
    cmd, kw = spawned[0]
    assert "start" not in cmd, "an elevated launch must not spawn a lingering console"
    assert kw.get("creationflags"), "and must suppress its own window"


def test_launch_keeps_a_real_window_when_NOT_elevated(monkeypatch):
    """Without elevation the .bat self-elevates, and a hidden console means an
    invisible consent dialog and a launch that looks hung."""
    monkeypatch.setattr(oracle_health, "is_elevated", lambda: False)
    monkeypatch.setattr(oracle_health.os.path, "exists", lambda p: True)
    spawned = []
    monkeypatch.setattr(oracle_health.subprocess, "Popen",
                        lambda cmd, **kw: spawned.append((cmd, kw)) or None)

    m = oracle_health.OracleHealthMonitor(auto_recover=False)
    m._launch_game()
    assert "start" in spawned[0][0], "the UAC prompt must remain reachable"

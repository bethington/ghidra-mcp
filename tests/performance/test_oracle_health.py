"""
Tests for fun-doc/oracle_health.py -- the D2Debugger live-oracle health
poller and one-click relaunch orchestration.

Background (2026-07-27): the port worker only ever checked oracle
reachability ONCE, at worker startup, and latched FUNDOC_LIVE_PROVE /
FUNDOC_SHADOW_PROMOTE for that worker's whole lifetime. A mid-run oracle
death (confirmed live: a bad proof vector crashed it, the game process later
disappeared entirely) went unnoticed for hours -- the worker kept spending
full LLM-driven draft passes on port_live candidates whose final live-prove
step was doomed to fail. These tests lock in the fix: reachability is now a
LIVE fact refreshed on a background thread, and every existing
os.environ.get("FUNDOC_LIVE_PROVE") gate throughout fun_doc.py picks it up
automatically.

Design: OracleHealthMonitor takes bus/launch_bat/character as constructor
args and never spawns the real background thread in these tests (call
check_once()/relaunch() directly, synchronously) so nothing here touches a
real Game.exe, a real :8790, or the real environment beyond what monkeypatch
restores.
"""

from __future__ import annotations

import sys
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


class FakeBus:
    def __init__(self):
        self.emitted = []  # list of (event_type, data)

    def emit(self, event_type, data=None):
        self.emitted.append((event_type, data))

    def of_type(self, event_type):
        return [d for (t, d) in self.emitted if t == event_type]


@pytest.fixture
def clean_gate_env(monkeypatch):
    """FUNDOC_LIVE_PROVE/FUNDOC_SHADOW_PROMOTE start unset; monkeypatch
    restores whatever check_once() mutates after the test."""
    monkeypatch.delenv("FUNDOC_LIVE_PROVE", raising=False)
    monkeypatch.delenv("FUNDOC_SHADOW_PROMOTE", raising=False)
    yield


@pytest.fixture(autouse=True)
def isolate_event_log(tmp_path):
    """Every relaunch()/check_once() call in this file goes through
    event_log.log_event for real (most tests don't mock it) -- redirect the
    module-level log path so test runs (fake 'oracle_relaunch_result' rows,
    etc.) never land in the real fun-doc/logs/events.jsonl. Mirrors
    test_worker_watchdog.py's fast_watchdog_env fixture."""
    import event_log

    original_path = event_log._EVENT_LOG_FILE
    event_log._EVENT_LOG_FILE = tmp_path / "events.jsonl"
    yield
    event_log._EVENT_LOG_FILE = original_path


def _make_monitor(bus=None, **kwargs):
    from oracle_health import OracleHealthMonitor

    return OracleHealthMonitor(bus=bus or FakeBus(), **kwargs)


# -- check_once(): the env-var gate ----------------------------------------


def test_check_once_reachable_sets_live_prove_gates(monkeypatch, clean_gate_env):
    import os
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: True)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    mon = _make_monitor()

    state = mon.check_once()

    assert state["reachable"] is True
    assert state["game_running"] is True
    assert os.environ.get("FUNDOC_LIVE_PROVE") == "1"
    assert os.environ.get("FUNDOC_SHADOW_PROMOTE") == "1"


def test_check_once_unreachable_clears_live_prove_gates(monkeypatch, clean_gate_env):
    import os
    import oracle_health

    os.environ["FUNDOC_LIVE_PROVE"] = "1"
    os.environ["FUNDOC_SHADOW_PROMOTE"] = "1"
    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: False)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: False)
    mon = _make_monitor()

    state = mon.check_once()

    assert state["reachable"] is False
    assert os.environ.get("FUNDOC_LIVE_PROVE") is None
    assert os.environ.get("FUNDOC_SHADOW_PROMOTE") is None


def test_check_once_tracks_consecutive_down_and_resets_on_recovery(monkeypatch, clean_gate_env):
    import oracle_health

    reachable = {"v": False}
    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: reachable["v"])
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: False)
    mon = _make_monitor()

    s1 = mon.check_once()
    s2 = mon.check_once()
    s3 = mon.check_once()
    assert [s1["consecutive_down"], s2["consecutive_down"], s3["consecutive_down"]] == [1, 2, 3]

    reachable["v"] = True
    s4 = mon.check_once()
    assert s4["consecutive_down"] == 0


def test_check_once_emits_bus_event_every_call(monkeypatch, clean_gate_env):
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: True)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    bus = FakeBus()
    mon = _make_monitor(bus=bus)

    mon.check_once()
    mon.check_once()

    assert len(bus.of_type("oracle_health")) == 2


def test_check_once_logs_only_on_transition(monkeypatch, clean_gate_env):
    """A steady 'still down' state must not spam events.jsonl every poll
    tick -- only the up<->down transition is audit-history-worthy."""
    import oracle_health

    logged = []
    monkeypatch.setattr("event_log.log_event", lambda event, **f: logged.append((event, f)))
    reachable = {"v": False}
    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: reachable["v"])
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: False)
    mon = _make_monitor()

    mon.check_once()  # None -> unreachable: a transition
    mon.check_once()  # unreachable -> unreachable: no transition
    mon.check_once()  # unreachable -> unreachable: no transition
    reachable["v"] = True
    mon.check_once()  # unreachable -> reachable: a transition

    health_changed = [f for (e, f) in logged if e == "oracle_health_changed"]
    assert len(health_changed) == 2


# -- is_game_running() ------------------------------------------------------


def test_is_game_running_true_when_tasklist_lists_it(monkeypatch):
    import subprocess
    import oracle_health

    class FakeResult:
        stdout = '"Game.exe","16984","Console","1","123,456 K"\r\n'

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeResult())
    assert oracle_health.is_game_running() is True


def test_is_game_running_false_when_tasklist_empty(monkeypatch):
    import subprocess
    import oracle_health

    class FakeResult:
        stdout = "INFO: No tasks are running which match the specified criteria.\r\n"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeResult())
    assert oracle_health.is_game_running() is False


def test_is_game_running_false_on_subprocess_error(monkeypatch):
    import subprocess
    import oracle_health

    def _raise(*a, **k):
        raise OSError("tasklist not found")

    monkeypatch.setattr(subprocess, "run", _raise)
    assert oracle_health.is_game_running() is False


# -- relaunch(): guards -------------------------------------------------------


def test_relaunch_rejects_concurrent_relaunch(monkeypatch):
    mon = _make_monitor()
    mon._state["relaunching"] = True

    result = mon.relaunch()

    assert result["ok"] is False
    assert "already in progress" in result["error"]


def test_relaunch_refuses_when_game_running_but_oracle_unreachable(monkeypatch):
    """LaunchPD2-Oracle.bat itself refuses to double-launch -- if Game.exe is
    up but unreachable, relaunching would corrupt state per the .bat's own
    guard. Must surface a clear, actionable error instead of trying anyway."""
    import oracle_health

    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    launched = []
    mon = _make_monitor()
    monkeypatch.setattr(mon, "_launch_game", lambda: launched.append(1))

    result = mon.relaunch()

    assert result["ok"] is False
    assert "already running" in result["error"]
    assert launched == []  # _launch_game must never be called


def test_relaunch_reports_missing_launcher_script(monkeypatch):
    import oracle_health

    monkeypatch.setattr(oracle_health, "is_game_running", lambda: False)
    mon = _make_monitor(launch_bat=r"C:\definitely\does\not\exist.bat")

    result = mon.relaunch()

    assert result["ok"] is False
    assert "launcher script not found" in result["error"]
    assert mon.get_state()["relaunching"] is False


# -- relaunch(): full sequence (mocked I/O) ----------------------------------


def test_relaunch_success_path(monkeypatch, tmp_path):
    """Happy path: launch succeeds, oracle comes up on the first wait,
    character-load succeeds -> relaunch reports ready with no error."""
    import oracle_health

    fake_bat = tmp_path / "LaunchPD2-Oracle.bat"
    fake_bat.write_text("@echo off\n")
    monkeypatch.setattr(oracle_health.time, "sleep", lambda s: None)  # no real waiting

    oracle_up = {"v": False}
    # is_game_running: False before launch (so the "already running" guard
    # doesn't fire), True after -- mirrors the real world once Game.exe boots.
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: oracle_up["v"])
    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: oracle_up["v"])

    mon = _make_monitor(launch_bat=str(fake_bat), character="summoner-skele")
    monkeypatch.setattr(mon, "_launch_game", lambda: oracle_up.__setitem__("v", True))
    monkeypatch.setattr(mon, "_navigate_and_load_character",
                         lambda character, timeout: {"ok": True})

    result = mon.relaunch()

    assert result == {"ok": True, "character": "summoner-skele"}
    state = mon.get_state()
    assert state["relaunching"] is False
    assert state["relaunch_stage"] == "ready"
    assert state["relaunch_error"] is None


def test_relaunch_dismisses_transient_error_dialog_and_retries_once(monkeypatch, tmp_path):
    """LOOP_PLAYBOOK.md: a lingering lock from a crashed prior instance can
    pop a 'Diablo II Error' dialog on the first relaunch; dismissing it and
    retrying once is documented to come up clean."""
    import oracle_health

    fake_bat = tmp_path / "LaunchPD2-Oracle.bat"
    fake_bat.write_text("@echo off\n")
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: False)
    monkeypatch.setattr(oracle_health.time, "sleep", lambda s: None)

    launch_count = {"n": 0}
    oracle_up_after_attempt = {"n": None}  # set once the 2nd launch "boots"

    def _fake_launch():
        launch_count["n"] += 1
        if launch_count["n"] == 2:
            oracle_up_after_attempt["n"] = 2

    def _fake_check():
        return oracle_up_after_attempt["n"] == 2

    dismiss_calls = []

    def _fake_dismiss():
        dismiss_calls.append(1)
        return True  # a dialog WAS found and closed -> relaunch retries once

    monkeypatch.setattr(oracle_health, "check_oracle_alive", _fake_check)
    monkeypatch.setattr(oracle_health, "_dismiss_diablo_error_dialog", _fake_dismiss)

    mon = _make_monitor(launch_bat=str(fake_bat))
    monkeypatch.setattr(mon, "_launch_game", _fake_launch)
    monkeypatch.setattr(mon, "_navigate_and_load_character",
                         lambda character, timeout: {"ok": True})

    result = mon.relaunch(timeout_boot=0.01)

    assert launch_count["n"] == 2, "expected exactly one retry (two total launches)"
    assert dismiss_calls == [1]
    assert result["ok"] is True


def test_relaunch_fails_clearly_after_boot_timeout_with_no_dialog(monkeypatch, tmp_path):
    import oracle_health

    fake_bat = tmp_path / "LaunchPD2-Oracle.bat"
    fake_bat.write_text("@echo off\n")
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: False)
    monkeypatch.setattr(oracle_health.time, "sleep", lambda s: None)
    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: False)
    monkeypatch.setattr(oracle_health, "_dismiss_diablo_error_dialog", lambda: False)

    mon = _make_monitor(launch_bat=str(fake_bat))
    monkeypatch.setattr(mon, "_launch_game", lambda: None)

    result = mon.relaunch(timeout_boot=0.01)

    assert result["ok"] is False
    assert "did not come up" in result["error"]
    assert mon.get_state()["relaunching"] is False


# -- _navigate_and_load_character() ------------------------------------------


def test_navigate_reports_character_not_found(monkeypatch):
    import oracle_health

    monkeypatch.setattr(oracle_health, "_oracle_post", lambda path, body, timeout=15.0: {"ok": True})
    monkeypatch.setattr(
        oracle_health, "_oracle_get",
        lambda path, timeout=10.0: [{"index": 0, "name": "some-other-char", "class": "necromancer"}],
    )
    mon = _make_monitor()

    result = mon._navigate_and_load_character("summoner-skele", timeout=1.0)

    assert result["ok"] is False
    assert "summoner-skele" in result["error"]
    assert "some-other-char" in result["error"]


def test_navigate_loads_the_matching_character(monkeypatch):
    import oracle_health

    posted = []
    monkeypatch.setattr(
        oracle_health, "_oracle_post",
        lambda path, body, timeout=15.0: posted.append((path, body)) or {"ok": True},
    )
    monkeypatch.setattr(
        oracle_health, "_oracle_get",
        lambda path, timeout=10.0: [{"index": 0, "name": "summoner-skele", "class": "necromancer"}],
    )
    mon = _make_monitor()

    result = mon._navigate_and_load_character("summoner-skele", timeout=1.0)

    assert result == {"ok": True}
    load_calls = [b for (p, b) in posted if p == "/action/load-character"]
    assert load_calls == [{"name": "summoner-skele", "difficulty": 0, "confirm": True}]


# -- stale relaunch failure is cleared on recovery (2026-07-30) --------------
#
# relaunch_stage/relaunch_error are written ONLY by _set_relaunch, i.e. only
# while this class is driving a relaunch. A failed attempt therefore pinned
# "failed" + its error forever, and any other route back to health -- above all
# the operator relaunching by hand, which is the common one -- left the
# dashboard reporting reachable=true, game_running=true and
# relaunch_stage="failed" simultaneously. Observed live 2026-07-30.

def test_recovery_clears_a_stale_relaunch_failure(monkeypatch, clean_gate_env):
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: True)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    mon = _make_monitor()
    mon._set_relaunch(False, "failed", "Game.exe is already running but the oracle is unreachable")

    state = mon.check_once()

    assert state["reachable"] is True
    assert state["relaunch_stage"] is None
    assert state["relaunch_error"] is None


def test_recovery_emits_so_the_dashboard_stops_rendering_the_stale_failure(
        monkeypatch, clean_gate_env):
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: True)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    bus = FakeBus()
    mon = _make_monitor(bus=bus)
    mon._set_relaunch(False, "failed", "boom")
    before = len(bus.emitted)

    mon.check_once()

    kinds = [t for (t, _d) in bus.emitted[before:]]
    assert "oracle_relaunch_progress" in kinds, kinds
    # and the pushed snapshot must actually carry the cleared state
    cleared = bus.of_type("oracle_relaunch_progress")[-1]
    assert cleared["relaunch_stage"] is None and cleared["relaunch_error"] is None


def test_a_successful_relaunch_stage_is_preserved(monkeypatch, clean_gate_env):
    """Only a FAILED stage is stale. 'ready' is real information about a
    relaunch that actually worked and must survive the next poll."""
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: True)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    mon = _make_monitor()
    mon._set_relaunch(False, "ready", None)

    state = mon.check_once()

    assert state["relaunch_stage"] == "ready"


def test_in_progress_relaunch_is_not_clobbered(monkeypatch, clean_gate_env):
    """A relaunch in flight legitimately owns the stage; the poller must not
    wipe it just because the oracle answered mid-sequence."""
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: True)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    mon = _make_monitor()
    mon._set_relaunch(True, "waiting_for_oracle", None)

    state = mon.check_once()

    assert state["relaunching"] is True
    assert state["relaunch_stage"] == "waiting_for_oracle"


def test_failure_is_retained_while_still_unreachable(monkeypatch, clean_gate_env):
    """Nothing has recovered -- the diagnosis is still the current truth."""
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: False)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    mon = _make_monitor()
    mon._set_relaunch(False, "failed", "oracle crashed without killing the game")

    state = mon.check_once()

    assert state["relaunch_stage"] == "failed"
    assert state["relaunch_error"] == "oracle crashed without killing the game"


# -- wedged game: process alive, embedded oracle dead ----------------------
#
# The 2026-07-30 incident: a D2 "Halt / Unrecoverable internal error 6fdb767c"
# box left Game.exe alive and message-pumping (is_game_running() True, the
# window even reported Responding=True) while its embedded oracle was gone.
# check_oracle_alive() went False, every live candidate short-circuited to
# oracle_unavailable, and the whole 12-worker Prove fleet drained its pools
# into skips -- while relaunch() refused to act BECAUSE the game was
# "running". Recovery was blocked precisely when it was needed most.


def test_wedged_state_needs_a_sustained_down_streak(monkeypatch, clean_gate_env):
    """One slow poll is not a crash. game_wedged only latches once the oracle
    has been down for AUTO_RECOVER_AFTER_DOWN consecutive checks."""
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: False)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    mon = _make_monitor()

    for _ in range(oracle_health.AUTO_RECOVER_AFTER_DOWN - 1):
        assert mon.check_once()["game_wedged"] is False
    assert mon.check_once()["game_wedged"] is True


def test_game_down_entirely_is_not_wedged(monkeypatch, clean_gate_env):
    """No process at all is the ordinary relaunch case, not a wedge -- they
    need different recovery, so they must not collapse into one flag."""
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: False)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: False)
    mon = _make_monitor()

    for _ in range(oracle_health.AUTO_RECOVER_AFTER_DOWN + 2):
        snap = mon.check_once()
    assert snap["game_wedged"] is False


def test_relaunch_force_closes_the_wedged_game_then_launches(monkeypatch, tmp_path):
    """force=True is the whole point: dismiss the Halt dialog, kill the corpse,
    then run the normal launch sequence."""
    import oracle_health

    bat = tmp_path / "LaunchPD2-Oracle.bat"
    bat.write_text("@echo off\n")
    calls = []
    alive = {"v": True}

    monkeypatch.setattr(oracle_health, "is_game_running", lambda: alive["v"])
    monkeypatch.setattr(oracle_health, "_dismiss_diablo_error_dialog",
                        lambda: calls.append("dismiss") or True)

    def _kill(timeout=20.0):
        calls.append("kill")
        alive["v"] = False
        return True

    monkeypatch.setattr(oracle_health, "kill_game", _kill)
    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: True)

    mon = _make_monitor(launch_bat=str(bat))
    monkeypatch.setattr(mon, "_launch_game", lambda: calls.append("launch"))
    monkeypatch.setattr(mon, "_navigate_and_load_character",
                        lambda c, t: {"ok": True, "character": c})

    result = mon.relaunch(force=True)

    assert result["ok"] is True
    # Order matters: the corpse must be gone BEFORE the launcher runs, or
    # the launcher's own double-launch guard refuses.
    assert calls == ["dismiss", "kill", "launch"]


def test_relaunch_force_fails_clearly_when_the_game_will_not_die(monkeypatch, tmp_path):
    """An elevated/unkillable game must not silently fall through to a launch
    the launcher will refuse anyway -- say so and stop."""
    import oracle_health

    bat = tmp_path / "LaunchPD2-Oracle.bat"
    bat.write_text("@echo off\n")
    launched = []

    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    monkeypatch.setattr(oracle_health, "_dismiss_diablo_error_dialog", lambda: False)
    monkeypatch.setattr(oracle_health, "kill_game", lambda timeout=20.0: False)

    mon = _make_monitor(launch_bat=str(bat))
    monkeypatch.setattr(mon, "_launch_game", lambda: launched.append(1))

    result = mon.relaunch(force=True)

    assert result["ok"] is False
    assert "could not terminate" in result["error"]
    assert launched == []


def test_relaunch_without_force_still_refuses_and_says_how(monkeypatch):
    """The default must keep its hands off a running game -- but now point at
    the way out instead of dead-ending."""
    import oracle_health

    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    killed = []
    monkeypatch.setattr(oracle_health, "kill_game",
                        lambda timeout=20.0: killed.append(1) or True)
    mon = _make_monitor()

    result = mon.relaunch()

    assert result["ok"] is False
    assert "force" in result["error"]
    assert killed == []


# -- unattended recovery gating -------------------------------------------


def _wedge(monkeypatch):
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: False)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)


def _drive_to_wedged(mon):
    import oracle_health

    snap = None
    for _ in range(oracle_health.AUTO_RECOVER_AFTER_DOWN):
        snap = mon.check_once()
    return snap


def test_auto_recover_fires_when_a_port_worker_is_waiting(monkeypatch, clean_gate_env):
    _wedge(monkeypatch)
    attempts = []
    mon = _make_monitor(auto_recover_needed=lambda: True)
    monkeypatch.setattr(mon, "relaunch",
                        lambda **kw: attempts.append(kw) or {"ok": True})

    _drive_to_wedged(mon)

    assert attempts == [{"force": True}]


def test_auto_recover_declines_when_nothing_needs_the_oracle(monkeypatch, clean_gate_env):
    """A game the operator is driving by hand must never be killed just because
    the dashboard happens to be up."""
    _wedge(monkeypatch)
    attempts = []
    mon = _make_monitor(auto_recover_needed=lambda: False)
    monkeypatch.setattr(mon, "relaunch", lambda **kw: attempts.append(kw))

    _drive_to_wedged(mon)

    assert attempts == []


def test_auto_recover_declines_without_a_need_predicate(monkeypatch, clean_gate_env):
    """A bare monitor (scripts, tests) must not close a game on spec."""
    _wedge(monkeypatch)
    attempts = []
    mon = _make_monitor()  # no predicate
    monkeypatch.setattr(mon, "relaunch", lambda **kw: attempts.append(kw))

    _drive_to_wedged(mon)

    assert attempts == []


def test_auto_recover_can_be_switched_off(monkeypatch, clean_gate_env):
    _wedge(monkeypatch)
    attempts = []
    mon = _make_monitor(auto_recover=False, auto_recover_needed=lambda: True)
    monkeypatch.setattr(mon, "relaunch", lambda **kw: attempts.append(kw))

    _drive_to_wedged(mon)

    assert attempts == []


def test_auto_recover_slows_down_rather_than_giving_up(monkeypatch, clean_gate_env):
    """CONTRACT CHANGED 2026-07-30. This used to assert a permanent give-up
    after AUTO_RECOVER_MAX_ATTEMPTS, and that was the right call for an
    attended session but the wrong one for the overnight fleet this exists to
    protect -- the third failure stalled the run until a human looked, which
    at 2am costs the whole night.

    The kill/launch-loop concern the old test guarded is now handled by the
    BACKOFF (see test_auto_recover_cooldown_blocks_a_rapid_second_attempt and
    test_cooldown_backs_off_past_the_burst_and_is_capped in
    test_oracle_recovery.py): attempts continue indefinitely but settle at
    AUTO_RECOVER_MAX_COOLDOWN_SEC apart, i.e. ~2/hour, not a tight loop.

    With the cooldown pinned to 0 here, every poll is allowed to attempt, so
    attempts must keep accruing past the burst instead of flatlining."""
    import oracle_health

    _wedge(monkeypatch)
    monkeypatch.setattr(oracle_health, "AUTO_RECOVER_COOLDOWN_SEC", 0.0)
    monkeypatch.setattr(oracle_health, "AUTO_RECOVER_MAX_COOLDOWN_SEC", 0.0)
    attempts = []
    mon = _make_monitor(auto_recover_needed=lambda: True)
    monkeypatch.setattr(
        mon, "relaunch",
        lambda **kw: (attempts.append(kw), {"ok": False, "error": "boom"})[1])

    extra = 5
    for _ in range(oracle_health.AUTO_RECOVER_BURST + extra):
        mon.check_once()

    assert len(attempts) > oracle_health.AUTO_RECOVER_BURST, (
        "recovery must not stop permanently at the burst size"
    )
    # And it must have announced that it is no longer keeping up.
    assert mon.get_state()["recovery_degraded"] is True


def test_auto_recover_cooldown_blocks_a_rapid_second_attempt(monkeypatch, clean_gate_env):
    import oracle_health

    _wedge(monkeypatch)
    monkeypatch.setattr(oracle_health, "AUTO_RECOVER_COOLDOWN_SEC", 9999.0)
    attempts = []
    mon = _make_monitor(auto_recover_needed=lambda: True)
    monkeypatch.setattr(
        mon, "relaunch",
        lambda **kw: (attempts.append(kw), {"ok": False, "error": "boom"})[1])

    for _ in range(oracle_health.AUTO_RECOVER_AFTER_DOWN + 6):
        mon.check_once()

    assert len(attempts) == 1


def test_a_successful_auto_recovery_rearms_the_attempt_budget(monkeypatch, clean_gate_env):
    """Two unrelated crashes hours apart must both get recovered; the counter
    is for a failing LOOP, not a lifetime quota."""
    import oracle_health

    _wedge(monkeypatch)
    monkeypatch.setattr(oracle_health, "AUTO_RECOVER_COOLDOWN_SEC", 0.0)
    mon = _make_monitor(auto_recover_needed=lambda: True)
    monkeypatch.setattr(mon, "relaunch", lambda **kw: {"ok": True})

    _drive_to_wedged(mon)
    assert mon._auto_recover_attempts == 0


class _Completed:
    """Minimal subprocess.CompletedProcess stand-in for kill_game tests."""

    def __init__(self, stdout=b"", stderr=b""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = 0


class _FakeWindll:
    """ctypes.windll stand-in: records ShellExecuteW calls so a test can assert
    whether a UAC elevation was attempted."""

    def __init__(self, sink, shell_exec=None):
        outer = self

        class _Shell32:
            def ShellExecuteW(self, *args):
                if shell_exec is not None:
                    return shell_exec(*args)
                sink.append(args)
                return 42

        class _User32:
            def __getattr__(self, _name):
                return lambda *a, **k: 0

        self.shell32 = _Shell32()
        self.user32 = _User32()


# -- kill_game: PD2 runs elevated -----------------------------------------


def test_kill_game_succeeds_without_elevation_when_taskkill_works(monkeypatch):
    import oracle_health

    calls = []
    monkeypatch.setattr(oracle_health.subprocess, "run",
                        lambda *a, **k: calls.append(a) or _Completed(b"", b""))
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: False)
    shell = []
    monkeypatch.setattr(oracle_health.ctypes, "windll", _FakeWindll(shell), raising=False)

    assert oracle_health.kill_game(timeout=1.0) is True
    assert shell == []  # no UAC prompt when it wasn't needed


def test_kill_game_escalates_to_uac_when_access_is_denied(monkeypatch):
    """PD2 self-elevates, so a normal-integrity dashboard gets 'Access is
    denied' -- measured 2026-07-30. Without the runas retry a wedged game is
    simply unrecoverable from the dashboard."""
    import oracle_health

    monkeypatch.setattr(oracle_health.subprocess, "run",
                        lambda *a, **k: _Completed(b"", b"ERROR: Access is denied."))
    alive = {"v": True}
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: alive["v"])
    shell = []

    def _shell_exec(*args):
        shell.append(args)
        alive["v"] = False   # the user approved the prompt
        return 42

    monkeypatch.setattr(oracle_health.ctypes, "windll",
                        _FakeWindll(shell, shell_exec=_shell_exec), raising=False)

    assert oracle_health.kill_game(timeout=0.5) is True
    assert len(shell) == 1
    assert shell[0][1] == "runas"


def test_kill_game_does_not_escalate_for_a_non_permission_failure(monkeypatch):
    """A kill that failed for some other reason must not spam a UAC prompt."""
    import oracle_health

    monkeypatch.setattr(oracle_health.subprocess, "run",
                        lambda *a, **k: _Completed(b"", b"ERROR: process not found"))
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    shell = []
    monkeypatch.setattr(oracle_health.ctypes, "windll", _FakeWindll(shell), raising=False)

    assert oracle_health.kill_game(timeout=0.5) is False
    assert shell == []


def test_kill_game_can_refuse_to_elevate(monkeypatch):
    import oracle_health

    monkeypatch.setattr(oracle_health.subprocess, "run",
                        lambda *a, **k: _Completed(b"", b"Access is denied."))
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    shell = []
    monkeypatch.setattr(oracle_health.ctypes, "windll", _FakeWindll(shell), raising=False)

    assert oracle_health.kill_game(timeout=0.5, allow_elevate=False) is False
    assert shell == []


# -- elevation reporting ---------------------------------------------------
#
# PD2 self-elevates, so a normal-integrity dashboard cannot taskkill a wedged
# game and "unattended" recovery silently degrades to waiting on a UAC click.
# Whether we are elevated is therefore load-bearing operational state, not
# decoration -- it must be readable rather than assumed.


def test_health_state_reports_elevation(monkeypatch, clean_gate_env):
    import oracle_health

    monkeypatch.setattr(oracle_health, "check_oracle_alive", lambda: True)
    monkeypatch.setattr(oracle_health, "is_game_running", lambda: True)
    mon = _make_monitor()

    assert "elevated" in mon.get_state()
    assert mon.check_once()["elevated"] in (True, False)


def test_is_elevated_is_false_when_the_api_is_unavailable(monkeypatch):
    """Never raise out of a health check -- a probe that explodes is worse than
    one that answers 'no'."""
    import oracle_health

    class _Boom:
        @property
        def shell32(self):
            raise OSError("no shell32 here")

    monkeypatch.setattr(oracle_health.ctypes, "windll", _Boom(), raising=False)

    assert oracle_health.is_elevated() is False


def test_is_elevated_reflects_the_win32_answer(monkeypatch):
    import oracle_health

    for raw, expected in ((1, True), (0, False)):
        class _Shell:
            def IsUserAnAdmin(self_inner):
                return raw

        class _Windll:
            shell32 = _Shell()

        monkeypatch.setattr(oracle_health.ctypes, "windll", _Windll(), raising=False)
        assert oracle_health.is_elevated() is expected

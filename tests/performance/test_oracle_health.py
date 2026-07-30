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

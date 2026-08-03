"""Coverage for the pieces that keep the fleet alive across a dependency
outage: the PORT oracle backoff, the desktop notifier, and the worker roster
restore offer.

All three come from the same incident (2026-07-30): the D2Debugger oracle
died, six prove workers burned their candidate pools against it and exited,
the roster emptied so nothing was offered on restart, and the only record of
any of it was a log file inside a hidden elevated window.
"""

import sys
import threading
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

notify = pytest.importorskip("notify")


# =========================================================== port backoff ===

def _backoff(**kw):
    from fun_doc import PortOracleBackoff

    kw.setdefault("worker_id", "test0001")
    kw.setdefault("stop_flag", threading.Event())
    kw.setdefault("sleep", lambda s: None)      # never actually sleep
    kw.setdefault("oracle_probe", lambda: False)
    return PortOracleBackoff(**kw)


def test_streak_trips_only_on_consecutive_oracle_unavailable():
    b = _backoff(after=3)
    assert b.note("oracle_unavailable") is False
    assert b.note("oracle_unavailable") is False
    assert b.note("oracle_unavailable") is True


def test_any_other_outcome_resets_the_streak():
    """Static-harness progress interleaved with live failures means the
    oracle is not the bottleneck -- e6847b8c produced 11 shadow_leaf_pending
    DURING the outage. Only an unbroken run should trip the backoff."""
    b = _backoff(after=3)
    b.note("oracle_unavailable")
    b.note("oracle_unavailable")
    assert b.note("shadow_leaf_pending") is False
    assert b.streak == 0
    assert b.note("oracle_unavailable") is False


def test_wait_returns_true_and_clears_when_oracle_returns():
    calls = {"n": 0}

    def probe():
        calls["n"] += 1
        return calls["n"] >= 2          # back on the second check

    b = _backoff(after=1, max_wait=600, oracle_probe=probe)
    b.note("oracle_unavailable")
    assert b.wait_for_oracle() is True
    assert b.streak == 0


def test_wait_gives_up_at_the_cap_so_static_work_is_not_starved():
    """The cap is the whole reason this is not a blanket pause. A long outage
    must not stop the static harness lane forever."""
    b = _backoff(after=1, max_wait=30, oracle_probe=lambda: False)
    b.note("oracle_unavailable")
    assert b.wait_for_oracle() is False
    assert b.streak == 0, "streak must reset so we re-arm rather than re-trip instantly"


def test_wait_is_responsive_to_stop():
    stop = threading.Event()
    stop.set()
    b = _backoff(after=1, max_wait=99999, stop_flag=stop, oracle_probe=lambda: False)
    b.note("oracle_unavailable")
    assert b.wait_for_oracle() is False


def test_wait_heartbeats_through_on_idle():
    """Without this the watchdog stall-kills a deliberately-waiting worker --
    the exact false-kill that took 18e96b51 at the 900s threshold."""
    beats = []
    b = _backoff(after=1, max_wait=60, on_idle=lambda: beats.append(1),
                 oracle_probe=lambda: False)
    b.note("oracle_unavailable")
    b.wait_for_oracle()
    assert beats, "on_idle must fire while waiting or the watchdog kills the worker"


def test_probe_exception_does_not_escape():
    def boom():
        raise RuntimeError("oracle socket exploded")

    b = _backoff(after=1, max_wait=30, oracle_probe=boom)
    b.note("oracle_unavailable")
    assert b.wait_for_oracle() is False


# ================================================================ notify ===

def test_notify_is_edge_triggered(monkeypatch):
    """Level-triggered would re-toast every 45s poll for a whole outage,
    which trains you to dismiss them unread."""
    sent = []
    monkeypatch.setattr(notify, "send", lambda t, b: sent.append((t, b)) or True)
    notify.reset_for_tests()
    assert notify.notify_transition("oracle", "down", "T", "B") is True
    assert notify.notify_transition("oracle", "down", "T", "B") is False
    assert notify.notify_transition("oracle", "down", "T", "B") is False
    assert len(sent) == 1


def test_notify_fires_again_on_a_real_state_change(monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "send", lambda t, b: sent.append((t, b)) or True)
    monkeypatch.setattr(notify, "_MIN_REPEAT_SEC", 0.0)
    notify.reset_for_tests()
    notify.notify_transition("oracle", "down", "down", "b")
    notify.notify_transition("oracle", "up", "up", "b")
    notify.notify_transition("oracle", "down", "down", "b")
    assert [t for t, _ in sent] == ["down", "up", "down"]


def test_notify_rate_limits_a_flapping_dependency(monkeypatch):
    """down -> up -> down inside the repeat window is a flap, not news."""
    sent = []
    monkeypatch.setattr(notify, "send", lambda t, b: sent.append(t) or True)
    monkeypatch.setattr(notify, "_MIN_REPEAT_SEC", 9999.0)
    notify.reset_for_tests()
    assert notify.notify_transition("ghidra", "down", "d", "b") is True
    assert notify.notify_transition("ghidra", "up", "u", "b") is True
    assert notify.notify_transition("ghidra", "down", "d", "b") is False


def test_notify_subsystems_are_independent(monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "send", lambda t, b: sent.append(t) or True)
    notify.reset_for_tests()
    notify.notify_transition("oracle", "down", "o", "b")
    notify.notify_transition("ghidra", "down", "g", "b")
    assert sent == ["o", "g"]


def test_notify_disabled_is_a_clean_noop(monkeypatch):
    monkeypatch.setattr(notify, "NOTIFY_ENABLED", False)
    assert notify.send("t", "b") is False


def test_powershell_quoting_neutralises_injection():
    """Bodies carry provider names, launcher paths and exception text. In a
    DOUBLE-quoted PowerShell string `$(...)` executes; single-quoted has
    exactly one escape, the doubled quote."""
    nasty = "it's $(Remove-Item C:\\ -Recurse) `bad`"
    quoted = notify._ps_quote(nasty)
    assert quoted.startswith("'") and quoted.endswith("'")
    assert "it''s" in quoted
    # No unescaped quote can terminate the literal early.
    assert quoted.count("'") % 2 == 0


def test_script_embeds_text_via_dom_not_concatenation():
    """A function name with < or & must not be able to produce invalid toast
    XML (which the shell drops silently -- the worst alerting failure)."""
    script = notify._build_script("A & B", "<flag> set")
    assert "CreateTextNode" in script
    assert "$title" in script and "$body" in script


# ================================================= worker roster offer ======

class _FakeQueueStore:
    """Stands in for load/save of priority_queue.json."""

    def __init__(self):
        self.data = {}

    def load(self):
        import copy
        return copy.deepcopy(self.data)

    def save(self, q):
        import copy
        self.data = copy.deepcopy(q)


def _manager(store):
    """A WorkerManager with its background threads never started.

    __init__ spawns a watchdog plus two health monitors that poll real
    endpoints; this is a roster test, so build the object without running it.
    """
    import web

    mgr = object.__new__(web.WorkerManager)
    mgr._workers = {}
    mgr._lock = threading.RLock()
    mgr._load_queue = store.load
    mgr._save_queue = store.save
    # Scopes the sticky roster's peak rule to one dashboard run.
    mgr._session_id = "test-session"
    return mgr


def _worker(mode="port", binary="/Mods/PD2-S12/D2Client.dll", status="running"):
    return {
        "provider": "minimax", "count": 12, "continuous": True, "model": None,
        "binary": binary, "mode": mode, "addresses": None,
        "status": status, "restore_on_restart": True,
    }


def test_sticky_roster_survives_the_stop_that_clears_the_live_one():
    """THE regression. All six workers ended `user_stop` when the oracle
    died; stop_worker sets restore_on_restart=False, the live roster emptied,
    and the restart had nothing to offer."""
    import web

    store = _FakeQueueStore()
    mgr = _manager(store)
    mgr._workers = {f"w{i}": _worker(binary=f"/b/{i}.dll") for i in range(6)}
    mgr._persist_active_workers()

    offer = mgr.load_restore_offer()
    assert offer and len(offer["workers"]) == 6

    # Now every worker stops, exactly as they did that night.
    for w in mgr._workers.values():
        w["status"] = "stopped"
        w["restore_on_restart"] = False
    mgr._persist_active_workers()

    meta = store.data["meta"]
    assert meta[web.WorkerManager.RESTORE_META_KEY] == [], "live roster clears"
    offer = mgr.load_restore_offer()
    assert offer is not None, "sticky roster must survive the stop"
    assert len(offer["workers"]) == 6
    assert offer["source"] == "last known roster"


def test_sequential_shutdown_keeps_the_first_worker_stopped():
    """MEASURED 2026-07-31: a 6-worker fleet came back as 5, silently.

    Workers are stopped one at a time, and `_persist_active_workers` runs on
    each stop -- so the FIRST worker stopped never appears in any later
    snapshot. A max-length peak rule therefore cannot recover it, and the
    restore reported ok:true / errors:[] while quietly dropping D2Common.
    """
    store = _FakeQueueStore()
    mgr = _manager(store)
    names = [f"/b/{i}.dll" for i in range(6)]
    mgr._workers = {f"w{i}": _worker(binary=n) for i, n in enumerate(names)}
    mgr._persist_active_workers()

    for i in range(6):                       # sequential shutdown
        w = mgr._workers[f"w{i}"]
        w["status"] = "stopped"
        w["restore_on_restart"] = False
        mgr._persist_active_workers()

    offer = mgr.load_restore_offer()
    assert offer is not None
    got = {w["binary"] for w in offer["workers"]}
    assert got == set(names), f"lost {set(names) - got}"


def test_sticky_peak_is_not_clobbered_by_a_shrunken_first_snapshot():
    """The other path to the same loss: the peak was never banked this session,
    so the first (already-shrunken) snapshot adopts itself as the peak."""
    store = _FakeQueueStore()
    mgr = _manager(store)
    mgr._workers = {f"w{i}": _worker(binary=f"/b/{i}.dll") for i in range(6)}
    # Pre-existing sticky copy from a PREVIOUS dashboard run.
    mgr._persist_active_workers()
    store.data["meta"][__import__("web").WorkerManager.LAST_ROSTER_META_KEY]["session"] = "older-run"

    mgr._workers["w0"]["status"] = "stopped"
    mgr._workers["w0"]["restore_on_restart"] = False
    mgr._persist_active_workers()

    offer = mgr.load_restore_offer()
    # w0 belongs to the previous session's roster, so it is not resurrected --
    # but the five genuinely live ones must all still be offered.
    assert len({w["binary"] for w in offer["workers"]}) >= 5


def test_roster_union_does_not_duplicate_a_restarted_worker():
    """Same binary+mode restarted is the same slot, offered once."""
    store = _FakeQueueStore()
    mgr = _manager(store)
    mgr._workers = {"a": _worker(binary="/b/x.dll")}
    mgr._persist_active_workers()
    mgr._workers = {"b": _worker(binary="/b/x.dll")}   # restarted, new id
    mgr._persist_active_workers()

    offer = mgr.load_restore_offer()
    assert len(offer["workers"]) == 1


def test_new_session_does_not_inherit_yesterdays_bigger_fleet():
    store = _FakeQueueStore()
    mgr = _manager(store)
    mgr._workers = {f"w{i}": _worker(binary=f"/b/{i}.dll") for i in range(6)}
    mgr._persist_active_workers()

    mgr2 = _manager(store)
    mgr2._session_id = "a-new-day"
    mgr2._workers = {"only": _worker(binary="/b/deliberate.dll")}
    mgr2._persist_active_workers()

    offer = mgr2.load_restore_offer()
    assert [w["binary"] for w in offer["workers"]] == ["/b/deliberate.dll"]


def test_live_roster_is_preferred_over_sticky():
    store = _FakeQueueStore()
    mgr = _manager(store)
    mgr._workers = {"a": _worker(binary="/b/old.dll")}
    mgr._persist_active_workers()
    mgr._workers = {"b": _worker(binary="/b/new.dll"), "c": _worker(binary="/b/new2.dll")}
    mgr._persist_active_workers()
    offer = mgr.load_restore_offer()
    assert offer["source"] == "running at shutdown"
    assert {w["binary"] for w in offer["workers"]} == {"/b/new.dll", "/b/new2.dll"}


def test_empty_roster_never_overwrites_the_sticky_copy():
    store = _FakeQueueStore()
    mgr = _manager(store)
    mgr._workers = {"a": _worker()}
    mgr._persist_active_workers()
    mgr._workers = {}
    mgr._persist_active_workers()
    mgr._persist_active_workers()
    offer = mgr.load_restore_offer()
    assert offer and len(offer["workers"]) == 1


def test_roster_preserves_mode_so_a_port_worker_does_not_return_as_a_doc_worker():
    """Regression from 2026-07-25: _serialize_worker omitted mode, so
    restore_workers defaulted to "functions" and a live port worker silently
    came back as a FULL-doc worker on the same binary."""
    store = _FakeQueueStore()
    mgr = _manager(store)
    mgr._workers = {"a": _worker(mode="port"), "b": _worker(mode="globals")}
    mgr._persist_active_workers()
    modes = sorted(w["mode"] for w in mgr.load_restore_offer()["workers"])
    assert modes == ["globals", "port"]


def test_no_roster_means_no_offer():
    assert _manager(_FakeQueueStore()).load_restore_offer() is None


def test_dismiss_clears_both_rosters():
    store = _FakeQueueStore()
    mgr = _manager(store)
    mgr._workers = {"a": _worker()}
    mgr._persist_active_workers()
    assert mgr.load_restore_offer() is not None
    assert mgr.dismiss_restore_offer() is True
    assert mgr.load_restore_offer() is None


def test_restore_is_never_automatic():
    """Auto-restore stays retired: nothing may start workers as a side effect
    of reading the offer. A crash-looping dashboard would otherwise re-spawn
    the whole fleet every cycle."""
    store = _FakeQueueStore()
    mgr = _manager(store)
    started = []
    mgr.start_worker = lambda **kw: started.append(kw) or "wid"
    mgr._workers = {"a": _worker()}
    mgr._persist_active_workers()
    mgr.load_restore_offer()
    assert started == [], "load_restore_offer must not start anything"


def test_restore_continues_past_a_rejected_worker():
    """Per-binary locks legitimately reject some of a roster (half already
    restarted by hand). A partial restore beats an aborted one."""
    store = _FakeQueueStore()
    mgr = _manager(store)
    started = []

    def _start(**kw):
        if kw.get("binary") == "/b/1.dll":
            raise ValueError("A port worker is already running on /b/1.dll")
        started.append(kw)
        return f"w{len(started)}"

    mgr.start_worker = _start
    mgr._workers = {f"w{i}": _worker(binary=f"/b/{i}.dll") for i in range(3)}
    mgr._persist_active_workers()

    result = mgr.restore_workers()
    assert len(result["restored"]) == 2
    assert len(result["errors"]) == 1
    assert "/b/1.dll" in result["errors"][0]


def test_sticky_roster_captures_the_PEAK_not_the_last_survivor():
    """Found by using the feature (2026-07-31): a 7-worker fleet offered ONE
    worker on restore. _persist_active_workers runs on every stop, so a
    sequential shutdown rewrote the sticky copy with a progressively smaller
    roster and whichever worker stopped last won.

    What you want back is what the machine ran at its fullest.
    """
    store = _FakeQueueStore()
    mgr = _manager(store)
    mgr._session_id = "session-A"

    mgr._workers = {f"w{i}": _worker(binary=f"/b/{i}.dll") for i in range(7)}
    mgr._persist_active_workers()
    assert len(mgr.load_restore_offer()["workers"]) == 7

    # Shut down one at a time, exactly as stop-all does.
    for i in range(7):
        mgr._workers[f"w{i}"]["status"] = "stopped"
        mgr._workers[f"w{i}"]["restore_on_restart"] = False
        mgr._persist_active_workers()

    offer = mgr.load_restore_offer()
    assert offer is not None
    assert len(offer["workers"]) == 7, (
        "the sticky roster must hold the peak, not the last survivor"
    )


def test_new_session_adopts_its_own_smaller_roster():
    """The peak rule is scoped to a session -- otherwise yesterday's 12-worker
    fleet would outrank today's deliberate 2."""
    store = _FakeQueueStore()
    mgr = _manager(store)

    mgr._session_id = "session-A"
    mgr._workers = {f"w{i}": _worker(binary=f"/b/{i}.dll") for i in range(6)}
    mgr._persist_active_workers()
    assert len(mgr.load_restore_offer()["workers"]) == 6

    mgr._session_id = "session-B"
    mgr._workers = {"z": _worker(binary="/b/only.dll")}
    mgr._persist_active_workers()
    offer = mgr.load_restore_offer()
    assert len(offer["workers"]) == 1
    assert offer["workers"][0]["binary"] == "/b/only.dll"


# =================================================== in-place self-restart ====

def test_request_restart_spawns_a_child_and_does_not_prompt(monkeypatch, tmp_path):
    """The dashboard runs ELEVATED so it can taskkill a self-elevated PD2.
    The consequence is that a non-elevated shell cannot stop it, so every code
    deploy needed an interactive UAC click -- which an unattended pipeline
    cannot wait on. Registering the Scheduled Task does not fix that: it
    removes UAC from STARTING the dashboard, not from stopping a running
    elevated one.

    Restarting from inside the elevated process crosses no privilege boundary:
    the child inherits the token. This test pins that the spawn is a plain
    child process with NO 'runas'/elevation verb anywhere.
    """
    import web

    mgr = _manager(_FakeQueueStore())
    mgr._dashboard_port = 5000
    launcher = Path(web.__file__).resolve().parent / "start-dashboard.ps1"
    assert launcher.exists(), "request_restart hands off to start-dashboard.ps1"

    import os as _os
    import time as _time

    spawned, exited, killed = [], [], []
    # The dashboard is a parent/child pair: the process serving this request is
    # NOT always the one bound to port 5000. Handing off on os.getpid() waited
    # on a process that exited immediately while the port stayed bound, so
    # start-dashboard.ps1 refused with "already listening" and the restart
    # silently did nothing (2026-07-31: served by 132424, listener was 171288).
    LISTENER = 999001
    monkeypatch.setattr(web, "_listener_pid", lambda port: LISTENER)
    monkeypatch.setattr(web.subprocess, "Popen",
                        lambda cmd, **kw: spawned.append((cmd, kw)) or None)
    monkeypatch.setattr(web.subprocess, "run",
                        lambda cmd, **kw: killed.append(cmd) or None)
    monkeypatch.setattr(web.os, "_exit", lambda code: exited.append(code))

    result = mgr.request_restart(stop_timeout=0)
    assert result["ok"] is True
    # The thread sleeps ~2s before exiting so the HTTP response can flush.
    deadline = _time.monotonic() + 15
    while _time.monotonic() < deadline and not (spawned and exited):
        _time.sleep(0.05)

    assert spawned, "a replacement dashboard must be spawned"
    joined = " ".join(str(c) for c in spawned[0][0]).lower()
    assert "start-dashboard.ps1" in joined
    assert "-waitforpid" in joined, "the child must wait for the port to free"
    assert str(LISTENER) in joined, (
        "the hand-off must target the SOCKET OWNER, not whichever process "
        "happened to serve the request"
    )
    assert str(_os.getpid()) not in joined.replace(str(LISTENER), "")
    # The socket owner is a different process and will not exit on its own; if
    # it is not ended the port never frees and the replacement refuses to bind.
    assert any("taskkill" in " ".join(str(c) for c in k).lower() for k in killed), (
        "a listener that is not us must be terminated"
    )
    # The whole point: no elevation request anywhere in the spawn.
    assert "runas" not in joined
    assert "-verb" not in joined
    assert exited == [0], "the old process must exit so the port frees"


def test_restart_endpoint_is_loopback_only():
    """An endpoint that restarts an ELEVATED process is the one to check
    twice -- a future bind-address change must not silently turn it into a
    remote control."""
    import web

    src = Path(web.__file__).resolve()
    text = src.read_text(encoding="utf-8")
    idx = text.index("def post_admin_restart")
    body = text[idx:idx + 900]
    assert "127.0.0.1" in body
    assert "403" in body


# ====================================================== oracle health dot ===
#
# The dashboard's Oracle + Game dot keyed on `reachable` alone, so of
# oracle_health.py's FOUR fault shapes the two that answer HTTP perfectly --
# FROZEN (alive, oracle replying, drawing nothing) and IDLE (parked at a menu,
# no world to prove against) -- both rendered as a green "live-prove enabled".
# That is the 2026-07-31 incident verbatim: a deploy restart left the game at
# the main menu and the fleet sat idle behind a green banner for 70 minutes.
#
# Detection was never the problem; `game_frozen` / `game_idle` were already in
# the payload. Nothing consumed them. These tests pin the mapping so it cannot
# silently revert to "reachable == healthy".


class _FakeOracleMonitor:
    def __init__(self, **state):
        base = {
            "reachable": True, "game_running": True, "game_wedged": False,
            "game_dead": False, "game_idle": False, "game_frozen": False,
            "relaunching": False, "relaunch_stage": None, "relaunch_error": None,
            "recover_attempts": 0, "next_retry_in": None,
            "recovery_degraded": False, "present_rate": 25.0,
        }
        base.update(state)
        self._state = base

    def get_state(self):
        return self._state


def _oracle_dot(**state):
    """Call WorkerManager._health_oracle against a fake monitor."""
    import web

    mgr = web.WorkerManager.__new__(web.WorkerManager)
    mgr._oracle_monitor = _FakeOracleMonitor(**state)
    return web.WorkerManager._health_oracle(mgr)


def test_healthy_oracle_is_ok_with_no_action():
    dot = _oracle_dot()
    assert dot["state"] == "ok"
    assert dot["action"] is None


def test_frozen_game_is_not_reported_as_healthy():
    """A stalled render thread raises no exception, so /crash stays null and
    every probe but the frame counter reads fine."""
    dot = _oracle_dot(game_frozen=True, present_rate=0)
    assert dot["state"] == "down", f"FROZEN game reported as {dot['state']}"
    assert "frozen" in dot["detail"].lower()
    assert dot["action"] == "relaunch_oracle", (
        "FROZEN recovers on the WEDGED path, so a relaunch must be offered"
    )


def test_idle_game_is_degraded_and_offers_no_relaunch():
    """IDLE passes every liveness check while proving is stalled. It must be
    visible -- but the cure is navigation, and offering a one-click relaunch
    of a HEALTHY game is the mistake oracle_health.py exists to prevent."""
    dot = _oracle_dot(game_idle=True)
    assert dot["state"] == "degraded", f"IDLE game reported as {dot['state']}"
    assert "menu" in dot["detail"].lower() or "parked" in dot["detail"].lower()
    assert dot["action"] is None, (
        "an IDLE game must not offer a one-click relaunch of a healthy game"
    )


def test_frozen_outranks_idle_when_both_are_set():
    """Both flags can ride together; the worse one has to win, because a
    frozen game cannot be cured by navigating it."""
    dot = _oracle_dot(game_frozen=True, game_idle=True)
    assert dot["state"] == "down"
    assert "frozen" in dot["detail"].lower()


def test_flags_are_exposed_so_the_ui_need_not_re_derive_them():
    for key in ("game_frozen", "game_idle"):
        assert key in _oracle_dot(), f"health payload drops {key}"


def test_unreachable_shapes_are_unchanged():
    wedged = _oracle_dot(reachable=False, game_wedged=True)
    assert wedged["state"] == "down" and "wedged" in wedged["detail"].lower()
    dead = _oracle_dot(reachable=False, game_dead=True)
    assert dead["state"] == "down" and "not running" in dead["detail"].lower()
    unprobed = _oracle_dot(reachable=None)
    assert unprobed["state"] == "unknown"

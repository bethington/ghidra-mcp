"""Live D2Debugger oracle health monitoring + one-click relaunch.

Background (2026-07-27): the port worker only ever checked oracle reachability
ONCE, at worker startup (`_run_worker_port` in web.py), and latched
FUNDOC_LIVE_PROVE/FUNDOC_SHADOW_PROMOTE as a one-time snapshot for that
worker's entire lifetime. When the oracle died mid-run -- confirmed live: a
bad proof vector crashed it at 16:19, and the whole Game.exe process was gone
entirely a couple hours later -- the worker kept grinding for hours, running
full LLM-driven draft/generation passes on port_live candidates whose final
live-prove step was doomed to fail with "D2Debugger :8790 unreachable". Wasted
tokens, zero chance of a CONF_LIVE promotion, and nothing surfaced it short of
someone noticing runs.jsonl had gone quiet on real proofs.

This module makes reachability a LIVE, periodically-refreshed fact instead of
a startup snapshot: `OracleHealthMonitor` polls on a background thread and
keeps FUNDOC_LIVE_PROVE/FUNDOC_SHADOW_PROMOTE in sync with *current* oracle
state. Every existing `os.environ.get("FUNDOC_LIVE_PROVE")` gate check
throughout fun_doc.py (process_port_candidate and friends) is evaluated fresh
per-candidate, so toggling the env var here automatically pauses/resumes the
live-prove and shadow-promote lanes without touching those call sites.

It also drives the documented one-click recovery sequence: launch Game.exe
with the oracle embedded (LaunchPD2-Oracle.bat, D2_DEBUGGER=1), wait for
:8790, advance the game to character-select, and auto-load the standard
proving character (LOOP_PLAYBOOK.md, PROVE_OPPORTUNITIES_BACKLOG.md,
LaunchPD2-Oracle.bat all reference "summoner-skele" as that character).
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

from port_live_prove import check_oracle_alive, ORACLE_URL  # single source of truth

# Windows spawns a console for every child process unless told not to, and
# several of these run on a POLL -- is_game_running every 45s, _pid_alive on
# every in-flight check -- so each one flashed a console window on the desktop.
# CREATE_NO_WINDOW suppresses it; the attribute is absent (and the flag 0) on
# non-Windows, so this stays inert there.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

DEFAULT_LAUNCH_BAT = r"C:\Users\benam\source\cpp\D2MOO\LaunchPD2-Oracle.bat"
LAUNCH_BAT = os.environ.get("D2MOO_LAUNCH_BAT", DEFAULT_LAUNCH_BAT)
DEFAULT_PROVE_CHARACTER = os.environ.get("D2MOO_PROVE_CHARACTER", "summoner-skele")
POLL_INTERVAL_SEC = float(os.environ.get("FUNDOC_ORACLE_POLL_SEC", "45"))
GAME_PROCESS_NAME = "Game.exe"

# Unattended recovery from an oracle that is DOWN -- either because the game
# is wedged (process alive, embedded oracle dead: the "Halt / Unrecoverable
# internal error" shape a bad proof vector produces) or because the game is
# not running at all.
#
# The dead-game case was added 2026-07-30 after it cost a night of fleet
# throughput. Recovery used to be reachable ONLY through `game_wedged`, which
# requires `running and not reachable` -- so a game that fully EXITED had no
# unattended path back at all. Measured that evening: oracle down 94
# consecutive polls (~70 min), `game_running: false`, `relaunch_stage: null`.
# Zero attempts were ever made, because the one predicate that could have
# started one is false by construction when the process is gone.
AUTO_RECOVER = os.environ.get("FUNDOC_ORACLE_AUTO_RECOVER", "1") == "1"
# Poll cycles the oracle must stay down before we treat it as a real outage
# rather than a briefly busy game. At the default 45s poll that is ~2 minutes
# of hard evidence.
AUTO_RECOVER_AFTER_DOWN = int(os.environ.get("FUNDOC_ORACLE_AUTO_RECOVER_AFTER", "3"))
# Cooldown between attempts inside the opening burst.
AUTO_RECOVER_COOLDOWN_SEC = float(os.environ.get("FUNDOC_ORACLE_AUTO_RECOVER_COOLDOWN", "600"))
# Size of the fast burst. This USED to be a permanent give-up cap: after 3
# failures the monitor stopped forever and waited for a human. That is the
# right call for an attended session and the wrong one for the overnight
# fleet it exists to protect -- a stall at 2am cost the whole night.
#
# It is now the burst size only. Attempts 1..N run at the flat cooldown
# above; past that the interval doubles to AUTO_RECOVER_MAX_COOLDOWN_SEC and
# retries continue INDEFINITELY. Never a tight loop (a permanently broken
# launcher settles at 2 attempts/hour), never a permanent stall. Crossing out
# of the burst flips `recovery_degraded`, which is what raises the banner and
# fires the desktop notification -- so "we gave up" became "we are still
# trying, slowly, and you have been told".
AUTO_RECOVER_BURST = int(os.environ.get("FUNDOC_ORACLE_AUTO_RECOVER_MAX", "3"))
AUTO_RECOVER_MAX_COOLDOWN_SEC = float(
    os.environ.get("FUNDOC_ORACLE_AUTO_RECOVER_MAX_COOLDOWN", "1800")
)
# Backwards-compatible alias: this name is referenced by older scripts and by
# the operator docs. It means "burst size" now, not "hard cap".
AUTO_RECOVER_MAX_ATTEMPTS = AUTO_RECOVER_BURST

# How many consecutive polls of zero gameplay traffic before the game counts as
# parked at a menu. Two (~90s at the default cadence) rides out a legitimately
# quiet stretch -- an act transition, a long load -- without letting a genuinely
# stranded game sit. Loading screens still accrue dispatcher hits, so the quiet
# window this has to survive is short.
IDLE_AFTER_POLLS = int(os.environ.get("FUNDOC_ORACLE_IDLE_AFTER", "2"))
# Floor between two enter-game attempts. Entering a world takes real time; the
# cooldown stops a slow load from being read as failure and re-nudged into a
# navigation loop.
ENTER_GAME_COOLDOWN_SEC = float(os.environ.get("FUNDOC_ORACLE_ENTER_GAME_COOLDOWN", "300"))
# Consecutive polls with the game presenting ZERO frames before it counts as
# hung. The render thread stopping is not an exception, so the in-process fault
# observer never sees it -- /crash stayed null through every freeze measured on
# 2026-07-31 while the game drew nothing for twenty minutes at a time.
NOT_PRESENTING_AFTER_POLLS = int(os.environ.get("FUNDOC_ORACLE_FROZEN_AFTER", "2"))
# Minimum wall time between two frame samples before a flat counter means
# anything at all. D2 presents at 25-49 fps, i.e. one frame every 20-40 ms, so
# two polls taken closer together than that legitimately read the SAME count on
# a perfectly healthy game. With NOT_PRESENTING_AFTER_POLLS=2 that made a pair
# of back-to-back polls enough to declare FROZEN -- and FROZEN takes the
# force-close path, so the penalty for the false positive is killing a healthy
# game. Measured 2026-08-02: a game presenting a steady 25.0/sec was declared
# "0 frames drawn over 2 polls" by two check_once() calls in a row.
#
# The scheduled loop polls every POLL_INTERVAL_SEC (45s) and clears this
# trivially. The guard exists for the OFF-CADENCE callers, which is every other
# entry point: start()'s synchronous first check, the post-relaunch refresh, and
# the dashboard's on-demand /api/health route.
MIN_PRESENT_SAMPLE_SEC = float(os.environ.get("FUNDOC_ORACLE_PRESENT_MIN_SEC", "1.0"))

# Live-confirmed 2026-07-27: after killing a wedged worker subprocess with no
# oracle, `os.environ` gating recovered the worker on the very next candidate.
# This module extends that same gate to be periodically refreshed instead of
# a startup-only snapshot -- see module docstring.


def is_game_running() -> bool:
    """Whether Game.exe is currently running. Shells out to tasklist (mirrors
    LaunchPD2-Oracle.bat's own double-launch guard) rather than adding a new
    psutil dependency."""
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {GAME_PROCESS_NAME}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=5, creationflags=_NO_WINDOW,
        )
        return GAME_PROCESS_NAME.lower() in out.stdout.lower()
    except Exception:
        return False


def _oracle_get(path: str, timeout: float = 10.0):
    with urllib.request.urlopen(f"{ORACLE_URL}{path}", timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _oracle_post(path: str, body: dict, timeout: float = 15.0):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{ORACLE_URL}{path}", data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def is_elevated() -> bool:
    """Whether this process runs with an elevated token.

    Load-bearing, not cosmetic: PD2 self-elevates, so a normal-integrity
    dashboard cannot taskkill a wedged game and unattended recovery degrades to
    "pop a UAC prompt and hope somebody is sitting there". Reported at startup
    and in /api/oracle/status so the answer to "will this self-heal?" is a fact
    you can read, not an assumption."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _wait_for_game_exit(timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not is_game_running():
            return True
        time.sleep(0.5)
    return not is_game_running()


def kill_game(timeout: float = 20.0, allow_elevate: bool = True) -> bool:
    """Terminate Game.exe and wait for it to actually disappear.

    Only ever called for a WEDGED game -- one whose embedded oracle is gone.
    A D2 "Halt / Unrecoverable internal error" dialog leaves the process alive
    and message-pumping (so `is_game_running()` stays True and the window even
    reports Responding=True) while the game itself can no longer execute
    anything. There is nothing to save in that state; the alternative to
    killing it is a permanently blocked recovery path.

    PD2 runs ELEVATED (LaunchPD2-Oracle.bat self-elevates), so a plain taskkill
    from a normal-integrity dashboard always fails with "Access is denied" --
    measured 2026-07-30, which is what turned a wedged game into a dead end.
    We therefore retry once via ShellExecute `runas`, which raises a UAC prompt
    on the interactive desktop. That makes recovery one click instead of
    impossible; for FULLY unattended recovery, run the dashboard elevated so
    the first taskkill succeeds outright."""
    try:
        proc = subprocess.run(["taskkill", "/F", "/T", "/IM", GAME_PROCESS_NAME],
                              creationflags=_NO_WINDOW,
                              capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return False
    if _wait_for_game_exit(timeout):
        return True

    denied = b"denied" in (proc.stderr or b"").lower() + (proc.stdout or b"").lower()
    if not (allow_elevate and denied):
        return False
    print("  [oracle] taskkill was denied (the game runs elevated) -- requesting "
          "an elevated kill; APPROVE THE UAC PROMPT to finish recovery", flush=True)
    try:
        # ShellExecuteW verb "runas" is the only way to cross the integrity
        # boundary without a pre-elevated helper. Fire-and-poll: the call
        # returns as soon as the user answers the prompt.
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "taskkill.exe", f"/F /T /IM {GAME_PROCESS_NAME}", None, 0)
    except Exception:
        return False
    # Generous: this window includes a human noticing and clicking UAC.
    return _wait_for_game_exit(max(timeout, 60.0))


def _present_count():
    """The game's frame counter (StretchBlt calls), or None if unreadable.

    D2 presents through GDI's StretchBlt (~25-49/sec). This is the ONLY probe
    that distinguishes a running game from a hung one: the oracle answers from
    its own thread and keeps answering long after the render thread has stopped,
    which is exactly why a frozen game read healthy on every other signal.

    None, never 0, on a failed read -- 0 is indistinguishable from "hung" and
    would turn a dropped HTTP call into a phantom fault.
    """
    try:
        resp = _oracle_get("/capture/probe")
    except Exception:
        return None
    if not isinstance(resp, dict):
        return None
    for api in resp.get("apis") or []:
        if isinstance(api, dict) and api.get("api") == "StretchBlt":
            try:
                return int(api.get("calls"))
            except Exception:
                return None
    return None


def _fetch_crash(consume: bool = True):
    """The D2Debugger fault observer's latest record, or None.

    Reported at the MOMENT of the fault (see D2Debugger.crash.cpp) rather than
    inferred later from a stopped oracle -- by which point the faulting address,
    the registers and which candidate was being proven are all gone.
    """
    try:
        resp = _oracle_get("/crash" + ("?consume=1" if consume else ""))
    except Exception:
        return None
    if not isinstance(resp, dict):
        return None
    crash = resp.get("crash")
    return crash if isinstance(crash, dict) else None


def _dismiss_diablo_error_dialog() -> bool:
    """Best-effort dismissal of a "Diablo II Error"/"Exception" dialog -- both the transient
    startup one documented in LOOP_PLAYBOOK.md (a lingering lock from a crashed
    prior instance) and the terminal "Halt / Unrecoverable internal error <addr>"
    box a bad proof vector can produce. Win32 EnumWindows + WM_CLOSE, no pywin32
    dependency. Returns True if a matching window was found and closed."""
    try:
        user32 = ctypes.windll.user32
        found = []
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def _cb(hwnd, _lparam):
            length = user32.GetWindowTextLengthW(hwnd)
            if length:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                title = buf.value.lower()
                # MEASURED 2026-07-31: the box that actually appears is titled
                # "Diablo II Exception" ("UNHANDLED EXCEPTION: ACCESS_VIOLATION
                # (c0000005)"). Requiring the word "error" meant this never
                # matched it, so the one dialog that hard-blocks the game was
                # the one dialog never dismissed.
                if "diablo ii" in title and ("error" in title or "exception" in title):
                    found.append(hwnd)
            return True

        user32.EnumWindows(WNDENUMPROC(_cb), 0)
        WM_CLOSE = 0x0010
        for hwnd in found:
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        return bool(found)
    except Exception:
        return False


class OracleHealthMonitor:
    """Background poller + relaunch orchestrator for the D2Debugger oracle.

    One instance lives on WorkerManager, started at dashboard boot (not tied
    to any single worker) so the dashboard can show live status even with no
    worker running, and so FUNDOC_LIVE_PROVE/FUNDOC_SHADOW_PROMOTE stay fresh
    the whole time the dashboard is up.
    """

    def __init__(self, bus=None, poll_interval=None, launch_bat=None, character=None,
                 auto_recover=None, auto_recover_needed=None):
        self._bus = bus
        self._poll_interval = poll_interval or POLL_INTERVAL_SEC
        self.launch_bat = launch_bat or LAUNCH_BAT
        self.character = character or DEFAULT_PROVE_CHARACTER
        self._lock = threading.Lock()
        self._state = {
            # None (not False) until the first check_once() runs, so that
            # first observation always counts as a transition worth logging
            # -- "the dashboard just booted and found it down" is distinct
            # audit-history information from "still down since last tick".
            "reachable": None,
            "game_running": None,
            "last_checked_at": None,
            "consecutive_down": 0,
            "relaunching": False,
            "relaunch_stage": None,
            "relaunch_error": None,
            # WEDGED: the process is up but its embedded oracle is gone -- the
            # D2 "Halt / Unrecoverable internal error" shape. Distinct from
            # "game not running" because the recovery differs (this one has to
            # close the corpse first) and because it is the state that silently
            # starves every port worker of live candidates.
            "game_wedged": False,
            # DEAD: oracle down and the process is gone entirely. Recovery is
            # a plain launch (no corpse to close first). Tracked separately
            # from `game_wedged` because for 3 days only the wedged branch
            # could reach auto-recovery and this state silently could not.
            "game_dead": False,
            # IDLE: oracle reachable, process alive -- and the game parked at the
            # title/character-select screen with no world loaded. Every liveness
            # signal reads HEALTHY here, which is exactly the problem: proving
            # needs a world, so six workers sit with nothing to prove against
            # while the banner shows green. Observed 2026-07-31 after a deploy
            # restart: the game came back to the main menu and stayed there,
            # because recovery only ever fired on "oracle stopped answering".
            "game_idle": False,
            "consecutive_idle": 0,
            # FROZEN: oracle answering, process alive, and the game drawing
            # NOTHING. Distinct from IDLE (parked at a menu, which still
            # presents) and from WEDGED (oracle gone). Measured 2026-07-31: two
            # fresh launches in a row came up alive, answering and blank, and
            # every existing probe called them healthy -- including the fault
            # observer, because a stalled render thread raises no exception.
            "game_frozen": False,
            "consecutive_not_presenting": 0,
            "present_rate": None,
            # True once the opening burst is spent and we have dropped into
            # slow-retry. This is the "a human should look" line: recovery is
            # still running, but it is no longer keeping up on its own.
            "recovery_degraded": False,
            "recover_attempts": 0,
            # Seconds until the next attempt is allowed, or None when no
            # recovery is pending. Rendered in the banner so the wait is a
            # visible countdown rather than an apparently-hung dashboard.
            "next_retry_in": None,
            # Surfaced so the dashboard can show "auto-recovery will need a UAC
            # click" instead of silently promising self-healing it can't do.
            "elevated": is_elevated(),
        }
        self._stop = threading.Event()
        self._thread = None
        self._auto_recover = AUTO_RECOVER if auto_recover is None else bool(auto_recover)
        # Predicate: "does anything actually need the oracle right now?" The
        # WorkerManager passes 'is a port worker running'. Without it the
        # monitor would happily kill a game the operator is using by hand.
        self._auto_recover_needed = auto_recover_needed
        self._auto_recover_attempts = 0
        self._last_auto_recover_at = None
        # Total dispatcher hits at the previous poll. Comparing ACROSS polls is
        # both free and a wider window than sampling inline would give, and
        # gameplay traffic is the only reliable in-world test -- /status's
        # charSelectReady reads False at the title screen AND in-world alike
        # (LOOP_PLAYBOOK.md), so it cannot tell "not there yet" from "playing".
        self._prev_hits_total = None
        self._last_enter_game_at = None
        self._prev_present = None
        self._prev_present_at = None
        # Edge-triggered: level-triggered would re-toast every poll for the
        # whole freeze, which trains you to ignore it.
        self._reported_frozen = False

    # ---- lifecycle -------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        # Say up front whether unattended recovery can actually complete. A
        # non-elevated dashboard CANNOT kill a wedged (elevated) PD2, so the
        # auto-recovery it advertises will stall on a UAC prompt -- far better
        # to announce that at boot than to discover it mid-incident.
        if self._auto_recover:
            if is_elevated():
                print("  [oracle] auto-recovery armed (dashboard is elevated)", flush=True)
            else:
                print("  [oracle] auto-recovery armed but the dashboard is NOT "
                      "elevated -- PD2 self-elevates, so closing a wedged game "
                      "will need a UAC prompt. Start via "
                      "fun-doc/start-dashboard.ps1 for unattended recovery.",
                      flush=True)
        self._stop.clear()
        self.check_once()  # synchronous first check -- no stale-gate window
        self._thread = threading.Thread(
            target=self._loop, name="fun-doc-oracle-health", daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(self._poll_interval):
            self.check_once()

    # ---- state -------------------------------------------------------
    def get_state(self) -> dict:
        with self._lock:
            return dict(self._state)

    def _emit_health(self, snapshot):
        if self._bus is not None:
            try:
                self._bus.emit("oracle_health", snapshot)
            except Exception:
                pass

    def _emit_relaunch_progress(self, snapshot):
        if self._bus is not None:
            try:
                self._bus.emit("oracle_relaunch_progress", snapshot)
            except Exception:
                pass

    def _set_relaunch(self, active, stage, error):
        with self._lock:
            self._state["relaunching"] = active
            self._state["relaunch_stage"] = stage
            self._state["relaunch_error"] = error
            snapshot = dict(self._state)
        self._emit_relaunch_progress(snapshot)

    # ---- the actual health check -------------------------------------------------------
    def check_once(self) -> dict:
        """One poll cycle: check reachability + game-process state, gate
        FUNDOC_LIVE_PROVE/FUNDOC_SHADOW_PROMOTE on the result, and emit on
        change. Safe to call synchronously (e.g. right after a relaunch, or
        at worker-start) as well as from the background loop."""
        reachable = check_oracle_alive()
        running = is_game_running()
        hits_total = self._gameplay_hits_total() if (reachable and running) else None
        present = _present_count() if (reachable and running) else None
        with self._lock:
            prev_reachable = self._state["reachable"]
            self._state["reachable"] = reachable
            self._state["game_running"] = running
            self._state["last_checked_at"] = datetime.now().isoformat()
            self._state["consecutive_down"] = (
                0 if reachable else self._state["consecutive_down"] + 1
            )
            # A sustained down-streak separates a real outage from one slow
            # poll. Both shapes below need recovery; they differ only in
            # whether there is a corpse to close first.
            sustained = self._state["consecutive_down"] >= AUTO_RECOVER_AFTER_DOWN
            # Game up + oracle down = the embedded oracle died without taking
            # the process with it.
            self._state["game_wedged"] = bool(running and not reachable and sustained)
            # Game gone + oracle down = nothing to kill, just launch. This is
            # the branch that had no recovery path until 2026-07-30.
            self._state["game_dead"] = bool(not running and not reachable and sustained)
            self._state["next_retry_in"] = self._seconds_until_next_attempt() if (
                not reachable and sustained
            ) else None

            # A healthy oracle in front of a game that is not actually PLAYING.
            # Compared against the previous poll, so no inline sleep is needed;
            # `None` on either side means "no usable sample" and never counts as
            # idle, which keeps a failed /dispatchers read from manufacturing a
            # phantom recovery.
            idle_now = False
            if hits_total is not None and self._prev_hits_total is not None:
                idle_now = hits_total <= self._prev_hits_total
            if hits_total is not None:
                self._prev_hits_total = hits_total
            elif not reachable:
                # Drop the baseline across an outage: comparing a pre-outage
                # total against a post-relaunch one (counters reset to zero)
                # would read the fresh game as idle forever.
                self._prev_hits_total = None
            self._state["consecutive_idle"] = (
                self._state["consecutive_idle"] + 1 if idle_now else 0
            )
            self._state["game_idle"] = bool(
                reachable and running
                and self._state["consecutive_idle"] >= IDLE_AFTER_POLLS
            )

            # Frames drawn since the previous poll. Same None-discipline as the
            # dispatcher sample: an unreadable probe is not evidence of a hang.
            stalled = False
            now_mono = time.monotonic()
            if present is not None and self._prev_present is not None:
                elapsed = max(0.001, now_mono - (self._prev_present_at or now_mono))
                self._state["present_rate"] = round((present - self._prev_present) / elapsed, 1)
                # Same discipline as an unreadable probe: a sample window too
                # short for a frame to have landed is NOT evidence of a hang.
                stalled = (present <= self._prev_present
                           and elapsed >= MIN_PRESENT_SAMPLE_SEC)
            if present is not None:
                self._prev_present = present
                self._prev_present_at = now_mono
            elif not reachable:
                self._prev_present = None      # rebaseline across an outage
                self._state["present_rate"] = None
            self._state["consecutive_not_presenting"] = (
                self._state["consecutive_not_presenting"] + 1 if stalled else 0
            )
            self._state["game_frozen"] = bool(
                reachable and running
                and self._state["consecutive_not_presenting"] >= NOT_PRESENTING_AFTER_POLLS
            )
            # Clear a STALE relaunch failure once the oracle is actually back
            # (2026-07-30). relaunch_stage/relaunch_error are written only by
            # _set_relaunch, i.e. only while THIS class is driving a relaunch --
            # so a failed attempt left "failed" + its error pinned forever, and
            # any other route to recovery (the operator relaunching by hand,
            # which is the common one) left the dashboard reporting
            # reachable=true, game_running=true, relaunch_stage="failed" all at
            # once. Cosmetic until it isn't: a stale "failed" sitting next to a
            # healthy oracle is exactly what sends you debugging the wrong thing.
            #
            # Narrow on purpose: only a FAILED stage is cleared, and only when
            # we are not mid-relaunch. A successful relaunch's "ready" is real
            # information and survives.
            cleared_stale = False
            if (reachable and not self._state.get("relaunching")
                    and (self._state.get("relaunch_error")
                         or self._state.get("relaunch_stage") == "failed")):
                self._state["relaunch_error"] = None
                if self._state.get("relaunch_stage") == "failed":
                    self._state["relaunch_stage"] = None
                cleared_stale = True
            changed = prev_reachable != reachable
            snapshot = dict(self._state)

        if reachable and not self._state.get("game_frozen"):
            os.environ["FUNDOC_LIVE_PROVE"] = "1"
            os.environ["FUNDOC_SHADOW_PROMOTE"] = "1"
            # A reachable oracle re-arms the burst. Without this, three
            # failures spread across an entire day would leave the monitor
            # permanently in slow-retry even though every outage since had
            # recovered on the first try.
            if self._auto_recover_attempts or self._state.get("recovery_degraded"):
                with self._lock:
                    self._state["recovery_degraded"] = False
                    self._state["recover_attempts"] = 0
                self._auto_recover_attempts = 0
                self._last_auto_recover_at = None
        else:
            os.environ.pop("FUNDOC_LIVE_PROVE", None)
            os.environ.pop("FUNDOC_SHADOW_PROMOTE", None)

        # A fault the observer caught. Polled while the oracle still answers,
        # because that is the window in which the record can still be collected
        # -- once the process dies only the on-disk copy survives.
        if reachable:
            try:
                self._report_crash_if_any()
            except Exception as e:
                print(f"[oracle_health] crash poll failed: {e}", flush=True)

        # Edge-triggered desktop notification. Level-triggered would re-toast
        # every 45s poll for the whole outage, which trains you to dismiss
        # them unread -- the same end state as sending nothing.
        self._notify_health_transition(reachable, running, snapshot)

        if changed:
            try:
                from event_log import log_event
                log_event("oracle_health_changed", reachable=reachable, game_running=running)
            except Exception:
                pass
        if cleared_stale:
            # Push the cleared state to the dashboard too, or the stale "failed"
            # keeps rendering until some other change happens to emit.
            self._emit_relaunch_progress(snapshot)
        self._emit_health(snapshot)
        # Recover on EITHER shape. Gating this on `game_wedged` alone is the
        # bug that let a dead game sit for 70 minutes with zero attempts.
        if snapshot["game_frozen"] and not self._reported_frozen:
            self._reported_frozen = True
            print("[oracle_health] GAME FROZEN: oracle answering but 0 frames "
                  f"drawn over {snapshot['consecutive_not_presenting']} polls", flush=True)
            self._log_event("game_frozen",
                            polls=snapshot.get("consecutive_not_presenting"))
            try:
                import notify
                notify.notify("D2 frozen", "The game is running but drawing nothing.")
            except Exception:
                pass
        elif not snapshot["game_frozen"]:
            self._reported_frozen = False

        if snapshot["game_wedged"] or snapshot["game_dead"]:
            self._maybe_auto_recover(snapshot)
        elif snapshot["game_frozen"]:
            # Treated exactly like WEDGED: the process must be force-closed.
            # A frozen game cannot be asked to exit -- the menu pump runs on the
            # stalled thread -- so a graceful request just times out, and
            # navigation (the IDLE cure) is hopeless against a game that draws
            # nothing. Observed looping fruitlessly for 20 minutes before this
            # state was distinguished at all.
            self._maybe_auto_recover(snapshot)
        elif snapshot["game_idle"]:
            # Deliberately NOT a relaunch: the process is fine, it just needs
            # navigating into a world. Killing a healthy game to fix a menu
            # would throw away a working oracle and every restored shadow mode.
            self._maybe_enter_game(snapshot)
        return snapshot

    def _report_crash_if_any(self):
        """Surface a D2 fault immediately: event, log line, desktop toast.

        `consume=1`, so each crash reports exactly once no matter how often we
        poll. The durable copy lives on disk under
        conformance/behavioral/crashes/ and is never removed.
        """
        crash = _fetch_crash(consume=True)
        if not crash:
            return
        where = crash.get("module") or "?"
        rva = crash.get("rva") or "?"
        name = crash.get("codeName") or crash.get("code") or "fault"
        proving = crash.get("proving")

        # LOUD. A silent crash report is the same as no crash report.
        print(f"[oracle_health] D2 FAULT: {name} at {where}+{rva}"
              + (f" while proving {proving}" if proving else ""), flush=True)
        self._log_event("d2_exception", **{
            k: crash.get(k) for k in
            ("code", "codeName", "module", "rva", "address", "origin", "proving")
        })
        try:
            import notify
            body = f"{name} in {where}+{rva}"
            if proving:
                body += f"\nwhile proving {proving}"
            notify.notify("D2 crashed", body)
        except Exception:
            pass

    def _gameplay_hits_total(self):
        """Sum of dispatcher hit counters, or None if unreadable.

        Gameplay traffic is the ONLY reliable in-world signal (see
        `_prev_hits_total`). Returning None rather than 0 on a failed read
        matters: 0 would look like a perfectly idle game and trigger recovery
        on what is really just a dropped HTTP call.
        """
        try:
            resp = _oracle_get("/dispatchers")
        except Exception:
            return None
        if not isinstance(resp, dict):
            return None
        ds = resp.get("dispatchers") or []
        if not isinstance(ds, list) or not ds:
            return None
        try:
            return sum(int(d.get("hits", 0)) for d in ds if isinstance(d, dict))
        except Exception:
            return None

    def _gameplay_started(self, timeout):
        """Did gameplay traffic actually start within `timeout` seconds?

        Polls rather than sleeping the whole budget so a fast load returns fast.
        """
        base = self._gameplay_hits_total()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(3.0)
            now = self._gameplay_hits_total()
            if base is None:
                base = now
                continue
            if now is not None and now > base:
                return True
        return False

    def _maybe_enter_game(self, snapshot):
        """Navigate a parked game back into a world, at most once per cooldown."""
        if not self._auto_recover:
            return
        if snapshot.get("relaunching"):
            return
        # Same courtesy as auto-recovery: don't drive a game nobody is waiting
        # on. An operator poking around at the menu is not a fault to correct.
        if self._auto_recover_needed is not None:
            try:
                if not self._auto_recover_needed():
                    return
            except Exception:
                return
        now = time.monotonic()
        if (self._last_enter_game_at is not None
                and now - self._last_enter_game_at < ENTER_GAME_COOLDOWN_SEC):
            return
        self._last_enter_game_at = now

        self._log_event("oracle_game_idle_enter_game",
                        consecutive_idle=snapshot.get("consecutive_idle"))
        try:
            import notify
            notify.notify("fun-doc", "Game was parked at a menu -- entering a world")
        except Exception:
            pass

        self._set_relaunch(True, "game idle at menu, entering a world", None)
        try:
            result = self._navigate_and_load_character(self.character, 120.0)
        except Exception as e:
            result = {"ok": False, "error": str(e)}
        if isinstance(result, dict) and result.get("ok") is not False:
            # Verify by OUTCOME. /action/* reports that the CALL succeeded, not
            # that the game moved, and both exit actions have been observed
            # returning ok:true while nothing changed (dispatch_control.py).
            # Without this, a no-op nav would clear the idle state and the next
            # real check would be a full cooldown away.
            if not self._gameplay_started(20.0):
                result = {"ok": False,
                          "error": "load-character reported ok but no gameplay traffic followed"}
        if isinstance(result, dict) and result.get("ok") is False:
            # Non-fatal and LOUD: the next poll retries after the cooldown, but
            # a silent failure here is indistinguishable from a healthy game.
            err = result.get("error", "enter-game failed")
            print(f"[oracle_health] enter-game failed: {err}", flush=True)
            self._set_relaunch(False, "failed", err)
            self._log_event("oracle_game_idle_enter_game_failed", error=str(err))
            return
        with self._lock:
            self._state["consecutive_idle"] = 0
            self._state["game_idle"] = False
        self._prev_hits_total = None      # counters move on from here; rebaseline
        self._set_relaunch(False, "ready", None)
        self._log_event("oracle_game_idle_enter_game_ok")

    def _notify_health_transition(self, reachable, running, snapshot):
        """Desktop toast on oracle down/up, at most once per state change."""
        try:
            import notify
            if reachable:
                notify.notify_transition(
                    "oracle", "up", "fun-doc: oracle recovered",
                    "D2Debugger :8790 is answering again -- live-prove resumed.",
                )
            elif snapshot["consecutive_down"] >= AUTO_RECOVER_AFTER_DOWN:
                shape = ("Game.exe is wedged (process alive, oracle dead)"
                         if running else "Game.exe is not running")
                notify.notify_transition(
                    "oracle", "down", "fun-doc: oracle DOWN",
                    f"{shape}. Live-prove and shadow-promote are paused; "
                    "auto-recovery is attempting a relaunch.",
                )
        except Exception:
            pass

    # ---- unattended recovery -------------------------------------------------------
    def _cooldown_for_attempt(self, attempts_so_far: int) -> float:
        """Seconds to wait before attempt number `attempts_so_far + 1`.

        Flat for the opening burst, then doubling to a hard ceiling. The
        ceiling is what makes indefinite retry safe: a launcher that is
        permanently broken settles at one attempt per AUTO_RECOVER_MAX_COOLDOWN
        (2/hour by default) instead of hammering the machine, while a
        transient failure at 2am still self-heals on its own.
        """
        if attempts_so_far < AUTO_RECOVER_BURST:
            return AUTO_RECOVER_COOLDOWN_SEC
        over = attempts_so_far - AUTO_RECOVER_BURST + 1
        # Guard the shift: `2 ** over` with a large `over` is an arbitrarily
        # big int, and min() on it is wasted work. Cap the exponent well
        # before that matters.
        backoff = AUTO_RECOVER_COOLDOWN_SEC * (2 ** min(over, 16))
        return min(backoff, AUTO_RECOVER_MAX_COOLDOWN_SEC)

    def _seconds_until_next_attempt(self):
        """Countdown to the next permitted attempt, or None if one may run now."""
        if self._last_auto_recover_at is None:
            return None
        cooldown = self._cooldown_for_attempt(self._auto_recover_attempts)
        remaining = cooldown - (time.monotonic() - self._last_auto_recover_at)
        return int(remaining) if remaining > 0 else None

    def _auto_recover_blocked_reason(self, snapshot):
        """Why auto-recovery will NOT fire, or None when it should. Split out so
        the reason can be logged -- a recovery that silently declines is
        indistinguishable from one that is broken."""
        if not self._auto_recover:
            return "disabled (FUNDOC_ORACLE_AUTO_RECOVER=0)"
        if snapshot.get("relaunching"):
            return "a relaunch is already in progress"
        # NOTE: no permanent give-up. Past the burst we slow down; we do not
        # stop. See AUTO_RECOVER_BURST for why.
        if self._last_auto_recover_at is not None:
            cooldown = self._cooldown_for_attempt(self._auto_recover_attempts)
            waited = time.monotonic() - self._last_auto_recover_at
            if waited < cooldown:
                return f"cooling down ({int(cooldown - waited)}s left)"
        # No predicate -> we cannot know that anything wants the oracle, and
        # "kill the game on a hunch" is not a safe default. The dashboard always
        # supplies one; a bare monitor (scripts, tests) deliberately never
        # auto-kills.
        if self._auto_recover_needed is None:
            return "no need-predicate configured -- refusing to close a game on spec"
        try:
            if not self._auto_recover_needed():
                return "nothing needs the oracle right now (no port worker running)"
        except Exception as e:
            return f"need-predicate raised: {e}"
        return None

    def _maybe_auto_recover(self, snapshot):
        """Wedged game + something waiting on the oracle -> close it and relaunch.

        Loud either way. The failure this exists to prevent is silent: a halted
        game starves every port worker of live candidates, they drain their pools
        into `oracle_unavailable` and exit `exhausted`, and the only symptom is
        that real proofs quietly stop appearing (the same shape as the 2026-07-27
        incident this module was written for)."""
        # The two shapes need different words -- "WEDGED" printed over a game
        # that simply exited sends you looking for a Halt dialog that was
        # never there.
        shape = ("game WEDGED (process up, oracle dead)" if snapshot.get("game_wedged")
                 else "game NOT RUNNING (oracle down, no process)")
        reason = self._auto_recover_blocked_reason(snapshot)
        if reason is not None:
            print(f"  [oracle] {shape} -- auto-recovery declined: {reason}", flush=True)
            self._log_event("oracle_auto_recover_declined", reason=reason, shape=shape)
            return
        self._auto_recover_attempts += 1
        self._last_auto_recover_at = time.monotonic()
        attempt = self._auto_recover_attempts
        degraded = attempt > AUTO_RECOVER_BURST
        with self._lock:
            self._state["recover_attempts"] = attempt
        phase = (f"attempt {attempt}, slow-retry every "
                 f"{int(self._cooldown_for_attempt(attempt))}s" if degraded
                 else f"attempt {attempt}/{AUTO_RECOVER_BURST}")
        print(f"  [oracle] {shape} -- auto-recovering ({phase})", flush=True)
        self._log_event("oracle_auto_recover_started", attempt=attempt, shape=shape,
                        degraded=degraded)
        # force=True is safe for both shapes: relaunch() only reaches its kill
        # branch when is_game_running(), so a dead game goes straight to launch.
        result = self.relaunch(force=True)
        if result.get("ok"):
            self._auto_recover_attempts = 0
            self._last_auto_recover_at = None
            with self._lock:
                self._state["recovery_degraded"] = False
                self._state["recover_attempts"] = 0
            print("  [oracle] auto-recovery succeeded -- live-prove is back", flush=True)
        else:
            print(f"  [oracle] auto-recovery FAILED: {result.get('error')}", flush=True)
            # Crossing out of the burst is the moment this stops being
            # self-healing and starts being a thing a human should look at.
            if attempt >= AUTO_RECOVER_BURST:
                with self._lock:
                    already = self._state.get("recovery_degraded")
                    self._state["recovery_degraded"] = True
                if not already:
                    self._log_event("oracle_recovery_degraded", attempt=attempt,
                                    error=result.get("error"))
                    try:
                        import notify
                        notify.notify_transition(
                            "oracle_recovery", "degraded",
                            "fun-doc: oracle recovery is failing",
                            f"{attempt} relaunch attempts failed "
                            f"({result.get('error') or 'unknown error'}). Still retrying "
                            f"every {int(AUTO_RECOVER_MAX_COOLDOWN_SEC / 60)} min -- "
                            "check the launcher.",
                        )
                    except Exception:
                        pass
        self._log_event("oracle_auto_recover_result", attempt=attempt,
                        ok=bool(result.get("ok")), error=result.get("error"))

    def _log_event(self, name, **fields):
        try:
            from event_log import log_event
            log_event(name, **fields)
        except Exception:
            pass

    # ---- relaunch orchestration -------------------------------------------------------
    def _wait_for(self, predicate, timeout, interval):
        deadline = time.monotonic() + timeout
        while True:
            try:
                if predicate():
                    return True
            except Exception:
                pass
            if self._stop.is_set() or time.monotonic() >= deadline:
                return False
            time.sleep(interval)

    def _launch_game(self):
        if not os.path.exists(self.launch_bat):
            return f"launcher script not found: {self.launch_bat}"
        # Enforce the window geometry BEFORE launch: ddraw.ini is read at
        # startup, and cnc-ddraw rewrites it on exit (savesettings=1), so
        # writing it here is what makes the setting durable. Best-effort --
        # a layout problem must never block a recovery launch.
        try:
            import game_window
            r = game_window.apply_ddraw_ini()
            if r.get("error"):
                print(f"  [game-window] ddraw.ini not applied: {r['error']}",
                      flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"  [game-window] ddraw.ini step skipped: {e}", flush=True)
        try:
            if is_elevated():
                # ALREADY ELEVATED -> run the .bat directly, windowless.
                #
                # `start` exists only to give the .bat a window on the
                # interactive desktop so its UAC self-elevation prompt can
                # surface. When we are already elevated the .bat's `net
                # session` check passes and it never elevates, so that window
                # buys nothing -- and it LINGERS: LaunchPD2-Oracle.bat ends
                # with `endlocal` and no `exit`, so the console it ran in sits
                # at a prompt forever. Two such "Administrator:" windows were
                # found on the desktop 2026-07-31, one per auto-recovery, each
                # with a dead parent and nothing but conhost inside.
                #
                # The game still gets its own window: the .bat launches it via
                # its own `start "" "%LAUNCHER%"`.
                subprocess.Popen(["cmd", "/c", self.launch_bat],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 stdin=subprocess.DEVNULL,
                                 creationflags=_NO_WINDOW)
            else:
                # NOT elevated -> the .bat must self-elevate, and its UAC
                # prompt has to be reachable. Keep `start`'s real window; a
                # hidden console here means an invisible consent dialog and a
                # launch that appears to hang.
                subprocess.Popen(["cmd", "/c", "start", "", self.launch_bat],
                                 creationflags=_NO_WINDOW)
        except Exception as e:
            return f"failed to spawn launcher: {e}"
        return None

    def _navigate_and_load_character(self, character, timeout):
        # Best-effort: documented-safe to call even past the title screen
        # (LOOP_PLAYBOOK.md: main_menu_singleplayer no-ops/harmlessly errors
        # from char-select, it does not need to gate on being at the title).
        try:
            _oracle_post("/action/main-menu-singleplayer", {"confirm": True})
        except Exception:
            pass

        self._set_relaunch(True, "waiting for character list", None)
        # RELIABLE readiness signal per LOOP_PLAYBOOK.md: poll list-characters
        # and ignore status flags (charSelectReady is not reliable here).
        deadline = time.monotonic() + timeout
        chars = []
        while time.monotonic() < deadline:
            try:
                resp = _oracle_get("/action/list-characters")
                if isinstance(resp, list):
                    chars = resp
                elif isinstance(resp, dict):
                    chars = resp.get("characters") or resp.get("chars") or []
            except Exception:
                chars = []
            if chars:
                break
            time.sleep(6.0)  # matches the playbook's documented ~6s poll cadence

        if not chars:
            return {"ok": False,
                    "error": f"no characters found at character-select within {int(timeout)}s"}

        names = [c.get("name") for c in chars if isinstance(c, dict)]
        if character not in names:
            return {"ok": False,
                    "error": f"configured character {character!r} not found among {names!r}"}

        self._set_relaunch(True, f"loading character {character!r}", None)
        try:
            result = _oracle_post(
                "/action/load-character",
                {"name": character, "difficulty": 0, "confirm": True},
            )
        except Exception as e:
            return {"ok": False, "error": f"load-character failed: {e}"}
        if isinstance(result, dict) and result.get("ok") is False:
            return {"ok": False, "error": result.get("error", "load-character returned ok=false")}
        return {"ok": True}

    def relaunch(self, character=None, timeout_boot=120.0, timeout_menu=90.0,
                 force=False) -> dict:
        """Full one-click sequence: launch Game.exe + embedded oracle, wait
        for :8790, advance to character-select, auto-load `character`.
        Synchronous -- callers (the dashboard route) run this in a thread.

        `force=True` additionally CLOSES a wedged Game.exe first (dismiss the
        Halt dialog, then taskkill). Without it a halted-but-alive game blocks
        recovery forever, which is exactly how a whole Prove fleet ends up with
        nothing live to do."""
        character = character or self.character

        if self.get_state().get("relaunching"):
            return {"ok": False, "error": "a relaunch is already in progress"}

        if is_game_running():
            # LaunchPD2-Oracle.bat itself refuses to double-launch ("two games
            # vs one oracle corrupt state") -- if Game.exe is up but the oracle
            # is unreachable, the embedded oracle almost certainly crashed
            # without taking the game process down with it. We can't safely
            # re-embed hooks into an already-running process from here, so the
            # corpse has to go before we can launch a fresh one.
            if not force:
                err = ("Game.exe is already running but the oracle is unreachable. "
                       "This usually means the embedded oracle crashed without "
                       "killing the game (a bad proof vector can do this). Close "
                       "Game.exe manually first, then relaunch -- or retry with "
                       "force to have the dashboard close it for you.")
                self._set_relaunch(False, "failed", err)
                return {"ok": False, "error": err}

            self._set_relaunch(True, "closing the wedged Game.exe", None)
            _dismiss_diablo_error_dialog()
            if not kill_game():
                err = ("could not terminate the wedged Game.exe. PD2 runs "
                       "elevated, so either approve the UAC prompt, close the "
                       "game by hand, or run the dashboard elevated to make "
                       "recovery fully unattended.")
                self._set_relaunch(False, "failed", err)
                self._log_result(False, err, character)
                return {"ok": False, "error": err}

        self._set_relaunch(True, "starting", None)
        try:
            oracle_up = False
            for attempt in (1, 2):
                self._set_relaunch(True, f"launching Game.exe (attempt {attempt}/2)", None)
                launch_err = self._launch_game()
                if launch_err:
                    self._set_relaunch(False, "failed", launch_err)
                    return {"ok": False, "error": launch_err}

                self._set_relaunch(True, "waiting for oracle on :8790", None)
                oracle_up = self._wait_for(check_oracle_alive, timeout_boot, 3.0)
                if oracle_up:
                    break

                if attempt == 1:
                    self._set_relaunch(True, "checking for a startup error dialog", None)
                    if _dismiss_diablo_error_dialog():
                        self._set_relaunch(
                            True, "dismissed a startup error dialog, retrying launch", None,
                        )
                        continue

                err = f"oracle did not come up on :8790 within {int(timeout_boot)}s"
                self._set_relaunch(False, "failed", err)
                self._log_result(False, err, character)
                return {"ok": False, "error": err}

            # Windows exist by now (the oracle answering means the game is up),
            # so enforce the layout. ddraw.ini is only advisory -- it is read at
            # startup by the renderer and says nothing about the D2Debugger
            # window -- so this is what actually guarantees the result.
            # Best-effort: a layout failure must never fail a recovery.
            try:
                import game_window
                lay = game_window.apply_layout()
                if lay.get("game") or lay.get("debugger"):
                    print(f"  [game-window] layout applied: {lay}", flush=True)
            except Exception as e:  # noqa: BLE001
                print(f"  [game-window] layout skipped: {e}", flush=True)

            self._set_relaunch(True, "oracle up, entering single-player", None)
            nav = self._navigate_and_load_character(character, timeout_menu)
            if not nav.get("ok"):
                self._set_relaunch(False, "failed", nav.get("error"))
                self._log_result(False, nav.get("error"), character)
                return nav

            self._set_relaunch(False, "ready", None)
            self.check_once()  # refresh reachable/game_running immediately
            self._log_result(True, None, character)
            return {"ok": True, "character": character}
        except Exception as e:
            self._set_relaunch(False, "failed", str(e))
            self._log_result(False, str(e), character)
            return {"ok": False, "error": str(e)}

    def _log_result(self, ok, error, character):
        try:
            from event_log import log_event
            log_event("oracle_relaunch_result", ok=ok, error=error, character=character)
        except Exception:
            pass

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

DEFAULT_LAUNCH_BAT = r"C:\Users\benam\source\cpp\D2MOO\LaunchPD2-Oracle.bat"
LAUNCH_BAT = os.environ.get("D2MOO_LAUNCH_BAT", DEFAULT_LAUNCH_BAT)
DEFAULT_PROVE_CHARACTER = os.environ.get("D2MOO_PROVE_CHARACTER", "summoner-skele")
POLL_INTERVAL_SEC = float(os.environ.get("FUNDOC_ORACLE_POLL_SEC", "45"))
GAME_PROCESS_NAME = "Game.exe"

# Unattended recovery from a WEDGED game (process alive, embedded oracle dead --
# the "Halt / Unrecoverable internal error" shape a bad proof vector produces).
# ON by default, but deliberately narrow: it only fires when a port worker is
# actually running, so it can never kill a game nobody is proving against.
AUTO_RECOVER = os.environ.get("FUNDOC_ORACLE_AUTO_RECOVER", "1") == "1"
# Poll cycles the oracle must stay down before we call it wedged rather than
# briefly busy. At the default 45s poll that is ~2 minutes of hard evidence.
AUTO_RECOVER_AFTER_DOWN = int(os.environ.get("FUNDOC_ORACLE_AUTO_RECOVER_AFTER", "3"))
# Floor between attempts, and a hard cap. A relaunch that keeps failing must not
# become a kill/launch loop chewing the machine -- after the cap it stays down
# and stays LOUD until a human looks.
AUTO_RECOVER_COOLDOWN_SEC = float(os.environ.get("FUNDOC_ORACLE_AUTO_RECOVER_COOLDOWN", "600"))
AUTO_RECOVER_MAX_ATTEMPTS = int(os.environ.get("FUNDOC_ORACLE_AUTO_RECOVER_MAX", "3"))

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
            capture_output=True, text=True, timeout=5,
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


def _dismiss_diablo_error_dialog() -> bool:
    """Best-effort dismissal of a "Diablo II Error" dialog -- both the transient
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
                if "diablo ii" in title and "error" in title:
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

    # ---- lifecycle -------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
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
        with self._lock:
            prev_reachable = self._state["reachable"]
            self._state["reachable"] = reachable
            self._state["game_running"] = running
            self._state["last_checked_at"] = datetime.now().isoformat()
            self._state["consecutive_down"] = (
                0 if reachable else self._state["consecutive_down"] + 1
            )
            # Game up + oracle down = the embedded oracle died without taking
            # the process with it. Requiring a sustained down-streak keeps a
            # single slow poll from being mistaken for a crash.
            self._state["game_wedged"] = bool(
                running and not reachable
                and self._state["consecutive_down"] >= AUTO_RECOVER_AFTER_DOWN
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

        if reachable:
            os.environ["FUNDOC_LIVE_PROVE"] = "1"
            os.environ["FUNDOC_SHADOW_PROMOTE"] = "1"
        else:
            os.environ.pop("FUNDOC_LIVE_PROVE", None)
            os.environ.pop("FUNDOC_SHADOW_PROMOTE", None)

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
        if snapshot["game_wedged"]:
            self._maybe_auto_recover(snapshot)
        return snapshot

    # ---- unattended recovery -------------------------------------------------------
    def _auto_recover_blocked_reason(self, snapshot):
        """Why auto-recovery will NOT fire, or None when it should. Split out so
        the reason can be logged -- a recovery that silently declines is
        indistinguishable from one that is broken."""
        if not self._auto_recover:
            return "disabled (FUNDOC_ORACLE_AUTO_RECOVER=0)"
        if snapshot.get("relaunching"):
            return "a relaunch is already in progress"
        if self._auto_recover_attempts >= AUTO_RECOVER_MAX_ATTEMPTS:
            return (f"gave up after {self._auto_recover_attempts} attempt(s) -- "
                    "recover by hand and check the launcher")
        if self._last_auto_recover_at is not None:
            waited = time.monotonic() - self._last_auto_recover_at
            if waited < AUTO_RECOVER_COOLDOWN_SEC:
                return f"cooling down ({int(AUTO_RECOVER_COOLDOWN_SEC - waited)}s left)"
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
        reason = self._auto_recover_blocked_reason(snapshot)
        if reason is not None:
            print(f"  [oracle] game WEDGED (process up, oracle dead) -- "
                  f"auto-recovery declined: {reason}", flush=True)
            self._log_event("oracle_auto_recover_declined", reason=reason)
            return
        self._auto_recover_attempts += 1
        self._last_auto_recover_at = time.monotonic()
        attempt = self._auto_recover_attempts
        print(f"  [oracle] game WEDGED (process up, oracle dead) -- auto-recovering "
              f"(attempt {attempt}/{AUTO_RECOVER_MAX_ATTEMPTS})", flush=True)
        self._log_event("oracle_auto_recover_started", attempt=attempt)
        result = self.relaunch(force=True)
        if result.get("ok"):
            self._auto_recover_attempts = 0
            print("  [oracle] auto-recovery succeeded -- live-prove is back", flush=True)
        else:
            print(f"  [oracle] auto-recovery FAILED: {result.get('error')}", flush=True)
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
        try:
            # `start` opens its own window for the .bat regardless of how
            # this wrapping cmd is spawned -- needed so the .bat's UAC
            # self-elevation prompt actually surfaces on the interactive
            # desktop instead of being tied to a hidden/background handle.
            subprocess.Popen(["cmd", "/c", "start", "", self.launch_bat])
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

r"""Live Ghidra HTTP health monitoring + guarded relaunch.

Companion to oracle_health.py, same shape, different dependency. Ghidra is the
OTHER hard dependency of every fun-doc worker -- documentation, globals and
port lanes all decompile through `http://127.0.0.1:8089` -- and until now it
had no monitor at all:

* Workers each ran their own local `check_ghidra_online()` backoff, so an
  outage was visible only inside whichever worker happened to hit it.
* `audit/rules.yaml` has carried a `ghidra_offline_sustained` rule since
  Phase 1, keyed on a `ghidra_health` bus event. Nothing in production has
  ever emitted that event -- only `tests/performance/test_audit_rules.py`
  does. The rule has never fired in its life. This module is the emitter it
  was written against.
* The dashboard had no Ghidra indicator whatsoever. The header's live-dot is
  the browser's socket.io link, which stays green while Ghidra is dead.

Restore policy is deliberately narrower than the oracle's (operator decision,
2026-07-30): **launch only when no Ghidra exists at all; never kill one.**

A running-but-unresponsive Ghidra is reported loudly and left alone. Killing
it risks unsaved program state and stranded shared-server checkouts, and the
project rule is graceful lifecycle only -- save_program -> exit_ghidra -> wait
(see CLAUDE.md). Workers already back off and retry, so a hand-fixed Ghidra
self-heals the fleet without anything here doing the fixing.

Two traps this module exists to avoid, both confirmed on this machine:

1. **Instance stacking.** `fun_doc.try_launch_ghidra()` guards on a
   per-process `_ghidra_launch_attempted` flag and never checks whether a
   Ghidra is already running -- so every dashboard restart could spawn
   another one. We check for a live process first, every time.
2. **Launching the WRONG Ghidra.** `GHIDRA_INSTALL_DIR` is `F:\ghidra_11.4.2`
   here, which does not exist; `try_launch_ghidra`'s fallback list then hits
   `F:/ghidra_12.1_PUBLIC`, which does exist and is a DIFFERENT VERSION from
   the 12.1.2 the project actually runs. Auto-launch would silently start a
   stale Ghidra against a 12.1.2 project. We prefer the install dir observed
   on the running process's own command line, and refuse to guess when we
   cannot establish one.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# Ghidra's launcher signature. Precise on purpose: a bare "*ghidra*" match
# against java command lines false-positives on this very repo -- the VSCode
# Java language server carries the workspace path, and the workspace is named
# `ghidra-mcp`. A false positive here suppresses a legitimate launch, so the
# marker has to be something only Ghidra itself sets.
_GHIDRA_PROC_MARKER = "ghidra.GhidraClassLoader"

# Pull the install root out of the -cp argument on a running Ghidra:
#   -cp "F:\ghidra_12.1.2_PUBLIC\support\..\Ghidra\Framework\...\Utility.jar"
_INSTALL_FROM_CP = re.compile(
    r'-cp\s+"?([A-Za-z]:[^"]*?)[\\/]support[\\/]', re.IGNORECASE
)

POLL_INTERVAL_SEC = float(os.environ.get("FUNDOC_GHIDRA_POLL_SEC", "45"))
AUTO_LAUNCH = os.environ.get("FUNDOC_GHIDRA_AUTO_LAUNCH", "1") == "1"
# Poll cycles offline before we act. Ghidra can block its HTTP thread for a
# while during heavy analysis, so this is deliberately more patient than the
# oracle's -- ~2.5 min at the default poll.
AUTO_LAUNCH_AFTER_DOWN = int(os.environ.get("FUNDOC_GHIDRA_AUTO_LAUNCH_AFTER", "4"))
# Same burst-then-slow-retry budget as the oracle: Ghidra takes minutes to
# come up and analyze, so the flat cooldown is longer.
AUTO_LAUNCH_COOLDOWN_SEC = float(os.environ.get("FUNDOC_GHIDRA_LAUNCH_COOLDOWN", "900"))
AUTO_LAUNCH_BURST = int(os.environ.get("FUNDOC_GHIDRA_LAUNCH_BURST", "3"))
AUTO_LAUNCH_MAX_COOLDOWN_SEC = float(
    os.environ.get("FUNDOC_GHIDRA_LAUNCH_MAX_COOLDOWN", "1800")
)


def _run_powershell(script: str, timeout: float = 20.0):
    """Run a PowerShell snippet, returning stdout or None. Never raises."""
    ps = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
    )
    if not os.path.exists(ps):
        ps = "powershell.exe"
    try:
        creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        out = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=timeout, creationflags=creation,
        )
        return out.stdout
    except Exception:
        return None


def find_ghidra_processes() -> list[dict]:
    """Every running Ghidra JVM, as [{pid, install_dir}].

    Command-line inspection (not a name match) because Ghidra runs as a plain
    `javaw.exe` indistinguishable from any other JVM by name alone. Non-Windows
    returns empty -- this module's launch path is Windows-only anyway.
    """
    if not sys.platform.startswith("win"):
        return []
    out = _run_powershell(
        "Get-CimInstance Win32_Process -Filter \"Name='java.exe' OR Name='javaw.exe'\" "
        f"| Where-Object {{ $_.CommandLine -like '*{_GHIDRA_PROC_MARKER}*' }} "
        "| ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }"
    )
    if not out:
        return []
    found = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        pid_s, cmdline = line.split("\t", 1)
        try:
            pid = int(pid_s.strip())
        except ValueError:
            continue
        m = _INSTALL_FROM_CP.search(cmdline)
        found.append({"pid": pid, "install_dir": m.group(1) if m else None})
    return found


def is_ghidra_process_running() -> bool:
    return bool(find_ghidra_processes())


def _default_search_roots() -> list[Path]:
    """Where to look for an install when nothing better is known. Split out so
    tests can drive the version-comparison branch over a controlled tree
    instead of whatever happens to be on the developer's F: drive."""
    return [Path("F:/"), Path("C:/"), Path(os.path.expanduser("~"))]


def resolve_install_dir(observed: str | None = None,
                        search_roots: list | None = None) -> tuple[str | None, str | None]:
    """Best-known Ghidra install root, as (path, how_we_know).

    Priority order is about correctness, not convenience:

    1. `observed` -- the root taken off a Ghidra we actually saw running. The
       only source that cannot be stale or misconfigured.
    2. `GHIDRA_INSTALL_DIR` / `GHIDRA_HOME`, but ONLY if it really contains a
       ghidraRun.bat. On this machine the variable points at a path that does
       not exist, and honouring it blindly is how you end up two entries down
       a fallback list launching the wrong version.
    3. Newest versioned install found on disk, by parsed version number --
       never list order. `try_launch_ghidra`'s hand-ordered list puts
       `ghidra_12.1_PUBLIC` ahead of `ghidra_12.1.2_PUBLIC`, so it picks the
       older one whenever both exist, which is exactly the case here.

    Returns (None, reason) rather than guessing when nothing qualifies.
    """
    if observed and (Path(observed) / "ghidraRun.bat").exists():
        return observed, "observed on the running Ghidra process"

    for var in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        val = os.environ.get(var)
        if not val:
            continue
        if (Path(val) / "ghidraRun.bat").exists():
            return val, f"${var}"
        # Loud, because a stale value here is silently dangerous.
        print(f"  [ghidra] ignoring ${var}={val!r} -- no ghidraRun.bat there",
              flush=True)

    best = None
    for root in (search_roots if search_roots is not None else _default_search_roots()):
        try:
            entries = list(root.glob("ghidra_*"))
        except OSError:
            continue
        for entry in entries:
            if not (entry / "ghidraRun.bat").exists():
                continue
            m = re.search(r"ghidra_(\d+(?:\.\d+)*)", entry.name)
            if not m:
                continue
            version = tuple(int(p) for p in m.group(1).split("."))
            if best is None or version > best[0]:
                best = (version, str(entry))
    if best:
        return best[1], f"newest install on disk (v{'.'.join(map(str, best[0]))})"
    return None, "no Ghidra installation found (set GHIDRA_INSTALL_DIR)"


class GhidraHealthMonitor:
    """Background poller for the Ghidra HTTP server, with guarded relaunch.

    Mirrors OracleHealthMonitor so the dashboard can treat both the same way,
    but never kills anything -- see the module docstring.
    """

    def __init__(self, bus=None, poll_interval=None, auto_launch=None,
                 launcher=None):
        self._bus = bus
        self._poll_interval = poll_interval or POLL_INTERVAL_SEC
        self._auto_launch = AUTO_LAUNCH if auto_launch is None else bool(auto_launch)
        # Injectable for tests: () -> (ok: bool, error: str | None)
        self._launcher = launcher or self._launch_ghidra
        self._lock = threading.Lock()
        self._state = {
            # None until the first poll, so the first observation is itself a
            # transition worth logging (same rationale as the oracle monitor).
            "reachable": None,
            "process_running": None,
            "last_checked_at": None,
            "consecutive_down": 0,
            "launching": False,
            "launch_stage": None,
            "launch_error": None,
            "launch_attempts": 0,
            # Up but not answering /mcp/schema. We report this and explicitly
            # do NOT act on it -- the remedy risks unsaved work.
            "unresponsive": False,
            "recovery_degraded": False,
            "next_retry_in": None,
            "install_dir": None,
        }
        self._stop = threading.Event()
        self._thread = None
        self._attempts = 0
        self._last_attempt_at = None
        # Remembered from the last time we saw a live Ghidra, so a relaunch
        # reproduces the install that was actually in use rather than whatever
        # a stale env var points at.
        self._observed_install_dir = None

    # ---- lifecycle -------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        if self._auto_launch:
            print("  [ghidra] health monitor armed (launch-if-absent; "
                  "never kills a running Ghidra)", flush=True)
        else:
            print("  [ghidra] health monitor armed (report-only)", flush=True)
        self._stop.clear()
        self.check_once()
        self._thread = threading.Thread(
            target=self._loop, name="fun-doc-ghidra-health", daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(self._poll_interval):
            self.check_once()

    def get_state(self) -> dict:
        with self._lock:
            return dict(self._state)

    # ---- health check ----------------------------------------------------
    def check_once(self) -> dict:
        """One poll: probe the HTTP surface, classify, emit, maybe launch."""
        from fun_doc import check_ghidra_online

        try:
            reachable = bool(check_ghidra_online())
        except Exception:
            reachable = False

        # Process enumeration costs a PowerShell spawn (~0.3-1s), so only pay
        # for it when the answer can change what we do: when reachable, a live
        # process is implied.
        if reachable:
            running = True
        else:
            procs = find_ghidra_processes()
            running = bool(procs)
            for p in procs:
                if p.get("install_dir"):
                    self._observed_install_dir = p["install_dir"]
                    break

        with self._lock:
            prev = self._state["reachable"]
            self._state["reachable"] = reachable
            self._state["process_running"] = running
            self._state["last_checked_at"] = datetime.now().isoformat()
            self._state["consecutive_down"] = (
                0 if reachable else self._state["consecutive_down"] + 1
            )
            sustained = self._state["consecutive_down"] >= AUTO_LAUNCH_AFTER_DOWN
            # Up but silent. Reported, never acted on.
            self._state["unresponsive"] = bool(running and not reachable and sustained)
            self._state["next_retry_in"] = (
                self._seconds_until_next_attempt() if not reachable and sustained
                else None
            )
            if self._observed_install_dir:
                self._state["install_dir"] = self._observed_install_dir
            if reachable and (self._attempts or self._state["recovery_degraded"]):
                self._state["recovery_degraded"] = False
                self._state["launch_attempts"] = 0
            changed = prev != reachable
            snapshot = dict(self._state)

        if reachable:
            self._attempts = 0
            self._last_attempt_at = None

        # Emit EVERY poll, not only on change: the audit watcher's
        # ghidra_offline_sustained rule measures how long a status has held,
        # and a level signal is what lets it do that after a restart.
        self._emit_health(snapshot, changed)
        self._notify_transition(reachable, running, snapshot)

        # Absent + sustained -> launch. Unresponsive is deliberately excluded.
        if not reachable and sustained and not running:
            self._maybe_launch(snapshot)
        elif snapshot["unresponsive"] and changed:
            print("  [ghidra] UNRESPONSIVE: process is alive but /mcp/schema is "
                  "not answering. Not touching it -- a forced restart risks "
                  "unsaved programs and stranded shared-server checkouts. "
                  "Workers will back off and resume automatically.", flush=True)
        return snapshot

    def _emit_health(self, snapshot, changed):
        if self._bus is None:
            return
        payload = dict(snapshot)
        # `new` is the field audit/watcher.py::_on_ghidra_health reads. Its
        # vocabulary ("healthy"/"offline") comes from the rule fixtures in
        # tests/performance/test_audit_rules.py -- match it exactly or the
        # rule stays as dead as it has been since Phase 1.
        payload["new"] = "healthy" if snapshot["reachable"] else "offline"
        payload["changed"] = bool(changed)
        try:
            self._bus.emit("ghidra_health", payload)
        except Exception:
            pass

    def _notify_transition(self, reachable, running, snapshot):
        try:
            import notify
            if reachable:
                notify.notify_transition(
                    "ghidra", "up", "fun-doc: Ghidra recovered",
                    "127.0.0.1:8089 is answering again -- workers resuming.",
                )
            elif snapshot["consecutive_down"] >= AUTO_LAUNCH_AFTER_DOWN:
                shape = ("process alive but not answering (will NOT be restarted)"
                         if running else "no Ghidra process found")
                notify.notify_transition(
                    "ghidra", "down", "fun-doc: Ghidra DOWN",
                    f"127.0.0.1:8089 unreachable -- {shape}. "
                    "Every worker lane is blocked until it returns.",
                )
        except Exception:
            pass

    # ---- guarded launch --------------------------------------------------
    def _cooldown_for_attempt(self, attempts_so_far: int) -> float:
        if attempts_so_far < AUTO_LAUNCH_BURST:
            return AUTO_LAUNCH_COOLDOWN_SEC
        over = attempts_so_far - AUTO_LAUNCH_BURST + 1
        return min(AUTO_LAUNCH_COOLDOWN_SEC * (2 ** min(over, 16)),
                   AUTO_LAUNCH_MAX_COOLDOWN_SEC)

    def _seconds_until_next_attempt(self):
        if self._last_attempt_at is None:
            return None
        remaining = (self._cooldown_for_attempt(self._attempts)
                     - (time.monotonic() - self._last_attempt_at))
        return int(remaining) if remaining > 0 else None

    def _launch_blocked_reason(self, snapshot):
        if not self._auto_launch:
            return "disabled (FUNDOC_GHIDRA_AUTO_LAUNCH=0)"
        if snapshot.get("launching"):
            return "a launch is already in progress"
        # The load-bearing guard. Re-checked here and not just in check_once
        # because minutes of cooldown can elapse in between, and the whole
        # point is never to stack a second instance.
        if is_ghidra_process_running():
            return "a Ghidra process is already running (never stacking a second)"
        if self._last_attempt_at is not None:
            cooldown = self._cooldown_for_attempt(self._attempts)
            waited = time.monotonic() - self._last_attempt_at
            if waited < cooldown:
                return f"cooling down ({int(cooldown - waited)}s left)"
        return None

    def _maybe_launch(self, snapshot):
        reason = self._launch_blocked_reason(snapshot)
        if reason is not None:
            print(f"  [ghidra] OFFLINE (no process) -- launch declined: {reason}",
                  flush=True)
            self._log_event("ghidra_auto_launch_declined", reason=reason)
            return
        self._attempts += 1
        self._last_attempt_at = time.monotonic()
        attempt = self._attempts
        with self._lock:
            self._state["launch_attempts"] = attempt
        print(f"  [ghidra] OFFLINE (no process) -- launching (attempt {attempt})",
              flush=True)
        self._log_event("ghidra_auto_launch_started", attempt=attempt)
        self._set_launch(True, "launching Ghidra", None)
        ok, err = self._launcher()
        if ok:
            self._set_launch(False, "launched", None)
            print("  [ghidra] launch spawned -- waiting for :8089 to answer",
                  flush=True)
        else:
            self._set_launch(False, "failed", err)
            print(f"  [ghidra] launch FAILED: {err}", flush=True)
            if attempt >= AUTO_LAUNCH_BURST:
                with self._lock:
                    already = self._state["recovery_degraded"]
                    self._state["recovery_degraded"] = True
                if not already:
                    self._log_event("ghidra_recovery_degraded", attempt=attempt,
                                    error=err)
                    try:
                        import notify
                        notify.notify_transition(
                            "ghidra_recovery", "degraded",
                            "fun-doc: Ghidra launch is failing",
                            f"{attempt} attempts failed ({err}). Still retrying "
                            f"every {int(AUTO_LAUNCH_MAX_COOLDOWN_SEC / 60)} min.",
                        )
                    except Exception:
                        pass
        self._log_event("ghidra_auto_launch_result", attempt=attempt, ok=ok, error=err)

    def _launch_ghidra(self):
        """Spawn ghidraRun.bat. Returns (ok, error)."""
        install, how = resolve_install_dir(self._observed_install_dir)
        if not install:
            return False, how
        bat = Path(install) / "ghidraRun.bat"
        if not bat.exists():
            return False, f"ghidraRun.bat missing under {install}"
        print(f"  [ghidra] using install {install} ({how})", flush=True)
        with self._lock:
            self._state["install_dir"] = install
        try:
            subprocess.Popen(
                [str(bat)], cwd=install,
                creationflags=(subprocess.CREATE_NEW_CONSOLE
                               if sys.platform == "win32" else 0),
            )
        except Exception as e:
            return False, f"failed to spawn {bat}: {e}"
        return True, None

    def _set_launch(self, active, stage, error):
        with self._lock:
            self._state["launching"] = active
            self._state["launch_stage"] = stage
            self._state["launch_error"] = error
            snapshot = dict(self._state)
        if self._bus is not None:
            try:
                self._bus.emit("ghidra_launch_progress", snapshot)
            except Exception:
                pass

    def _log_event(self, name, **fields):
        try:
            from event_log import log_event
            log_event(name, **fields)
        except Exception:
            pass

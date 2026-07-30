"""Reap provider subprocesses orphaned by a hard dashboard shutdown.

Why this exists (2026-07-29). `_invoke_provider_with_watchdog` spawns each
provider session as a `multiprocessing` child and reliably terminates it in a
`finally` block. That covers every in-process path. What it cannot cover is the
DASHBOARD ITSELF being force-killed: `taskkill /F`, a crash, or an OOM kill runs
no handler, so any in-flight provider child is orphaned. A wedged child (stuck
in the socket read that the streaming fix addresses) never exits on its own, so
it lingers indefinitely.

Measured on this machine 2026-07-29: four such orphans, born 07-25 06:11,
07-25 08:23, 07-25 12:38 and 07-28 21:03 -- each within minutes of a dashboard
start whose session later ended hard. They had been idle for up to five days.

An `atexit`/signal handler is NOT sufficient for this: the kill that caused all
four (`taskkill /F` / SIGKILL) runs no handler by definition. A startup sweep is
the only thing that actually recovers them, so that is what this module is.

ATTRIBUTION IS THE WHOLE PROBLEM. Killing by "python process with a dead
parent" would be reckless -- and PID-file bookkeeping is defeated by PID reuse.
Instead a process must satisfy ALL THREE of:

  1. it is a `multiprocessing` spawn child (``--multiprocessing-fork`` in argv),
  2. its parent process no longer exists,
  3. it has a DLL/so mapped from *this interpreter's* ``sys.prefix`` -- i.e. it
     is running out of our venv.

(3) is what makes PID reuse a non-issue: a recycled PID belonging to some
unrelated program will not have our venv mapped into it. Note that the
executable path is useless for this -- a venv's spawn child reports the BASE
interpreter (``C:\\Python313\\python.exe``), identical to any other Python on
the box. Loaded modules are the reliable fingerprint.

(2) is also what protects the CURRENT dashboard's live children: their parent is
alive, so they are never candidates.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

__all__ = ["find_orphans", "reap_orphans"]


# PowerShell emits one object per candidate: pid, parent pid, whether the
# parent is still alive, and whether any loaded module sits under our prefix.
# Doing the module scan inside PowerShell keeps it to a single subprocess call
# instead of one per candidate.
_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$prefix = $args[0].ToLower()
$out = @()
Get-CimInstance Win32_Process -Filter "Name like '%python%'" | ForEach-Object {
  if ($_.CommandLine -notmatch 'multiprocessing-fork') { return }
  $parentAlive = $null -ne (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue)
  $inPrefix = $false
  if (-not $parentAlive) {
    $p = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
    if ($p) {
      try {
        foreach ($m in $p.Modules) {
          if ($m.FileName -and $m.FileName.ToLower().StartsWith($prefix)) { $inPrefix = $true; break }
        }
      } catch { }
    }
  }
  $out += [PSCustomObject]@{
    pid = [int]$_.ProcessId
    ppid = [int]$_.ParentProcessId
    parent_alive = [bool]$parentAlive
    in_prefix = [bool]$inPrefix
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


def _default_runner(prefix):
    """Return candidate process records as a list of dicts."""
    if os.name == "nt":
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             _PS_SCRIPT, "-args", prefix],
            capture_output=True, text=True, timeout=60, check=False,
        )
        raw = (proc.stdout or "").strip()
        if not raw:
            return []
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]
    return _posix_candidates(prefix)


def _posix_candidates(prefix):
    records = []
    prefix_l = prefix.lower()
    try:
        pids = [int(d) for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return records
    for pid in pids:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmdline = fh.read().decode("utf-8", "replace")
            if "multiprocessing-fork" not in cmdline:
                continue
            with open(f"/proc/{pid}/stat", "r") as fh:
                # ppid is field 4, but comm (field 2) may contain spaces, so
                # split after the closing paren.
                ppid = int(fh.read().rsplit(")", 1)[1].split()[1])
            parent_alive = ppid > 1 and os.path.isdir(f"/proc/{ppid}")
            in_prefix = False
            if not parent_alive:
                with open(f"/proc/{pid}/maps", "r") as fh:
                    in_prefix = prefix_l in fh.read().lower()
            records.append({"pid": pid, "ppid": ppid,
                            "parent_alive": parent_alive, "in_prefix": in_prefix})
        except (OSError, ValueError, IndexError):
            continue
    return records


def _default_killer(pid):
    if os.name == "nt":
        return subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30, check=False,
        ).returncode == 0
    import signal
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except OSError:
        return False


def find_orphans(prefix=None, runner=None):
    """PIDs of provider subprocesses orphaned by a previous dashboard.

    All three attribution conditions in the module docstring must hold. Our own
    PID is excluded defensively; live children are already excluded by the
    parent-alive check.
    """
    prefix = prefix or sys.prefix
    runner = runner or _default_runner
    try:
        records = runner(prefix)
    except Exception:
        # Never let a diagnostic sweep block dashboard startup.
        return []
    me = os.getpid()
    return [
        int(r["pid"]) for r in records
        if r.get("in_prefix") and not r.get("parent_alive")
        and int(r.get("pid", 0)) not in (me, 0)
    ]


def reap_orphans(prefix=None, runner=None, killer=None, log=print):
    """Find and terminate orphans. Returns (reaped_pids, failed_pids).

    Loud on both outcomes: a silent reaper is indistinguishable from one that
    never ran, which is how four of these went unnoticed for five days.
    """
    killer = killer or _default_killer
    orphans = find_orphans(prefix=prefix, runner=runner)
    if not orphans:
        return [], []
    reaped, failed = [], []
    for pid in orphans:
        try:
            (reaped if killer(pid) else failed).append(pid)
        except Exception:
            failed.append(pid)
    if log:
        if reaped:
            log(f"  [orphan-reaper] terminated {len(reaped)} orphaned provider "
                f"subprocess(es) from a previous dashboard: {reaped}")
        if failed:
            log(f"  [orphan-reaper] FAILED to terminate {failed} -- "
                f"still holding resources; investigate manually")
    return reaped, failed

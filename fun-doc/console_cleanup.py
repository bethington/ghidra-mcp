r"""Close leftover console windows this project's tooling left on the desktop.

Goal: after a launch, the only windows on screen should be the GAME and the
D2Debugger -- not a drift of orphaned cmd/powershell consoles.

TWO HALVES, AND THIS IS THE SECOND ONE
--------------------------------------
Most of the clutter was never leftovers at all: it was FLASHES. Several helpers
shell out on a poll (`oracle_health.is_game_running` every 45s,
`port_live_prove._pid_alive` on every in-flight check, netstat/tasklist/cmake),
and on Windows every child process gets a console unless you pass
CREATE_NO_WINDOW. Those calls now all pass it -- that is the real fix and it
prevents rather than cleans.

This module handles the residue: consoles from launches that died badly (a
force-killed dashboard, a UAC-declined elevation, a crashed .bat) whose parent
is gone and which nothing will ever close.

ATTRIBUTION IS THE WHOLE PROBLEM
--------------------------------
A naive "kill stray cmd/powershell/conhost" would close the operator's own
terminals, VS Code's integrated shells, and the agent session driving the
cleanup. Same discipline as orphan_reaper.py, and for the same reason: a reaper
is judged by what it REFUSES to kill.

Every one of these must hold before anything is touched:

  * the process is cmd.exe / powershell.exe / pwsh.exe (never conhost --
    conhost is owned by its console's client and dies with it);
  * its command line references one of OUR paths (the ghidra-mcp repo, the
    D2MOO repo, or the PD2 launcher). A shell with no such reference is
    somebody else's;
  * its PARENT IS DEAD. A live parent means something still owns it -- that is
    a running launch, not litter;
  * it is not this process, nor any ancestor of this process. Cleaning up must
    never kill the thing doing the cleaning.

Dry-run by default. `find_orphan_consoles()` reports; `close_orphan_consoles()`
acts.

USAGE
    python fun-doc/console_cleanup.py            # report only
    python fun-doc/console_cleanup.py --apply
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Shells only. conhost.exe is deliberately absent: it is the console HOST for
# another process and exits when that process does, so killing conhost directly
# closes a window out from under a live owner.
SHELL_NAMES = {"cmd.exe", "powershell.exe", "pwsh.exe"}

# A command line must mention one of these to be considered ours.
_DEFAULT_MARKERS = (
    r"ghidra-mcp",
    r"D2MOO",
    r"LaunchPD2-Oracle",
    r"start-dashboard",
    r"fun_doc",
)


def _markers() -> tuple:
    extra = os.environ.get("FUNDOC_CONSOLE_MARKERS", "")
    return _DEFAULT_MARKERS + tuple(m for m in extra.split(";") if m)


def _ps(script: str, timeout: float = 30.0):
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                       "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    if not os.path.exists(exe):
        exe = "powershell.exe"
    try:
        out = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=_NO_WINDOW)
        return out.stdout
    except Exception:
        return ""


def _snapshot() -> list:
    """[{pid, ppid, name, cmdline}] for every shell process."""
    if not sys.platform.startswith("win"):
        return []
    raw = _ps(
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.Name -in 'cmd.exe','powershell.exe','pwsh.exe' } | "
        "ForEach-Object { [pscustomobject]@{pid=$_.ProcessId; ppid=$_.ParentProcessId; "
        "name=$_.Name; cmdline=$_.CommandLine} } | ConvertTo-Json -Compress -Depth 3"
    )
    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    return data if isinstance(data, list) else [data]


def _live_pids() -> set:
    raw = _ps("(Get-Process -ErrorAction SilentlyContinue).Id -join ','")
    return {int(x) for x in raw.strip().split(",") if x.strip().isdigit()}


def _ancestors(pid: int, by_pid: dict) -> set:
    """PIDs from `pid` up to the root, guarded against a cycle."""
    seen, cur = set(), pid
    while cur and cur not in seen:
        seen.add(cur)
        cur = (by_pid.get(cur) or {}).get("ppid")
    return seen


def find_orphan_consoles(snapshot=None, live=None, unattributable=None) -> list:
    """Shells that are ours, parentless, and not part of our own tree.

    Pass a list as `unattributable` to also collect parentless consoles whose
    command line could not be read (elevated). Those are reported, never
    closed.
    """
    procs = _snapshot() if snapshot is None else snapshot
    if not procs:
        return []
    live = _live_pids() if live is None else live
    by_pid = {int(p["pid"]): {"ppid": int(p.get("ppid") or 0)} for p in procs}
    mine = _ancestors(os.getpid(), by_pid) | {os.getpid()}
    markers = _markers()

    out = []
    if unattributable is None:
        unattributable = []
    for p in procs:
        pid = int(p["pid"])
        if pid in mine:
            continue                       # never the hand that cleans
        name = str(p.get("name") or "").lower()
        if name not in SHELL_NAMES:
            continue
        ppid = int(p.get("ppid") or 0)
        if ppid and ppid in live:
            continue                       # a live owner means it is in use
        cmd = str(p.get("cmdline") or "")
        if not cmd:
            # UNREADABLE, not absent. Win32_Process returns an empty command
            # line for a process at a higher integrity level than the reader,
            # so an unelevated sweep cannot attribute an ELEVATED console --
            # which is exactly what LaunchPD2-Oracle.bat leaves behind.
            #
            # Reported rather than silently skipped: "found nothing" and "found
            # things I am not allowed to identify" are different answers, and
            # conflating them is how a cleaner looks like it works while doing
            # nothing. Never auto-closed -- an unidentifiable elevated console
            # may be the operator's own.
            unattributable.append({"pid": pid, "name": name,
                                   "reason": "elevated: command line unreadable "
                                             "from this integrity level"})
            continue
        if not any(m.lower() in cmd.lower() for m in markers):
            continue                       # somebody else's shell
        out.append({"pid": pid, "name": name, "cmdline": cmd[:200]})
    return out


def close_orphan_consoles(dry_run: bool = True, pids=None) -> dict:
    """Close attributable orphans, or exactly `pids` when given.

    `pids` is the escape hatch for consoles this process cannot attribute
    because they are elevated -- the operator identifies them and names them
    explicitly, rather than the tool guessing at a higher integrity level.
    """
    unattributable = []
    if pids:
        found = [{"pid": int(x), "name": "(explicit)", "cmdline": ""} for x in pids]
    else:
        found = find_orphan_consoles(unattributable=unattributable)
    closed, failed = [], []
    if not dry_run:
        for p in found:
            try:
                subprocess.run(["taskkill", "/PID", str(p["pid"]), "/T", "/F"],
                               capture_output=True, timeout=15,
                               creationflags=_NO_WINDOW)
                closed.append(p["pid"])
            except Exception as e:  # noqa: BLE001
                failed.append({"pid": p["pid"], "error": str(e)})
    return {"found": found, "closed": closed, "failed": failed,
            "unattributable": unattributable, "dry_run": dry_run}


def sweep_on_launch() -> None:
    """Best-effort startup sweep. Never raises, never blocks startup."""
    if os.environ.get("FUNDOC_CONSOLE_CLEANUP", "1") != "1":
        return
    try:
        res = close_orphan_consoles(dry_run=False)
        if res["closed"]:
            print(f"  [console-cleanup] closed {len(res['closed'])} orphaned "
                  f"console(s): {res['closed']}", flush=True)
        for f in res["failed"]:
            print(f"  [console-cleanup] could not close {f['pid']}: {f['error']}",
                  flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"  [console-cleanup] sweep skipped: {e}", flush=True)


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="close them (default: report)")
    ap.add_argument("--pid", type=int, action="append",
                    help="close this PID explicitly. For an ELEVATED console "
                         "this tool can see but cannot attribute; repeatable. "
                         "Needs to run elevated itself to succeed.")
    args = ap.parse_args()
    res = close_orphan_consoles(dry_run=not args.apply, pids=args.pid)
    if not res["found"] and not res.get("unattributable"):
        print("no orphaned consoles attributable to this project.")
        return 0
    for u in res.get("unattributable", []):
        print(f"   pid={u['pid']:<8} {u['name']:<16} UNATTRIBUTABLE -- {u['reason']}")
    if res.get("unattributable"):
        print("   (close one explicitly with --pid <PID> --apply, run elevated)")
    if not res["found"]:
        return 0
    print(f"{len(res['found'])} orphaned console(s):")
    for p in res["found"]:
        print(f"   pid={p['pid']:<8} {p['name']:<16} {p['cmdline'][:110]}")
    if res["dry_run"]:
        print("\nDRY RUN -- re-run with --apply to close them.")
    else:
        print(f"\nclosed: {res['closed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

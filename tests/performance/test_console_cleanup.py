"""Coverage for the orphaned-console sweep.

A reaper is judged by what it REFUSES to kill. A naive "close stray
cmd/powershell" would take out the operator's own terminals, VS Code's
integrated shells, and the very session running the cleanup -- so these tests
are mostly about refusals.

Same discipline as test_orphan_reaper.py, for the same reason.
"""

import os
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

cc = pytest.importorskip("console_cleanup")

OURS = r"powershell -File C:\Users\x\source\mcp\ghidra-mcp\fun-doc\start-dashboard.ps1"
THEIRS = r"powershell -NoExit -Command Get-ChildItem C:\Users\x\Documents"


def _proc(pid, ppid, name="powershell.exe", cmdline=OURS):
    return {"pid": pid, "ppid": ppid, "name": name, "cmdline": cmdline}


def test_finds_our_orphan():
    found = cc.find_orphan_consoles(snapshot=[_proc(111, 999)], live={os.getpid()})
    assert [p["pid"] for p in found] == [111]


def test_spares_a_shell_with_a_LIVE_parent():
    """A live parent means something still owns it -- that is a running launch,
    not litter."""
    found = cc.find_orphan_consoles(snapshot=[_proc(111, 222)],
                                    live={222, os.getpid()})
    assert found == []


def test_spares_someone_elses_shell():
    """No reference to our paths means it is not ours to close. This is what
    protects the operator's own terminals."""
    found = cc.find_orphan_consoles(
        snapshot=[_proc(111, 999, cmdline=THEIRS)], live={os.getpid()})
    assert found == []


def test_never_closes_conhost():
    """conhost is the console HOST for another process and exits with it;
    killing it directly closes a window out from under a live owner."""
    found = cc.find_orphan_consoles(
        snapshot=[_proc(111, 999, name="conhost.exe")], live={os.getpid()})
    assert found == []


def test_never_closes_itself():
    found = cc.find_orphan_consoles(
        snapshot=[_proc(os.getpid(), 999)], live={os.getpid()})
    assert found == []


def test_never_closes_an_ancestor():
    """Killing the parent of the cleaning process kills the cleaning process."""
    me = os.getpid()
    snapshot = [_proc(me, 4242), _proc(4242, 999)]
    found = cc.find_orphan_consoles(snapshot=snapshot, live={me})
    assert 4242 not in [p["pid"] for p in found]


def test_ancestor_walk_survives_a_cycle():
    """A corrupt ppid chain must not hang the sweep."""
    by_pid = {1: {"ppid": 2}, 2: {"ppid": 1}}
    assert cc._ancestors(1, by_pid) == {1, 2}


def test_dry_run_closes_nothing(monkeypatch):
    monkeypatch.setattr(cc, "find_orphan_consoles", lambda **kw: [{"pid": 111}])
    killed = []
    monkeypatch.setattr(cc.subprocess, "run",
                        lambda *a, **k: killed.append(a) or None)
    res = cc.close_orphan_consoles(dry_run=True)
    assert res["closed"] == [] and killed == []


def test_apply_closes_what_it_found(monkeypatch):
    monkeypatch.setattr(cc, "find_orphan_consoles",
                        lambda **kw: [{"pid": 111, "name": "cmd.exe", "cmdline": OURS}])
    killed = []
    monkeypatch.setattr(cc.subprocess, "run",
                        lambda cmd, **k: killed.append(cmd) or None)
    res = cc.close_orphan_consoles(dry_run=False)
    assert res["closed"] == [111]
    assert any("111" in " ".join(str(c) for c in k) for k in killed)


def test_sweep_on_launch_never_raises(monkeypatch):
    """Startup must not be blocked by a cleanup failure."""
    def boom(**kw):
        raise RuntimeError("WMI exploded")
    monkeypatch.setattr(cc, "close_orphan_consoles", boom)
    cc.sweep_on_launch()          # must not raise


def test_sweep_can_be_disabled(monkeypatch):
    monkeypatch.setenv("FUNDOC_CONSOLE_CLEANUP", "0")
    called = []
    monkeypatch.setattr(cc, "close_orphan_consoles",
                        lambda **kw: called.append(1) or {})
    cc.sweep_on_launch()
    assert called == []


# ------------------------------------------- unreadable (elevated) consoles ==

def test_unreadable_cmdline_is_reported_not_silently_skipped():
    """Win32_Process returns an EMPTY command line for a process at a higher
    integrity level than the reader, so an unelevated sweep cannot attribute an
    ELEVATED console -- exactly what LaunchPD2-Oracle.bat leaves behind.

    "found nothing" and "found things I am not allowed to identify" are
    different answers. Conflating them is how a cleaner looks like it works
    while doing nothing: the sweep reported a clean desktop while three
    orphaned Administrator consoles sat on screen (2026-07-31).
    """
    unattr = []
    found = cc.find_orphan_consoles(
        snapshot=[_proc(111, 999, name="cmd.exe", cmdline="")],
        live={os.getpid()}, unattributable=unattr)
    assert found == [], "an unidentifiable elevated console is never auto-closed"
    assert [u["pid"] for u in unattr] == [111]
    assert "unreadable" in unattr[0]["reason"]


def test_unreadable_but_LIVE_parent_is_not_even_reported():
    """A live parent still means something owns it -- not litter, not a
    candidate, not worth mentioning."""
    unattr = []
    cc.find_orphan_consoles(
        snapshot=[_proc(111, 222, name="cmd.exe", cmdline="")],
        live={222, os.getpid()}, unattributable=unattr)
    assert unattr == []


def test_explicit_pids_bypass_attribution(monkeypatch):
    """The escape hatch for elevated consoles: the operator identifies them and
    names them, rather than the tool guessing across an integrity boundary."""
    killed = []
    monkeypatch.setattr(cc.subprocess, "run",
                        lambda cmd, **k: killed.append(cmd) or None)
    res = cc.close_orphan_consoles(dry_run=False, pids=[4242])
    assert res["closed"] == [4242]
    assert any("4242" in " ".join(str(c) for c in k) for k in killed)


def test_explicit_pids_still_honour_dry_run(monkeypatch):
    killed = []
    monkeypatch.setattr(cc.subprocess, "run",
                        lambda cmd, **k: killed.append(cmd) or None)
    res = cc.close_orphan_consoles(dry_run=True, pids=[4242])
    assert res["closed"] == [] and killed == []

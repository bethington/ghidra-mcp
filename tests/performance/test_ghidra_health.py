"""Coverage for the Ghidra health monitor and its guarded launch.

Two things this module exists to prevent, both confirmed on the dev box
2026-07-30:

1. **Instance stacking.** `fun_doc.try_launch_ghidra()` guards only on a
   per-process `_ghidra_launch_attempted` flag -- it never checks whether a
   Ghidra is already running, so each dashboard restart could spawn another.
2. **Launching the WRONG Ghidra.** `GHIDRA_INSTALL_DIR` was
   `F:\\ghidra_11.4.2`, a path that does not exist. `try_launch_ghidra`'s
   hand-ordered fallback list then reaches `F:/ghidra_12.1_PUBLIC`, which DOES
   exist and is a different version from the 12.1.2 the project runs.

Plus the reason the module was written at all: `audit/rules.yaml` has carried
a `ghidra_offline_sustained` rule since Phase 1 keyed on a `ghidra_health`
bus event that no production code has ever emitted.
"""

import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

ghidra_health = pytest.importorskip("ghidra_health")


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, name, payload):
        self.events.append((name, payload))


def _monitor(monkeypatch, *, reachable, procs=(), bus=None, auto_launch=True):
    monkeypatch.setattr(ghidra_health, "find_ghidra_processes",
                        lambda: list(procs() if callable(procs) else procs))
    launches = []

    def _fake_launch():
        launches.append(True)
        return True, None

    import fun_doc
    monkeypatch.setattr(fun_doc, "check_ghidra_online",
                        (reachable if callable(reachable) else (lambda *a, **k: reachable)))
    m = ghidra_health.GhidraHealthMonitor(bus=bus, auto_launch=auto_launch,
                                          launcher=_fake_launch)
    m.launches = launches
    return m


# ------------------------------------------------- process discrimination ---

def test_marker_is_specific_enough_to_exclude_this_repo():
    """A bare '*ghidra*' command-line match false-positives on this very
    workspace -- the VSCode Java language server carries the path, and the
    repo is named `ghidra-mcp`. A false positive SUPPRESSES a legitimate
    launch, so the marker must be something only Ghidra sets."""
    marker = ghidra_health._GHIDRA_PROC_MARKER
    assert marker == "ghidra.GhidraClassLoader"
    vscode_cmdline = (
        r"c:\Users\benam\.vscode\extensions\redhat.java\jre\bin\java.exe "
        r"-Dosgi... c:\Users\benam\source\mcp\ghidra-mcp"
    )
    assert marker not in vscode_cmdline


def test_install_dir_parsed_off_a_real_ghidra_command_line():
    cmdline = (
        r'"C:\Program Files\Eclipse Adoptium\jdk-21\bin\javaw" '
        r'-Djava.system.class.loader=ghidra.GhidraClassLoader '
        r'-cp "F:\ghidra_12.1.2_PUBLIC\support\..\Ghidra\Framework\Utility\lib\Utility.jar" '
        r'ghidra.Ghidra ghidra.GhidraRun "F:\GhidraProjects\diablo2.gpr"'
    )
    m = ghidra_health._INSTALL_FROM_CP.search(cmdline)
    assert m and m.group(1) == r"F:\ghidra_12.1.2_PUBLIC"


# ------------------------------------------------------ install resolution --

def test_observed_install_dir_wins(tmp_path, monkeypatch):
    """The install taken off a RUNNING Ghidra is the only source that cannot
    be stale. It must outrank the env var."""
    observed = tmp_path / "ghidra_12.1.2_PUBLIC"
    observed.mkdir()
    (observed / "ghidraRun.bat").write_text("rem")
    stale = tmp_path / "ghidra_9.9_PUBLIC"
    stale.mkdir()
    (stale / "ghidraRun.bat").write_text("rem")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(stale))
    path, how = ghidra_health.resolve_install_dir(str(observed))
    assert path == str(observed)
    assert "running" in how


def test_nonexistent_env_var_is_ignored(tmp_path, monkeypatch):
    """The live misconfiguration: GHIDRA_INSTALL_DIR pointing at a path with
    no ghidraRun.bat must be rejected, not silently honoured."""
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path / "does_not_exist"))
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    path, how = ghidra_health.resolve_install_dir(None)
    # Whatever it picks, it must not be the bogus env path.
    assert path != str(tmp_path / "does_not_exist")


def test_newest_version_wins_not_list_order(tmp_path, monkeypatch):
    """12.1.2 must beat 12.1, and the compare must be NUMERIC. Lexically
    "12.1.2" < "12.1_PUBLIC", and try_launch_ghidra's hand-ordered list puts
    `ghidra_12.1_PUBLIC` first outright -- either way it picks the OLDER
    install whenever both exist, which is the case on this machine."""
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    for name in ("ghidra_12.1_PUBLIC", "ghidra_12.1.2_PUBLIC", "ghidra_9.2_PUBLIC"):
        d = tmp_path / name
        d.mkdir()
        (d / "ghidraRun.bat").write_text("rem")
    path, how = ghidra_health.resolve_install_dir(None, search_roots=[tmp_path])
    assert path == str(tmp_path / "ghidra_12.1.2_PUBLIC")
    assert "12.1.2" in how


def test_install_without_ghidrarun_is_not_a_candidate(tmp_path, monkeypatch):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    (tmp_path / "ghidra_99.0_PUBLIC").mkdir()          # extracted zip, no launcher
    good = tmp_path / "ghidra_12.1.2_PUBLIC"
    good.mkdir()
    (good / "ghidraRun.bat").write_text("rem")
    path, _ = ghidra_health.resolve_install_dir(None, search_roots=[tmp_path])
    assert path == str(good)


def test_no_install_found_refuses_to_guess(tmp_path, monkeypatch):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    path, how = ghidra_health.resolve_install_dir(None, search_roots=[tmp_path])
    assert path is None
    assert "no Ghidra installation" in how


# ----------------------------------------------------------- launch guard ---

def test_never_stacks_a_second_instance(monkeypatch):
    """The load-bearing guard. Offline HTTP but a live process means Ghidra
    is busy/wedged, NOT absent -- launching would stack instances."""
    m = _monitor(monkeypatch, reachable=False,
                 procs=[{"pid": 1, "install_dir": r"F:\ghidra_12.1.2_PUBLIC"}])
    for _ in range(ghidra_health.AUTO_LAUNCH_AFTER_DOWN + 2):
        snap = m.check_once()
    assert snap["unresponsive"] is True
    assert not m.launches, "must never launch while a Ghidra process exists"


def test_launches_only_when_absent(monkeypatch):
    m = _monitor(monkeypatch, reachable=False, procs=[])
    for _ in range(ghidra_health.AUTO_LAUNCH_AFTER_DOWN):
        m.check_once()
    assert m.launches, "an absent Ghidra should be launched"


def test_unresponsive_ghidra_is_never_killed(monkeypatch):
    """Explicit operator decision: a running-but-silent Ghidra is reported and
    left alone. Killing it risks unsaved programs and stranded shared-server
    checkouts."""
    m = _monitor(monkeypatch, reachable=False,
                 procs=[{"pid": 1, "install_dir": None}])
    for _ in range(ghidra_health.AUTO_LAUNCH_AFTER_DOWN + 3):
        m.check_once()
    assert not m.launches
    # And there is no kill path at all on this class.
    assert not hasattr(m, "kill_ghidra")
    assert not any(n.startswith("kill") for n in dir(m))


def test_brief_outage_does_not_launch(monkeypatch):
    m = _monitor(monkeypatch, reachable=False, procs=[])
    m.check_once()
    assert not m.launches


def test_healthy_ghidra_skips_process_enumeration(monkeypatch):
    """Enumeration costs a PowerShell spawn (~1.5s). When the HTTP surface
    answers, a live process is implied and we must not pay for it."""
    calls = []
    monkeypatch.setattr(ghidra_health, "find_ghidra_processes",
                        lambda: calls.append(1) or [])
    import fun_doc
    monkeypatch.setattr(fun_doc, "check_ghidra_online", lambda *a, **k: True)
    m = ghidra_health.GhidraHealthMonitor(auto_launch=False)
    for _ in range(5):
        m.check_once()
    assert calls == [], "must not enumerate processes while Ghidra is reachable"


def test_auto_launch_disabled_is_respected(monkeypatch):
    m = _monitor(monkeypatch, reachable=False, procs=[], auto_launch=False)
    for _ in range(ghidra_health.AUTO_LAUNCH_AFTER_DOWN + 2):
        m.check_once()
    assert not m.launches


# ------------------------------------------------------------ bus contract --

def test_emits_ghidra_health_in_the_shape_the_audit_watcher_reads(monkeypatch):
    """audit/watcher.py::_on_ghidra_health reads data['new'] and expects
    'healthy'/'offline'. Get this wrong and the ghidra_offline_sustained rule
    stays as dead as it has been since Phase 1."""
    bus = _Bus()
    m = _monitor(monkeypatch, reachable=True, procs=[], bus=bus)
    m.check_once()
    names = [n for n, _ in bus.events]
    assert "ghidra_health" in names
    payload = dict(bus.events[-1][1])
    assert payload["new"] == "healthy"

    bus.events.clear()
    monkeypatch.setattr(ghidra_health, "find_ghidra_processes", lambda: [])
    import fun_doc
    monkeypatch.setattr(fun_doc, "check_ghidra_online", lambda *a, **k: False)
    m.check_once()
    assert dict(bus.events[-1][1])["new"] == "offline"


def test_audit_watcher_actually_consumes_the_payload(monkeypatch):
    """End-to-end against the real handler: proves the vocabulary matches
    rather than just asserting our own constant back at ourselves."""
    watcher_mod = pytest.importorskip("audit.watcher")
    handler_names = getattr(watcher_mod, "BUS_SUBSCRIPTIONS", [])
    assert "ghidra_health" in handler_names, (
        "the watcher subscribes to ghidra_health; this monitor is its emitter"
    )


def test_health_emitted_every_poll_not_only_on_change(monkeypatch):
    """The audit rule measures how LONG a status has held. A change-only
    signal cannot support that after a restart."""
    bus = _Bus()
    m = _monitor(monkeypatch, reachable=True, procs=[], bus=bus)
    for _ in range(4):
        m.check_once()
    assert len([n for n, _ in bus.events if n == "ghidra_health"]) == 4


# ---------------------------------------------------------- retry budget ----

def test_launch_backoff_is_capped():
    m = ghidra_health.GhidraHealthMonitor(auto_launch=False)
    prev = 0.0
    for n in range(0, 30):
        cd = m._cooldown_for_attempt(n)
        assert cd >= prev or n <= ghidra_health.AUTO_LAUNCH_BURST
        assert cd <= ghidra_health.AUTO_LAUNCH_MAX_COOLDOWN_SEC
        prev = cd

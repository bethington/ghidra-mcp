"""Regression tests for tools.setup.ghidra process detection.

The deploy flow needs to know about TWO kinds of running Ghidras:

  * Ones from the install path we're deploying TO — gracefully shut
    those down before extension replacement.
  * Ones from a DIFFERENT install — leave alone (might be unrelated
    work) but warn loudly, because an old Ghidra still bound to MCP
    port 8089 will intercept the deploy's post-start smoke checks
    intended for the new install.

The earlier `_find_matching_ghidra_processes` did the install-path
filter on the same pass as the process scan, which silently lost
the mismatched set. The v5.10 → v5.11 cutover (Ghidra 12.0.4 → 12.1)
hit this in production: the deploy log said "No matching running
Ghidra process detected" while an old 12.0.4 was still up. These
tests pin the split (`_enumerate_*` returns every Ghidra,
`_find_matching_*` / `_find_mismatched_*` partition by install path)
so the same blind spot can't sneak back.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


# The positive-match tests below build synthetic Windows install paths
# (``F:\ghidra_NEW_PUBLIC``) and rely on ``Path(...).resolve()`` returning
# the path unchanged. That holds on Windows (the drive-letter form is a
# valid absolute path), but POSIX treats backslashes as filename chars,
# so ``resolve()`` prepends the test's cwd and the substring match in
# ``_find_matching_ghidra_processes`` no longer finds the target inside
# the (still-Windows-shaped) command line. The deploy flow runs on
# Windows in practice, so the cleanest contract is "Windows-only" rather
# than building POSIX-compatible fakes for a Windows-only deploy path.
pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Process-detection scenarios use Windows install paths; "
           "Path.resolve() mangles them on POSIX in a way that defeats "
           "the substring match — the matcher itself is platform-agnostic "
           "but the deploy flow is Windows-only.",
)


@pytest.fixture
def ghidra_module(monkeypatch):
    """Import tools.setup.ghidra with a clean monkeypatch context."""
    from tools.setup import ghidra

    return ghidra


def _process(pid: int, cmd: str, name: str = "javaw.exe") -> dict:
    return {"pid": pid, "name": name, "command": cmd}


# ---------------------------------------------------------------------------
# _find_matching / _find_mismatched as partitions of _enumerate
# ---------------------------------------------------------------------------


def test_matching_excludes_mismatched_install_paths(ghidra_module, monkeypatch):
    """A Ghidra from an OLDER install is NOT a match for a deploy
    targeting the new install — exactly the v5.10→v5.11 case.

    Uses synthetic _OLD_/_NEW_ install paths instead of literal version
    numbers so a linter/auto-replace can't silently rewrite "the old
    version" string into "the new version" and break the test invariant
    (that bit us once).
    """
    monkeypatch.setattr(
        ghidra_module,
        "_enumerate_ghidra_processes",
        lambda: [
            _process(
                101,
                r"javaw -cp F:\ghidra_OLD_PUBLIC\support\..\Ghidra\Framework\Utility\lib\Utility.jar ghidra.Ghidra ghidra.GhidraRun",
            ),
        ],
    )
    matches = ghidra_module._find_matching_ghidra_processes(
        Path(r"F:\ghidra_NEW_PUBLIC")
    )
    assert matches == []


def test_mismatched_finds_the_other_install(ghidra_module, monkeypatch):
    """The mismatched probe — the bit the v5.10→v5.11 deploy was
    missing — flags the older Ghidra when we deploy to the newer one."""
    monkeypatch.setattr(
        ghidra_module,
        "_enumerate_ghidra_processes",
        lambda: [
            _process(
                101,
                r"javaw -cp F:\ghidra_OLD_PUBLIC\support\..\Ghidra\Framework\Utility\lib\Utility.jar ghidra.Ghidra ghidra.GhidraRun",
            ),
        ],
    )
    mismatched = ghidra_module._find_mismatched_ghidra_processes(
        Path(r"F:\ghidra_NEW_PUBLIC")
    )
    assert len(mismatched) == 1
    assert mismatched[0]["pid"] == 101


def test_matching_includes_target_install(ghidra_module, monkeypatch):
    """A Ghidra running from the exact install we're deploying TO
    still gets detected — the graceful-exit case must not regress."""
    monkeypatch.setattr(
        ghidra_module,
        "_enumerate_ghidra_processes",
        lambda: [
            _process(
                101,
                r"javaw -cp F:\ghidra_NEW_PUBLIC\support\..\Ghidra\Framework\Utility\lib\Utility.jar ghidra.Ghidra ghidra.GhidraRun",
            ),
        ],
    )
    matches = ghidra_module._find_matching_ghidra_processes(
        Path(r"F:\ghidra_NEW_PUBLIC")
    )
    assert len(matches) == 1
    assert matches[0]["pid"] == 101


def test_mixed_installs_partitioned_correctly(ghidra_module, monkeypatch):
    """Realistic case: target install is up AND an old install is up.
    Matching gets the target one, mismatched gets the old one."""
    monkeypatch.setattr(
        ghidra_module,
        "_enumerate_ghidra_processes",
        lambda: [
            _process(
                101,
                r"javaw -cp F:\ghidra_OLD_PUBLIC\... ghidra.Ghidra ghidra.GhidraRun",
            ),
            _process(
                202,
                r"javaw -cp F:\ghidra_NEW_PUBLIC\... ghidra.Ghidra ghidra.GhidraRun",
            ),
        ],
    )
    target = Path(r"F:\ghidra_NEW_PUBLIC")
    matches = ghidra_module._find_matching_ghidra_processes(target)
    mismatched = ghidra_module._find_mismatched_ghidra_processes(target)
    assert [p["pid"] for p in matches] == [202]
    assert [p["pid"] for p in mismatched] == [101]
    # Sanity: their union covers everything _enumerate returned.
    assert {p["pid"] for p in matches} | {p["pid"] for p in mismatched} == {101, 202}


def test_no_processes_means_empty_partitions(ghidra_module, monkeypatch):
    monkeypatch.setattr(ghidra_module, "_enumerate_ghidra_processes", lambda: [])
    target = Path(r"F:\ghidra_NEW_PUBLIC")
    assert ghidra_module._find_matching_ghidra_processes(target) == []
    assert ghidra_module._find_mismatched_ghidra_processes(target) == []


def test_path_match_is_case_insensitive(ghidra_module, monkeypatch):
    """Windows surfaces the drive letter inconsistently (lower from
    some shells, upper from others). Match must be case-insensitive on
    the install path so a `F:` target still detects a `f:` command-line."""
    monkeypatch.setattr(
        ghidra_module,
        "_enumerate_ghidra_processes",
        lambda: [
            # Lower-case drive letter, native backslashes
            _process(
                101,
                r"javaw -cp f:\ghidra_new_public\support\..\Ghidra\Framework\Utility\lib\Utility.jar ghidra.Ghidra ghidra.GhidraRun",
            ),
        ],
    )
    matches = ghidra_module._find_matching_ghidra_processes(
        Path(r"F:\ghidra_NEW_PUBLIC")
    )
    assert len(matches) == 1

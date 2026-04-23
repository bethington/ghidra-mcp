"""
Gradle task registration smoke tests.

These tests invoke the Gradle wrapper (./gradlew) via subprocess to verify
custom tasks are registered and the build configuration is parseable without
requiring GHIDRA_INSTALL_DIR.  They are intentionally slow — deselect with
`-m "not slow"`.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GRADLEW = REPO_ROOT / ("gradlew.bat" if sys.platform == "win32" else "gradlew")


def _run_gradlew(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(GRADLEW), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=None,  # inherit — no GHIDRA_INSTALL_DIR needed for these tasks
    )


@pytest.mark.slow
def test_gradlew_tasks_lists_all_custom_tasks():
    """All custom GhidraMCP tasks must appear in `./gradlew tasks --all`."""
    result = _run_gradlew("tasks", "--all")

    assert result.returncode == 0, (
        f"./gradlew tasks --all failed (rc={result.returncode}):\n{result.stderr}"
    )

    expected = [
        "buildExtension",
        "prepareGhidraClasspath",
        "verifyVersion",
        "preflight",
        "deployExtension",
        "installUserExtension",
        "patchGhidraUserConfig",
        "deploy",
        "startGhidra",
        "cleanAll",
    ]
    missing = [t for t in expected if t not in result.stdout]
    assert not missing, f"Custom Gradle tasks not found in task list: {missing}"


@pytest.mark.slow
def test_gradlew_verify_version_without_ghidra_dir():
    """verifyVersion should succeed without GHIDRA_INSTALL_DIR (prints skip message)."""
    import os

    env = {k: v for k, v in __import__("os").environ.items() if k != "GHIDRA_INSTALL_DIR"}
    result = subprocess.run(
        [str(GRADLEW), "verifyVersion"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )

    assert result.returncode == 0, (
        f"verifyVersion failed without GHIDRA_INSTALL_DIR:\n{result.stdout}\n{result.stderr}"
    )
    combined = result.stdout + result.stderr
    assert "Project version" in combined or "skip" in combined.lower()


@pytest.mark.slow
def test_gradlew_build_extension_dry_run():
    """./gradlew buildExtension --dry-run prints the task plan without building."""
    result = _run_gradlew("buildExtension", "--dry-run", "-PGHIDRA_INSTALL_DIR=nonexistent")

    # --dry-run succeeds (rc=0) even with a bogus GHIDRA_INSTALL_DIR because
    # doLast blocks are skipped; only the task graph is printed.
    assert result.returncode == 0, (
        f"buildExtension --dry-run failed:\n{result.stdout}\n{result.stderr}"
    )
    assert "buildExtension" in result.stdout


@pytest.mark.slow
def test_gradlew_reads_version_from_pom():
    """The build script must parse pom.xml and expose the project version."""
    result = _run_gradlew("properties", "--property", "version")

    assert result.returncode == 0, (
        f"./gradlew properties failed:\n{result.stderr}"
    )
    # pom.xml contains a semver version — verify it's read
    import re
    assert re.search(r"version: \d+\.\d+\.\d+", result.stdout), (
        f"No semver found in 'version' property output:\n{result.stdout}"
    )

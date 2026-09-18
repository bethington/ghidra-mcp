"""
Gradle task registration smoke tests.

These tests invoke the Gradle wrapper (./gradlew) via subprocess to verify
custom tasks are registered and the build configuration is parseable without
requiring GHIDRA_INSTALL_DIR.  They are intentionally slow — deselect with
`-m "not slow"`.
"""
from __future__ import annotations

import re
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
        "stopGhidra",
        "deploy",
        "startGhidra",
        "cleanAll",
    ]
    missing = [t for t in expected if t not in result.stdout]
    assert not missing, f"Custom Gradle tasks not found in task list: {missing}"


@pytest.mark.slow
def test_gradlew_deploy_task_order():
    """`./gradlew deploy --dry-run` must schedule stopGhidra before any
    write-into-Ghidra task, and patchGhidraUserConfig after the extension
    is installed. Without the stop, Windows holds a file lock on
    GhidraMCP-*.jar (install fails) and Ghidra rewrites FrontEndTool.xml
    on exit (config patch silently discarded)."""
    result = _run_gradlew("deploy", "--dry-run", "-PGHIDRA_INSTALL_DIR=nonexistent")
    assert result.returncode == 0, (
        f"deploy --dry-run failed:\n{result.stdout}\n{result.stderr}"
    )
    plan = [
        ln.split()[0].lstrip(":")
        for ln in result.stdout.splitlines()
        if ln.startswith(":")
    ]

    def idx(t):
        assert t in plan, f"task :{t} not in deploy plan: {plan}"
        return plan.index(t)

    assert idx("stopGhidra") < idx("deployExtension")
    assert idx("stopGhidra") < idx("installUserExtension")
    assert idx("stopGhidra") < idx("patchGhidraUserConfig")
    assert idx("installUserExtension") < idx("patchGhidraUserConfig"), (
        "config patch must run AFTER extension is installed"
    )


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


# ---------------------------------------------------------------------------
# Offline: the docs must not name a Gradle task that does not exist.
#
# Gradle became the documented default on 2026-09-18. The hazard that creates
# is a plausible-looking `./gradlew <something>` in a runbook that was never
# run: Gradle answers an unknown task with a hard error, so the cost lands on
# whoever followed the doc, usually mid-release.
#
# These need no Gradle daemon, so they are not marked slow.
# ---------------------------------------------------------------------------

#: Tasks the java/base plugins provide that `build.gradle` does not register.
#: Anything here is genuinely runnable; anything else must be registered.
GRADLE_BUILTIN_TASKS = frozenset(
    {
        "assemble", "build", "check", "classes", "clean", "compileJava",
        "compileTestJava", "dependencies", "help", "jar", "javadoc",
        "processResources", "projects", "properties", "tasks", "test",
        "testClasses", "wrapper",
    }
)

#: Where a `./gradlew` invocation is a operator instruction rather than prose.
_DOCS_WITH_GRADLE_COMMANDS = [
    "CLAUDE.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "README.md",
    "docs/TESTING.md",
    "docs/releases/RELEASE_CHECKLIST.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
]

#: Matches `./gradlew test`, `.\gradlew.bat test` and a bare `gradlew.bat test`,
#: capturing the run of task names that follows (options start with `-` and so
#: terminate the run).
_GRADLEW_INVOCATION = re.compile(r"gradlew(?:\.bat)?\s+((?:[A-Za-z][\w:]*\s*)+)")


def registered_gradle_tasks() -> set[str]:
    """Task names `build.gradle` registers, read from the file itself."""
    text = (REPO_ROOT / "build.gradle").read_text(encoding="utf-8")
    return set(re.findall(r"tasks\.register\(\s*['\"]([A-Za-z][\w]*)['\"]", text))


def test_build_gradle_registers_the_tasks_this_file_expects():
    """Keep the offline task list honest against build.gradle itself."""
    registered = registered_gradle_tasks()
    assert "buildExtension" in registered and "deploy" in registered, (
        f"build.gradle no longer registers the core tasks; parsed: "
        f"{sorted(registered)}"
    )


def test_docs_only_name_gradle_tasks_that_exist():
    """No `./gradlew <task>` in a runbook may name an unregistered task."""
    known = registered_gradle_tasks() | GRADLE_BUILTIN_TASKS
    problems = []
    for rel in _DOCS_WITH_GRADLE_COMMANDS:
        path = REPO_ROOT / rel
        assert path.is_file(), f"{rel} is missing; update _DOCS_WITH_GRADLE_COMMANDS"
        text = path.read_text(encoding="utf-8")
        for match in _GRADLEW_INVOCATION.finditer(text):
            for name in match.group(1).split():
                if name in known:
                    continue
                context = " ".join(
                    text[max(0, match.start() - 40): match.end() + 40].split()
                )
                problems.append(
                    f"{rel}: './gradlew {name}' names a task build.gradle does "
                    f"not register and Gradle does not provide.\n    ...{context}..."
                )
    assert not problems, (
        "The documentation invents a Gradle task. Gradle fails hard on an "
        "unknown task, so this lands on whoever follows the doc:\n"
        + "\n".join(problems)
    )


def test_every_documented_gradle_task_is_reachable_from_at_least_one_doc():
    """A registered task nobody documents is fine; the reverse is not.

    This is the ratchet's other side: it records which tasks the docs actually
    lead a reader to, so deleting a task without touching the docs fails above
    rather than silently.
    """
    documented: set[str] = set()
    for rel in _DOCS_WITH_GRADLE_COMMANDS:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        for match in _GRADLEW_INVOCATION.finditer(text):
            documented.update(match.group(1).split())
    assert {"buildExtension", "test", "preflight", "deploy"} <= documented, (
        f"The runbooks no longer name the core Gradle workflow. Documented: "
        f"{sorted(documented)}"
    )

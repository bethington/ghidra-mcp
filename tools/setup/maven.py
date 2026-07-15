from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


REQUIRED_JAVA_MAJOR = 21


def ensure_maven_java_supported(maven_command: Path) -> bool:
    completed = subprocess.run(
        [str(maven_command), "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    match = re.search(r"(?im)^Java version:\s*(?:1\.)?(\d+)", output)
    if not match or int(match.group(1)) >= REQUIRED_JAVA_MAJOR:
        return True

    print(
        f"Java {REQUIRED_JAVA_MAJOR}+ is required to build ghidra-mcp; "
        f"Maven is running on Java {match.group(1)}.",
        file=sys.stderr,
    )
    print(
        "Set JAVA_HOME to a JDK 21 install and put %JAVA_HOME%\\bin first on PATH.",
        file=sys.stderr,
    )
    return False


# ---------------------------------------------------------------------------
# Gradle
# ---------------------------------------------------------------------------

def candidate_gradle_commands(repo_root: Path) -> list[Path]:
    """Return candidate Gradle executable paths in preference order."""
    candidates: list[Path] = []

    # Gradle wrapper in the repo root is the canonical launcher when present.
    if sys.platform == "win32":
        candidates.append(repo_root / "gradlew.bat")
    else:
        candidates.append(repo_root / "gradlew")

    # System-installed Gradle via GRADLE_HOME.
    gradle_home = os.environ.get("GRADLE_HOME")
    if gradle_home:
        candidates.append(Path(gradle_home) / "bin" / "gradle")
        candidates.append(Path(gradle_home) / "bin" / "gradle.bat")

    # Gradle on PATH.
    for exe in ("gradle", "gradle.bat"):
        resolved = shutil.which(exe)
        if resolved:
            candidates.append(Path(resolved))

    # Common install locations.
    candidates.extend([
        Path("/opt/gradle/bin/gradle"),
        Path("/usr/local/bin/gradle"),
        Path("/usr/share/gradle/bin/gradle"),
    ])

    seen: set[str] = set()
    unique: list[Path] = []
    for c in candidates:
        key = str(c)
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def find_gradle_command(repo_root: Path) -> Path:
    for candidate in candidate_gradle_commands(repo_root):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "Unable to locate Gradle. Add a Gradle wrapper (gradlew) to the repo root, "
        "install Gradle and set GRADLE_HOME, or put 'gradle' on PATH."
    )


def run_gradle(
    repo_root: Path,
    tasks: list[str],
    *,
    ghidra_path: Path | None = None,
    extra_args: list[str] | None = None,
    dry_run: bool = False,
) -> int:
    """Run Gradle tasks against the repo root.

    Passes GHIDRA_INSTALL_DIR as a Gradle project property when ghidra_path is
    provided.  dry_run maps to Gradle's --dry-run flag, which prints the task
    execution plan without executing doLast blocks.
    """
    gradle = find_gradle_command(repo_root)

    command: list[str] = [str(gradle), *tasks]
    if ghidra_path is not None:
        command.append(f"-PGHIDRA_INSTALL_DIR={ghidra_path}")
    if extra_args:
        command.extend(extra_args)
    if dry_run:
        command.append("--dry-run")

    completed = subprocess.run(command, cwd=repo_root, check=False)
    return completed.returncode


# ---------------------------------------------------------------------------
# Maven (kept for rollback; removed in Phase 8)
# ---------------------------------------------------------------------------

def candidate_maven_commands() -> list[Path]:
    candidates: list[Path] = []

    for executable in ("mvn", "mvn.cmd"):
        resolved = shutil.which(executable)
        if resolved:
            candidates.append(Path(resolved))

    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        candidates.append(Path(user_profile) / "tools" / "apache-maven-3.9.6" / "bin" / "mvn.cmd")

    m2_home = os.environ.get("M2_HOME")
    if m2_home:
        if sys.platform == "win32":
            candidates.append(Path(m2_home) / "bin" / "mvn.cmd")
        else:
            candidates.append(Path(m2_home) / "bin" / "mvn")

    candidates.extend(
        [
            Path("/opt/maven/bin/mvn"),
            Path("/usr/local/bin/mvn"),
            Path("/usr/share/maven/bin/mvn"),
        ]
    )

    unique_candidates: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = str(candidate)
        if normalized in seen:
            continue
        seen.add(normalized)
        unique_candidates.append(candidate)

    return unique_candidates


def find_maven_command() -> Path:
    for candidate in candidate_maven_commands():
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(
        "Unable to locate Maven. Install mvn or configure M2_HOME/USERPROFILE tools path."
    )


def run_maven(repo_root: Path, goals: list[str], dry_run: bool = False) -> int:
    maven_command = find_maven_command()
    command = [str(maven_command), *goals]
    if dry_run:
        print("DRY RUN:", " ".join(command))
        return 0
    if not ensure_maven_java_supported(maven_command):
        return 1

    completed = subprocess.run(command, cwd=repo_root, check=False)
    return completed.returncode

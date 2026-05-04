from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


# ---------------------------------------------------------------------------
# Maven
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
        candidates.append(Path(m2_home) / "bin" / "mvn")
        candidates.append(Path(m2_home) / "bin" / "mvn.cmd")

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
    command = [str(find_maven_command()), *goals]
    if dry_run:
        print("DRY RUN:", " ".join(command))
        return 0

    completed = subprocess.run(command, cwd=repo_root, check=False)
    return completed.returncode
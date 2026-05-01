from __future__ import annotations

import sys
from pathlib import Path


def detect_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def candidate_venv_pythons(repo_root: Path) -> list[Path]:
    return [
        repo_root / ".venv" / "Scripts" / "python.exe",
        repo_root / ".venv" / "bin" / "python",
    ]


def find_repo_python(repo_root: Path, explicit_python: Path | None = None) -> Path:
    if explicit_python is not None:
        return explicit_python.resolve()

    for candidate in candidate_venv_pythons(repo_root):
        if candidate.is_file():
            return candidate

    return Path(sys.executable).resolve()

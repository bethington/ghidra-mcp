from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InstallPlan:
    python_executable: Path
    requirements_files: list[Path]
    install_debugger: bool
    debugger_requirements_file: Path


def resolve_requirements_files(repo_root: Path, raw_values: list[str]) -> list[Path]:
    values = raw_values or ["requirements.txt"]
    result: list[Path] = []
    for raw_value in values:
        candidate = (repo_root / raw_value).resolve()
        if not candidate.is_file():
            raise FileNotFoundError(f"Requirements file not found: {raw_value}")
        result.append(candidate)
    return result


def make_install_plan(
    repo_root: Path,
    python_executable: Path,
    requirements_files: list[Path],
    install_debugger: bool,
) -> InstallPlan:
    debugger_requirements_file = (repo_root / "requirements-debugger.txt").resolve()
    if install_debugger and not debugger_requirements_file.is_file():
        raise FileNotFoundError(
            "Requirements file not found: requirements-debugger.txt"
        )

    return InstallPlan(
        python_executable=python_executable,
        requirements_files=requirements_files,
        install_debugger=install_debugger,
        debugger_requirements_file=debugger_requirements_file,
    )


def install_requirements_file(python_executable: Path, requirements_file: Path) -> None:
    subprocess.run(
        [str(python_executable), "-m", "pip", "install", "-r", str(requirements_file)],
        check=True,
    )


def execute_install_plan(plan: InstallPlan) -> None:
    for requirements_file in plan.requirements_files:
        install_requirements_file(plan.python_executable, requirements_file)

    if plan.install_debugger:
        install_requirements_file(
            plan.python_executable, plan.debugger_requirements_file
        )

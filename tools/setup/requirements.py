from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


# Cache the resolved pip invocation per python_executable so we don't probe
# twice. Some environments (nix, certain Linux distros) install pip as a
# standalone executable but don't expose it as a module; others (Windows
# venvs, most Mac setups) only have python -m pip. Probing once per process
# lets us route to whichever works without forcing one or the other on users.
# See #190.
_PIP_COMMAND_CACHE: dict[str, list[str]] = {}


def pip_command(python_executable: Path) -> list[str]:
    """Return a command-list prefix that invokes pip for the given Python.

    Prefers ``python -m pip`` (consistent with the active interpreter's
    site-packages), falls back to a bare ``pip`` if the module path isn't
    available — this is the nix-style environment where pip ships as an
    executable but the python interpreter can't import it. Raises if neither
    form works.
    """
    key = str(python_executable)
    cached = _PIP_COMMAND_CACHE.get(key)
    if cached is not None:
        return list(cached)

    # First try: python -m pip
    module_form = [str(python_executable), "-m", "pip"]
    probe = subprocess.run(
        module_form + ["--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode == 0:
        _PIP_COMMAND_CACHE[key] = module_form
        return list(module_form)

    # Fallback: bare pip on PATH
    bare = shutil.which("pip")
    if bare:
        probe = subprocess.run(
            [bare, "--version"], capture_output=True, text=True, check=False,
        )
        if probe.returncode == 0:
            bare_form = [bare]
            _PIP_COMMAND_CACHE[key] = bare_form
            return list(bare_form)

    raise FileNotFoundError(
        f"pip is not available for {python_executable} — neither "
        f"`{python_executable} -m pip` nor a bare `pip` on PATH responded "
        "to --version. Install pip into the active Python environment."
    )


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
        pip_command(python_executable) + ["install", "-r", str(requirements_file)],
        check=True,
    )


def execute_install_plan(plan: InstallPlan) -> None:
    for requirements_file in plan.requirements_files:
        install_requirements_file(plan.python_executable, requirements_file)

    if plan.install_debugger:
        install_requirements_file(
            plan.python_executable, plan.debugger_requirements_file
        )

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


def uv_executable() -> str:
    """Locate the ``uv`` executable, falling back to the bare name on PATH.

    The whole project's Python dependencies are managed through uv + the root
    ``pyproject.toml`` / ``uv.lock`` (PEP 735 dependency groups). Setup commands
    install them with ``uv sync`` rather than ``pip install -r requirements*.txt``.
    """
    return shutil.which("uv") or "uv"


def ensure_uv_available() -> str:
    """Return the uv executable, raising FileNotFoundError if it can't run."""
    uv = uv_executable()
    try:
        probe = subprocess.run(
            [uv, "--version"], capture_output=True, text=True, check=False
        )
    except OSError as exc:
        # uv isn't on PATH / isn't executable — subprocess.run raises before we
        # ever see a returncode. Funnel it through the same actionable message.
        raise FileNotFoundError(
            "uv is not available — `uv --version` could not be run. Install uv: "
            "https://docs.astral.sh/uv/getting-started/installation/"
        ) from exc
    if probe.returncode != 0:
        raise FileNotFoundError(
            "uv is not available — `uv --version` did not respond. Install uv: "
            "https://docs.astral.sh/uv/getting-started/installation/"
        )
    return uv


@dataclass(frozen=True)
class InstallPlan:
    """Describes a ``uv sync`` invocation for the repo's dependency groups."""

    repo_root: Path
    groups: tuple[str, ...]
    install_debugger: bool


def make_install_plan(
    repo_root: Path,
    install_debugger: bool,
    base_groups: tuple[str, ...] = ("dev",),
) -> InstallPlan:
    """Build the dependency-group install plan.

    The ``dev`` group (which includes ``test``) is always synced; the optional
    ``debugger`` group is added when requested (Windows debugger backend).
    """
    groups = list(base_groups)
    if install_debugger and "debugger" not in groups:
        groups.append("debugger")
    return InstallPlan(
        repo_root=repo_root,
        groups=tuple(groups),
        install_debugger=install_debugger,
    )


def uv_sync_command(plan: InstallPlan) -> list[str]:
    """Return the ``uv sync`` command-list for the given plan."""
    cmd = [uv_executable(), "sync"]
    for group in plan.groups:
        cmd += ["--group", group]
    return cmd


def execute_install_plan(plan: InstallPlan) -> None:
    """Run ``uv sync`` for the plan's dependency groups.

    Validate uv at the point of execution so every install path raises the same
    actionable :func:`ensure_uv_available` message instead of a raw
    ``OSError``/``CalledProcessError`` — callers must not have to remember to
    pre-check.
    """
    ensure_uv_available()
    subprocess.run(uv_sync_command(plan), check=True, cwd=str(plan.repo_root))

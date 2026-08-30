"""
Unit tests for tools.setup.cli — backend dispatch, subcommand routing, helpers.

All tests run without a live Ghidra server or Maven/Gradle installation.
Subprocess-calling functions are stubbed via monkeypatch.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _args(**kwargs) -> argparse.Namespace:
    defaults = dict(
        dry_run=False,
        ghidra_path=None,
        strict=False,
        use_debugger_toggle=False,
        with_debugger=False,
        force=False,
        test=[],
        env_file=None,
        new=None,
        old=None,
        tag=False,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ===========================================================================
# _get_backend
# ===========================================================================


def test_get_backend_defaults_to_maven(monkeypatch):
    monkeypatch.delenv("TOOLS_SETUP_BACKEND", raising=False)
    from tools.setup import cli

    assert cli._get_backend() == "maven"


def test_get_backend_gradle_when_env_set(monkeypatch):
    monkeypatch.setenv("TOOLS_SETUP_BACKEND", "gradle")
    from tools.setup import cli

    assert cli._get_backend() == "gradle"


def test_get_backend_case_insensitive(monkeypatch):
    monkeypatch.setenv("TOOLS_SETUP_BACKEND", "GRADLE")
    from tools.setup import cli

    assert cli._get_backend() == "gradle"


# ===========================================================================
# cmd_build
# ===========================================================================


def test_cmd_build_uses_skiptests_for_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("C:/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_maven",
        lambda root, goals, dry_run=False: recorded.update({"goals": goals}) or 0,
    )

    result = cli.cmd_build(_args())

    assert result == 0
    assert recorded["goals"] == ["clean", "package", "assembly:single", "-DskipTests"]


def test_cmd_build_routes_to_gradle(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_gradle",
        lambda root, tasks, **kw: recorded.update({"tasks": tasks}) or 0,
    )

    result = cli.cmd_build(_args())

    assert result == 0
    assert recorded["tasks"] == ["buildExtension"]


def test_cmd_build_dry_run_passed_to_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_maven",
        lambda root, goals, dry_run=False: recorded.update({"dry_run": dry_run}) or 0,
    )

    cli.cmd_build(_args(dry_run=True))
    assert recorded["dry_run"] is True


# ===========================================================================
# cmd_clean
# ===========================================================================


def test_cmd_clean_routes_to_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_maven",
        lambda root, goals, dry_run=False: recorded.update({"goals": goals}) or 0,
    )

    cli.cmd_clean(_args())
    assert recorded["goals"] == ["clean"]


def test_cmd_clean_routes_to_gradle(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_gradle",
        lambda root, tasks, **kw: recorded.update({"tasks": tasks}) or 0,
    )

    cli.cmd_clean(_args())
    assert recorded["tasks"] == ["clean"]


# ===========================================================================
# cmd_run_tests
# ===========================================================================


def test_cmd_run_tests_routes_to_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_maven",
        lambda root, goals, dry_run=False: recorded.update({"goals": goals}) or 0,
    )

    cli.cmd_run_tests(_args())
    assert recorded["goals"] == ["test"]


def test_cmd_run_tests_routes_to_gradle(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_gradle",
        lambda root, tasks, **kw: recorded.update({"tasks": tasks}) or 0,
    )

    cli.cmd_run_tests(_args())
    assert recorded["tasks"] == ["test"]


# ===========================================================================
# cmd_deploy
# ===========================================================================


def test_cmd_deploy_routes_to_gradle(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_gradle",
        lambda root, tasks, **kw: recorded.update({"tasks": tasks, **kw}) or 0,
    )

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_deploy(_args(ghidra_path=ghidra_path))

    assert result == 0
    assert recorded["tasks"] == ["deploy"]
    assert recorded.get("ghidra_path") == ghidra_path.resolve()


def test_cmd_deploy_routes_to_maven(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    called = []
    monkeypatch.setattr(
        cli,
        "deploy_to_ghidra",
        lambda root, path, dry_run=False, test_modes=None: called.append(
            (path, test_modes)
        )
        or 0,
    )

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_deploy(_args(ghidra_path=ghidra_path))

    assert result == 0
    assert called
    assert called[0][1] == []


def test_deploy_parser_accepts_release_test_tier():
    from tools.setup import cli

    parser = cli.build_parser()
    args = parser.parse_args(["deploy", "--ghidra-path", "C:/ghidra", "--test", "release"])

    assert args.test == ["release"]


def test_cmd_deploy_raises_when_no_ghidra_path(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    with pytest.raises(ValueError, match="Ghidra path is required"):
        cli.cmd_deploy(_args(ghidra_path=None))


# ===========================================================================
# cmd_start_ghidra
# ===========================================================================


def test_cmd_start_ghidra_routes_to_gradle(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_gradle",
        lambda root, tasks, **kw: recorded.update({"tasks": tasks}) or 0,
    )

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_start_ghidra(_args(ghidra_path=ghidra_path))

    assert result == 0
    assert recorded["tasks"] == ["startGhidra"]


def test_cmd_start_ghidra_routes_to_maven(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    called = []
    monkeypatch.setattr(
        cli, "start_ghidra", lambda path, dry_run=False: called.append(path) or 0
    )

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_start_ghidra(_args(ghidra_path=ghidra_path))

    assert result == 0
    assert called


def test_cmd_start_ghidra_requires_ghidra_path(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    with pytest.raises(ValueError, match="Ghidra path is required"):
        cli.cmd_start_ghidra(_args(ghidra_path=None))


# ===========================================================================
# cmd_clean_all
# ===========================================================================


def test_cmd_clean_all_routes_to_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")

    called = []
    monkeypatch.setattr(
        cli, "clean_all", lambda root, dry_run=False: called.append(root) or 0
    )

    cli.cmd_clean_all(_args())
    assert called


def test_cmd_clean_all_routes_to_gradle(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_gradle",
        lambda root, tasks, **kw: recorded.update({"tasks": tasks}) or 0,
    )

    cli.cmd_clean_all(_args())
    assert recorded["tasks"] == ["cleanAll"]


# ===========================================================================
# cmd_install_ghidra_deps
# ===========================================================================


def test_cmd_install_ghidra_deps_routes_to_maven(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    called = []
    monkeypatch.setattr(
        cli,
        "install_ghidra_dependencies",
        lambda root, path, force=False, dry_run=False: called.append(path) or 0,
    )

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    cli.cmd_install_ghidra_deps(_args(ghidra_path=ghidra_path))
    assert called


def test_cmd_install_ghidra_deps_routes_to_gradle(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_gradle",
        lambda root, tasks, **kw: recorded.update({"tasks": tasks}) or 0,
    )

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    cli.cmd_install_ghidra_deps(_args(ghidra_path=ghidra_path))
    assert recorded["tasks"] == ["prepareGhidraClasspath"]


# ===========================================================================
# cmd_verify_version
# ===========================================================================


def test_cmd_verify_version_maven_no_ghidra_path(tmp_path, monkeypatch, capsys):
    from tools.setup import cli
    from tools.setup.versioning import VersionInfo

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(
        cli, "read_pom_versions", lambda root: VersionInfo("5.4.1", "12.1")
    )

    result = cli.cmd_verify_version(_args(ghidra_path=None))

    assert result == 0
    out = capsys.readouterr().out
    assert "5.4.1" in out
    assert "12.1" in out


def test_cmd_verify_version_maven_versions_match(tmp_path, monkeypatch):
    from tools.setup import cli
    from tools.setup.versioning import VersionInfo

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(
        cli, "read_pom_versions", lambda root: VersionInfo("5.4.1", "12.1")
    )
    monkeypatch.setattr(cli, "infer_ghidra_version_from_path", lambda path: "12.1")

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_verify_version(_args(ghidra_path=ghidra_path))

    assert result == 0


def test_cmd_verify_version_maven_version_mismatch(tmp_path, monkeypatch):
    from tools.setup import cli
    from tools.setup.versioning import VersionInfo

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(
        cli, "read_pom_versions", lambda root: VersionInfo("5.4.1", "12.1")
    )
    monkeypatch.setattr(cli, "infer_ghidra_version_from_path", lambda path: "11.0.0")

    ghidra_path = tmp_path / "ghidra_11.0.0_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_verify_version(_args(ghidra_path=ghidra_path))

    assert result == 1


def test_cmd_verify_version_maven_uninferrable_path(tmp_path, monkeypatch):
    from tools.setup import cli
    from tools.setup.versioning import VersionInfo

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(
        cli, "read_pom_versions", lambda root: VersionInfo("5.4.1", "12.1")
    )
    monkeypatch.setattr(cli, "infer_ghidra_version_from_path", lambda path: None)

    ghidra_path = tmp_path / "custom-ghidra-dir"
    ghidra_path.mkdir()
    result = cli.cmd_verify_version(_args(ghidra_path=ghidra_path))

    assert result == 1


def test_cmd_verify_version_routes_to_gradle(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_gradle",
        lambda root, tasks, **kw: recorded.update({"tasks": tasks}) or 0,
    )

    result = cli.cmd_verify_version(_args())
    assert result == 0
    assert recorded["tasks"] == ["verifyVersion"]


# ===========================================================================
# cmd_bump_version
# ===========================================================================


def test_cmd_bump_version_calls_apply_version_bump(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "apply_version_bump",
        lambda root, new, old_version=None, dry_run=False, tag=False: recorded.update(
            {"new": new, "old_version": old_version, "dry_run": dry_run, "tag": tag}
        )
        or 0,
    )

    result = cli.cmd_bump_version(
        _args(new="5.5.0", old=None, dry_run=False, tag=False)
    )

    assert result == 0
    assert recorded["new"] == "5.5.0"
    assert recorded["old_version"] is None
    assert recorded["dry_run"] is False
    assert recorded["tag"] is False


def test_cmd_bump_version_passes_old_version(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "apply_version_bump",
        lambda root, new, old_version=None, dry_run=False, tag=False: recorded.update(
            {"old_version": old_version}
        )
        or 0,
    )

    cli.cmd_bump_version(_args(new="5.5.0", old="5.4.0"))
    assert recorded["old_version"] == "5.4.0"


def test_cmd_bump_version_passes_dry_run_and_tag(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "apply_version_bump",
        lambda root, new, old_version=None, dry_run=False, tag=False: recorded.update(
            {"dry_run": dry_run, "tag": tag}
        )
        or 0,
    )

    cli.cmd_bump_version(_args(new="5.5.0", old=None, dry_run=True, tag=True))
    assert recorded["dry_run"] is True
    assert recorded["tag"] is True


# ===========================================================================
# _resolve_ghidra_path / _require_ghidra_path
# ===========================================================================


def test_resolve_ghidra_path_prefers_arg(tmp_path, monkeypatch):
    from tools.setup import cli

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    other_path = tmp_path / "other"
    monkeypatch.setattr(
        cli, "_load_repo_env", lambda root: {"GHIDRA_PATH": str(other_path)}
    )

    resolved = cli._resolve_ghidra_path(tmp_path, ghidra_path)
    assert resolved == ghidra_path.resolve()


def test_resolve_ghidra_path_from_env(tmp_path, monkeypatch):
    from tools.setup import cli

    env_path = tmp_path / "ghidra_12.1_PUBLIC"
    env_path.mkdir()
    monkeypatch.setattr(
        cli, "_load_repo_env", lambda root: {"GHIDRA_PATH": str(env_path)}
    )

    resolved = cli._resolve_ghidra_path(tmp_path, None)
    assert resolved == env_path


def test_resolve_ghidra_path_returns_none_when_missing(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    resolved = cli._resolve_ghidra_path(tmp_path, None)
    assert resolved is None


def test_require_ghidra_path_raises_when_missing(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    with pytest.raises(ValueError, match="Ghidra path is required"):
        cli._require_ghidra_path(tmp_path, None)


def test_require_ghidra_path_returns_path_when_set(tmp_path, monkeypatch):
    from tools.setup import cli

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})

    result = cli._require_ghidra_path(tmp_path, ghidra_path)
    assert result == ghidra_path.resolve()


# ===========================================================================
# _should_install_debugger
# ===========================================================================


def test_should_install_debugger_with_flag():
    from tools.setup import cli

    assert (
        cli._should_install_debugger(
            {}, _args(with_debugger=True, use_debugger_toggle=False)
        )
        is True
    )


def test_should_install_debugger_from_env_toggle():
    from tools.setup import cli

    assert (
        cli._should_install_debugger(
            {"INSTALL_DEBUGGER_DEPS": "true"},
            _args(with_debugger=False, use_debugger_toggle=True),
        )
        is True
    )


def test_should_install_debugger_env_disabled():
    from tools.setup import cli

    assert (
        cli._should_install_debugger(
            {"INSTALL_DEBUGGER_DEPS": "false"},
            _args(with_debugger=False, use_debugger_toggle=True),
        )
        is False
    )


def test_should_install_debugger_toggle_off():
    from tools.setup import cli

    # INSTALL_DEBUGGER_DEPS=true in env, but toggle not passed — should NOT install
    assert (
        cli._should_install_debugger(
            {"INSTALL_DEBUGGER_DEPS": "true"},
            _args(with_debugger=False, use_debugger_toggle=False),
        )
        is False
    )


# ===========================================================================
# cmd_preflight — Maven backend
# ===========================================================================


def test_cmd_preflight_maven_missing_maven_returns_1(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "find_repo_python", lambda root: Path("python"))

    def raise_not_found():
        raise FileNotFoundError("Maven not found on PATH")

    monkeypatch.setattr(cli, "find_maven_command", raise_not_found)

    result = cli.cmd_preflight(_args())
    assert result == 1


def test_cmd_preflight_maven_missing_java_returns_1(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "find_repo_python", lambda root: Path("python"))
    monkeypatch.setattr(cli, "find_maven_command", lambda: Path("/usr/bin/mvn"))
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    )
    monkeypatch.setattr(cli, "shutil", SimpleNamespace(which=lambda name: None))

    result = cli.cmd_preflight(_args())
    assert result == 1


def test_cmd_preflight_maven_passes_without_ghidra_path(tmp_path, monkeypatch):
    from tools.setup import cli
    from tools.setup.versioning import VersionInfo

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "find_repo_python", lambda root: Path("python"))
    monkeypatch.setattr(cli, "find_maven_command", lambda: Path("/usr/bin/mvn"))
    monkeypatch.setattr(
        cli, "read_pom_versions", lambda root: VersionInfo("5.4.1", "12.1")
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    )
    # Patch the module reference on ``cli`` rather than mutating the shared
    # ``shutil`` module: tools.setup.spawn calls shutil.which too, and a
    # module-level patch would silently answer for it as well.
    monkeypatch.setattr(
        cli,
        "shutil",
        SimpleNamespace(which=lambda name: "/usr/bin/java" if name == "java" else None),
    )

    result = cli.cmd_preflight(_args(ghidra_path=None))
    assert result == 0


def test_cmd_preflight_gradle_routes_to_run_gradle(tmp_path, monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "find_repo_python", lambda root: Path("python"))
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    )

    recorded: dict = {}
    monkeypatch.setattr(
        cli,
        "run_gradle",
        lambda root, tasks, **kw: recorded.update({"tasks": tasks}) or 0,
    )

    result = cli.cmd_preflight(_args())
    assert result == 0
    assert recorded["tasks"] == ["preflight"]


# ===========================================================================
# cmd_ensure_prereqs — dry run
# ===========================================================================


def test_cmd_ensure_prereqs_dry_run_prints_plan(tmp_path, monkeypatch, capsys):
    from tools.setup import cli
    from tools.setup.requirements import InstallPlan

    fake_plan = InstallPlan(
        repo_root=tmp_path,
        groups=("dev",),
        install_debugger=False,
    )

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "make_install_plan", lambda *a, **kw: fake_plan)
    monkeypatch.setattr(cli, "execute_install_plan", lambda plan: None)
    monkeypatch.setattr(cli, "run_gradle", lambda root, tasks, **kw: 0)

    ghidra_path = tmp_path / "ghidra_12.1_PUBLIC"
    ghidra_path.mkdir()
    result = cli.cmd_ensure_prereqs(_args(ghidra_path=ghidra_path, dry_run=True))

    assert result == 0
    assert "DRY RUN" in capsys.readouterr().out


# ===========================================================================
# argparse
# ===========================================================================


def test_parser_bump_version_requires_new_arg():
    from tools.setup.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["bump-version"])
    assert exc_info.value.code != 0


def test_parser_build_subcommand_recognized():
    from tools.setup.cli import build_parser

    args = build_parser().parse_args(["build"])
    assert args.command == "build"


def test_parser_deploy_subcommand_recognized():
    from tools.setup.cli import build_parser

    args = build_parser().parse_args(["deploy"])
    assert args.command == "deploy"


def test_parser_install_python_deps_rejects_obsolete_flags():
    # --requirements / --python were vestiges of the old pip flow; uv sync
    # ignored their values, so they're removed rather than left to silently
    # mask misconfigured automation.
    from tools.setup.cli import build_parser

    parser = build_parser()
    for flag, value in (("--requirements", "requirements.txt"), ("--python", "python3")):
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["install-python-deps", flag, value])
        assert exc_info.value.code != 0


def test_parser_install_python_deps_accepts_supported_flags():
    from tools.setup.cli import build_parser

    args = build_parser().parse_args(
        ["install-python-deps", "--with-debugger", "--env-file", ".env.local"]
    )
    assert args.command == "install-python-deps"
    assert args.with_debugger is True
    assert args.env_file == Path(".env.local")


def test_parser_bump_version_parses_new_flag():
    from tools.setup.cli import build_parser

    args = build_parser().parse_args(["bump-version", "--new", "5.5.0"])
    assert args.new == "5.5.0"
    assert args.old is None
    assert args.tag is False
    assert args.dry_run is False


def test_parser_bump_version_parses_all_flags():
    from tools.setup.cli import build_parser

    args = build_parser().parse_args(
        ["bump-version", "--new", "5.5.0", "--old", "5.4.1", "--tag", "--dry-run"]
    )
    assert args.new == "5.5.0"
    assert args.old == "5.4.1"
    assert args.tag is True
    assert args.dry_run is True


# ===========================================================================
# main() integration
# ===========================================================================


def test_main_build_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "run_maven", lambda root, goals, dry_run=False: 0)

    assert cli.main(["build"]) == 0


def test_main_clean_gradle(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")
    monkeypatch.setattr(cli, "run_gradle", lambda root, tasks, **kw: 0)

    assert cli.main(["clean"]) == 0


def test_main_run_tests_maven(monkeypatch):
    from tools.setup import cli

    monkeypatch.setattr(cli, "detect_repo_root", lambda: Path("/repo"))
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "run_maven", lambda root, goals, dry_run=False: 0)

    assert cli.main(["run-tests"]) == 0


# ===========================================================================
# tools.setup.spawn — MCP client launcher resolution (issue #441)
#
# An MCP client launched from a systemd user service or a GUI session inherits
# that launcher's PATH, which routinely lacks ~/.local/bin, so the documented
# "command": "uv" dies with `spawn uv ENOENT` before any bridge code runs.
# Every test below drives a monkeypatched PATH, so the result never depends on
# what happens to be installed on the machine running the suite.
# ===========================================================================


def _make_launcher(directory: Path, name: str) -> Path:
    """Create a file shutil.which will accept as an executable on this OS."""
    if os.name == "nt":
        target = directory / f"{name}.EXE"
        target.write_text("")
    else:
        target = directory / name
        target.write_text("#!/bin/sh\n")
        target.chmod(0o755)
    return target


@pytest.fixture
def isolated_path(tmp_path, monkeypatch):
    """A PATH containing exactly one directory we control."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", str(bin_dir))
    if os.name == "nt":
        monkeypatch.setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
    return bin_dir


def test_resolve_spawn_command_found_returns_absolute_path(isolated_path):
    from tools.setup import spawn

    launcher = _make_launcher(isolated_path, "uv")

    resolution = spawn.resolve_spawn_command("uv")

    assert resolution.found is True
    assert Path(resolution.path) == launcher
    assert Path(resolution.path).is_absolute()
    assert resolution.searched == (str(isolated_path),)


def test_resolve_spawn_command_not_found_records_searched_path(isolated_path):
    from tools.setup import spawn

    resolution = spawn.resolve_spawn_command("uv")

    assert resolution.found is False
    assert resolution.path is None
    assert resolution.searched == (str(isolated_path),)


def test_search_path_entries_drops_blanks_and_duplicates(monkeypatch):
    from tools.setup import spawn

    sep = os.pathsep
    monkeypatch.setenv("PATH", sep.join(["/a", "", "/b", "/a", " /c "]))

    assert spawn.search_path_entries() == ("/a", "/b", "/c")


def test_report_prints_every_searched_path_entry_when_not_found(
    tmp_path, monkeypatch, capsys
):
    """The whole point of issue #441: say which PATH was actually walked."""
    from tools.setup import spawn

    first = tmp_path / "one"
    second = tmp_path / "two"
    third = tmp_path / "three"
    for directory in (first, second, third):
        directory.mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join(str(d) for d in (first, second, third)))
    if os.name == "nt":
        monkeypatch.setenv("PATHEXT", ".COM;.EXE")

    spawn.report_spawn_commands(tmp_path, names=("uv",))

    out = capsys.readouterr().out
    assert "NOT FOUND on this PATH" in out
    assert "PATH searched (3 entries):" in out
    # every entry, one per line, in order
    printed = [line.strip() for line in out.splitlines()]
    for directory in (first, second, third):
        assert str(directory) in printed
    assert "https://docs.astral.sh/uv/getting-started/installation/" in out


def test_report_names_the_empty_path_rather_than_printing_nothing(
    tmp_path, monkeypatch, capsys
):
    from tools.setup import spawn

    monkeypatch.setenv("PATH", "")

    spawn.report_spawn_commands(tmp_path, names=("uv",))

    out = capsys.readouterr().out
    assert "PATH searched (0 entries):" in out
    assert "PATH is empty" in out


def test_report_admits_it_cannot_speak_for_the_client_environment(
    tmp_path, isolated_path, capsys
):
    """A pass here is evidence, not proof — the report must never imply proof."""
    from tools.setup import spawn

    _make_launcher(isolated_path, "uv")

    spawn.report_spawn_commands(tmp_path, names=("uv",))

    out = capsys.readouterr().out
    assert "does NOT prove" in out
    assert "systemd user service" in out
    assert "issue #441" in out


def test_report_emits_a_pasteable_config_with_an_absolute_command(
    tmp_path, isolated_path, capsys
):
    from tools.setup import spawn

    launcher = _make_launcher(isolated_path, "uv")

    spawn.report_spawn_commands(tmp_path, names=("uv",))

    out = capsys.readouterr().out
    snippet = out[out.index("{") :]
    parsed = json.loads(snippet[: snippet.rindex("}") + 1])
    command = parsed["mcpServers"]["ghidra-mcp"]["command"]
    assert Path(command) == launcher
    assert Path(command).is_absolute()
    assert str(tmp_path) in parsed["mcpServers"]["ghidra-mcp"]["args"]


def test_config_snippet_falls_back_to_a_marked_placeholder(tmp_path, isolated_path):
    from tools.setup import spawn

    resolutions = spawn.resolve_spawn_commands()
    assert all(not r.found for r in resolutions)

    parsed = json.loads(spawn.client_config_snippet(resolutions, tmp_path))
    assert parsed["mcpServers"]["ghidra-mcp"]["command"] == "/absolute/path/to/uv"


def test_missing_console_script_is_reported_but_not_alarming(
    tmp_path, isolated_path, capsys
):
    """`uv run` never installs the console script; its absence is not a fault."""
    from tools.setup import spawn

    _make_launcher(isolated_path, "uv")

    resolutions = spawn.report_spawn_commands(tmp_path)

    out = capsys.readouterr().out
    assert "bridge-mcp-ghidra -> not on PATH" in out
    assert "optional" in out
    # The optional launcher must not drag the whole PATH listing into every run.
    assert out.count("PATH searched") == 0
    assert [r.name for r in resolutions] == ["uv", "bridge-mcp-ghidra"]


def test_cmd_preflight_maven_reports_spawn_commands(tmp_path, monkeypatch, capsys):
    """The check is wired into preflight, not merely importable."""
    from tools.setup import cli
    from tools.setup.versioning import VersionInfo

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "find_repo_python", lambda root: Path("python"))
    monkeypatch.setattr(cli, "find_maven_command", lambda: Path("/usr/bin/mvn"))
    monkeypatch.setattr(
        cli, "read_pom_versions", lambda root: VersionInfo("7.0.0", "12.1")
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
    )
    # Patch the module reference on ``cli`` rather than mutating the shared
    # ``shutil`` module: tools.setup.spawn calls shutil.which too, and a
    # module-level patch would silently answer for it as well.
    monkeypatch.setattr(
        cli,
        "shutil",
        SimpleNamespace(which=lambda name: "/usr/bin/java" if name == "java" else None),
    )
    monkeypatch.setenv("PATH", str(tmp_path))

    assert cli.cmd_preflight(_args(ghidra_path=None)) == 0

    out = capsys.readouterr().out
    assert "MCP client spawn commands:" in out
    assert "does NOT prove" in out


def test_cmd_preflight_does_not_fail_when_launchers_are_missing(
    tmp_path, monkeypatch, capsys
):
    """Advisory only — a missing launcher must not red-line preflight by itself."""
    from tools.setup import cli
    from tools.setup.versioning import VersionInfo

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "find_repo_python", lambda root: Path("python"))
    monkeypatch.setattr(cli, "find_maven_command", lambda: Path("/usr/bin/mvn"))
    monkeypatch.setattr(
        cli, "read_pom_versions", lambda root: VersionInfo("7.0.0", "12.1")
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
    )
    # Patch the module reference on ``cli`` rather than mutating the shared
    # ``shutil`` module: tools.setup.spawn calls shutil.which too, and a
    # module-level patch would silently answer for it as well.
    monkeypatch.setattr(
        cli,
        "shutil",
        SimpleNamespace(which=lambda name: "/usr/bin/java" if name == "java" else None),
    )
    monkeypatch.setenv("PATH", "")

    assert cli.cmd_preflight(_args(ghidra_path=None)) == 0
    assert "NOT FOUND on this PATH" in capsys.readouterr().out

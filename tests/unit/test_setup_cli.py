"""
Unit tests for tools.setup.cli — backend dispatch, subcommand routing, helpers.

All tests run without a live Ghidra server or Maven/Gradle installation.
Subprocess-calling functions are stubbed via monkeypatch.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

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
        requirements=[],
        python=None,
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

    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
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

    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
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

    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
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

    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
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

    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
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

    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
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
        cli, "read_pom_versions", lambda root: VersionInfo("5.4.1", "12.0.4")
    )

    result = cli.cmd_verify_version(_args(ghidra_path=None))

    assert result == 0
    out = capsys.readouterr().out
    assert "5.4.1" in out
    assert "12.0.4" in out


def test_cmd_verify_version_maven_versions_match(tmp_path, monkeypatch):
    from tools.setup import cli
    from tools.setup.versioning import VersionInfo

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "maven")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(
        cli, "read_pom_versions", lambda root: VersionInfo("5.4.1", "12.0.4")
    )
    monkeypatch.setattr(cli, "infer_ghidra_version_from_path", lambda path: "12.0.4")

    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
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
        cli, "read_pom_versions", lambda root: VersionInfo("5.4.1", "12.0.4")
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
        cli, "read_pom_versions", lambda root: VersionInfo("5.4.1", "12.0.4")
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

    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
    ghidra_path.mkdir()
    other_path = tmp_path / "other"
    monkeypatch.setattr(
        cli, "_load_repo_env", lambda root: {"GHIDRA_PATH": str(other_path)}
    )

    resolved = cli._resolve_ghidra_path(tmp_path, ghidra_path)
    assert resolved == ghidra_path.resolve()


def test_resolve_ghidra_path_from_env(tmp_path, monkeypatch):
    from tools.setup import cli

    env_path = tmp_path / "ghidra_12.0.4_PUBLIC"
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

    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
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
        subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0})()
    )
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)

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
        cli, "read_pom_versions", lambda root: VersionInfo("5.4.1", "12.0.4")
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0})()
    )
    monkeypatch.setattr(
        cli.shutil, "which", lambda name: "/usr/bin/java" if name == "java" else None
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
        subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0})()
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

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests\n")

    fake_plan = InstallPlan(
        python_executable=Path("python"),
        requirements_files=[req_file],
        install_debugger=False,
        debugger_requirements_file=tmp_path / "requirements-debugger.txt",
    )

    monkeypatch.setattr(cli, "detect_repo_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_get_backend", lambda: "gradle")
    monkeypatch.setattr(cli, "_load_repo_env", lambda root: {})
    monkeypatch.setattr(cli, "find_repo_python", lambda root: Path("python"))
    monkeypatch.setattr(cli, "resolve_requirements_files", lambda root, raw: [req_file])
    monkeypatch.setattr(cli, "make_install_plan", lambda *a, **kw: fake_plan)
    monkeypatch.setattr(cli, "execute_install_plan", lambda plan: None)
    monkeypatch.setattr(cli, "run_gradle", lambda root, tasks, **kw: 0)

    ghidra_path = tmp_path / "ghidra_12.0.4_PUBLIC"
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

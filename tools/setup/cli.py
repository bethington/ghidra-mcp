from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .envfile import get_env_flag, load_env_file
from .ghidra import (
    clean_all,
    collect_preflight_issues,
    deploy_to_ghidra,
    install_ghidra_dependencies,
    start_ghidra,
)
from .python_env import detect_repo_root, find_repo_python
from .maven import find_maven_command, run_gradle, run_maven
from .requirements import (
    execute_install_plan,
    make_install_plan,
    resolve_requirements_files,
)
from .version_bump import apply_version_bump
from .versioning import infer_ghidra_version_from_path, read_pom_versions


def _get_backend() -> str:
    """Return the active build backend.

    Set TOOLS_SETUP_BACKEND=gradle to use Gradle.  Maven is the default.
    """
    return os.environ.get("TOOLS_SETUP_BACKEND", "maven").lower()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cross-platform repo setup helpers")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser(
        "install-python-deps",
        help="Install one or more Python requirements files",
    )
    install_parser.add_argument(
        "--requirements",
        action="append",
        default=[],
        help="Requirements file relative to the repo root. May be passed multiple times.",
    )
    install_parser.add_argument(
        "--use-debugger-toggle",
        action="store_true",
        help="Read INSTALL_DEBUGGER_DEPS from .env and install debugger requirements when enabled.",
    )
    install_parser.add_argument(
        "--with-debugger",
        action="store_true",
        help="Force-install debugger requirements regardless of .env.",
    )
    install_parser.add_argument(
        "--python",
        type=Path,
        help="Interpreter to use for pip installs. Defaults to the repo venv when present.",
    )
    install_parser.add_argument(
        "--env-file",
        type=Path,
        help="Path to an env file. Defaults to .env in the repo root.",
    )
    install_parser.set_defaults(func=cmd_install_python_deps)

    verify_parser = subparsers.add_parser(
        "verify-version",
        help="Verify repo and optional Ghidra installation version consistency",
    )
    verify_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    verify_parser.set_defaults(func=cmd_verify_version)

    preflight_parser = subparsers.add_parser(
        "preflight",
        help="Check Python, build-tool, and optional Ghidra path availability",
    )
    preflight_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    preflight_parser.add_argument(
        "--strict",
        action="store_true",
        help="Also check network reachability for Maven Central and PyPI (Maven backend only).",
    )
    preflight_parser.add_argument(
        "--use-debugger-toggle",
        action="store_true",
        help="Read INSTALL_DEBUGGER_DEPS from .env and validate debugger requirements when enabled.",
    )
    preflight_parser.add_argument(
        "--with-debugger",
        action="store_true",
        help="Force debugger requirement validation regardless of .env.",
    )
    preflight_parser.set_defaults(func=cmd_preflight)

    build_parser = subparsers.add_parser(
        "build",
        help="Build the plugin jar and extension ZIP",
    )
    build_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the build command without running it.",
    )
    build_parser.set_defaults(func=cmd_build)

    clean_parser = subparsers.add_parser(
        "clean",
        help="Remove build outputs",
    )
    clean_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the clean command without running it.",
    )
    clean_parser.set_defaults(func=cmd_clean)

    test_parser = subparsers.add_parser(
        "run-tests",
        help="Run Java tests",
    )
    test_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the test command without running it.",
    )
    test_parser.set_defaults(func=cmd_run_tests)

    ghidra_deps_parser = subparsers.add_parser(
        "install-ghidra-deps",
        help="Prepare Ghidra jars for compilation (Maven: installs to local repo; Gradle: validates jars in place)",
    )
    ghidra_deps_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    ghidra_deps_parser.add_argument(
        "--force",
        action="store_true",
        help="Reinstall jars even if already present (Maven backend only).",
    )
    ghidra_deps_parser.add_argument(
        "--dry-run", action="store_true", help="Print actions without executing them."
    )
    ghidra_deps_parser.set_defaults(func=cmd_install_ghidra_deps)

    deploy_parser = subparsers.add_parser(
        "deploy",
        help="Copy the built plugin archive and bridge files into a Ghidra installation",
    )
    deploy_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    deploy_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print copy actions without executing them.",
    )
    deploy_parser.add_argument(
        "--test",
        action="append",
        choices=[
            "benchmark-read",
            "benchmark-write",
            "debugger-live",
            "endpoint-catalog",
            "multi-program",
            "negative-contract",
            "release",
            "selected-contract",
        ],
        default=[],
        help=(
            "Run an optional post-deploy test tier. May be passed multiple times. "
            "A plain deploy only runs MCP health/schema checks and does not import Benchmark.dll. "
            "Use --test release before cutting releases, or set GHIDRA_MCP_DEPLOY_TESTS in local .env."
        ),
    )
    deploy_parser.set_defaults(func=cmd_deploy)

    start_parser = subparsers.add_parser(
        "start-ghidra",
        help="Start the configured Ghidra installation",
    )
    start_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    start_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the launcher command without starting Ghidra.",
    )
    start_parser.set_defaults(func=cmd_start_ghidra)

    clean_all_parser = subparsers.add_parser(
        "clean-all",
        help="Remove build output and common local cache artifacts",
    )
    clean_all_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print cleanup actions without executing them.",
    )
    clean_all_parser.set_defaults(func=cmd_clean_all)

    ensure_prereqs_parser = subparsers.add_parser(
        "ensure-prereqs",
        help="Install Python dependencies and prepare Ghidra jars for compilation",
    )
    ensure_prereqs_parser.add_argument(
        "--ghidra-path",
        type=Path,
        help="Optional Ghidra installation path. Defaults to GHIDRA_PATH from .env when set.",
    )
    ensure_prereqs_parser.add_argument(
        "--use-debugger-toggle",
        action="store_true",
        help="Read INSTALL_DEBUGGER_DEPS from .env and install debugger requirements when enabled.",
    )
    ensure_prereqs_parser.add_argument(
        "--with-debugger",
        action="store_true",
        help="Force-install debugger requirements regardless of .env.",
    )
    ensure_prereqs_parser.add_argument(
        "--force",
        action="store_true",
        help="Reinstall Ghidra jars even if present in ~/.m2.",
    )
    ensure_prereqs_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print dependency actions without executing them.",
    )
    ensure_prereqs_parser.set_defaults(func=cmd_ensure_prereqs)

    bump_version_parser = subparsers.add_parser(
        "bump-version",
        help="Update project version references across maintained files",
    )
    bump_version_parser.add_argument(
        "--new", required=True, help="New semantic version in X.Y.Z form."
    )
    bump_version_parser.add_argument(
        "--old", help="Override the current version if pom.xml is already bumped."
    )
    bump_version_parser.add_argument(
        "--tag",
        action="store_true",
        help="Create an annotated git tag after updating files.",
    )
    bump_version_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print matching updates without modifying files.",
    )
    bump_version_parser.set_defaults(func=cmd_bump_version)

    return parser


def cmd_install_python_deps(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    env_file = args.env_file or repo_root / ".env"
    env_values = load_env_file(env_file)
    install_debugger = args.with_debugger or (
        args.use_debugger_toggle and get_env_flag(env_values, "INSTALL_DEBUGGER_DEPS")
    )

    python_executable = find_repo_python(repo_root, args.python)
    requirements_files = resolve_requirements_files(repo_root, args.requirements)
    plan = make_install_plan(
        repo_root, python_executable, requirements_files, install_debugger
    )
    execute_install_plan(plan)

    if install_debugger:
        print("Debugger dependencies installed.")
    elif args.use_debugger_toggle:
        print("Debugger dependencies skipped (INSTALL_DEBUGGER_DEPS not enabled).")

    return 0


def _load_repo_env(repo_root: Path) -> dict[str, str]:
    return load_env_file(repo_root / ".env")


def _should_install_debugger(
    env_values: dict[str, str], args: argparse.Namespace
) -> bool:
    return bool(
        getattr(args, "with_debugger", False)
        or (
            getattr(args, "use_debugger_toggle", False)
            and get_env_flag(env_values, "INSTALL_DEBUGGER_DEPS")
        )
    )


def _resolve_ghidra_path(repo_root: Path, ghidra_path: Path | None) -> Path | None:
    if ghidra_path is not None:
        return ghidra_path.resolve()

    env_values = _load_repo_env(repo_root)
    raw_path = env_values.get("GHIDRA_PATH", "").strip()
    if not raw_path:
        return None

    return Path(raw_path)


def _require_ghidra_path(repo_root: Path, ghidra_path: Path | None) -> Path:
    resolved_path = _resolve_ghidra_path(repo_root, ghidra_path)
    if resolved_path is None:
        raise ValueError(
            "A Ghidra path is required. Pass --ghidra-path or set GHIDRA_PATH in .env."
        )
    return resolved_path


def cmd_verify_version(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    ghidra_path = _resolve_ghidra_path(repo_root, args.ghidra_path)

    if _get_backend() == "gradle":
        return run_gradle(repo_root, ["verifyVersion"], ghidra_path=ghidra_path)

    versions = read_pom_versions(repo_root)
    print(f"Project version: {versions.project_version}")
    print(f"Ghidra version from pom.xml: {versions.ghidra_version}")
    if ghidra_path is None:
        print("No Ghidra path configured; pom.xml version verified.")
        return 0
    inferred_version = infer_ghidra_version_from_path(ghidra_path)
    print(f"Ghidra path: {ghidra_path}")
    if inferred_version is None:
        print("Unable to infer Ghidra version from the provided path.")
        return 1
    print(f"Ghidra version from path: {inferred_version}")
    if inferred_version != versions.ghidra_version:
        print(
            "Version mismatch detected between pom.xml and Ghidra path.",
            file=sys.stderr,
        )
        return 1
    print("Version check passed.")
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    env_values = _load_repo_env(repo_root)
    python_executable = find_repo_python(repo_root)

    if _get_backend() == "gradle":
        pip_check = subprocess.run(
            [str(python_executable), "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        if pip_check.returncode != 0:
            print(
                "pip is not available for the selected Python interpreter.",
                file=sys.stderr,
            )
            return 1
        print(f"Python: {python_executable}")
        print("pip: available")
        ghidra_path = _resolve_ghidra_path(repo_root, args.ghidra_path)
        return run_gradle(repo_root, ["preflight"], ghidra_path=ghidra_path)

    try:
        maven_command = find_maven_command()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Python: {python_executable}")
    print(f"Maven: {maven_command}")
    pip_check = subprocess.run(
        [str(python_executable), "-m", "pip", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if pip_check.returncode != 0:
        print(
            "pip is not available for the selected Python interpreter.", file=sys.stderr
        )
        return 1
    print("pip: available")
    if shutil.which("java") is None:
        print("Java not found on PATH.", file=sys.stderr)
        return 1
    print("Java: available on PATH")
    repo_versions = read_pom_versions(repo_root)
    ghidra_path = _resolve_ghidra_path(repo_root, args.ghidra_path)
    print(f"Project version: {repo_versions.project_version}")
    print(f"Ghidra version from pom.xml: {repo_versions.ghidra_version}")
    if ghidra_path is None:
        print("No Ghidra path configured; skipped Ghidra-specific preflight checks.")
        return 0
    inferred_version = infer_ghidra_version_from_path(ghidra_path)
    print(f"Ghidra path: {ghidra_path}")
    if inferred_version is None:
        print("Unable to infer Ghidra version from the provided path.", file=sys.stderr)
        return 1
    print(f"Ghidra version from path: {inferred_version}")
    if inferred_version != repo_versions.ghidra_version:
        print(
            "Version mismatch detected between pom.xml and Ghidra path.",
            file=sys.stderr,
        )
        return 1
    issues = collect_preflight_issues(
        repo_root,
        ghidra_path,
        python_executable,
        install_debugger=_should_install_debugger(env_values, args),
        strict=args.strict,
    )
    if issues:
        print("Preflight checks failed:", file=sys.stderr)
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
        return 1
    print("Preflight checks passed.")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    if _get_backend() == "gradle":
        return run_gradle(repo_root, ["buildExtension"], dry_run=args.dry_run)
    return run_maven(
        repo_root,
        ["clean", "package", "assembly:single", "-DskipTests"],
        dry_run=args.dry_run,
    )


def cmd_clean(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    if _get_backend() == "gradle":
        return run_gradle(repo_root, ["clean"], dry_run=args.dry_run)
    return run_maven(repo_root, ["clean"], dry_run=args.dry_run)


def cmd_run_tests(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    if _get_backend() == "gradle":
        return run_gradle(repo_root, ["test"], dry_run=args.dry_run)
    return run_maven(repo_root, ["test"], dry_run=args.dry_run)


def cmd_install_ghidra_deps(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    ghidra_path = _require_ghidra_path(repo_root, args.ghidra_path)
    if _get_backend() == "gradle":
        return run_gradle(
            repo_root,
            ["prepareGhidraClasspath"],
            ghidra_path=ghidra_path,
            dry_run=args.dry_run,
        )
    return install_ghidra_dependencies(
        repo_root, ghidra_path, force=args.force, dry_run=args.dry_run
    )


def cmd_deploy(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    ghidra_path = _require_ghidra_path(repo_root, args.ghidra_path)
    if _get_backend() == "gradle":
        return run_gradle(
            repo_root, ["deploy"], ghidra_path=ghidra_path, dry_run=args.dry_run
        )
    return deploy_to_ghidra(
        repo_root, ghidra_path, dry_run=args.dry_run, test_modes=args.test
    )


def cmd_start_ghidra(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    ghidra_path = _require_ghidra_path(repo_root, args.ghidra_path)
    if _get_backend() == "gradle":
        return run_gradle(
            repo_root, ["startGhidra"], ghidra_path=ghidra_path, dry_run=args.dry_run
        )
    return start_ghidra(ghidra_path, dry_run=args.dry_run)


def cmd_clean_all(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    if _get_backend() == "gradle":
        return run_gradle(repo_root, ["cleanAll"], dry_run=args.dry_run)
    return clean_all(repo_root, dry_run=args.dry_run)


def cmd_ensure_prereqs(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    env_values = _load_repo_env(repo_root)
    install_debugger = _should_install_debugger(env_values, args)
    python_executable = find_repo_python(repo_root)
    requirements_files = resolve_requirements_files(repo_root, [])
    plan = make_install_plan(
        repo_root, python_executable, requirements_files, install_debugger
    )

    if args.dry_run:
        for requirements_file in plan.requirements_files:
            print(f"DRY RUN: install python requirements from {requirements_file}")
        if plan.install_debugger:
            print(
                f"DRY RUN: install debugger requirements from {plan.debugger_requirements_file}"
            )
    else:
        execute_install_plan(plan)
        print("Python dependencies are ready.")
        if plan.install_debugger:
            print("Debugger Python dependencies are ready.")

    ghidra_path = _require_ghidra_path(repo_root, args.ghidra_path)
    if _get_backend() == "gradle":
        return run_gradle(
            repo_root,
            ["prepareGhidraClasspath"],
            ghidra_path=ghidra_path,
            dry_run=args.dry_run,
        )
    return install_ghidra_dependencies(
        repo_root, ghidra_path, force=args.force, dry_run=args.dry_run
    )


def cmd_bump_version(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    return apply_version_bump(
        repo_root,
        args.new,
        old_version=args.old,
        dry_run=args.dry_run,
        tag=args.tag,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

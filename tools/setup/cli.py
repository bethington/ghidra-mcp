from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .envfile import get_env_flag, load_env_file
from .ghidra import (
    DEPLOY_TEST_MODES,
    UnknownDeployTestMode,
    clean_all,
    collect_preflight_issues,
    deploy_to_ghidra,
    install_ghidra_dependencies,
    resolve_deploy_test_modes,
    start_ghidra,
)
from .python_env import detect_repo_root, find_repo_python
from .maven import (
    REQUIRED_JAVA_MAJOR,
    MavenNotFoundError,
    detect_maven_java_major,
    locate_maven_command,
    run_gradle,
    run_maven,
)
from .requirements import (
    ensure_uv_available,
    execute_install_plan,
    make_install_plan,
    uv_sync_command,
)
from .spawn import report_spawn_commands
from .version_bump import apply_version_bump
from .versioning import (
    infer_ghidra_version_from_path,
    is_ghidra_version_compatible,
    read_pom_versions,
)


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
        help="Install the repo's Python dependency groups via uv sync",
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
        # Read from ghidra.DEPLOY_TEST_MODES rather than restated here. A copy
        # drifts: the .env route had no validation at all, so a typo there
        # resolved to a tier nothing dispatches and deploy exited 0 having run
        # only the smoke test (#484). One list, both routes.
        choices=list(DEPLOY_TEST_MODES),
        default=[],
        help=(
            "Run an optional post-deploy test tier. May be passed multiple times. "
            "A plain deploy only runs MCP health/schema checks and does not import Benchmark.dll. "
            "Use --test release before cutting releases, or set GHIDRA_MCP_DEPLOY_TESTS in local .env "
            "(validated against the same list; an unknown tier is refused, not ignored)."
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

    plan = make_install_plan(repo_root, install_debugger)
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
    if not is_ghidra_version_compatible(versions.ghidra_version, inferred_version):
        print(
            "Version mismatch detected between pom.xml and Ghidra path.",
            file=sys.stderr,
        )
        return 1
    if inferred_version != versions.ghidra_version:
        print(
            f"Note: Ghidra path is {inferred_version}, pom.xml pins "
            f"{versions.ghidra_version} — same minor series, treated as compatible."
        )
    print("Version check passed.")
    return 0


def _report_maven(maven_command: Path | None) -> None:
    """Print Maven's status as a preflight report line. Never fails preflight.

    ``preflight`` does not invoke Maven, and Gradle -- the backend the docs lead
    with -- needs it for nothing, so a contributor who has no Maven must still
    get the full report. Before this, ``find_maven_command()`` ran first and its
    ``FileNotFoundError`` aborted the command after one line, which hard-failed
    the "check what you have" step CONTRIBUTING.md hands a Python-only
    contributor for a reason that does not apply to them.

    The hard failure still lives where Maven is actually needed: ``run_maven``
    (``build`` / ``clean`` / ``run-tests`` under the Maven backend) and
    ``install_ghidra_dependencies`` (``ensure-prereqs`` /
    ``install-ghidra-deps``) both call ``find_maven_command()``.
    """
    if maven_command is None:
        print("Maven: not found (the Gradle backend does not need it)")
        print(
            "  Maven is required only by `tools.setup build|clean|run-tests` under the "
            "Maven backend\n"
            "  and by `ensure-prereqs`/`install-ghidra-deps`. To build without it: "
            "`./gradlew buildExtension`\n"
            "  or TOOLS_SETUP_BACKEND=gradle."
        )
        return

    print(f"Maven: {maven_command}")
    java_major = detect_maven_java_major(maven_command)
    if java_major is not None and java_major < REQUIRED_JAVA_MAJOR:
        print(
            f"  WARNING: this Maven runs on Java {java_major}; Java "
            f"{REQUIRED_JAVA_MAJOR}+ is required to build with it.\n"
            f"  Set JAVA_HOME to a JDK {REQUIRED_JAVA_MAJOR} install, or build with "
            "`./gradlew buildExtension`."
        )


def cmd_preflight(args: argparse.Namespace) -> int:
    repo_root = detect_repo_root()
    env_values = _load_repo_env(repo_root)
    python_executable = find_repo_python(repo_root)

    if _get_backend() == "gradle":
        try:
            ensure_uv_available()
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"Python: {python_executable}")
        print("uv: available")
        report_spawn_commands(repo_root)
        ghidra_path = _resolve_ghidra_path(repo_root, args.ghidra_path)
        return run_gradle(repo_root, ["preflight"], ghidra_path=ghidra_path)

    print(f"Python: {python_executable}")
    _report_maven(locate_maven_command())
    try:
        ensure_uv_available()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("uv: available")
    report_spawn_commands(repo_root)
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
    if not is_ghidra_version_compatible(repo_versions.ghidra_version, inferred_version):
        print(
            "Version mismatch detected between pom.xml and Ghidra path.",
            file=sys.stderr,
        )
        return 1
    if inferred_version != repo_versions.ghidra_version:
        print(
            f"Note: Ghidra path is {inferred_version}, pom.xml pins "
            f"{repo_versions.ghidra_version} — same minor series, treated as compatible."
        )
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

    # Resolve (and therefore validate) the tiers BEFORE anything is built,
    # copied or restarted. An unknown tier costs a second here instead of
    # surfacing after a build, a Ghidra restart and a deploy -- or, before
    # #484, not surfacing at all.
    try:
        test_modes = resolve_deploy_test_modes(repo_root, args.test)
    except UnknownDeployTestMode as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if _get_backend() == "gradle":
        if test_modes:
            # build.gradle's `deploy` task is stopGhidra + deployExtension +
            # installUserExtension + patchGhidraUserConfig. It runs no
            # post-deploy tier and has no way to. Until #484 this branch
            # accepted `--test release` and dropped it on the floor, exiting 0
            # -- the same silence the .env typo produced, through a different
            # door. Refuse instead: naming the tier and not running it is the
            # failure mode, not the message length.
            print(
                "ERROR: the Gradle backend's `deploy` task runs no post-deploy "
                f"test tiers, so {test_modes} would be accepted and silently "
                "skipped.\n"
                "Use the Maven backend for tiered deploys (unset "
                "TOOLS_SETUP_BACKEND, or set it to 'maven'), or drop --test / "
                "set GHIDRA_MCP_DEPLOY_TESTS=off to deploy without them.",
                file=sys.stderr,
            )
            return 2
        return run_gradle(
            repo_root, ["deploy"], ghidra_path=ghidra_path, dry_run=args.dry_run
        )
    return deploy_to_ghidra(
        repo_root, ghidra_path, dry_run=args.dry_run, test_modes=test_modes
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
    plan = make_install_plan(repo_root, install_debugger)

    if args.dry_run:
        print(f"DRY RUN: {' '.join(uv_sync_command(plan))}")
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
    try:
        return args.func(args)
    except MavenNotFoundError as exc:
        # A refusal, not a crash. `preflight` now tells the reader which
        # commands need Maven; those commands should answer in the same voice
        # rather than with a traceback.
        print(str(exc), file=sys.stderr)
        print(
            f"`tools.setup {args.command}` runs Maven directly, so it cannot proceed "
            "without it.\nFor the Java build, use `./gradlew buildExtension "
            "-PGHIDRA_INSTALL_DIR=<dir>` or set TOOLS_SETUP_BACKEND=gradle.",
            file=sys.stderr,
        )
        return 1

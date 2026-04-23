from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

from .maven import find_maven_command
from .versioning import infer_ghidra_version_from_path, read_pom_versions


REQUIRED_GHIDRA_JARS: tuple[tuple[str, str], ...] = (
    ("Base", "Ghidra/Features/Base/lib/Base.jar"),
    ("Decompiler", "Ghidra/Features/Decompiler/lib/Decompiler.jar"),
    ("Docking", "Ghidra/Framework/Docking/lib/Docking.jar"),
    ("Generic", "Ghidra/Framework/Generic/lib/Generic.jar"),
    ("Project", "Ghidra/Framework/Project/lib/Project.jar"),
    ("SoftwareModeling", "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar"),
    ("Utility", "Ghidra/Framework/Utility/lib/Utility.jar"),
    ("Gui", "Ghidra/Framework/Gui/lib/Gui.jar"),
    ("FileSystem", "Ghidra/Framework/FileSystem/lib/FileSystem.jar"),
    ("Graph", "Ghidra/Framework/Graph/lib/Graph.jar"),
    ("DB", "Ghidra/Framework/DB/lib/DB.jar"),
    ("Emulation", "Ghidra/Framework/Emulation/lib/Emulation.jar"),
    ("PDB", "Ghidra/Features/PDB/lib/PDB.jar"),
    ("FunctionID", "Ghidra/Features/FunctionID/lib/FunctionID.jar"),
    ("Help", "Ghidra/Framework/Help/lib/Help.jar"),
    ("Debugger-api", "Ghidra/Debug/Debugger-api/lib/Debugger-api.jar"),
    (
        "Framework-TraceModeling",
        "Ghidra/Debug/Framework-TraceModeling/lib/Framework-TraceModeling.jar",
    ),
    (
        "Debugger-rmi-trace",
        "Ghidra/Debug/Debugger-rmi-trace/lib/Debugger-rmi-trace.jar",
    ),
)

PLUGIN_CLASS = "com.xebyte.GhidraMCPPlugin"


def ghidra_user_base_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "ghidra"
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "ghidra"
        return Path.home() / "AppData" / "Roaming" / "ghidra"

    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return Path(xdg_config_home) / "ghidra"
    return Path.home() / ".config" / "ghidra"


def _version_sort_key(name: str) -> tuple[int, int, int]:
    match = re.search(r"ghidra_(\d+)\.(\d+)(?:\.(\d+))?", name)
    if not match:
        return (0, 0, 0)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def resolve_ghidra_user_dir(
    ghidra_path: Path, user_base_dir: Path | None = None
) -> Path:
    user_base_dir = user_base_dir or ghidra_user_base_dir()
    target_version = infer_ghidra_version_from_path(ghidra_path)

    if user_base_dir.is_dir() and target_version:
        matching_dirs = sorted(user_base_dir.glob(f"ghidra_{target_version}*"))
        if matching_dirs:
            public_dir = next(
                (path for path in matching_dirs if "PUBLIC" in path.name), None
            )
            return public_dir or matching_dirs[0]

    if user_base_dir.is_dir():
        version_dirs = sorted(
            (path for path in user_base_dir.glob("ghidra_*") if path.is_dir()),
            key=lambda path: _version_sort_key(path.name),
            reverse=True,
        )
        if version_dirs:
            return version_dirs[0]

    if target_version:
        return user_base_dir / f"ghidra_{target_version}_PUBLIC"
    return user_base_dir / "ghidra_unknown_PUBLIC"


def patch_frontend_tool_config(content: str) -> tuple[str, bool]:
    original = content
    updated = content

    for package_name in ("Developer", "GhidraMCP"):
        updated = re.sub(
            rf"\s*<PACKAGE NAME=\"{re.escape(package_name)}\"\s*/>\s*",
            "\n",
            updated,
        )
        updated = re.sub(
            rf"(?s)\s*<PACKAGE NAME=\"{re.escape(package_name)}\">\s*.*?</PACKAGE>\s*",
            "\n",
            updated,
        )

    if PLUGIN_CLASS in updated:
        return updated, updated != original

    utility_self_closing = '<PACKAGE NAME="Utility" />'
    if utility_self_closing in updated:
        replacement = (
            '<PACKAGE NAME="Utility">\n'
            f'                <INCLUDE CLASS="{PLUGIN_CLASS}" />\n'
            "            </PACKAGE>"
        )
        updated = updated.replace(utility_self_closing, replacement, 1)
        return updated, True

    utility_block = '<PACKAGE NAME="Utility">'
    if utility_block in updated:
        replacement = (
            '<PACKAGE NAME="Utility">\n'
            f'                <INCLUDE CLASS="{PLUGIN_CLASS}" />'
        )
        updated = updated.replace(utility_block, replacement, 1)
        return updated, True

    root_node = "<ROOT_NODE"
    if root_node in updated:
        insertion = (
            '<PACKAGE NAME="Utility">\n'
            f'                <INCLUDE CLASS="{PLUGIN_CLASS}" />\n'
            "            </PACKAGE>\n"
            "<ROOT_NODE"
        )
        updated = updated.replace(root_node, insertion, 1)
        return updated, True

    return updated, updated != original


def patch_codebrowser_tcd(content: str) -> tuple[str, bool]:
    updated = re.sub(
        rf'\s*<PACKAGE NAME="GhidraMCP">\s*<INCLUDE CLASS="{re.escape(PLUGIN_CLASS)}"\s*/>\s*</PACKAGE>',
        "",
        content,
    )
    return updated, updated != content


def _write_text_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="")


def patch_ghidra_user_configs(user_base_dir: Path, *, dry_run: bool = False) -> None:
    if not user_base_dir.is_dir():
        return

    for front_end_file in sorted(user_base_dir.glob("*/FrontEndTool.xml")):
        updated, modified = patch_frontend_tool_config(
            front_end_file.read_text(encoding="utf-8")
        )
        if not modified:
            continue
        if dry_run:
            print(f"DRY RUN: patch {front_end_file}")
            continue
        _write_text_file(front_end_file, updated)
        print(f"Patched FrontEnd config {front_end_file}")

    for tcd_file in sorted(user_base_dir.glob("*/tools/_code_browser.tcd")):
        updated, modified = patch_codebrowser_tcd(tcd_file.read_text(encoding="utf-8"))
        if not modified:
            continue
        if dry_run:
            print(f"DRY RUN: patch {tcd_file}")
            continue
        _write_text_file(tcd_file, updated)
        print(f"Cleaned CodeBrowser config {tcd_file}")


def _find_plugin_jar(repo_root: Path) -> Path | None:
    target_dir = repo_root / "target"
    version = read_pom_versions(repo_root).project_version
    candidates = [
        target_dir / "GhidraMCP.jar",
        target_dir / f"GhidraMCP-{version}.jar",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    jars = sorted(
        target_dir.glob("GhidraMCP*.jar"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return jars[0] if jars else None


def install_user_extension(
    repo_root: Path, ghidra_path: Path, archive_path: Path, *, dry_run: bool = False
) -> Path:
    user_base_dir = ghidra_user_base_dir()
    user_version_dir = resolve_ghidra_user_dir(ghidra_path, user_base_dir)
    user_extensions_base = user_version_dir / "Extensions"
    user_extension_dir = user_extensions_base / "GhidraMCP"
    user_lib_dir = user_extension_dir / "lib"

    if dry_run:
        print(f"DRY RUN: ensure directory {user_extensions_base}")
        print(f"DRY RUN: remove stale jars matching {user_lib_dir / 'GhidraMCP*.jar'}")
        print(f"DRY RUN: extract {archive_path} -> {user_extensions_base}")
        return user_extension_dir

    user_extensions_base.mkdir(parents=True, exist_ok=True)
    user_lib_dir.mkdir(parents=True, exist_ok=True)
    for stale_jar in user_lib_dir.glob("GhidraMCP*.jar"):
        stale_jar.unlink(missing_ok=True)
        print(f"Removed stale plugin jar {stale_jar}")

    try:
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(user_extensions_base)
        print(f"Installed user extension to {user_extension_dir}")
        return user_extension_dir
    except Exception as exc:
        plugin_jar = _find_plugin_jar(repo_root)
        if plugin_jar is None:
            raise RuntimeError(
                "Extension extraction failed and no fallback plugin jar was found"
            ) from exc

        fallback_destination = user_lib_dir / "GhidraMCP.jar"
        shutil.copy2(plugin_jar, fallback_destination)
        print(f"Fell back to jar-only install at {fallback_destination}")
        return user_extension_dir


def find_ghidra_executable(ghidra_path: Path) -> Path:
    candidates = [
        ghidra_path / "ghidraRun.bat",
        ghidra_path / "ghidraRun",
        ghidra_path / "ghidra",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"Unable to find Ghidra launcher under {ghidra_path}")


def find_plugin_archive(repo_root: Path) -> Path:
    version = read_pom_versions(repo_root).project_version
    # Check Gradle output first, then Maven target/ for backward compatibility during transition.
    candidates = [
        repo_root / "build" / "distributions" / f"GhidraMCP-{version}.zip",
        repo_root / "target" / f"GhidraMCP-{version}.zip",
        repo_root / "target" / "GhidraMCP.zip",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    for search_dir in [repo_root / "build" / "distributions", repo_root / "target"]:
        archives = sorted(
            search_dir.glob("GhidraMCP*.zip"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if archives:
            return archives[0]

    raise FileNotFoundError(
        "No GhidraMCP plugin archive found in build/distributions/ or target/"
    )


def print_command(command: list[str]) -> None:
    print(" ".join(command))


def install_ghidra_dependencies(
    repo_root: Path,
    ghidra_path: Path,
    *,
    force: bool = False,
    dry_run: bool = False,
) -> int:
    maven_command = str(find_maven_command())
    ghidra_version = read_pom_versions(repo_root).ghidra_version
    m2_root = Path.home() / ".m2" / "repository" / "ghidra"

    for artifact_id, relative_path in REQUIRED_GHIDRA_JARS:
        jar_path = ghidra_path / relative_path
        if not jar_path.is_file():
            raise FileNotFoundError(f"Missing required Ghidra jar: {jar_path}")

        cached_jar = (
            m2_root
            / artifact_id
            / ghidra_version
            / f"{artifact_id}-{ghidra_version}.jar"
        )
        if cached_jar.is_file() and not force:
            print(f"Skipping already installed dependency: {artifact_id}")
            continue

        command = [
            maven_command,
            "install:install-file",
            f"-Dfile={jar_path}",
            "-DgroupId=ghidra",
            f"-DartifactId={artifact_id}",
            f"-Dversion={ghidra_version}",
            "-Dpackaging=jar",
            "-DgeneratePom=true",
        ]
        if dry_run:
            print("DRY RUN:", end=" ")
            print_command(command)
            continue

        completed = subprocess.run(command, cwd=repo_root, check=False)
        if completed.returncode != 0:
            return completed.returncode

    return 0


def test_write_access(path_to_test: Path) -> bool:
    try:
        path_to_test.mkdir(parents=True, exist_ok=True)
        probe = path_to_test / ".ghidra-mcp-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def collect_preflight_issues(
    repo_root: Path,
    ghidra_path: Path,
    python_executable: Path,
    *,
    install_debugger: bool,
    strict: bool = False,
    user_base_dir: Path | None = None,
) -> list[str]:
    issues: list[str] = []

    pip_check = subprocess.run(
        [str(python_executable), "-m", "pip", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if pip_check.returncode != 0:
        issues.append("pip is not available for the selected Python interpreter.")

    if shutil.which("java") is None:
        issues.append("Java not found on PATH (JDK 21 recommended).")

    try:
        find_ghidra_executable(ghidra_path)
    except FileNotFoundError:
        issues.append(f"Ghidra executable not found at: {ghidra_path}")
        return issues

    for _artifact_id, relative_path in REQUIRED_GHIDRA_JARS:
        jar_path = ghidra_path / relative_path
        if not jar_path.is_file():
            issues.append(f"Missing required Ghidra dependency: {jar_path}")

    if install_debugger:
        debugger_requirements = repo_root / "requirements-debugger.txt"
        if not debugger_requirements.is_file():
            issues.append(
                f"Debugger requirements file not found: {debugger_requirements}"
            )

    extensions_dir = ghidra_path / "Extensions" / "Ghidra"
    if not test_write_access(extensions_dir):
        issues.append(
            f"No write access to Ghidra extensions directory: {extensions_dir}"
        )

    user_extension_dir = (
        resolve_ghidra_user_dir(ghidra_path, user_base_dir) / "Extensions"
    )
    if not test_write_access(user_extension_dir):
        issues.append(
            f"No write access to user extension directory: {user_extension_dir}"
        )

    if strict:
        for url in ("https://repo.maven.apache.org", "https://pypi.org"):
            try:
                request = urllib.request.Request(url, method="HEAD")
                with urllib.request.urlopen(request, timeout=10):
                    pass
            except Exception:
                issues.append(f"Network check failed: {url}")

    return issues


def deploy_to_ghidra(
    repo_root: Path, ghidra_path: Path, *, dry_run: bool = False
) -> int:
    archive_path = find_plugin_archive(repo_root)
    extensions_dir = ghidra_path / "Extensions" / "Ghidra"
    destination_archive = extensions_dir / archive_path.name
    bridge_source = repo_root / "bridge_mcp_ghidra.py"
    requirements_source = repo_root / "requirements.txt"
    dotenv_source = repo_root / ".env"
    user_base_dir = ghidra_user_base_dir()

    if dry_run:
        print(f"DRY RUN: ensure directory {extensions_dir}")
        print(
            f"DRY RUN: remove existing archives matching {extensions_dir / 'GhidraMCP*.zip'}"
        )
        print(f"DRY RUN: copy {archive_path} -> {destination_archive}")
        if bridge_source.is_file():
            print(
                f"DRY RUN: copy {bridge_source} -> {ghidra_path / bridge_source.name}"
            )
        if requirements_source.is_file():
            print(
                f"DRY RUN: copy {requirements_source} -> {ghidra_path / requirements_source.name}"
            )
        if dotenv_source.is_file():
            print(
                f"DRY RUN: copy {dotenv_source} -> {ghidra_path / dotenv_source.name}"
            )
        install_user_extension(repo_root, ghidra_path, archive_path, dry_run=True)
        patch_ghidra_user_configs(user_base_dir, dry_run=True)
        return 0

    extensions_dir.mkdir(parents=True, exist_ok=True)
    for existing_archive in extensions_dir.glob("GhidraMCP*.zip"):
        existing_archive.unlink()

    shutil.copy2(archive_path, destination_archive)
    print(f"Installed plugin archive to {destination_archive}")

    if bridge_source.is_file():
        bridge_destination = ghidra_path / bridge_source.name
        bridge_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bridge_source, bridge_destination)
        print(f"Copied bridge to {bridge_destination}")

    if requirements_source.is_file():
        requirements_destination = ghidra_path / requirements_source.name
        shutil.copy2(requirements_source, requirements_destination)
        print(f"Copied requirements to {requirements_destination}")

    if dotenv_source.is_file():
        dotenv_destination = ghidra_path / dotenv_source.name
        shutil.copy2(dotenv_source, dotenv_destination)
        print(f"Copied .env to {dotenv_destination}")

    install_user_extension(repo_root, ghidra_path, archive_path)
    patch_ghidra_user_configs(user_base_dir)

    return 0


def start_ghidra(ghidra_path: Path, *, dry_run: bool = False) -> int:
    executable = find_ghidra_executable(ghidra_path)
    if executable.suffix.lower() in {".bat", ".cmd"}:
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/c", str(executable)]
    else:
        command = [str(executable)]

    if dry_run:
        print("DRY RUN:", end=" ")
        print_command(command)
        return 0

    subprocess.Popen(command, cwd=ghidra_path)
    print(f"Started Ghidra from {executable}")
    return 0


def clean_all(repo_root: Path, *, dry_run: bool = False) -> int:
    paths_to_remove = [
        repo_root / "target",
        repo_root / ".pytest_cache",
        repo_root / "__pycache__",
    ]

    log_dir = repo_root / "logs"
    log_files = sorted(log_dir.glob("*.log")) if log_dir.is_dir() else []

    for path in paths_to_remove:
        if not path.exists():
            continue
        if dry_run:
            print(f"DRY RUN: remove {path}")
            continue
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)

    for log_file in log_files:
        if dry_run:
            print(f"DRY RUN: remove {log_file}")
            continue
        log_file.unlink(missing_ok=True)

    print("Cleanup completed.")
    return 0

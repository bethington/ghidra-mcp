from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .envfile import load_env_file
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
PLUGIN_EXTENSION_NAME = "GhidraMCP"
DEFAULT_MCP_URL = "http://127.0.0.1:8089"
DEFAULT_MCP_WAIT_SECONDS = 120
DEFAULT_GHIDRA_EXIT_WAIT_SECONDS = 15
DEFAULT_BENCHMARK_DLL = Path("fun-doc") / "benchmark" / "build" / "Benchmark.dll"
DEFAULT_BENCHMARK_DEBUG_EXE = Path("fun-doc") / "benchmark" / "build" / "BenchmarkDebug.exe"
LEGACY_BENCHMARK_PROGRAM = "/benchmark/Benchmark.dll"
DEFAULT_BENCHMARK_FOLDER = "/testing/benchmark"
DEFAULT_BENCHMARK_PROGRAM = f"{DEFAULT_BENCHMARK_FOLDER}/Benchmark.dll"
DEFAULT_BENCHMARK_DEBUG_PROGRAM = f"{DEFAULT_BENCHMARK_FOLDER}/BenchmarkDebug.exe"
DEFAULT_BENCHMARK_FUNCTION = "calc_crc16"
BENCHMARK_DEPLOY_TEST_MODES = {
    "benchmark-read",
    "benchmark-write",
    "release",
    "debugger-live",
    "multi-program",
}
SMOKE_REQUIRED_TOOLS = {
    "decompile_function",
    "get_function_variables",
    "analyze_function_completeness",
    "batch_set_comments",
    "set_local_variable_type",
    "rename_variables",
    "prompt_policy",
    "save_program",
    "save_all_programs",
    "set_function_prototype",
    "rename_function_by_address",
    "search_data_types",
    "create_struct",
    "get_struct_layout",
    "list_open_programs",
    "debugger/launch",
}
RELEASE_CONTRACT_TOOLS = SMOKE_REQUIRED_TOOLS | {
    "analysis_status",
    "create_folder",
    "delete_file",
    "import_file",
    "list_project_files",
    "list_functions",
    "search_functions",
    "get_address_spaces",
    "list_imports",
    "list_exports",
    "list_strings",
    "debugger/launch",
    "debugger/status",
    "debugger/modules",
}


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
        updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
        return updated, updated != original

    utility_self_closing = '<PACKAGE NAME="Utility" />'
    if utility_self_closing in updated:
        replacement = (
            '<PACKAGE NAME="Utility">\n'
            f'                <INCLUDE CLASS="{PLUGIN_CLASS}" />\n'
            "            </PACKAGE>"
        )
        updated = updated.replace(utility_self_closing, replacement, 1)
        updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
        return updated, True

    utility_block = '<PACKAGE NAME="Utility">'
    if utility_block in updated:
        replacement = (
            '<PACKAGE NAME="Utility">\n'
            f'                <INCLUDE CLASS="{PLUGIN_CLASS}" />'
        )
        updated = updated.replace(utility_block, replacement, 1)
        updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
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
        updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
        return updated, True

    updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
    return updated, updated != original


def mark_extension_known_in_tool_config(content: str, extension_name: str) -> str:
    """Record an installed extension as known to suppress Ghidra's first-run plugin dialog."""
    if re.search(
        rf'<EXTENSION\s+(?:[^>]*\s)?NAME="{re.escape(extension_name)}"',
        content,
    ):
        return content

    extension_entry = f'            <EXTENSION NAME="{extension_name}" />\n'
    empty_extensions = re.compile(r"(?m)^([ \t]*)<EXTENSIONS\s*/>\s*$")
    if empty_extensions.search(content):
        return empty_extensions.sub(
            rf"\1<EXTENSIONS>\n{extension_entry}\1</EXTENSIONS>",
            content,
            count=1,
        )

    extensions_open = re.compile(r"(?m)^([ \t]*)<EXTENSIONS>\s*$")
    match = extensions_open.search(content)
    if match:
        insert_at = match.end()
        return content[:insert_at] + "\n" + extension_entry + content[insert_at:]

    if "</TOOL>" not in content:
        return content
    return content.replace(
        "</TOOL>",
        f"        <EXTENSIONS>\n{extension_entry}        </EXTENSIONS>\n    </TOOL>",
        1,
    )


def patch_tool_tcd(content: str) -> tuple[str, bool]:
    original = content
    updated = re.sub(
        rf'\s*<PACKAGE NAME="GhidraMCP">\s*<INCLUDE CLASS="{re.escape(PLUGIN_CLASS)}"\s*/>\s*</PACKAGE>',
        "",
        content,
    )
    updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
    return updated, updated != original


def patch_codebrowser_tcd(content: str) -> tuple[str, bool]:
    return patch_tool_tcd(content)


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

    for tcd_file in sorted(user_base_dir.glob("*/tools/*.tcd")):
        updated, modified = patch_tool_tcd(tcd_file.read_text(encoding="utf-8"))
        if not modified:
            continue
        if dry_run:
            print(f"DRY RUN: patch {tcd_file}")
            continue
        _write_text_file(tcd_file, updated)
        print(f"Patched tool config {tcd_file}")


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
        for attempt in range(10):
            try:
                stale_jar.unlink(missing_ok=True)
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(1)
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


def resolve_mcp_url(repo_root: Path) -> str:
    env_values = load_env_file(repo_root / ".env")
    if env_values.get("GHIDRA_MCP_URL"):
        return env_values["GHIDRA_MCP_URL"].rstrip("/")
    port = env_values.get("GHIDRA_MCP_PORT", "8089").strip() or "8089"
    bind = env_values.get("GHIDRA_MCP_BIND_ADDRESS", "127.0.0.1").strip()
    if not bind or bind in {"0.0.0.0", "::"}:
        bind = "127.0.0.1"
    return f"http://{bind}:{port}".rstrip("/")


def resolve_deploy_test_modes(repo_root: Path, cli_modes: list[str] | None) -> list[str]:
    modes = list(cli_modes or [])
    env_values = load_env_file(repo_root / ".env")
    raw_modes = env_values.get("GHIDRA_MCP_DEPLOY_TESTS", "").strip()
    if raw_modes and raw_modes.lower() not in {"0", "false", "no", "none", "off"}:
        modes.extend(
            mode.strip()
            for mode in re.split(r"[,;\s]+", raw_modes)
            if mode.strip()
        )
    return list(dict.fromkeys(modes))


def _mcp_headers(repo_root: Path) -> dict[str, str]:
    env_values = load_env_file(repo_root / ".env")
    token = env_values.get("GHIDRA_MCP_AUTH_TOKEN", "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def _mcp_request(
    repo_root: Path,
    mcp_url: str,
    path: str,
    *,
    method: str = "GET",
    data: dict | None = None,
    params: dict | None = None,
    timeout: int = 10,
) -> tuple[int, object]:
    body = None
    headers = _mcp_headers(repo_root)
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    url = f"{mcp_url}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        text = response.read().decode("utf-8", errors="replace")
        try:
            parsed: object = json.loads(text)
        except ValueError:
            parsed = text
        return response.status, parsed


def _ensure_mcp_ok(path: str, payload: object) -> None:
    if isinstance(payload, dict) and payload.get("error"):
        raise RuntimeError(f"{path} failed: {payload['error']}")
    if isinstance(payload, str) and payload.lower().startswith("failed"):
        raise RuntimeError(f"{path} failed: {payload}")


def _mcp_error_message(payload: object) -> str:
    if isinstance(payload, dict):
        error = payload.get("error")
        if error is not None:
            return str(error)
    if isinstance(payload, str):
        return payload
    return ""


def _expect_mcp_error(path: str, payload: object, required_terms: tuple[str, ...]) -> None:
    message = _mcp_error_message(payload)
    if not message:
        raise RuntimeError(f"{path} was expected to fail but returned: {payload}")
    lowered = message.lower()
    missing = [term for term in required_terms if term.lower() not in lowered]
    if missing:
        raise RuntimeError(
            f"{path} error was not actionable enough; missing {missing}. Error: {message}"
        )


def _find_matching_ghidra_processes(ghidra_path: Path) -> list[dict[str, object]]:
    target = str(ghidra_path.resolve()).lower()
    if os.name == "nt":
        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "Get-CimInstance Win32_Process | "
                "Where-Object { $_.Name -match '^(javaw?|ghidra).*' } | "
                "Select-Object ProcessId,Name,ExecutablePath,CommandLine | "
                "ConvertTo-Json -Compress"
            ),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0 or not completed.stdout.strip():
            return []
        raw = json.loads(completed.stdout)
        rows = raw if isinstance(raw, list) else [raw]
        matches = []
        for row in rows:
            cmd = str(row.get("CommandLine") or "")
            name = str(row.get("Name") or "").lower()
            cmd_lower = cmd.lower()
            is_ghidra_process = (
                name in {"java.exe", "javaw.exe", "ghidrarun.bat", "ghidrarun"}
                and ("ghidra.ghidra" in cmd_lower or "ghidrarun" in cmd_lower)
            )
            if target in cmd_lower and is_ghidra_process:
                matches.append(
                    {
                        "pid": int(row["ProcessId"]),
                        "name": row.get("Name", ""),
                        "command": cmd,
                    }
                )
        return matches
    ps = subprocess.run(["ps", "-eo", "pid=,args="], capture_output=True, text=True, check=False)
    matches = []
    for line in ps.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pid_text, _, command = stripped.partition(" ")
        command_lower = command.lower()
        if target in command_lower and ("ghidra.ghidra" in command_lower or "ghidrarun" in command_lower):
            matches.append({"pid": int(pid_text), "name": "process", "command": command})
    return matches


def _terminate_process(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=False)
    else:
        os.kill(pid, signal.SIGKILL)


def _terminate_processes_by_name(process_name: str) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/IM", process_name, "/F"], check=False)
        return
    subprocess.run(["pkill", "-f", process_name], check=False)


def _project_state_path_from_gpr(project_path: str) -> Path | None:
    if not project_path:
        return None
    gpr = Path(project_path)
    if gpr.suffix.lower() != ".gpr":
        return None
    return gpr.with_suffix(".rep") / "projectState"


def _deploy_tests_use_benchmark(test_modes: list[str]) -> bool:
    return any(mode in BENCHMARK_DEPLOY_TEST_MODES for mode in test_modes)


def clear_restored_benchmark_tools(repo_root: Path, *, dry_run: bool = False) -> int:
    env_values = load_env_file(repo_root / ".env")
    project_state = _project_state_path_from_gpr(env_values.get("GHIDRA_PROJECT_PATH", "").strip())
    if project_state is None or not project_state.is_file():
        return 0

    try:
        tree = ET.parse(project_state)
    except ET.ParseError as exc:
        print(f"WARNING: Could not parse Ghidra project state {project_state}: {exc}")
        return 0

    root = tree.getroot()
    parent_by_child = {child: parent for parent in root.iter() for child in parent}
    removed = 0
    benchmark_state_markers = (
        f'VALUE="{DEFAULT_BENCHMARK_PROGRAM}"',
        f'VALUE="diablo2:{DEFAULT_BENCHMARK_PROGRAM}"',
        f'VALUE="{DEFAULT_BENCHMARK_DEBUG_PROGRAM}"',
        f'VALUE="diablo2:{DEFAULT_BENCHMARK_DEBUG_PROGRAM}"',
        f'VALUE="{LEGACY_BENCHMARK_PROGRAM}"',
        "/testing/benchmark/",
        "/New Traces/pydbg/BenchmarkDebug.exe",
    )
    for tool in list(root.iter("RUNNING_TOOL")):
        if tool.attrib.get("TOOL_NAME") not in {"CodeBrowser", "Debugger"}:
            continue
        tool_xml = ET.tostring(tool, encoding="unicode")
        if not any(marker in tool_xml for marker in benchmark_state_markers):
            continue
        parent = parent_by_child.get(tool)
        if parent is None:
            continue
        if dry_run:
            removed += 1
            continue
        parent.remove(tool)
        removed += 1

    if removed == 0:
        return 0
    if dry_run:
        print(f"DRY RUN: remove {removed} restored benchmark CodeBrowser tool(s) from {project_state}")
        return removed

    backup_path = project_state.with_name(project_state.name + ".GhidraMCP.bak")
    shutil.copy2(project_state, backup_path)
    tree.write(project_state, encoding="utf-8", xml_declaration=True)
    print(f"Removed {removed} restored benchmark CodeBrowser tool(s) from {project_state}")
    print(f"Backed up previous project state to {backup_path}")
    return removed


def close_running_ghidra_for_deploy(
    repo_root: Path,
    ghidra_path: Path,
    *,
    mcp_url: str,
    dry_run: bool = False,
    wait_seconds: int = DEFAULT_GHIDRA_EXIT_WAIT_SECONDS,
) -> bool:
    matches = _find_matching_ghidra_processes(ghidra_path)
    if not matches:
        print("No matching running Ghidra process detected.")
        return False
    for proc in matches:
        print(f"Detected running Ghidra PID {proc['pid']}: {proc['command']}")
    if dry_run:
        print(f"DRY RUN: save all open programs via {mcp_url}/save_all_programs")
        print(f"DRY RUN: graceful exit via {mcp_url}/exit_ghidra")
        for proc in matches:
            print(f"DRY RUN: force-kill PID {proc['pid']} if still running")
        return True

    try:
        _mcp_request(repo_root, mcp_url, "/save_all_programs", timeout=60)
        print("Requested save for all open Ghidra programs.")
    except Exception as exc:
        print(f"WARNING: save_all_programs failed before deploy: {exc}")
        try:
            _mcp_request(repo_root, mcp_url, "/save_program", timeout=60)
            print("Requested fallback Ghidra program save.")
        except Exception as fallback_exc:
            print(f"WARNING: fallback save_program failed before deploy: {fallback_exc}")
    try:
        _mcp_request(repo_root, mcp_url, "/exit_ghidra", timeout=10)
        print("Requested graceful Ghidra exit.")
    except Exception as exc:
        print(f"WARNING: exit_ghidra failed before deploy: {exc}")

    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if not _find_matching_ghidra_processes(ghidra_path):
            print("Ghidra exited cleanly.")
            return True
        time.sleep(1)
    for proc in _find_matching_ghidra_processes(ghidra_path):
        print(f"Force-killing Ghidra PID {proc['pid']}.")
        _terminate_process(int(proc["pid"]))
    return True


def wait_for_mcp(
    repo_root: Path,
    mcp_url: str,
    *,
    timeout_seconds: int = DEFAULT_MCP_WAIT_SECONDS,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        for path in ("/mcp/health", "/health", "/check_connection"):
            try:
                status, _payload = _mcp_request(repo_root, mcp_url, path, timeout=5)
                if status == 200:
                    print(f"MCP ready at {mcp_url} ({path}).")
                    return
            except Exception as exc:
                last_error = exc
        time.sleep(2)
    raise RuntimeError(f"MCP did not become ready at {mcp_url}: {last_error}")


def wait_for_project(
    repo_root: Path,
    mcp_url: str,
    *,
    timeout_seconds: int = DEFAULT_MCP_WAIT_SECONDS,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _status, payload = _mcp_request(
                repo_root,
                mcp_url,
                "/list_project_files",
                params={"folder": "/"},
                timeout=5,
            )
            if isinstance(payload, dict) and "error" not in payload:
                print("Ghidra project is ready.")
                return
            last_error = RuntimeError(
                payload.get("error", str(payload)) if isinstance(payload, dict) else str(payload)
            )
        except Exception as exc:
            last_error = exc
        time.sleep(2)
    raise RuntimeError(f"Ghidra project did not become ready: {last_error}")


def _schema_tools(schema: object) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    tools = schema.get("tools") or []
    names = set()
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        path = tool.get("path")
        if name:
            names.add(str(name))
        if path:
            names.add(str(path).lstrip("/"))
    return names


def _schema_tool_map(schema: object) -> dict[str, dict]:
    if not isinstance(schema, dict):
        return {}
    result: dict[str, dict] = {}
    for tool in schema.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        keys = []
        if tool.get("name"):
            keys.append(str(tool["name"]))
        if tool.get("path"):
            keys.append(str(tool["path"]).lstrip("/"))
        for key in keys:
            result[key] = tool
    return result


def run_default_smoke_test(repo_root: Path, mcp_url: str) -> None:
    _status, schema = _mcp_request(repo_root, mcp_url, "/mcp/schema", timeout=20)
    tools = _schema_tools(schema)
    missing = sorted(SMOKE_REQUIRED_TOOLS - tools)
    if missing:
        raise RuntimeError(f"MCP schema missing required tools: {', '.join(missing)}")
    print(f"MCP smoke passed: schema exposes {len(tools)} tools.")


def _close_and_delete_project_file(repo_root: Path, mcp_url: str, program_path: str) -> None:
    deadline = time.monotonic() + 90
    last_error = ""
    while time.monotonic() < deadline:
        try:
            _mcp_request(
                repo_root,
                mcp_url,
                "/close_program",
                data={"name": program_path},
                method="POST",
                timeout=30,
            )
            _status, payload = _mcp_request(
                repo_root,
                mcp_url,
                "/delete_file",
                data={"filePath": program_path},
                method="POST",
                timeout=30,
            )
            _ensure_mcp_ok("/delete_file", payload)
            return
        except Exception as exc:
            last_error = str(exc)
            if "in use" not in last_error.lower() and "background" not in last_error.lower():
                raise
            time.sleep(3)
    raise RuntimeError(f"Timed out deleting {program_path}: {last_error}")


def reset_benchmark_fixture(repo_root: Path, mcp_url: str) -> None:
    benchmark_dll = repo_root / DEFAULT_BENCHMARK_DLL
    benchmark_debug_exe = repo_root / DEFAULT_BENCHMARK_DEBUG_EXE
    _terminate_processes_by_name("BenchmarkDebug.exe")
    if not benchmark_dll.is_file() or not benchmark_debug_exe.is_file():
        print("Benchmark binary output missing; building it now.")
        subprocess.run(
            [sys.executable, str(repo_root / "fun-doc" / "benchmark" / "build.py")],
            cwd=repo_root,
            check=True,
        )
    for program_path in (
        LEGACY_BENCHMARK_PROGRAM,
        DEFAULT_BENCHMARK_PROGRAM,
        DEFAULT_BENCHMARK_DEBUG_PROGRAM,
    ):
        _close_and_delete_project_file(repo_root, mcp_url, program_path)
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/create_folder",
        data={"path": DEFAULT_BENCHMARK_FOLDER},
        method="POST",
        timeout=30,
    )
    _ensure_mcp_ok("/create_folder", payload)
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/import_file",
        data={
            "file_path": str(benchmark_dll),
            "project_folder": DEFAULT_BENCHMARK_FOLDER,
            "auto_analyze": True,
        },
        method="POST",
        timeout=120,
    )
    _ensure_mcp_ok("/import_file", payload)
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/import_file",
        data={
            "file_path": str(benchmark_debug_exe),
            "project_folder": DEFAULT_BENCHMARK_FOLDER,
            "auto_analyze": True,
        },
        method="POST",
        timeout=120,
    )
    _ensure_mcp_ok("/import_file", payload)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            _status, status = _mcp_request(
                repo_root,
                mcp_url,
                "/analysis_status",
                params={"program": DEFAULT_BENCHMARK_PROGRAM},
                timeout=10,
            )
            _ensure_mcp_ok("/analysis_status", status)
            _status, exe_status = _mcp_request(
                repo_root,
                mcp_url,
                "/analysis_status",
                params={"program": DEFAULT_BENCHMARK_DEBUG_PROGRAM},
                timeout=10,
            )
            _ensure_mcp_ok("/analysis_status", exe_status)
            state = (status.get("state") or status.get("status")) if isinstance(status, dict) else None
            exe_state = (
                (exe_status.get("state") or exe_status.get("status"))
                if isinstance(exe_status, dict)
                else None
            )
            is_idle = isinstance(status, dict) and status.get("analyzing") is False
            exe_idle = isinstance(exe_status, dict) and exe_status.get("analyzing") is False
            if (is_idle or state in {"complete", "done", "idle", "finished"}) and (
                exe_idle or exe_state in {"complete", "done", "idle", "finished"}
            ):
                print(f"Benchmark fixture reset at {DEFAULT_BENCHMARK_PROGRAM}.")
                return
        except Exception:
            pass
        time.sleep(2)
    print("WARNING: Benchmark analysis did not report complete within 90s; continuing.")


def _list_benchmark_functions(repo_root: Path, mcp_url: str) -> list[tuple[str, str]]:
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/list_functions",
        params={"program": DEFAULT_BENCHMARK_PROGRAM},
        timeout=60,
    )
    _ensure_mcp_ok("/list_functions", payload)
    functions: list[tuple[str, str]] = []
    if isinstance(payload, dict):
        raw_functions = payload.get("functions") or payload.get("results") or []
        for function in raw_functions:
            if not isinstance(function, dict):
                continue
            name = str(function.get("name") or "")
            address = function.get("address") or function.get("entry_point")
            if name and address:
                functions.append((name, str(address)))
    elif isinstance(payload, str):
        for line in payload.splitlines():
            match = re.match(r"(.+?)\s+at\s+([0-9a-fA-Fx]+)\s*$", line.strip())
            if match:
                functions.append((match.group(1), match.group(2)))
    return functions


def _list_benchmark_exports(repo_root: Path, mcp_url: str) -> list[tuple[str, str]]:
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/list_exports",
        params={"program": DEFAULT_BENCHMARK_PROGRAM},
        timeout=60,
    )
    _ensure_mcp_ok("/list_exports", payload)
    exports: list[tuple[str, str]] = []
    if isinstance(payload, str):
        for line in payload.splitlines():
            match = re.match(r"(.+?)\s+->\s+([0-9a-fA-Fx]+)\s*$", line.strip())
            if match:
                exports.append((match.group(1), match.group(2)))
    return exports


def _ensure_benchmark_function(repo_root: Path, mcp_url: str, address: str, name: str) -> None:
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/get_function_by_address",
        params={"program": DEFAULT_BENCHMARK_PROGRAM, "address": address},
        timeout=30,
    )
    if isinstance(payload, dict) and "error" not in payload:
        return
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/create_function",
        params={"program": DEFAULT_BENCHMARK_PROGRAM},
        data={
            "address": address,
            "name": re.sub(r"[^A-Za-z0-9_]", "_", name).strip("_") or "BenchmarkFunction",
            "disassemble_first": True,
        },
        method="POST",
        timeout=60,
    )
    _ensure_mcp_ok("/create_function", payload)


def _has_editable_variable(repo_root: Path, mcp_url: str, address: str) -> bool:
    _status, decompile_payload = _mcp_request(
        repo_root,
        mcp_url,
        "/decompile_function",
        params={"program": DEFAULT_BENCHMARK_PROGRAM, "address": address},
        timeout=60,
    )
    _ensure_mcp_ok("/decompile_function", decompile_payload)
    _status, variables = _mcp_request(
        repo_root,
        mcp_url,
        "/get_function_variables",
        params={"program": DEFAULT_BENCHMARK_PROGRAM, "address": address},
        timeout=30,
    )
    _ensure_mcp_ok("/get_function_variables", variables)
    if not isinstance(variables, dict):
        return False
    for variable in (variables.get("locals") or []) + (variables.get("parameters") or []):
        if isinstance(variable, dict) and variable.get("name") and not variable.get("is_phantom"):
            return True
    return False


def _find_benchmark_function(repo_root: Path, mcp_url: str, *, require_variable: bool = False) -> str:
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/search_functions",
        params={
            "program": DEFAULT_BENCHMARK_PROGRAM,
            "name_pattern": DEFAULT_BENCHMARK_FUNCTION,
            "limit": 10,
        },
        timeout=30,
    )
    functions = []
    if isinstance(payload, dict):
        _ensure_mcp_ok("/search_functions", payload)
        functions = payload.get("results") or payload.get("functions") or []
    for function in functions:
        if isinstance(function, dict) and DEFAULT_BENCHMARK_FUNCTION in str(function.get("name") or ""):
            address = function.get("address") or function.get("entry_point")
            if address and (not require_variable or _has_editable_variable(repo_root, mcp_url, str(address))):
                return str(address)

    fallback_functions = _list_benchmark_functions(repo_root, mcp_url)
    if require_variable:
        for _name, address in fallback_functions:
            if _has_editable_variable(repo_root, mcp_url, address):
                return address
    elif fallback_functions:
        return fallback_functions[0][1]

    for name, address in _list_benchmark_exports(repo_root, mcp_url):
        if name.startswith("Ordinal_") or name == "entry":
            continue
        if DEFAULT_BENCHMARK_FUNCTION not in name and not fallback_functions:
            continue
        _ensure_benchmark_function(repo_root, mcp_url, address, name)
        if not require_variable:
            return address
        for _ in range(5):
            if _has_editable_variable(repo_root, mcp_url, address):
                return address
            time.sleep(1)

    suffix = " with an editable variable" if require_variable else ""
    raise RuntimeError(f"Could not find a benchmark function{suffix} in {DEFAULT_BENCHMARK_PROGRAM}")


def run_benchmark_read_test(repo_root: Path, mcp_url: str) -> None:
    address = _find_benchmark_function(repo_root, mcp_url)
    read_calls = [
        ("/list_open_programs", {"program": DEFAULT_BENCHMARK_PROGRAM}),
        ("/search_data_types", {"program": DEFAULT_BENCHMARK_PROGRAM, "pattern": "int", "limit": 5}),
        ("/decompile_function", {"program": DEFAULT_BENCHMARK_PROGRAM, "address": address}),
        ("/get_function_variables", {"program": DEFAULT_BENCHMARK_PROGRAM, "address": address}),
        ("/analyze_function_completeness", {"program": DEFAULT_BENCHMARK_PROGRAM, "function_address": address}),
        ("/get_plate_comment", {"program": DEFAULT_BENCHMARK_PROGRAM, "address": address}),
        ("/save_program", {"program": DEFAULT_BENCHMARK_PROGRAM}),
    ]
    for path, params in read_calls:
        _status, payload = _mcp_request(repo_root, mcp_url, path, params=params, timeout=60)
        _ensure_mcp_ok(path, payload)
    struct_name = f"DeploySmokeStruct_{int(time.time())}"
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/create_struct",
        params={"program": DEFAULT_BENCHMARK_PROGRAM},
        data={
            "name": struct_name,
            "fields": [{"name": "dwValue", "type": "uint", "offset": 0}],
        },
        method="POST",
        timeout=60,
    )
    _ensure_mcp_ok("/create_struct", payload)
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/get_struct_layout",
        params={"program": DEFAULT_BENCHMARK_PROGRAM, "struct_name": struct_name},
        timeout=30,
    )
    _ensure_mcp_ok("/get_struct_layout", payload)
    print(f"Benchmark read/create test passed on benchmark function @ {address}.")


def run_benchmark_extended_read_test(repo_root: Path, mcp_url: str) -> None:
    address = _find_benchmark_function(repo_root, mcp_url)
    read_calls = [
        ("/list_project_files", {"folder": DEFAULT_BENCHMARK_FOLDER}),
        ("/analysis_status", {"program": DEFAULT_BENCHMARK_PROGRAM}),
        ("/list_functions", {"program": DEFAULT_BENCHMARK_PROGRAM}),
        (
            "/search_functions",
            {"program": DEFAULT_BENCHMARK_PROGRAM, "name_pattern": "FUN_", "limit": 10},
        ),
        ("/get_address_spaces", {"program": DEFAULT_BENCHMARK_PROGRAM}),
        ("/list_imports", {"program": DEFAULT_BENCHMARK_PROGRAM}),
        ("/list_exports", {"program": DEFAULT_BENCHMARK_PROGRAM}),
        ("/list_strings", {"program": DEFAULT_BENCHMARK_PROGRAM, "limit": 10}),
        ("/decompile_function", {"program": DEFAULT_BENCHMARK_PROGRAM, "address": address}),
    ]
    for path, params in read_calls:
        _status, payload = _mcp_request(repo_root, mcp_url, path, params=params, timeout=60)
        _ensure_mcp_ok(path, payload)
    print(f"Benchmark extended read test passed on benchmark function @ {address}.")


def run_benchmark_write_test(repo_root: Path, mcp_url: str) -> None:
    address = _find_benchmark_function(repo_root, mcp_url, require_variable=True)
    _status, variables = _mcp_request(
        repo_root,
        mcp_url,
        "/get_function_variables",
        params={"program": DEFAULT_BENCHMARK_PROGRAM, "address": address},
        timeout=30,
    )
    _ensure_mcp_ok("/get_function_variables", variables)
    variable_name = None
    if isinstance(variables, dict):
        for variable in (variables.get("locals") or []) + (variables.get("parameters") or []):
            if isinstance(variable, dict) and variable.get("name") and not variable.get("is_phantom"):
                variable_name = str(variable["name"])
                break
    if not variable_name:
        raise RuntimeError("No benchmark editable variable available for write smoke")
    write_calls = [
        (
            "/batch_set_comments",
            {
                "address": address,
                "plate_comment": "GhidraMCP deploy benchmark write probe",
                "disassembly_comments": [{"address": address, "comment": "deploy smoke"}],
            },
        ),
        (
            "/set_local_variable_type",
            {
                "function_address": address,
                "variable_name": variable_name,
                "new_type": "uint",
            },
        ),
        (
            "/rename_variables",
            {
                "function_address": address,
                "variable_renames": {variable_name: "dwDeploySmoke"},
                "force_individual": True,
            },
        ),
        (
            "/rename_function_by_address",
            {
                "function_address": address,
                "new_name": "DeploySmokeCalcCrc16",
            },
        ),
        (
            "/set_function_prototype",
            {
                "function_address": address,
                "prototype": "ushort DeploySmokeCalcCrc16(uchar * data, uint length)",
                "calling_convention": "__stdcall",
            },
        ),
    ]
    for path, data in write_calls:
        _status, payload = _mcp_request(
            repo_root,
            mcp_url,
            path,
            params={"program": DEFAULT_BENCHMARK_PROGRAM},
            data=data,
            method="POST",
            timeout=60,
        )
        _ensure_mcp_ok(path, payload)
    print(f"Benchmark write test passed on benchmark function @ {address}.")


def run_negative_contract_test(repo_root: Path, mcp_url: str) -> None:
    address = _find_benchmark_function(repo_root, mcp_url, require_variable=True)
    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/get_function_variables",
        params={"program": "/testing/benchmark/Missing.dll", "address": address},
        timeout=30,
    )
    _expect_mcp_error("/get_function_variables", payload, ("program not found", "available"))

    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/decompile_function",
        params={"program": DEFAULT_BENCHMARK_PROGRAM, "address": "not-an-address"},
        timeout=30,
    )
    _expect_mcp_error("/decompile_function", payload, ("address",))

    _status, payload = _mcp_request(
        repo_root,
        mcp_url,
        "/set_local_variable_type",
        params={"program": DEFAULT_BENCHMARK_PROGRAM},
        data={
            "function_address": address,
            "variable_name": "definitely_missing_local",
            "new_type": "uint",
        },
        method="POST",
        timeout=60,
    )
    _expect_mcp_error(
        "/set_local_variable_type",
        payload,
        ("definitely_missing_local", "available variables"),
    )
    print("Negative/error-shape contract test passed.")


def run_multi_program_targeting_test(repo_root: Path, mcp_url: str) -> None:
    address = _find_benchmark_function(repo_root, mcp_url)
    _status, programs = _mcp_request(repo_root, mcp_url, "/list_open_programs", timeout=30)
    _ensure_mcp_ok("/list_open_programs", programs)
    if not isinstance(programs, dict):
        raise RuntimeError("/list_open_programs returned an unexpected payload")
    open_programs = programs.get("programs") or []
    paths = {
        str(program.get("path"))
        for program in open_programs
        if isinstance(program, dict) and program.get("path")
    }
    if DEFAULT_BENCHMARK_PROGRAM not in paths:
        raise RuntimeError(f"{DEFAULT_BENCHMARK_PROGRAM} is not open; open paths: {sorted(paths)}")

    _status, by_path = _mcp_request(
        repo_root,
        mcp_url,
        "/get_function_variables",
        params={"program": DEFAULT_BENCHMARK_PROGRAM, "address": address},
        timeout=30,
    )
    _ensure_mcp_ok("/get_function_variables", by_path)
    if not isinstance(by_path, dict) or by_path.get("function_address") != address:
        raise RuntimeError("Program path targeting returned the wrong benchmark function")

    _status, by_name = _mcp_request(
        repo_root,
        mcp_url,
        "/analysis_status",
        params={"program": "Benchmark.dll"},
        timeout=30,
    )
    _ensure_mcp_ok("/analysis_status", by_name)
    _status, by_project_path = _mcp_request(
        repo_root,
        mcp_url,
        "/analysis_status",
        params={"program": DEFAULT_BENCHMARK_PROGRAM},
        timeout=30,
    )
    _ensure_mcp_ok("/analysis_status", by_project_path)
    print("Multi-program targeting test passed.")


def run_debugger_live_test(repo_root: Path, mcp_url: str) -> None:
    if os.name != "nt":
        raise RuntimeError("Debugger live regression is currently Windows-only.")
    benchmark_debug_exe = repo_root / DEFAULT_BENCHMARK_DEBUG_EXE
    if not benchmark_debug_exe.is_file():
        raise RuntimeError(f"BenchmarkDebug.exe not found at {benchmark_debug_exe}")

    env_values = load_env_file(repo_root / ".env")
    python_executable = (
        os.environ.get("GHIDRA_DEBUGGER_PYTHON", "").strip()
        or env_values.get("GHIDRA_DEBUGGER_PYTHON", "").strip()
    )
    launch_data: dict[str, object] = {
        "program": DEFAULT_BENCHMARK_DEBUG_PROGRAM,
        "executable_path": str(benchmark_debug_exe),
        "args": "--seconds 180",
        "cwd": str(benchmark_debug_exe.parent),
        "timeout_seconds": 90,
        "offer": "BATCH_FILE:local-dbgeng.bat",
    }
    if python_executable:
        launch_data["python_executable"] = python_executable

    try:
        _status, launch = _mcp_request(
            repo_root,
            mcp_url,
            "/debugger/launch",
            data=launch_data,
            method="POST",
            timeout=120,
        )
        _ensure_mcp_ok("/debugger/launch", launch)

        deadline = time.monotonic() + 45
        status_payload: object = {}
        while time.monotonic() < deadline:
            _status, status_payload = _mcp_request(
                repo_root,
                mcp_url,
                "/debugger/status",
                timeout=20,
            )
            _ensure_mcp_ok("/debugger/status", status_payload)
            if (
                isinstance(status_payload, dict)
                and status_payload.get("trace_active") is True
                and status_payload.get("target_connected") is True
                and status_payload.get("thread")
            ):
                break
            time.sleep(2)
        else:
            raise RuntimeError(f"Debugger did not report an active target: {status_payload}")

        for path, params in (
            ("/debugger/traces", {}),
            ("/debugger/modules", {}),
            ("/debugger/registers", {}),
            ("/debugger/stack_trace", {"depth": 8}),
        ):
            _status, payload = _mcp_request(
                repo_root,
                mcp_url,
                path,
                params=params,
                timeout=30,
            )
            _ensure_mcp_ok(path, payload)
        print("Debugger live test passed: launched BenchmarkDebug.exe and read trace state.")
    finally:
        _terminate_processes_by_name("BenchmarkDebug.exe")


def run_endpoint_catalog_test(repo_root: Path, mcp_url: str) -> None:
    _status, schema = _mcp_request(repo_root, mcp_url, "/mcp/schema", timeout=20)
    live_tools = _schema_tools(schema)
    catalog = json.loads((repo_root / "tests" / "endpoints.json").read_text(encoding="utf-8"))
    endpoints = catalog.get("endpoints", []) if isinstance(catalog, dict) else catalog
    expected = {
        str(endpoint.get("path", "")).lstrip("/")
        for endpoint in endpoints
        if isinstance(endpoint, dict) and endpoint.get("path")
    }
    missing = sorted(expected - live_tools)
    if missing:
        raise RuntimeError(f"Live schema missing {len(missing)} catalog endpoint(s): {', '.join(missing[:20])}")
    print(f"Endpoint catalog test passed: {len(expected)} catalog endpoints present.")


def run_selected_endpoint_contract_test(repo_root: Path, mcp_url: str) -> None:
    _status, schema = _mcp_request(repo_root, mcp_url, "/mcp/schema", timeout=20)
    tools = _schema_tool_map(schema)
    missing_tools = sorted(RELEASE_CONTRACT_TOOLS - set(tools))
    if missing_tools:
        raise RuntimeError(
            f"Release schema missing selected endpoint contract tool(s): {', '.join(missing_tools)}"
        )

    catalog = json.loads((repo_root / "tests" / "endpoints.json").read_text(encoding="utf-8"))
    endpoints = catalog.get("endpoints", []) if isinstance(catalog, dict) else catalog
    catalog_by_name = {
        str(endpoint.get("path", "")).lstrip("/"): endpoint
        for endpoint in endpoints
        if isinstance(endpoint, dict) and endpoint.get("path")
    }
    contract_errors: list[str] = []
    for name in sorted(RELEASE_CONTRACT_TOOLS):
        schema_tool = tools[name]
        catalog_tool = catalog_by_name.get(name)
        if catalog_tool is None:
            contract_errors.append(f"{name}: missing from tests/endpoints.json")
            continue
        schema_method = str(schema_tool.get("method") or "GET").upper()
        catalog_method = str(catalog_tool.get("method") or "GET").upper()
        if schema_method != catalog_method:
            contract_errors.append(f"{name}: method schema={schema_method} catalog={catalog_method}")
        schema_params = {
            str(param.get("name"))
            for param in schema_tool.get("params") or []
            if isinstance(param, dict) and param.get("name")
        }
        catalog_params = {str(param) for param in catalog_tool.get("params") or []}
        missing_params = sorted(catalog_params - schema_params)
        if missing_params:
            contract_errors.append(f"{name}: schema missing catalog params {missing_params}")
    if contract_errors:
        raise RuntimeError("Selected endpoint contract failed: " + "; ".join(contract_errors))
    print(f"Selected endpoint contract test passed for {len(RELEASE_CONTRACT_TOOLS)} tools.")


def run_release_regression_tests(repo_root: Path, mcp_url: str) -> None:
    reset_benchmark_fixture(repo_root, mcp_url)
    run_selected_endpoint_contract_test(repo_root, mcp_url)
    run_benchmark_extended_read_test(repo_root, mcp_url)
    run_multi_program_targeting_test(repo_root, mcp_url)
    run_negative_contract_test(repo_root, mcp_url)
    run_debugger_live_test(repo_root, mcp_url)
    print("Release regression tier passed.")


def run_deploy_tests(repo_root: Path, mcp_url: str, test_modes: list[str]) -> None:
    run_default_smoke_test(repo_root, mcp_url)
    if _deploy_tests_use_benchmark(test_modes):
        _mcp_request(
            repo_root,
            mcp_url,
            "/prompt_policy",
            data={"action": "enable", "reason": "deploy_tests", "seconds": 300},
            method="POST",
            timeout=10,
        )
    for mode in test_modes:
        if mode == "endpoint-catalog":
            run_endpoint_catalog_test(repo_root, mcp_url)
        elif mode == "benchmark-read":
            reset_benchmark_fixture(repo_root, mcp_url)
            run_benchmark_extended_read_test(repo_root, mcp_url)
        elif mode == "benchmark-write":
            reset_benchmark_fixture(repo_root, mcp_url)
            run_benchmark_write_test(repo_root, mcp_url)
        elif mode == "negative-contract":
            reset_benchmark_fixture(repo_root, mcp_url)
            run_negative_contract_test(repo_root, mcp_url)
        elif mode == "multi-program":
            reset_benchmark_fixture(repo_root, mcp_url)
            run_multi_program_targeting_test(repo_root, mcp_url)
        elif mode == "selected-contract":
            run_selected_endpoint_contract_test(repo_root, mcp_url)
        elif mode == "debugger-live":
            reset_benchmark_fixture(repo_root, mcp_url)
            run_debugger_live_test(repo_root, mcp_url)
        elif mode == "release":
            run_release_regression_tests(repo_root, mcp_url)


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
    repo_root: Path,
    ghidra_path: Path,
    *,
    dry_run: bool = False,
    test_modes: list[str] | None = None,
) -> int:
    archive_path = find_plugin_archive(repo_root)
    extensions_dir = ghidra_path / "Extensions" / "Ghidra"
    destination_archive = extensions_dir / archive_path.name
    bridge_source = repo_root / "bridge_mcp_ghidra.py"
    requirements_source = repo_root / "requirements.txt"
    dotenv_source = repo_root / ".env"
    user_base_dir = ghidra_user_base_dir()
    mcp_url = resolve_mcp_url(repo_root)
    test_modes = resolve_deploy_test_modes(repo_root, test_modes)

    close_running_ghidra_for_deploy(
        repo_root, ghidra_path, mcp_url=mcp_url, dry_run=dry_run
    )

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
        if _deploy_tests_use_benchmark(test_modes):
            clear_restored_benchmark_tools(repo_root, dry_run=True)
        start_ghidra(ghidra_path, repo_root=repo_root, dry_run=True)
        print(f"DRY RUN: wait up to {DEFAULT_MCP_WAIT_SECONDS}s for MCP at {mcp_url}")
        print(f"DRY RUN: wait up to {DEFAULT_MCP_WAIT_SECONDS}s for active project")
        print("DRY RUN: run default MCP smoke test")
        for mode in test_modes:
            print(f"DRY RUN: run deploy test {mode}")
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
    if _deploy_tests_use_benchmark(test_modes):
        clear_restored_benchmark_tools(repo_root)
    start_ghidra(ghidra_path, repo_root=repo_root)
    wait_for_mcp(repo_root, mcp_url, timeout_seconds=DEFAULT_MCP_WAIT_SECONDS)
    wait_for_project(repo_root, mcp_url, timeout_seconds=DEFAULT_MCP_WAIT_SECONDS)
    run_deploy_tests(repo_root, mcp_url, test_modes)

    return 0


def start_ghidra(ghidra_path: Path, *, repo_root: Path | None = None, dry_run: bool = False) -> int:
    executable = find_ghidra_executable(ghidra_path)
    env_root = repo_root if repo_root is not None else Path.cwd()
    env_values = load_env_file(env_root / ".env")
    project_path = env_values.get("GHIDRA_PROJECT_PATH", "").strip()
    if executable.suffix.lower() in {".bat", ".cmd"}:
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/c", str(executable)]
    else:
        command = [str(executable)]
    if project_path:
        command.append(project_path)

    if dry_run:
        print("DRY RUN:", end=" ")
        print_command(command)
        return 0

    subprocess.Popen(command, cwd=ghidra_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

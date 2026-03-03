# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp>=1.2.0,<2",
# ]
# ///
"""
GhidraMCP Bridge — thin MCP↔HTTP multiplexer.

On startup: exposes list_instances + connect_instance.
On connect_instance: fetches /mcp/schema from the Ghidra server,
dynamically registers every tool. All dynamic tools are generic HTTP dispatchers.

Supports two transports to Ghidra:
  - UDS (Unix domain sockets) — preferred for local instances
  - TCP (HTTP) — fallback for headless/remote servers
"""

import argparse
import json
import logging
import os
import socket
import time
import http.client
import inspect
from pathlib import Path
from urllib.parse import urlencode

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.lowlevel.server import NotificationOptions

# ==========================================================================
# Configuration
# ==========================================================================

REQUEST_TIMEOUT = 30

# Per-endpoint timeout overrides for expensive operations
ENDPOINT_TIMEOUTS = {
    "batch_rename_variables": 120,
    "batch_set_comments": 120,
    "analyze_function_complete": 120,
    "batch_rename_function_components": 120,
    "batch_set_variable_types": 90,
    "analyze_data_region": 90,
    "batch_create_labels": 60,
    "batch_delete_labels": 60,
    "disassemble_bytes": 120,
    "bulk_fuzzy_match": 180,
    "find_similar_functions_fuzzy": 60,
    "run_ghidra_script": 1800,
    "run_script_inline": 1800,
    "decompile_function": 45,
    "set_function_prototype": 45,
    "rename_function": 45,
    "rename_function_by_address": 45,
    "consolidate_duplicate_types": 60,
    "batch_analyze_completeness": 120,
    "apply_function_documentation": 60,
    "default": 30,
}

DEFAULT_TCP_URL = "http://127.0.0.1:8089"

# Logging
LOG_LEVEL = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global state
mcp = FastMCP("ghidra-mcp")

# Enable tools/list_changed notifications so clients re-fetch tools after dynamic registration
_orig_init_options = mcp._mcp_server.create_initialization_options
def _patched_init_options(**kwargs):
    return _orig_init_options(
        notification_options=NotificationOptions(tools_changed=True), **kwargs)
mcp._mcp_server.create_initialization_options = _patched_init_options

_active_socket: str | None = None  # UDS socket path
_active_tcp: str | None = None  # TCP base URL (e.g. "http://127.0.0.1:8089")
_transport_mode: str = "none"  # "uds", "tcp", or "none"


# ==========================================================================
# UDS Transport
# ==========================================================================


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP connection over a Unix domain socket."""

    def __init__(self, socket_path: str, timeout: int = 30):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def get_socket_dir() -> Path:
    """Get the GhidraMCP socket runtime directory."""
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "ghidra-mcp"
    user = os.getenv("USER", "unknown")
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        return Path(tmpdir) / f"ghidra-mcp-{user}"
    return Path(f"/tmp/ghidra-mcp-{user}")


def is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # Running but owned by another user


def uds_request(
    socket_path: str,
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Make an HTTP request over a Unix domain socket. Returns (body, status)."""
    conn = UnixHTTPConnection(socket_path, timeout=timeout)
    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if params:
        path = f"{path}?{urlencode(params)}"

    headers = {}
    body = None
    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if body:
        headers["Content-Length"] = str(len(body))

    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = response.read().decode("utf-8")
        status = response.status
        conn.close()
        return result, status
    except Exception:
        conn.close()
        raise


# ==========================================================================
# TCP Transport
# ==========================================================================


def tcp_request(
    base_url: str,
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Make an HTTP request over TCP. Returns (body, status)."""
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)

    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if params:
        path = f"{path}?{urlencode(params)}"

    headers = {}
    body = None
    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if body:
        headers["Content-Length"] = str(len(body))

    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = response.read().decode("utf-8")
        status = response.status
        conn.close()
        return result, status
    except Exception:
        conn.close()
        raise


# ==========================================================================
# Unified request function
# ==========================================================================


def do_request(
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Route request to the active transport (UDS or TCP)."""
    if _transport_mode == "uds" and _active_socket:
        return uds_request(_active_socket, method, endpoint, params, json_data, timeout)
    elif _transport_mode == "tcp" and _active_tcp:
        return tcp_request(_active_tcp, method, endpoint, params, json_data, timeout)
    else:
        raise ConnectionError("No Ghidra instance connected. Use connect_instance() first.")


# ==========================================================================
# Instance discovery
# ==========================================================================


def discover_instances() -> list[dict]:
    """Scan socket directory and query each live instance for info."""
    socket_dir = get_socket_dir()
    if not socket_dir.exists():
        return []

    instances = []
    for sock_file in sorted(socket_dir.glob("*.sock")):
        name = sock_file.stem  # ghidra-<pid>
        dash = name.rfind("-")
        if dash < 0:
            continue
        try:
            pid = int(name[dash + 1:])
        except ValueError:
            continue

        if not is_pid_alive(pid):
            logger.debug(f"Cleaning up stale socket: {sock_file}")
            try:
                sock_file.unlink(missing_ok=True)
            except OSError:
                pass
            continue

        info: dict = {"socket": str(sock_file), "pid": pid}
        try:
            text, status = uds_request(str(sock_file), "GET", "/mcp/instance_info", timeout=5)
            if status == 200:
                data = json.loads(text)
                # instance_info response is wrapped in Response.ok() → {"data": {...}}
                if "data" in data:
                    info.update(data["data"])
                else:
                    info.update(data)
        except Exception as e:
            logger.debug(f"Could not query {sock_file}: {e}")

        instances.append(info)

    return instances


# ==========================================================================
# HTTP dispatch
# ==========================================================================


def get_timeout(endpoint: str, payload: dict | None = None) -> int:
    """Get timeout for an endpoint, with dynamic scaling for batch ops."""
    name = endpoint.strip("/").split("/")[-1]
    base = ENDPOINT_TIMEOUTS.get(name, ENDPOINT_TIMEOUTS["default"])

    if not payload:
        return base

    if name == "batch_rename_variables":
        count = len(payload.get("variable_renames", {}))
        return min(base + count * 38, 600)

    if name == "batch_set_comments":
        count = len(payload.get("decompiler_comments", []))
        count += len(payload.get("disassembly_comments", []))
        count += 1 if payload.get("plate_comment") else 0
        return min(base + count * 8, 600)

    return base


def dispatch_get(endpoint: str, params: dict | None = None, retries: int = 3) -> str:
    """GET request via active transport. Returns raw response text."""
    if _transport_mode == "none":
        return json.dumps({"error": "No Ghidra instance connected. Use connect_instance() first."})

    timeout = get_timeout(endpoint)
    for attempt in range(retries):
        try:
            text, status = do_request("GET", endpoint, params=params, timeout=timeout)
            if status == 200:
                return text
            if status >= 500 and attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except Exception as e:
            if attempt < retries - 1:
                continue
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})


def dispatch_post(endpoint: str, data: dict, retries: int = 3) -> str:
    """POST JSON request via active transport. Returns raw response text."""
    if _transport_mode == "none":
        return json.dumps({"error": "No Ghidra instance connected. Use connect_instance() first."})

    timeout = get_timeout(endpoint, data)
    for attempt in range(retries):
        try:
            text, status = do_request("POST", endpoint, json_data=data, timeout=timeout)
            if status == 200:
                return text.strip()
            if status >= 500 and attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})


# ==========================================================================
# Dynamic tool registration from /mcp/schema
# ==========================================================================

_dynamic_tool_names: list[str] = []
_full_schema: list[dict] = []  # Complete schema from /mcp/schema
_loaded_groups: set[str] = set()  # Currently loaded tool groups

# Core groups always loaded on connect (essential for basic RE workflow)
CORE_GROUPS = {"listing", "function", "program"}


def _build_tool_function(endpoint: str, http_method: str, params_schema: dict):
    """Build a callable that dispatches to the Ghidra HTTP endpoint."""
    properties = params_schema.get("properties", {})
    required = set(params_schema.get("required", []))

    def handler(**kwargs):
        filtered = {k: v for k, v in kwargs.items() if v is not None}
        if http_method == "GET":
            str_params = {k: str(v) for k, v in filtered.items()}
            return dispatch_get(endpoint, params=str_params if str_params else None)
        else:
            return dispatch_post(endpoint, data=filtered)

    sig_params = []
    for pname, pdef in properties.items():
        json_type = pdef.get("type", "string")
        py_type = {"string": str, "integer": int, "boolean": bool, "number": float}.get(json_type, str)
        default = pdef.get("default", inspect.Parameter.empty)
        if pname not in required and default is inspect.Parameter.empty:
            default = None
            py_type = py_type | None if py_type != str else str | None
        sig_params.append(
            inspect.Parameter(pname, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=py_type)
        )

    handler.__signature__ = inspect.Signature(sig_params, return_annotation=str)
    handler.__annotations__ = {p.name: p.annotation for p in sig_params}
    handler.__annotations__["return"] = str

    return handler


def _register_tool_def(tool_def: dict) -> bool:
    """Register a single tool from a schema definition. Returns True if registered."""
    name = tool_def["name"]
    description = tool_def.get("description", "")
    endpoint = tool_def["endpoint"]
    http_method = tool_def.get("http_method", "GET")
    input_schema = tool_def.get("input_schema", {"type": "object", "properties": {}})

    handler = _build_tool_function(endpoint, http_method, input_schema)
    handler.__name__ = name
    handler.__doc__ = description

    mcp.tool(name=name, description=description)(handler)
    _dynamic_tool_names.append(name)
    return True


def register_tools_from_schema(schema: list[dict], groups: set[str] | None = None) -> int:
    """Register MCP tools from the /mcp/schema response.

    Args:
        schema: List of tool definitions from /mcp/schema
        groups: If provided, only register tools in these groups. None = register all.

    Returns: count of registered tools.
    """
    global _dynamic_tool_names, _full_schema, _loaded_groups

    # Remove previously registered dynamic tools
    for name in _dynamic_tool_names:
        try:
            mcp.remove_tool(name)
        except (KeyError, ValueError):
            pass
    _dynamic_tool_names.clear()
    _loaded_groups.clear()

    # Store full schema for lazy loading
    _full_schema = schema

    count = 0
    for tool_def in schema:
        category = tool_def.get("category", "unknown")
        if groups is not None and category not in groups:
            continue
        _register_tool_def(tool_def)
        _loaded_groups.add(category)
        count += 1

    return count


def _load_group(group_name: str) -> int:
    """Load tools for a specific group from cached schema. Returns count."""
    count = 0
    for tool_def in _full_schema:
        if tool_def.get("category") != group_name:
            continue
        name = tool_def["name"]
        if name in _dynamic_tool_names:
            continue  # Already loaded
        _register_tool_def(tool_def)
        count += 1
    if count > 0:
        _loaded_groups.add(group_name)
    return count


def _unload_group(group_name: str) -> int:
    """Unload tools for a specific group. Returns count of removed tools."""
    if group_name in CORE_GROUPS:
        return 0  # Core groups can't be unloaded

    to_remove = []
    for tool_def in _full_schema:
        if tool_def.get("category") == group_name:
            name = tool_def["name"]
            if name in _dynamic_tool_names:
                to_remove.append(name)

    for name in to_remove:
        try:
            mcp.remove_tool(name)
            _dynamic_tool_names.remove(name)
        except (KeyError, ValueError):
            pass

    if to_remove:
        _loaded_groups.discard(group_name)
    return len(to_remove)


def _get_group_info() -> list[dict]:
    """Get info about all tool groups from cached schema."""
    groups: dict[str, list[str]] = {}
    for tool_def in _full_schema:
        cat = tool_def.get("category", "unknown")
        groups.setdefault(cat, []).append(tool_def["name"])

    result = []
    for name, tools in sorted(groups.items()):
        result.append({
            "group": name,
            "tool_count": len(tools),
            "loaded": name in _loaded_groups,
            "core": name in CORE_GROUPS,
            "tools": sorted(tools),
        })
    return result


def _fetch_and_register_schema(load_all: bool = False) -> int:
    """Fetch /mcp/schema from connected instance and register tools.

    Args:
        load_all: If True, register all tools. If False, only core groups.

    Returns: count of registered tools.
    """
    text, status = do_request("GET", "/mcp/schema", timeout=10)
    if status != 200:
        raise RuntimeError(f"Failed to fetch schema: HTTP {status}")
    schema = json.loads(text)
    groups = None if load_all else CORE_GROUPS
    return register_tools_from_schema(schema, groups=groups)


async def _notify_tools_changed(ctx: Context | None) -> None:
    """Send tools/list_changed notification if context is available."""
    if ctx is not None and ctx._request_context is not None:
        await ctx.request_context.session.send_tool_list_changed()


# ==========================================================================
# Static MCP tools (always available)
# ==========================================================================


@mcp.tool()
def list_instances() -> str:
    """
    List all running Ghidra instances discovered via Unix domain sockets.

    Returns JSON with each instance's project name, PID, open programs, and socket path.
    Also shows which instance is currently connected.
    """
    instances = discover_instances()
    if not instances:
        return json.dumps({"instances": [], "note": "No running Ghidra instances found."})
    for inst in instances:
        inst["connected"] = inst["socket"] == _active_socket
    return json.dumps({"instances": instances}, indent=2)


@mcp.tool()
async def connect_instance(project: str, ctx: Context | None = None) -> str:
    """
    Switch the MCP bridge to a different Ghidra instance by project name.

    After connecting, fetches the tool schema from the instance and dynamically
    registers all available tools. Use list_instances() first to see available instances.

    Args:
        project: Project name (or substring) to connect to
    """
    global _active_socket, _active_tcp, _transport_mode

    instances = discover_instances()

    # Try UDS instances first
    if instances:
        match = None
        for inst in instances:
            if inst.get("project", "") == project:
                match = inst
                break
        if not match:
            for inst in instances:
                if project.lower() in inst.get("project", "").lower():
                    match = inst
                    break
        if match:
            _active_socket = match["socket"]
            _active_tcp = None
            _transport_mode = "uds"

            try:
                count = _fetch_and_register_schema()
                total = len(_full_schema)
                await _notify_tools_changed(ctx)
                return json.dumps({
                    "connected": True,
                    "transport": "uds",
                    "project": match.get("project"),
                    "socket": match["socket"],
                    "pid": match.get("pid"),
                    "tools_registered": count,
                    "tools_total": total,
                    "loaded_groups": sorted(_loaded_groups),
                    "note": f"Loaded {count}/{total} tools (core groups). Use load_tool_group() for more.",
                })
            except Exception as e:
                return json.dumps({"error": f"Schema fetch failed: {e}", "socket": _active_socket})

    # Try TCP fallback
    tcp_url = os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)
    try:
        _active_tcp = tcp_url
        _active_socket = None
        _transport_mode = "tcp"
        count = _fetch_and_register_schema()
        total = len(_full_schema)
        await _notify_tools_changed(ctx)
        return json.dumps({
            "connected": True,
            "transport": "tcp",
            "url": tcp_url,
            "tools_registered": count,
            "tools_total": total,
            "loaded_groups": sorted(_loaded_groups),
        })
    except Exception as e:
        _transport_mode = "none"
        _active_tcp = None
        available = [inst.get("project", "unknown") for inst in instances]
        return json.dumps({
            "error": f"No instance matching '{project}' (UDS: {len(instances)} found, TCP {tcp_url}: {e})",
            "available": available,
        })


@mcp.tool()
def list_tool_groups() -> str:
    """
    List all available tool groups with their tool counts and loaded status.

    Returns each category with: tool count, loaded status, and tool names.
    Use load_tool_group(group) to load a group's tools.
    """
    if not _full_schema:
        return json.dumps({"error": "No instance connected. Use connect_instance() first."})
    groups = _get_group_info()
    return json.dumps({"groups": groups, "total_tools": len(_full_schema)}, indent=2)


@mcp.tool()
async def load_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Load all tools in a category. Accepts a category name or "all" to load everything.

    Use list_tool_groups() to see available categories.

    Args:
        group: Category name (e.g. "function", "datatype") or "all"
    """
    if not _full_schema:
        return json.dumps({"error": "No instance connected. Use connect_instance() first."})

    if group == "all":
        # Load all unloaded groups
        all_groups = {td.get("category", "unknown") for td in _full_schema}
        total = 0
        for g in all_groups:
            total += _load_group(g)
        if total > 0:
            await _notify_tools_changed(ctx)
        return json.dumps({
            "loaded": "all",
            "new_tools": total,
            "total_loaded": len(_dynamic_tool_names),
        })

    count = _load_group(group)
    if count == 0:
        available = sorted({td.get("category", "unknown") for td in _full_schema})
        if group in _loaded_groups:
            return json.dumps({"message": f"Group '{group}' is already loaded.", "loaded_groups": sorted(_loaded_groups)})
        return json.dumps({"error": f"No tools found for group '{group}'", "available": available})

    await _notify_tools_changed(ctx)
    return json.dumps({
        "loaded": group,
        "new_tools": count,
        "total_loaded": len(_dynamic_tool_names),
        "loaded_groups": sorted(_loaded_groups),
    })


@mcp.tool()
async def unload_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Unload all tools in a category. Core tools are protected from unloading.

    Args:
        group: Category name to unload
    """
    if group in CORE_GROUPS:
        return json.dumps({"error": f"Cannot unload core group '{group}'", "core_groups": sorted(CORE_GROUPS)})

    count = _unload_group(group)
    if count == 0:
        return json.dumps({"message": f"Group '{group}' is not loaded or has no tools."})

    await _notify_tools_changed(ctx)
    return json.dumps({
        "unloaded": group,
        "removed_tools": count,
        "total_loaded": len(_dynamic_tool_names),
        "loaded_groups": sorted(_loaded_groups),
    })


# ==========================================================================
# Auto-connect on startup
# ==========================================================================


def _auto_connect():
    """Try to auto-connect to a single running instance on startup."""
    global _active_socket, _active_tcp, _transport_mode

    # Try UDS first
    instances = discover_instances()
    if len(instances) == 1:
        _active_socket = instances[0]["socket"]
        _transport_mode = "uds"
        logger.info(f"Auto-connecting via UDS to {instances[0].get('project', 'unknown')}")
        try:
            count = _fetch_and_register_schema()
            logger.info(f"Auto-registered {count} tools from {instances[0].get('project', 'unknown')}")
            return
        except Exception as e:
            logger.warning(f"UDS auto-connect schema fetch failed: {e}")
            _active_socket = None
            _transport_mode = "none"
    elif len(instances) > 1:
        logger.info(f"Multiple UDS instances found ({len(instances)}). Use connect_instance() to choose.")

    # Try TCP fallback
    tcp_url = os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)
    try:
        _active_tcp = tcp_url
        _transport_mode = "tcp"
        count = _fetch_and_register_schema()
        logger.info(f"Auto-connected via TCP to {tcp_url}, registered {count} tools")
    except Exception:
        _active_tcp = None
        _transport_mode = "none"
        if not instances:
            logger.info("No Ghidra instances found. Tools will be registered on connect_instance().")


_auto_connect()


# ==========================================================================
# Main
# ==========================================================================


def main():
    parser = argparse.ArgumentParser(description="GhidraMCP Bridge — MCP↔HTTP multiplexer")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="Host for SSE transport")
    parser.add_argument("--mcp-port", type=int, help="Port for SSE transport")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="MCP transport")
    args = parser.parse_args()

    if args.transport == "sse":
        mcp.settings.log_level = "INFO"
        mcp.settings.host = args.mcp_host
        if args.mcp_port:
            mcp.settings.port = args.mcp_port
        logger.info("Starting MCP bridge (SSE)")
        mcp.run(transport="sse")
    else:
        mcp.run()


if __name__ == "__main__":
    main()

# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp>=1.2.0,<2",
# ]
# ///
"""
GhidraMCP Bridge — thin MCP↔HTTP multiplexer over Unix domain sockets.

On startup: exposes list_instances + connect_instance.
On connect_instance: fetches /mcp/schema from the Ghidra UDS server,
dynamically registers every tool. All dynamic tools are generic HTTP dispatchers.
"""

import argparse
import json
import logging
import os
import socket
import time
import http.client
from pathlib import Path
from urllib.parse import urlencode

from mcp.server.fastmcp import FastMCP

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
    "default": 30,
}

# Logging
LOG_LEVEL = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global state
mcp = FastMCP("ghidra-mcp")
_active_socket: str | None = None

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
        return True


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
# Instance discovery (live queries via UDS)
# ==========================================================================


def discover_instances() -> list[dict]:
    """Scan socket directory and query each live instance for info."""
    socket_dir = get_socket_dir()
    if not socket_dir.exists():
        return []

    instances = []
    for sock_file in sorted(socket_dir.glob("*.sock")):
        # Extract PID from filename: ghidra-<pid>.sock
        name = sock_file.stem
        dash = name.rfind("-")
        if dash < 0:
            continue
        try:
            pid = int(name[dash + 1 :])
        except ValueError:
            continue

        if not is_pid_alive(pid):
            logger.debug(f"Cleaning up stale socket: {sock_file}")
            try:
                sock_file.unlink(missing_ok=True)
            except OSError:
                pass
            continue

        # Query live instance info
        info = {"socket": str(sock_file), "pid": pid}
        try:
            text, status = uds_request(str(sock_file), "GET", "/mcp/instance_info", timeout=5)
            if status == 200:
                info.update(json.loads(text))
        except Exception as e:
            logger.debug(f"Could not query {sock_file}: {e}")

        instances.append(info)

    return instances


# ==========================================================================
# HTTP dispatch via UDS
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
    """GET request via UDS. Returns raw response text."""
    sock = _active_socket
    if not sock:
        return json.dumps({"error": "No Ghidra instance connected. Use connect_instance() first."})

    timeout = get_timeout(endpoint)
    for attempt in range(retries):
        try:
            text, status = uds_request(sock, "GET", endpoint, params=params, timeout=timeout)
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
    """POST JSON request via UDS. Returns raw response text."""
    sock = _active_socket
    if not sock:
        return json.dumps({"error": "No Ghidra instance connected. Use connect_instance() first."})

    timeout = get_timeout(endpoint, data)
    for attempt in range(retries):
        try:
            text, status = uds_request(sock, "POST", endpoint, json_data=data, timeout=timeout)
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
_full_schema: list[dict] = []
_loaded_groups: set[str] = set()

CORE_TOOLS = {
    "list_functions", "decompile_function", "rename_function",
    "list_data_types", "get_function_xrefs", "get_metadata",
    "search_functions", "list_open_programs",
}
LOAD_ALL_TOOLS = os.getenv("GHIDRA_MCP_LOAD_ALL", "").lower() in ("1", "true", "yes")


def _build_tool_function(endpoint: str, http_method: str, params_schema: dict):
    """Build a callable that dispatches to the Ghidra HTTP endpoint."""
    import inspect

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


def _register_tool_list(tools: list[dict]) -> int:
    """Register a list of tool defs, skipping already-registered ones. Returns count added."""
    count = 0
    for tool_def in tools:
        name = tool_def["name"]
        if name in _dynamic_tool_names:
            continue
        description = tool_def.get("description", "")
        endpoint = tool_def["endpoint"]
        http_method = tool_def.get("http_method", "GET")
        input_schema = tool_def.get("input_schema", {"type": "object", "properties": {}})

        handler = _build_tool_function(endpoint, http_method, input_schema)
        handler.__name__ = name
        handler.__doc__ = description

        mcp.tool(name=name, description=description)(handler)
        _dynamic_tool_names.append(name)
        count += 1
    return count


def _unregister_tools(names: list[str]):
    """Remove tools by name."""
    for name in names:
        try:
            mcp.remove_tool(name)
        except (KeyError, ValueError):
            pass
        if name in _dynamic_tool_names:
            _dynamic_tool_names.remove(name)


def _get_group_tools(group: str) -> list[dict]:
    """Get tool defs belonging to a category."""
    return [t for t in _full_schema if t.get("category", "") == group]


def _get_all_groups() -> dict[str, list[dict]]:
    """Group all tools by category."""
    groups: dict[str, list[dict]] = {}
    for t in _full_schema:
        cat = t.get("category", "uncategorized")
        groups.setdefault(cat, []).append(t)
    return groups


def register_tools_from_schema(schema: list[dict]) -> dict:
    """Store full schema, register core tools (or all if LOAD_ALL_TOOLS). Returns summary."""
    global _dynamic_tool_names, _full_schema, _loaded_groups

    # Unregister any previously registered tools
    for name in list(_dynamic_tool_names):
        try:
            mcp.remove_tool(name)
        except (KeyError, ValueError):
            pass
    _dynamic_tool_names.clear()
    _loaded_groups.clear()
    _full_schema = schema

    groups = _get_all_groups()

    if LOAD_ALL_TOOLS:
        count = _register_tool_list(schema)
        _loaded_groups.update(groups.keys())
        return {"mode": "all", "tools_registered": count, "groups": list(groups.keys())}

    # Register only core tools
    core_defs = [t for t in schema if t["name"] in CORE_TOOLS]
    count = _register_tool_list(core_defs)

    group_summary = {name: len(tools) for name, tools in sorted(groups.items())}
    return {
        "mode": "grouped",
        "core_tools_loaded": count,
        "total_tools_available": len(schema),
        "groups": group_summary,
        "hint": "Use list_tool_groups() to see available groups, load_tool_group(group) to load one.",
    }


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
def connect_instance(project: str) -> str:
    """
    Switch the MCP bridge to a different Ghidra instance by project name.

    After connecting, fetches the tool schema from the instance and dynamically
    registers all available tools. Use list_instances() first to see available instances.

    Args:
        project: Project name (or substring) to connect to
    """
    global _active_socket
    instances = discover_instances()
    if not instances:
        return json.dumps({"error": "No running Ghidra instances found"})

    # Exact match first, then substring
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
    if not match:
        available = [inst.get("project", "unknown") for inst in instances]
        return json.dumps({"error": f"No instance matching '{project}'", "available": available})

    _active_socket = match["socket"]

    # Fetch schema and register tools
    try:
        text, status = uds_request(_active_socket, "GET", "/mcp/schema", timeout=10)
        if status != 200:
            return json.dumps({"error": f"Failed to fetch schema: HTTP {status}"})
        schema = json.loads(text)
        reg_result = register_tools_from_schema(schema)

        return json.dumps({
            "connected": True,
            "project": match.get("project"),
            "socket": match["socket"],
            "pid": match.get("pid"),
            **reg_result,
        })
    except Exception as e:
        return json.dumps({"error": f"Schema fetch failed: {e}", "connected_socket": _active_socket})


@mcp.tool()
def list_tool_groups() -> str:
    """
    List all available tool groups with their tool counts and loaded status.

    Returns each category with: tool count, loaded status, and tool names.
    Use load_tool_group(group) to load a group's tools.
    """
    if not _full_schema:
        return json.dumps({"error": "No Ghidra instance connected. Use connect_instance() first."})

    groups = _get_all_groups()
    result = {}
    for name, tools in sorted(groups.items()):
        tool_names = [t["name"] for t in tools]
        loaded_names = [n for n in tool_names if n in _dynamic_tool_names]
        result[name] = {
            "total": len(tools),
            "loaded": len(loaded_names),
            "tools": tool_names,
        }
    return json.dumps({"groups": result, "loaded_groups": sorted(_loaded_groups)}, indent=2)


@mcp.tool()
def load_tool_group(group: str) -> str:
    """
    Load all tools in a category. Accepts a category name or "all" to load everything.

    Use list_tool_groups() to see available categories.

    Args:
        group: Category name (e.g. "function", "datatype") or "all"
    """
    if not _full_schema:
        return json.dumps({"error": "No Ghidra instance connected. Use connect_instance() first."})

    if group == "all":
        count = _register_tool_list(_full_schema)
        _loaded_groups.update(_get_all_groups().keys())
        return json.dumps({"loaded": "all", "tools_added": count, "total_registered": len(_dynamic_tool_names)})

    tools = _get_group_tools(group)
    if not tools:
        available = sorted(_get_all_groups().keys())
        return json.dumps({"error": f"Unknown group '{group}'", "available_groups": available})

    count = _register_tool_list(tools)
    _loaded_groups.add(group)
    return json.dumps({
        "group": group,
        "tools_added": count,
        "total_registered": len(_dynamic_tool_names),
        "tools": [t["name"] for t in tools],
    })


@mcp.tool()
def unload_tool_group(group: str) -> str:
    """
    Unload all tools in a category. Core tools are protected from unloading.

    Args:
        group: Category name to unload
    """
    if not _full_schema:
        return json.dumps({"error": "No Ghidra instance connected. Use connect_instance() first."})

    tools = _get_group_tools(group)
    if not tools:
        available = sorted(_get_all_groups().keys())
        return json.dumps({"error": f"Unknown group '{group}'", "available_groups": available})

    names_to_remove = [t["name"] for t in tools if t["name"] not in CORE_TOOLS]
    protected = [t["name"] for t in tools if t["name"] in CORE_TOOLS]
    _unregister_tools(names_to_remove)
    _loaded_groups.discard(group)

    result = {"group": group, "tools_removed": len(names_to_remove), "total_registered": len(_dynamic_tool_names)}
    if protected:
        result["protected_core_tools"] = protected
    return json.dumps(result)


# ==========================================================================
# Auto-connect on startup
# ==========================================================================


def _auto_connect():
    """Try to auto-connect to a single running instance on startup."""
    instances = discover_instances()
    if len(instances) == 1:
        global _active_socket
        _active_socket = instances[0]["socket"]
        logger.info(f"Auto-connecting to {instances[0].get('project', 'unknown')}")
        try:
            text, status = uds_request(_active_socket, "GET", "/mcp/schema", timeout=10)
            if status == 200:
                schema = json.loads(text)
                reg_result = register_tools_from_schema(schema)
                logger.info(f"Auto-registered tools from {instances[0].get('project', 'unknown')}: {reg_result}")
        except Exception as e:
            logger.warning(f"Auto-connect schema fetch failed: {e}")
    elif len(instances) > 1:
        logger.info(f"Multiple instances found ({len(instances)}). Use connect_instance() to choose.")
    else:
        logger.info("No Ghidra instances found. Tools will be registered on connect_instance().")


_auto_connect()


# ==========================================================================
# Main
# ==========================================================================


def main():
    parser = argparse.ArgumentParser(description="GhidraMCP Bridge — MCP↔UDS multiplexer")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="Host for SSE transport")
    parser.add_argument("--mcp-port", type=int, help="Port for SSE transport")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"], help="MCP transport")
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

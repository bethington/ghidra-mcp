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
import asyncio
import json
import logging
import os
import re
import socket
import time
import threading
import http.client
import inspect
from pathlib import Path
from urllib.parse import urlencode, urlparse

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.lowlevel.server import NotificationOptions

# ==========================================================================
# Configuration
# ==========================================================================

REQUEST_TIMEOUT = 30

# Per-endpoint timeout overrides for expensive operations
ENDPOINT_TIMEOUTS = {
    "rename_variables": 120,
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
    "import_file": 300,
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
        notification_options=NotificationOptions(tools_changed=True), **kwargs
    )


mcp._mcp_server.create_initialization_options = _patched_init_options

_active_socket: str | None = None  # UDS socket path
_active_tcp: str | None = None  # TCP base URL (e.g. "http://127.0.0.1:8089")
_transport_mode: str = "none"  # "uds", "tcp", or "none"

# Serialization lock for Ghidra HTTP calls — prevents stdout corruption when
# multiple MCP tool calls arrive concurrently (see GitHub issue #91).
_ghidra_lock = asyncio.Lock()
_connected_project: str | None = None  # Project name for auto-reconnect

# Serialization lock for Ghidra HTTP calls — prevents stdout corruption when
# multiple MCP tool calls arrive concurrently (see GitHub issue #91).
_ghidra_lock = threading.Lock()


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

    getuid = getattr(os, "getuid", None)
    if callable(getuid):
        run_user_dir = Path(f"/run/user/{getuid()}")
        try:
            if run_user_dir.exists():
                return run_user_dir / "ghidra-mcp"
        except OSError:
            logger.debug("Ignoring unusable runtime dir candidate: %s", run_user_dir)

    user = os.getenv("USER", "unknown")
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        return Path(tmpdir) / f"ghidra-mcp-{user}"
    return Path(f"/tmp/ghidra-mcp-{user}")


# Enhanced error classes
class GhidraConnectionError(Exception):
    """Raised when connection to Ghidra server fails"""

    pass


class GhidraAnalysisError(Exception):
    """Raised when Ghidra analysis operation fails"""

    pass


class GhidraValidationError(Exception):
    """Raised when input validation fails"""

    pass


# Input validation patterns
HEX_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]+$")
SEGMENT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*:[0-9a-fA-F]+$")
# Handles space:0xHEX form (e.g., mem:0x1000, code:0xFF00).
# Must be checked BEFORE SEGMENT_ADDRESS_PATTERN because the 'x' in '0x' is not
# in [0-9a-fA-F], so the existing pattern rejects this form entirely.
SEGMENT_ADDR_WITH_0X_PATTERN = re.compile(
    r"^([a-zA-Z_][a-zA-Z0-9_]*):0[xX]([0-9a-fA-F]+)$"
)
FUNCTION_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # Running but owned by another user
    except OSError as e:
        # Windows may raise WinError 87 ("The parameter is incorrect")
        # for clearly invalid PIDs instead of ProcessLookupError.
        if getattr(e, "winerror", None) == 87:
            return False
        raise


def validate_server_url(url: str) -> bool:
    """Validate that the server URL is safe to use"""
    try:
        parsed = urlparse(url)
        return parsed.hostname in ("127.0.0.1", "localhost", "::1")
    except Exception:
        return False


def validate_hex_address(address: str) -> bool:
    """Validate that an address string looks like a valid hex address or segment:offset."""
    if not address:
        return False
    if SEGMENT_ADDR_WITH_0X_PATTERN.match(address):
        return True
    if SEGMENT_ADDRESS_PATTERN.match(address):
        return True
    return bool(HEX_ADDRESS_PATTERN.match(address))


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
    """Route request to the active transport (UDS or TCP).

    All requests are serialized via _ghidra_lock to prevent concurrent
    responses from corrupting JSON-RPC framing on stdio (GitHub #91).
    """
    with _ghidra_lock:
        if _transport_mode == "uds" and _active_socket:
            return uds_request(_active_socket, method, endpoint, params, json_data, timeout)
        elif _transport_mode == "tcp" and _active_tcp:
            return tcp_request(_active_tcp, method, endpoint, params, json_data, timeout)
        else:
            raise ConnectionError(
                "No Ghidra instance connected. Use connect_instance() first."
            )


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

        info: dict = {"socket": str(sock_file), "pid": pid}
        try:
            text, status = uds_request(
                str(sock_file), "GET", "/mcp/instance_info", timeout=5
            )
            if status == 200:
                info.update(_unwrap_response_data(text))
        except Exception as e:
            logger.debug(f"Could not query {sock_file}: {e}")

        instances.append(info)

    return instances


def _unwrap_response_data(text: str) -> dict:
    """Unwrap Response.ok() payloads while preserving plain JSON responses."""
    data = json.loads(text)
    if isinstance(data, dict) and "data" in data:
        return data["data"]
    return data


def discover_active_tcp_instance() -> dict | None:
    """Return the active TCP fallback connection as an instance-like record."""
    if _transport_mode != "tcp" or not _active_tcp:
        return None

    info: dict = {
        "transport": "tcp",
        "url": _active_tcp,
        "discovery": "active-tcp",
    }
    if _connected_project:
        info["project"] = _connected_project

    try:
        text, status = tcp_request(_active_tcp, "GET", "/mcp/instance_info", timeout=5)
        if status == 200:
            info.update(_unwrap_response_data(text))
            return info
    except Exception as e:
        logger.debug(f"Could not query TCP instance info for {_active_tcp}: {e}")

    try:
        text, status = tcp_request(_active_tcp, "GET", "/list_open_programs", timeout=5)
        if status == 200:
            data = _unwrap_response_data(text)
            if isinstance(data, dict):
                for key in ("programs", "count", "current_program"):
                    if key in data:
                        info[key] = data[key]
    except Exception as e:
        logger.debug(
            f"Could not query open programs for active TCP instance {_active_tcp}: {e}"
        )

    return info


# ==========================================================================
# HTTP dispatch
# ==========================================================================


def get_timeout(endpoint: str, payload: dict | None = None) -> int:
    """Get timeout for an endpoint, with dynamic scaling for batch ops."""
    name = endpoint.strip("/").split("/")[-1]
    base = ENDPOINT_TIMEOUTS.get(name, ENDPOINT_TIMEOUTS["default"])

    if not payload:
        return base

    if name in {"rename_variables", "batch_rename_variables"}:
        count = len(payload.get("variable_renames", {}))
        return min(base + count * 38, 600)

    if name == "batch_set_comments":
        count = len(payload.get("decompiler_comments", []))
        count += len(payload.get("disassembly_comments", []))
        count += 1 if payload.get("plate_comment") else 0
        return min(base + count * 8, 600)

    return base


def _try_reconnect() -> bool:
    """Try to reconnect to the previously connected project after Ghidra restarts.

    Scans for UDS instances matching _connected_project. If found, updates the
    active socket and re-fetches the schema. Returns True if reconnected.
    """
    global _active_socket, _active_tcp, _transport_mode

    if not _connected_project:
        return False

    instances = discover_instances()
    for inst in instances:
        if inst.get("project", "") == _connected_project:
            _active_socket = inst["socket"]
            _active_tcp = None
            _transport_mode = "uds"
            try:
                _fetch_and_register_schema()
                logger.info(
                    f"Reconnected to project '{_connected_project}' via {inst['socket']}"
                )
                return True
            except Exception as e:
                logger.warning(f"Reconnect schema fetch failed: {e}")
                return False

    # Exact match failed, try substring
    for inst in instances:
        if _connected_project.lower() in inst.get("project", "").lower():
            _active_socket = inst["socket"]
            _active_tcp = None
            _transport_mode = "uds"
            try:
                _fetch_and_register_schema()
                logger.info(
                    f"Reconnected to project '{inst.get('project')}' via {inst['socket']}"
                )
                return True
            except Exception as e:
                logger.warning(f"Reconnect schema fetch failed: {e}")
                return False

    return False


def _ensure_connected() -> str | None:
    """Check connection and attempt reconnect if needed. Returns error string or None."""
    if _transport_mode == "none":
        if _connected_project:
            if _try_reconnect():
                return None
            return (
                f"Ghidra instance for project '{_connected_project}' is not running. "
                "Start Ghidra and open the project, then retry."
            )
        return "No Ghidra instance connected. Use connect_instance() first."
    return None


def sanitize_address(address: str) -> str:
    """Normalize address format for Ghidra AddressFactory.

    Handles:
    - space:0xHEX  -> space:HEX   (strip 0x from offset; AddressFactory rejects 0x after colon)
    - SPACE:HEX    -> space:HEX   (lowercase space name; AddressFactory is case-sensitive)
    - 0xHEX        -> 0xhex       (lowercase)
    - HEX          -> 0xHEX       (add 0x prefix)
    """
    if not address:
        return address
    address = address.strip()

    # Step 1: handle space:0xHEX form (checked first — 'x' not in [0-9a-fA-F])
    m = SEGMENT_ADDR_WITH_0X_PATTERN.match(address)
    if m:
        # Lowercase space name; preserve offset case (AddressFactory handles hex case)
        return f"{m.group(1).lower()}:{m.group(2)}"

    # Step 2: normalize valid space:HEX form (lowercase space name only)
    if SEGMENT_ADDRESS_PATTERN.match(address):
        space, offset = address.split(":", 1)
        return f"{space.lower()}:{offset}"

    # Step 3: plain hex normalization (unchanged logic)
    if not address.startswith(("0x", "0X")):
        address = "0x" + address
    return address.lower()


def dispatch_get(endpoint: str, params: dict | None = None, retries: int = 3) -> str:
    """GET request via active transport. Returns raw response text."""
    err = _ensure_connected()
    if err:
        return json.dumps({"error": err})

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
        except (ConnectionError, OSError) as e:
            # Connection lost — try reconnect once, then retry
            if attempt == 0 and _try_reconnect():
                continue
            if attempt < retries - 1:
                continue
            return json.dumps({"error": str(e)})
        except Exception as e:
            if attempt < retries - 1:
                continue
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})


def dispatch_post(endpoint: str, data: dict, retries: int = 3, query_params: dict | None = None) -> str:
    """POST JSON request via active transport. Returns raw response text."""
    err = _ensure_connected()
    if err:
        return json.dumps({"error": err})

    timeout = get_timeout(endpoint, data)
    for attempt in range(retries):
        try:
            text, status = do_request("POST", endpoint, params=query_params, json_data=data, timeout=timeout)
            if status == 200:
                return text.strip()
            if status >= 500 and attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except (ConnectionError, OSError) as e:
            # Connection lost — try reconnect once, then retry
            if attempt == 0 and _try_reconnect():
                continue
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": str(e)})
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})


# ==========================================================================
# Schema parsing — converts upstream /mcp/schema to internal tool defs
# ==========================================================================

# JSON type → Python type mapping
_TYPE_MAP = {
    "string": str,
    "json": str,
    "integer": int,
    "boolean": bool,
    "number": float,
    "object": dict,
    "array": list,
    "any": str,
    "address": str,
}


def _parse_schema(raw: dict) -> list[dict]:
    """Convert upstream AnnotationScanner schema to internal tool defs.

    Upstream format: {"tools": [{"path", "method", "description", "category", "params": [...]}]}
    Internal format: [{"name", "endpoint", "http_method", "description", "category", "input_schema"}]
    """
    tool_defs = []
    for tool in raw.get("tools", []):
        path = tool["path"]
        name = path.lstrip("/")
        params = tool.get("params", [])

        properties = {}
        required = []
        for p in params:
            pdef: dict = {"type": p.get("type", "string")}
            if p.get("description"):
                pdef["description"] = p["description"]
            if "default" in p and p["default"] is not None:
                pdef["default"] = p["default"]
            properties[p["name"]] = pdef
            if p.get("required", False):
                required.append(p["name"])

        tool_defs.append(
            {
                "name": name,
                "endpoint": path,
                "http_method": tool.get("method", "GET"),
                "description": tool.get("description", ""),
                "category": tool.get("category", "unknown"),
                "category_description": tool.get("category_description", ""),
                "input_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            }
        )

    return tool_defs


# ==========================================================================
# Dynamic tool registration from /mcp/schema
# ==========================================================================

# Static tool names that should not be overwritten by dynamic registration
STATIC_TOOL_NAMES = {
    "list_instances",
    "connect_instance",
    "list_tool_groups",
    "load_tool_group",
    "unload_tool_group",
    "check_tools",
    "import_file",
    # Debugger tools (Phase 1+2+3)
    "debugger_attach",
    "debugger_detach",
    "debugger_status",
    "debugger_modules",
    "debugger_resolve_ordinal",
    "debugger_set_breakpoint",
    "debugger_remove_breakpoint",
    "debugger_list_breakpoints",
    "debugger_continue",
    "debugger_step_into",
    "debugger_step_over",
    "debugger_registers",
    "debugger_read_memory",
    "debugger_stack_trace",
    "debugger_read_args",
    "debugger_trace_function",
    "debugger_trace_stop",
    "debugger_trace_log",
    "debugger_trace_list",
    "debugger_watch_memory",
    "debugger_watch_stop",
    "debugger_watch_log",
}

_dynamic_tool_names: list[str] = []
_full_schema: list[dict] = []  # Complete parsed schema
_loaded_groups: set[str] = set()

# Core groups always loaded on connect (essential for basic RE workflow)
CORE_GROUPS = {"listing", "function", "program"}

# CLI-configurable: --lazy keeps only default groups, otherwise load all
_lazy_mode = True  # default: lazy (only load default groups on connect)
_default_groups: set[str] = CORE_GROUPS


def _build_tool_function(endpoint: str, http_method: str, params_schema: dict):
    """Build a callable that dispatches to the Ghidra HTTP endpoint."""
    properties = params_schema.get("properties", {})
    required = set(params_schema.get("required", []))

    def handler(**kwargs):
        # Sanitize address parameters before dispatch
        for pname, pdef in properties.items():
            if (
                pdef.get("paramType") == "address"
                and pname in kwargs
                and kwargs[pname] is not None
            ):
                kwargs[pname] = sanitize_address(str(kwargs[pname]))
        # Extract dry_run before filtering — it goes as a query param, not in the body
        dry_run = kwargs.pop("dry_run", None)
        # Filter out None AND empty strings. Codex's MCP client passes schema
        # default values (including "") to every call, which the Ghidra
        # handler treats as "present but empty" and fails on params that
        # require a real value (e.g. /get_function_callers rejects empty
        # name/address). minimax avoids this by only sending params the LLM
        # explicitly provided, but the bridge is schema-driven and doesn't
        # know which were defaults. Empty string is not a meaningful value
        # for any current Ghidra endpoint — safe to filter.
        filtered = {
            k: v for k, v in kwargs.items()
            if v is not None and not (isinstance(v, str) and v == "")
        }
        if http_method == "GET":
            str_params = {k: str(v) for k, v in filtered.items()}
            if dry_run:
                str_params["dry_run"] = "true"
            return dispatch_get(endpoint, params=str_params if str_params else None)
        else:
            if dry_run:
                return dispatch_post(
                    endpoint,
                    data=filtered,
                    query_params={"dry_run": "true"},
                )
            return dispatch_post(endpoint, data=filtered)

    # Build function signature with proper types and defaults
    # Params with defaults must come after params without defaults
    required_params = []
    optional_params = []
    for pname, pdef in properties.items():
        json_type = pdef.get("type", "string")
        py_type = _TYPE_MAP.get(json_type, str)
        default = pdef.get("default", inspect.Parameter.empty)
        if pname not in required and default is inspect.Parameter.empty:
            default = None
            py_type = py_type | None if py_type != str else str | None

        param = inspect.Parameter(
            pname, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=py_type
        )
        if default is inspect.Parameter.empty:
            required_params.append(param)
        else:
            optional_params.append(param)

    sig_params = required_params + optional_params
    # Add dry_run parameter for POST (write) endpoints
    if http_method == "POST":
        sig_params.append(
            inspect.Parameter(
                "dry_run", inspect.Parameter.KEYWORD_ONLY,
                default=False, annotation=bool
            )
        )
    handler.__signature__ = inspect.Signature(sig_params, return_annotation=str)
    handler.__annotations__ = {p.name: p.annotation for p in sig_params}
    handler.__annotations__["return"] = str

    return handler


def _register_tool_def(tool_def: dict) -> bool:
    """Register a single tool from a schema definition. Returns True if registered."""
    name = tool_def["name"]
    if name in STATIC_TOOL_NAMES:
        return False  # Don't overwrite static tools
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


def register_tools_from_schema(
    schema: list[dict], groups: set[str] | None = None
) -> int:
    """Register MCP tools from parsed schema.

    Args:
        schema: List of parsed tool definitions.
        groups: If provided, only register tools in these groups. None = register all.

    Returns: count of registered tools.
    """
    global _dynamic_tool_names, _full_schema, _loaded_groups

    # Remove previously registered dynamic tools
    for name in _dynamic_tool_names:
        try:
            mcp._tool_manager._tools.pop(name, None)
        except Exception:
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


def _load_group(group_name: str) -> list[str]:
    """Load tools for a specific group from cached schema. Returns list of newly loaded tool names."""
    loaded_names: list[str] = []
    for tool_def in _full_schema:
        if tool_def.get("category") != group_name:
            continue
        name = tool_def["name"]
        if name in _dynamic_tool_names:
            continue  # Already loaded
        _register_tool_def(tool_def)
        loaded_names.append(name)
    if loaded_names:
        _loaded_groups.add(group_name)
    return loaded_names


def _unload_group(group_name: str) -> int:
    """Unload tools for a specific group. Returns count of removed tools."""
    if group_name in _default_groups:
        return 0  # Default groups can't be unloaded

    to_remove = []
    for tool_def in _full_schema:
        if tool_def.get("category") == group_name:
            name = tool_def["name"]
            if name in _dynamic_tool_names:
                to_remove.append(name)

    for name in to_remove:
        try:
            mcp._tool_manager._tools.pop(name, None)
            _dynamic_tool_names.remove(name)
        except Exception:
            pass

    if to_remove:
        _loaded_groups.discard(group_name)
    return len(to_remove)


def _get_group_info() -> list[dict]:
    """Get info about all tool groups from cached schema."""
    groups: dict[str, list[str]] = {}
    descriptions: dict[str, str] = {}
    for tool_def in _full_schema:
        cat = tool_def.get("category", "unknown")
        groups.setdefault(cat, []).append(tool_def["name"])
        if cat not in descriptions and tool_def.get("category_description"):
            descriptions[cat] = tool_def["category_description"]

    result = []
    for name, tools in sorted(groups.items()):
        info: dict = {
            "group": name,
            "tool_count": len(tools),
            "loaded": name in _loaded_groups,
            "default": name in _default_groups,
        }
        if name in descriptions:
            info["description"] = descriptions[name]
        info["tools"] = sorted(tools)
        result.append(info)
    return result


def _fetch_and_register_schema(load_all: bool = False) -> int:
    """Fetch /mcp/schema from connected instance and register tools.

    Args:
        load_all: If True, register all tools. If False, only default groups.

    Returns: count of registered tools.
    """
    if not load_all:
        load_all = not _lazy_mode
    text, status = do_request("GET", "/mcp/schema", timeout=10)
    if status != 200:
        raise RuntimeError(f"Failed to fetch schema: HTTP {status}")
    raw = json.loads(text)
    schema = _parse_schema(raw)
    groups = None if load_all else _default_groups
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
    List known Ghidra instances from UDS discovery and the active TCP fallback.

    Returns JSON with each instance's project name, PID, open programs, and
    socket path or TCP URL. Also shows which instance is currently connected.
    """
    instances = discover_instances()
    tcp_instance = discover_active_tcp_instance()
    if tcp_instance:
        instances.append(tcp_instance)

    if not instances:
        return json.dumps(
            {"instances": [], "note": "No running Ghidra instances found."}
        )

    for inst in instances:
        if inst.get("transport") == "tcp":
            inst["connected"] = (
                _transport_mode == "tcp" and inst.get("url") == _active_tcp
            )
        else:
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
    global _active_socket, _active_tcp, _transport_mode, _connected_project

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
            _connected_project = match.get("project")

            try:
                count = _fetch_and_register_schema()
                total = len(_full_schema)
                await _notify_tools_changed(ctx)
                return json.dumps(
                    {
                        "connected": True,
                        "transport": "uds",
                        "project": _connected_project,
                        "socket": match["socket"],
                        "pid": match.get("pid"),
                        "tools_registered": count,
                        "tools_total": total,
                        "loaded_groups": sorted(_loaded_groups),
                        "note": f"Loaded {count}/{total} tools (core groups). Use load_tool_group() for more.",
                    }
                )
            except Exception as e:
                return json.dumps(
                    {"error": f"Schema fetch failed: {e}", "socket": _active_socket}
                )

    # Try TCP fallback
    tcp_url = os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)
    if not validate_server_url(tcp_url):
        return json.dumps(
            {
                "error": f"Refusing to connect to non-local URL: {tcp_url}. Only 127.0.0.1, localhost, and ::1 are allowed."
            }
        )
    try:
        _active_tcp = tcp_url
        _active_socket = None
        _transport_mode = "tcp"
        count = _fetch_and_register_schema()
        total = len(_full_schema)
        await _notify_tools_changed(ctx)
        return json.dumps(
            {
                "connected": True,
                "transport": "tcp",
                "url": tcp_url,
                "tools_registered": count,
                "tools_total": total,
                "loaded_groups": sorted(_loaded_groups),
            }
        )
    except Exception as e:
        _transport_mode = "none"
        _active_tcp = None
        available = [inst.get("project", "unknown") for inst in instances]
        return json.dumps(
            {
                "error": f"No instance matching '{project}' (UDS: {len(instances)} found, TCP {tcp_url}: {e})",
                "available": available,
            }
        )


@mcp.tool()
def list_tool_groups() -> str:
    """
    List all available tool groups with their tool counts and loaded status.

    Returns each category with: tool count, loaded status, and tool names.
    Use load_tool_group(group) to load a group's tools.
    """
    if not _full_schema:
        return json.dumps(
            {"error": "No instance connected. Use connect_instance() first."}
        )
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
        return json.dumps(
            {"error": "No instance connected. Use connect_instance() first."}
        )

    if group == "all":
        # Load all unloaded groups
        all_groups = {td.get("category", "unknown") for td in _full_schema}
        all_loaded: list[str] = []
        for g in sorted(all_groups):
            all_loaded.extend(_load_group(g))
        if all_loaded:
            await _notify_tools_changed(ctx)
        return json.dumps(
            {
                "loaded": "all",
                "new_tools": len(all_loaded),
                "new_tool_names": sorted(all_loaded),
                "total_loaded": len(_dynamic_tool_names),
            }
        )

    loaded_names = _load_group(group)
    if not loaded_names:
        available = sorted({td.get("category", "unknown") for td in _full_schema})
        if group in _loaded_groups:
            # Already loaded — return the tool names so the agent knows what's callable
            already = sorted(
                td["name"] for td in _full_schema if td.get("category") == group
            )
            return json.dumps(
                {
                    "message": f"Group '{group}' is already loaded.",
                    "tools": already,
                    "loaded_groups": sorted(_loaded_groups),
                }
            )
        return json.dumps(
            {
                "error": f"No tools found for group '{group}'",
                "available_groups": available,
            }
        )

    await _notify_tools_changed(ctx)
    return json.dumps(
        {
            "loaded": group,
            "new_tools": len(loaded_names),
            "tools": sorted(loaded_names),
            "total_loaded": len(_dynamic_tool_names),
            "loaded_groups": sorted(_loaded_groups),
        }
    )


@mcp.tool()
async def unload_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Unload all tools in a category. Default groups are protected from unloading.

    Args:
        group: Category name to unload
    """
    if group in _default_groups:
        return json.dumps(
            {
                "error": f"Cannot unload default group '{group}'",
                "default_groups": sorted(_default_groups),
            }
        )

    removed = _unload_group(group)
    if removed == 0:
        return json.dumps(
            {"message": f"Group '{group}' is not loaded or has no tools."}
        )

    await _notify_tools_changed(ctx)
    return json.dumps(
        {
            "unloaded": group,
            "removed_tools": removed,
            "total_loaded": len(_dynamic_tool_names),
            "loaded_groups": sorted(_loaded_groups),
        }
    )


@mcp.tool()
async def check_tools(tools: str) -> str:
    """
    Check if specific tools are callable right now. Returns status for each tool:
    "callable", "not_loaded" (exists but group not loaded), or "not_found" (doesn't exist).

    Args:
        tools: Comma-separated tool names, e.g. "rename_or_label,batch_set_comments,analyze_function_completeness"
    """
    tool_names = [t.strip() for t in tools.split(",") if t.strip()]
    if not tool_names:
        return json.dumps({"error": "Provide comma-separated tool names"})

    # Build lookup of all known tools -> their group
    all_known: dict[str, str] = {}
    for td in _full_schema:
        all_known[td["name"]] = td.get("category", "unknown")

    # Check each tool
    results: dict[str, dict] = {}
    for name in tool_names:
        if name in STATIC_TOOL_NAMES:
            results[name] = {"status": "callable", "type": "static"}
        elif name in _dynamic_tool_names:
            results[name] = {
                "status": "callable",
                "group": all_known.get(name, "unknown"),
            }
        elif name in all_known:
            group = all_known[name]
            results[name] = {
                "status": "not_loaded",
                "group": group,
                "fix": f'load_tool_group("{group}")',
            }
        else:
            results[name] = {"status": "not_found"}

    callable_count = sum(1 for r in results.values() if r["status"] == "callable")
    return json.dumps(
        {
            "results": results,
            "summary": f"{callable_count}/{len(tool_names)} callable",
        }
    )


@mcp.tool()
async def import_file(
    file_path: str,
    project_folder: str = "/",
    language: str | None = None,
    compiler_spec: str | None = None,
    auto_analyze: bool = True,
    ctx: Context | None = None,
) -> str:
    """
    Import a binary file from disk into the current Ghidra project.

    Imports the file, opens it in the CodeBrowser, and optionally starts auto-analysis.
    When analysis is enabled, sends a log notification when analysis completes.

    For raw firmware binaries, specify language (e.g. "ARM:LE:32:Cortex") and
    optionally compiler_spec (e.g. "default"). Without language, Ghidra auto-detects
    the format (works for ELF, PE, Mach-O, etc.).

    Args:
        file_path: Absolute path to the binary file on disk
        project_folder: Destination folder in the Ghidra project (default: "/")
        language: Language ID for raw binaries (e.g. "ARM:LE:32:Cortex", "x86:LE:64:default")
        compiler_spec: Compiler spec ID (e.g. "default", "gcc"). Uses language default if omitted.
        auto_analyze: Start auto-analysis after import (default: true)
    """
    payload: dict = {
        "file_path": file_path,
        "project_folder": project_folder,
        "auto_analyze": auto_analyze,
    }
    if language:
        payload["language"] = language
    if compiler_spec:
        payload["compiler_spec"] = compiler_spec

    result = dispatch_post("/import_file", payload)

    # Parse result to check if analysis was started
    try:
        data = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return result

    if data.get("data", {}).get("analyzing") and ctx is not None:
        program_name = data["data"].get("name", "unknown")
        # Capture the session before the tool call returns
        session = ctx.request_context.session

        async def _poll_analysis():
            """Poll analysis_status until analysis completes, then send log notification."""
            await asyncio.sleep(5)  # Initial delay
            for _ in range(360):  # Up to 30 minutes
                try:
                    status_text = dispatch_get(
                        "/analysis_status", {"program": program_name}
                    )
                    status = json.loads(status_text)
                    status_data = status.get("data", status)
                    if not status_data.get("analyzing", True):
                        fn_count = status_data.get("function_count", "?")
                        await session.send_log_message(
                            level="info",
                            data=f"Analysis complete for {program_name}: {fn_count} functions found",
                        )
                        return
                except Exception as e:
                    logger.debug(f"Analysis poll error for {program_name}: {e}")
                await asyncio.sleep(5)

        asyncio.create_task(_poll_analysis())

    return result


# ==========================================================================
# Auto-connect on startup
# ==========================================================================


def _auto_connect():
    """Try to auto-connect to a single running instance on startup."""
    global _active_socket, _active_tcp, _transport_mode, _connected_project

    # Try UDS first
    instances = discover_instances()
    if len(instances) == 1:
        _active_socket = instances[0]["socket"]
        _transport_mode = "uds"
        _connected_project = instances[0].get("project")
        logger.info(f"Auto-connecting via UDS to {_connected_project or 'unknown'}")
        try:
            count = _fetch_and_register_schema()
            logger.info(
                f"Auto-registered {count} tools from {_connected_project or 'unknown'}"
            )
            return
        except Exception as e:
            logger.warning(f"UDS auto-connect schema fetch failed: {e}")
            _active_socket = None
            _transport_mode = "none"
    elif len(instances) > 1:
        logger.info(
            f"Multiple UDS instances found ({len(instances)}). Use connect_instance() to choose."
        )

    # Try TCP fallback
    tcp_url = os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)
    if not validate_server_url(tcp_url):
        logger.warning(f"Refusing to auto-connect to non-local URL: {tcp_url}")
        return
    try:
        _active_tcp = tcp_url
        _transport_mode = "tcp"
        count = _fetch_and_register_schema()
        logger.info(f"Auto-connected via TCP to {tcp_url}, registered {count} tools")
    except Exception:
        _active_tcp = None
        _transport_mode = "none"
        if not instances:
            logger.info(
                "No Ghidra instances found. Tools will be registered on connect_instance()."
            )


# ==========================================================================
# Debugger tools (proxy to debugger/server.py on DEBUGGER_URL)
# ==========================================================================

DEBUGGER_URL = os.getenv("GHIDRA_DEBUGGER_URL", "http://127.0.0.1:8099")


def _debugger_request(method: str, path: str, body: dict | None = None,
                      query: dict | None = None, timeout: int = 30) -> str:
    """Send a request to the debugger server. Returns JSON string."""
    parsed = urlparse(DEBUGGER_URL)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        url = path
        if query:
            url += "?" + urlencode(query)
        headers = {"Content-Type": "application/json"} if body else {}
        conn.request(method, url, body=json.dumps(body) if body else None,
                     headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        if resp.status >= 400:
            try:
                err = json.loads(data)
                return json.dumps({"error": err.get("error", data)})
            except Exception:
                return json.dumps({"error": data})
        return data
    except ConnectionRefusedError:
        return json.dumps({"error": f"Debugger server not running at {DEBUGGER_URL}. "
                           "Start it with: python -m debugger"})
    except Exception as e:
        return json.dumps({"error": f"Debugger request failed: {e}"})
    finally:
        conn.close()


@mcp.tool()
def debugger_attach(target: str) -> str:
    """Attach the debugger to a running process for live dynamic analysis.

    Connects to the target process via dbgeng (WinDbg engine). After attaching,
    use debugger_modules() to see loaded DLLs and debugger_set_breakpoint() to
    set breakpoints.

    Args:
        target: Process name (e.g. "Game.exe") or PID.
    """
    result = _debugger_request("POST", "/debugger/attach", {"target": target})

    # Auto-sync address map if Ghidra is connected
    if _transport_mode != "none":
        try:
            # Fetch image bases from Ghidra for all open programs
            programs_text = dispatch_get("/list_open_programs")
            if programs_text:
                programs_data = json.loads(programs_text)
                programs = programs_data if isinstance(programs_data, list) else programs_data.get("programs", [])
                ghidra_bases = {}
                for prog in programs:
                    prog_path = prog if isinstance(prog, str) else prog.get("path", prog.get("name", ""))
                    if prog_path:
                        try:
                            meta_text = dispatch_get("/get_metadata", params={"program": prog_path})
                            meta = json.loads(meta_text)
                            image_base = meta.get("imageBase", meta.get("image_base"))
                            if image_base:
                                ghidra_bases[prog_path] = image_base
                        except Exception:
                            pass
                if ghidra_bases:
                    _debugger_request("POST", "/debugger/sync_modules",
                                      {"ghidra_bases": ghidra_bases})
        except Exception as e:
            logger.warning(f"Auto-sync address map failed (non-fatal): {e}")

    return result


@mcp.tool()
def debugger_detach() -> str:
    """Detach from the debugged process. The process continues running."""
    return _debugger_request("POST", "/debugger/detach")


@mcp.tool()
def debugger_status() -> str:
    """Get debugger connection status, loaded modules, active traces/watches."""
    return _debugger_request("GET", "/debugger/status")


@mcp.tool()
def debugger_modules() -> str:
    """List loaded modules (DLLs) with runtime and Ghidra base addresses.

    Shows each module's name, runtime base, Ghidra base (if mapped),
    and the address offset between them.
    """
    return _debugger_request("GET", "/debugger/modules")


@mcp.tool()
def debugger_resolve_ordinal(dll: str, ordinal: int) -> str:
    """Resolve a DLL ordinal export to its runtime and Ghidra addresses.

    Uses the ordinal export tables from dll_exports/*.txt combined with
    the current runtime address map.

    Args:
        dll: DLL name (e.g. "D2Common.dll").
        ordinal: Ordinal number (e.g. 10624).
    """
    return _debugger_request("GET", "/debugger/ordinal",
                             query={"dll": dll, "ordinal": str(ordinal)})


@mcp.tool()
def debugger_set_breakpoint(ghidra_address: str, module: str = "",
                            bp_type: str = "software",
                            oneshot: bool = False) -> str:
    """Set a breakpoint at a Ghidra address. Auto-translates to runtime address.

    Args:
        ghidra_address: Address in Ghidra (e.g. "0x6FD9F450").
        module: DLL name for disambiguation (e.g. "D2Common.dll").
        bp_type: "software" (INT3) or "hardware" (debug register).
        oneshot: If true, breakpoint is removed after first hit.
    """
    return _debugger_request("POST", "/debugger/breakpoint", {
        "ghidra_address": ghidra_address,
        "module": module,
        "type": bp_type,
        "oneshot": oneshot,
    })


@mcp.tool()
def debugger_remove_breakpoint(bp_id: int) -> str:
    """Remove a breakpoint by its ID.

    Args:
        bp_id: Breakpoint ID returned by debugger_set_breakpoint.
    """
    return _debugger_request("DELETE", f"/debugger/breakpoint/{bp_id}")


@mcp.tool()
def debugger_list_breakpoints() -> str:
    """List all active breakpoints with their addresses and status."""
    return _debugger_request("GET", "/debugger/breakpoints")


@mcp.tool()
def debugger_continue() -> str:
    """Resume execution of the debugged process.

    Returns immediately. The process runs until a breakpoint is hit,
    an exception occurs, or debugger_interrupt() is called.
    """
    return _debugger_request("POST", "/debugger/go")


@mcp.tool()
def debugger_step_into(count: int = 1) -> str:
    """Single-step into the next instruction(s). Follows calls.

    Args:
        count: Number of instructions to step (default 1).
    """
    return _debugger_request("POST", "/debugger/step_into", {"count": count})


@mcp.tool()
def debugger_step_over(count: int = 1) -> str:
    """Step over the next instruction(s). Steps over calls.

    Args:
        count: Number of instructions to step (default 1).
    """
    return _debugger_request("POST", "/debugger/step_over", {"count": count})


@mcp.tool()
def debugger_registers() -> str:
    """Read all CPU registers. Must be stopped at a breakpoint.

    Returns EAX-EDI, ESP, EBP, EIP, EFLAGS for x86.
    """
    return _debugger_request("GET", "/debugger/registers")


@mcp.tool()
def debugger_read_memory(address: str, size: int = 64,
                         address_type: str = "runtime",
                         module: str = "") -> str:
    """Read memory from the debugged process.

    Returns hex dump and 32-bit DWORD interpretation of the memory region.

    Args:
        address: Memory address (hex, e.g. "0x6FD9F450").
        size: Number of bytes to read (max 4096).
        address_type: "runtime" for live address, "ghidra" to auto-translate.
        module: DLL name when address_type="ghidra" for disambiguation.
    """
    return _debugger_request("GET", "/debugger/memory",
                             query={"address": address, "size": str(size),
                                    "address_type": address_type, "module": module})


@mcp.tool()
def debugger_stack_trace(depth: int = 20) -> str:
    """Get the call stack backtrace with return addresses mapped to Ghidra symbols.

    Args:
        depth: Maximum number of stack frames (default 20).
    """
    return _debugger_request("GET", "/debugger/stack", query={"depth": str(depth)})


@mcp.tool()
def debugger_read_args(convention: str = "__stdcall", count: int = 4,
                       arg_names: str = "") -> str:
    """Read function arguments at the current breakpoint based on calling convention.

    Reads arguments from registers and stack according to the calling convention.
    Must be stopped at a function entry point.

    Args:
        convention: __stdcall, __fastcall, __thiscall, or __cdecl.
        count: Number of arguments to read.
        arg_names: Comma-separated names for readability (e.g. "pUnit,nSkillId").
    """
    return _debugger_request("GET", "/debugger/read_args",
                             query={"convention": convention, "count": str(count),
                                    "arg_names": arg_names})


@mcp.tool()
def debugger_trace_function(ghidra_address: str, module: str = "",
                            convention: str = "__stdcall", arg_count: int = 4,
                            arg_names: str = "", capture_return: bool = False,
                            max_hits: int = 0) -> str:
    """Start non-breaking tracing on a function. Logs every call with arguments
    WITHOUT stopping the game.

    The handler reads arguments and auto-resumes execution in ~0.5ms,
    invisible at the game's 25fps. Use debugger_trace_log() to read results.

    Args:
        ghidra_address: Function address in Ghidra.
        module: DLL name (e.g. "D2Common.dll").
        convention: __stdcall, __fastcall, __thiscall, __cdecl.
        arg_count: Number of arguments to capture.
        arg_names: Comma-separated arg names (e.g. "pUnit,nSkillId,nWeaponSpeed").
        capture_return: Also capture return value (EAX).
        max_hits: Stop tracing after N hits (0 = unlimited).
    """
    return _debugger_request("POST", "/debugger/trace/start", {
        "ghidra_address": ghidra_address,
        "module": module,
        "convention": convention,
        "arg_count": arg_count,
        "arg_names": arg_names,
        "capture_return": capture_return,
        "max_hits": max_hits,
    })


@mcp.tool()
def debugger_trace_stop(trace_id: int = -1) -> str:
    """Stop a function trace. Use trace_id=-1 to stop all traces.

    Args:
        trace_id: ID returned by debugger_trace_function, or -1 for all.
    """
    return _debugger_request("POST", "/debugger/trace/stop",
                             {"trace_id": trace_id})


@mcp.tool()
def debugger_trace_log(trace_id: int = -1, last_n: int = 50) -> str:
    """Read the trace log. Shows timestamped function calls with arguments.

    Args:
        trace_id: Filter by trace ID, or -1 for all traces.
        last_n: Number of most recent entries to return.
    """
    return _debugger_request("GET", "/debugger/trace/log",
                             query={"trace_id": str(trace_id),
                                    "last_n": str(last_n)})


@mcp.tool()
def debugger_trace_list() -> str:
    """List all active and completed traces with hit counts."""
    return _debugger_request("GET", "/debugger/trace/list")


@mcp.tool()
def debugger_watch_memory(ghidra_address: str, size: int = 4,
                          access: str = "write", module: str = "") -> str:
    """Set a hardware watchpoint on a memory range to monitor read/write access.

    Limited to 4 simultaneous watchpoints (x86 debug register limit).
    Use debugger_watch_log() to see hits.

    Args:
        ghidra_address: Start address in Ghidra.
        size: Bytes to watch (1, 2, or 4).
        access: "read", "write", or "readwrite".
        module: DLL name for address resolution.
    """
    return _debugger_request("POST", "/debugger/watch/start", {
        "ghidra_address": ghidra_address,
        "module": module,
        "size": size,
        "access": access,
    })


@mcp.tool()
def debugger_watch_stop(watch_id: int = -1) -> str:
    """Stop a memory watchpoint. Use watch_id=-1 to stop all.

    Args:
        watch_id: ID returned by debugger_watch_memory, or -1 for all.
    """
    return _debugger_request("POST", "/debugger/watch/stop",
                             {"watch_id": watch_id})


@mcp.tool()
def debugger_watch_log(watch_id: int = -1, last_n: int = 50) -> str:
    """Read the watchpoint hit log. Shows memory accesses with values and accessors.

    Args:
        watch_id: Filter by watch ID, or -1 for all.
        last_n: Number of most recent entries.
    """
    return _debugger_request("GET", "/debugger/watch/log",
                             query={"watch_id": str(watch_id),
                                    "last_n": str(last_n)})


# ==========================================================================
# Main
# ==========================================================================


def main():
    global _lazy_mode, _default_groups

    parser = argparse.ArgumentParser(
        description="GhidraMCP Bridge — MCP↔HTTP multiplexer"
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host for HTTP transport (streamable-http or sse)",
    )
    parser.add_argument(
        "--mcp-port", type=int, help="Port for HTTP transport (streamable-http or sse)"
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse", "streamable-http"],
        help="MCP transport: stdio (default, recommended for AI tools), "
        "streamable-http (recommended for web/HTTP clients), "
        "sse (deprecated, use streamable-http instead)",
    )
    parser.add_argument(
        "--lazy",
        action="store_true",
        default=False,
        help="Only load default tool groups on connect (not recommended for Claude Code)",
    )
    parser.add_argument(
        "--no-lazy",
        dest="lazy",
        action="store_false",
        help="Load all tool groups on connect (default)",
    )
    parser.add_argument(
        "--default-groups",
        type=str,
        default=None,
        help="Comma-separated list of default tool groups to load on connect "
        "(default: listing,function,program)",
    )
    args = parser.parse_args()

    _lazy_mode = args.lazy
    if args.default_groups is not None:
        _default_groups = {
            g.strip() for g in args.default_groups.split(",") if g.strip()
        }

    if not _lazy_mode:
        logger.info(
            "Loading all tool groups on startup (clients that don't support tools/list_changed need this)"
        )
    _auto_connect()

    mcp.settings.log_level = "INFO"
    mcp.settings.host = args.mcp_host
    if args.mcp_port:
        mcp.settings.port = args.mcp_port
    logger.info(f"Starting MCP bridge ({args.transport})")
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()

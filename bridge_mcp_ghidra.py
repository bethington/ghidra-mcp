# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import requests
import argparse
import logging
import time
import re
import json
import socket
import http.client
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode

from mcp.server.fastmcp import FastMCP

# Performance optimization imports
from functools import lru_cache, wraps
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8089"

# Enhanced configuration and state management
# HTTP request timeout (30s chosen for slow decompilation operations)
REQUEST_TIMEOUT = 30
DEFAULT_PAGINATION_LIMIT = 100

# Per-endpoint timeout configuration for expensive operations (v1.6.1)
ENDPOINT_TIMEOUTS = {
    "batch_rename_variables": 120,  # 2 minutes - variable renames trigger re-analysis (increased from 90s)
    "batch_set_comments": 120,  # 2 minutes - multiple comment operations (increased from 90s)
    "analyze_function_complete": 120,  # 2 minutes - comprehensive analysis with decompilation (increased from 90s)
    "batch_rename_function_components": 120,  # 2 minutes - multiple rename operations (increased from 90s)
    "batch_set_variable_types": 90,  # 1.5 minutes - DataType lookups can be slow
    "analyze_data_region": 90,  # 1.5 minutes - complex data analysis
    "batch_create_labels": 60,  # 1 minute - creating multiple labels in transaction
    "delete_label": 30,  # 30 seconds - deleting single label
    "batch_delete_labels": 60,  # 1 minute - deleting multiple labels in transaction
    "set_plate_comment": 45,  # 45 seconds - plate comments can be lengthy
    "get_plate_comment": 10,  # 10 seconds - simple read operation
    "set_function_prototype": 45,  # 45 seconds - prototype changes trigger re-analysis
    "rename_function_by_address": 45,  # 45 seconds - function renames update xrefs
    "rename_variable": 30,  # 30 seconds - single variable rename
    "rename_function": 45,  # 45 seconds - function renames update xrefs
    "decompile_function": 45,  # 45 seconds - decompilation can be slow for large functions
    "disassemble_bytes": 120,  # 2 minutes - disassembly can be slow for large ranges
    "bulk_fuzzy_match": 180,  # 3 minutes - cross-binary bulk matching
    "find_similar_functions_fuzzy": 60,  # 1 minute - single function fuzzy search
    "diff_functions": 30,  # 30 seconds - structured function diff
    "get_function_signature": 10,  # 10 seconds - single signature extraction
    "run_ghidra_script": 1800,  # 30 minutes - scripts can iterate entire projects
    "run_script_inline": 1800,  # 30 minutes - inline scripts can also be long-running
    "default": 30,  # 30 seconds for all other operations
}
# Maximum retry attempts for transient failures (3 attempts with exponential backoff)
MAX_RETRIES = 3
# Exponential backoff factor (0.5s, 1s, 2s, 4s sequence)
RETRY_BACKOFF_FACTOR = 0.5
# Cache size (256 entries ≈ 1MB memory footprint for typical requests)
CACHE_SIZE = 256
ENABLE_CACHING = True

# Tool profiles for reducing schema overhead in specialized workflows
TOOL_PROFILES = {
    "re": {
        "check_connection", "get_current_program_info", "get_metadata",
        "save_program", "exit_ghidra",
        "list_open_programs", "switch_program", "open_program",
        "search_functions_enhanced", "find_next_undefined_function",
        "decompile_function", "analyze_function_complete", "analyze_for_documentation",
        "get_function_variables", "get_function_callees", "get_function_callers",
        "batch_apply_documentation", "analyze_function_completeness",
        "batch_analyze_completeness", "batch_set_variable_types",
        "set_bookmark", "get_function_xrefs",
        "get_function_hash", "propagate_documentation", "build_function_hash_index",
        "run_ghidra_script", "run_script_inline",
        "rename_function_by_address", "set_function_prototype",
        "rename_variables", "batch_set_comments", "set_plate_comment",
        "set_local_variable_type", "rename_or_label",
    },
}


def apply_tool_profile(mcp_instance, profile_name):
    """Remove tools not in the specified profile from the MCP server."""
    if profile_name not in TOOL_PROFILES:
        raise ValueError(f"Unknown profile '{profile_name}'. Available: {list(TOOL_PROFILES.keys())}")
    allowed = TOOL_PROFILES[profile_name]
    tool_mgr = getattr(mcp_instance, '_tool_manager', None)
    if tool_mgr is None:
        logger.warning("Could not access tool manager for profile filtering")
        return
    tools_dict = getattr(tool_mgr, '_tools', None)
    if tools_dict is None:
        logger.warning("Could not access tools dict for profile filtering")
        return
    all_tools = list(tools_dict.keys())
    removed = 0
    for name in all_tools:
        if name not in allowed:
            del tools_dict[name]
            removed += 1
    logger.info(f"Profile '{profile_name}': kept {len(allowed)} tools, removed {removed}")


# Connection pooling for better performance
session = requests.Session()
retry_strategy = Retry(
    total=MAX_RETRIES,
    backoff_factor=RETRY_BACKOFF_FACTOR,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Configure enhanced logging
# Make log level configurable via environment variable (DEBUG, INFO, WARNING, ERROR, CRITICAL)
# Default to INFO for production use
import os

LOG_LEVEL = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url: env var > .env file > default
ghidra_server_url = os.getenv("GHIDRA_SERVER_URL", DEFAULT_GHIDRA_SERVER)


# ==========================================================================
# UNIX DOMAIN SOCKET (UDS) TRANSPORT
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


# Cached active socket path (None = not discovered yet, "" = no UDS available)
_active_socket: str | None = None


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
        return True  # Process exists but we lack permission


def discover_instances() -> list[dict]:
    """Scan the socket directory for active GhidraMCP instances."""
    socket_dir = get_socket_dir()
    if not socket_dir.exists():
        return []

    instances = []
    for sock_file in sorted(socket_dir.glob("*.sock")):
        meta_file = sock_file.with_suffix(".json")
        meta = {}
        if meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text())
            except Exception:
                pass

        pid = meta.get("pid")
        if pid and is_pid_alive(pid):
            instances.append({"socket": str(sock_file), **meta})
        else:
            # Stale socket — clean up
            logger.debug(f"Cleaning up stale socket: {sock_file}")
            try:
                sock_file.unlink(missing_ok=True)
                meta_file.unlink(missing_ok=True)
            except OSError:
                pass

    return instances


def get_active_socket() -> str | None:
    """
    Get the UDS socket path to use for requests.

    Discovery order:
    1. GHIDRA_SOCKET env var (explicit override)
    2. Cached socket from previous discovery
    3. Auto-discover from socket directory

    Returns None if no UDS is available (fall back to TCP).
    """
    global _active_socket

    # Explicit socket override
    explicit = os.environ.get("GHIDRA_SOCKET")
    if explicit:
        return explicit

    # If GHIDRA_SERVER_URL is explicitly set, prefer TCP
    if os.environ.get("GHIDRA_SERVER_URL"):
        return None

    # Return cached socket if still valid
    if _active_socket:
        if Path(_active_socket).exists():
            return _active_socket
        _active_socket = None  # Stale, re-discover

    if _active_socket == "":
        return None  # Previously discovered no sockets

    # Auto-discover
    instances = discover_instances()
    if instances:
        _active_socket = instances[0]["socket"]
        logger.info(f"Auto-discovered GhidraMCP UDS at {_active_socket}")
        return _active_socket

    _active_socket = ""  # Mark as "no UDS available" to avoid repeated scans
    return None


def invalidate_socket_cache():
    """Force re-discovery of UDS sockets on next request."""
    global _active_socket
    _active_socket = None


def uds_request(
    socket_path: str,
    method: str,
    endpoint: str,
    params: dict | None = None,
    form_data: dict | str | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """
    Make an HTTP request over a Unix domain socket.

    Returns (response_body, status_code).
    """
    conn = UnixHTTPConnection(socket_path, timeout=timeout)

    # Build path with query params
    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if params:
        query = urlencode(params)
        path = f"{path}?{query}"

    headers = {}
    body = None

    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif form_data is not None:
        if isinstance(form_data, dict):
            body = urlencode(form_data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = form_data.encode("utf-8") if isinstance(form_data, str) else form_data

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
FUNCTION_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def validate_server_url(url: str) -> bool:
    """Validate that the server URL is safe to use"""
    try:
        parsed = urlparse(url)
        # Only allow HTTP/HTTPS protocols
        if parsed.scheme not in ["http", "https"]:
            return False
        # Only allow local addresses for security
        if parsed.hostname in ["localhost", "127.0.0.1", "::1"]:
            return True
        # Allow private network ranges
        if parsed.hostname and (
            parsed.hostname.startswith("192.168.")
            or parsed.hostname.startswith("10.")
            or parsed.hostname.startswith("172.")
        ):
            return True
        return False
    except Exception:
        return False


def get_timeout_for_endpoint(endpoint: str) -> int:
    """Get the appropriate timeout for a specific endpoint"""
    # Extract endpoint name from URL path
    endpoint_name = endpoint.strip("/").split("/")[-1]
    return ENDPOINT_TIMEOUTS.get(endpoint_name, ENDPOINT_TIMEOUTS["default"])


def calculate_dynamic_timeout(endpoint: str, payload: dict = None) -> int:
    """
    Calculate timeout dynamically based on operation complexity.

    For batch operations, scales timeout based on the number of items being processed.
    This prevents timeouts on large functions while protecting against indefinite hangs.

    Args:
        endpoint: API endpoint name
        payload: Request payload with operation parameters

    Returns:
        Calculated timeout in seconds (capped at 600s / 10 minutes)

    Examples:
        For batch_rename_variables with 14 variables:
        - Base: 120s
        - Per-variable: 25s × 1.5 safety = 37.5s
        - Total: 120 + (14 × 37.5) = 645s → capped at 600s
    """
    # Get base timeout for this endpoint
    endpoint_name = endpoint.strip("/").split("/")[-1]
    base_timeout = ENDPOINT_TIMEOUTS.get(endpoint_name, ENDPOINT_TIMEOUTS["default"])

    # If no payload or not a batch operation, return base timeout
    if not payload:
        return base_timeout

    # Dynamic timeout for batch variable renaming
    # Formula: base + (variables × per_variable_overhead × safety_multiplier)
    if endpoint_name == "batch_rename_variables":
        variable_count = len(payload.get("variable_renames", {}))

        # Per-variable overhead accounts for decompiler refresh on large functions
        # Safety margin accounts for variability in function complexity
        per_variable_time = 25  # seconds (empirical: large function decompile time)
        safety_multiplier = 1.5  # 50% safety margin

        calculated_timeout = int(
            base_timeout + (variable_count * per_variable_time * safety_multiplier)
        )

        # Cap at 10 minutes to prevent indefinite hangs
        max_timeout = 600
        timeout = min(calculated_timeout, max_timeout)

        logger.debug(
            f"Dynamic timeout for {variable_count} variables: {timeout}s (base={base_timeout}s, calculated={calculated_timeout}s)"
        )
        return timeout

    # Dynamic timeout for batch comments
    if endpoint_name == "batch_set_comments":
        comment_count = 0
        comment_count += len(payload.get("decompiler_comments", []))
        comment_count += len(payload.get("disassembly_comments", []))
        comment_count += 1 if payload.get("plate_comment") else 0

        per_comment_time = 5  # seconds per comment
        safety_multiplier = 1.5

        calculated_timeout = int(
            base_timeout + (comment_count * per_comment_time * safety_multiplier)
        )
        max_timeout = 600
        timeout = min(calculated_timeout, max_timeout)

        logger.debug(f"Dynamic timeout for {comment_count} comments: {timeout}s")
        return timeout

    # Dynamic timeout for batch labels
    if endpoint_name == "batch_create_labels":
        label_count = len(payload.get("labels", []))
        per_label_time = 2  # seconds per label
        safety_multiplier = 1.5

        calculated_timeout = int(
            base_timeout + (label_count * per_label_time * safety_multiplier)
        )
        max_timeout = 600
        timeout = min(calculated_timeout, max_timeout)

        logger.debug(f"Dynamic timeout for {label_count} labels: {timeout}s")
        return timeout

    # Default to base timeout for non-batch operations
    return base_timeout


def validate_hex_address(address: str) -> bool:
    """Validate hexadecimal address format"""
    if not address or not isinstance(address, str):
        return False
    return bool(HEX_ADDRESS_PATTERN.match(address))


def sanitize_address(address: str) -> str:
    """
    Normalize address format (handle with/without 0x prefix, case normalization).

    Args:
        address: Address string that may or may not have 0x prefix

    Returns:
        Normalized address with 0x prefix in lowercase

    Examples:
        sanitize_address("401000") -> "0x401000"
        sanitize_address("0X401000") -> "0x401000"
        sanitize_address("0x401000") -> "0x401000"
    """
    if not address:
        return address

    # Remove whitespace
    address = address.strip()

    # Add 0x prefix if not present
    if not address.startswith(("0x", "0X")):
        address = "0x" + address

    # Normalize to lowercase
    return address.lower()


def validate_function_name(name: str) -> bool:
    """Validate function name format"""
    return bool(FUNCTION_NAME_PATTERN.match(name)) if name else False


def normalize_address(address: str) -> str:
    """
    Normalize address to standard format (0x prefix, no leading zeros except for single 0x0).

    Args:
        address: Address in any format

    Returns:
        Normalized address string

    Examples:
        normalize_address("0x00401000") -> "0x401000"
        normalize_address("00401000") -> "0x401000"
        normalize_address("0x10") -> "0x10"
    """
    if not address:
        return address

    # Remove whitespace and lowercase
    address = address.strip().lower()

    # Remove 0x prefix if present
    if address.startswith(("0x", "0X")):
        address = address[2:]

    # Remove leading zeros but keep at least one digit
    address = address.lstrip("0") or "0"

    return "0x" + address


def format_success_response(operation: str, result: dict = None, **kwargs) -> str:
    """
    Format a standardized success response.

    Args:
        operation: Name of the operation
        result: Result data dictionary
        **kwargs: Additional fields to include

    Returns:
        JSON string with success response
    """
    response = {"success": True, "operation": operation}
    if result is not None:
        response["result"] = result
    response.update(kwargs)
    return json.dumps(response)


def format_error_response(
    operation: str, error: str, error_code: str = None, **kwargs
) -> str:
    """
    Format a standardized error response.

    Args:
        operation: Name of the operation
        error: Error message
        error_code: Optional error code
        **kwargs: Additional fields to include

    Returns:
        JSON string with error response
    """
    response = {"success": False, "operation": operation, "error": error}
    if error_code:
        response["error_code"] = error_code
    response.update(kwargs)
    return json.dumps(response)


def calculate_function_hash(bytecode: bytes) -> str:
    """
    Calculate a normalized hash for function bytecode.

    Used for cross-binary function matching.

    Args:
        bytecode: Raw function bytes

    Returns:
        Hex string hash
    """
    import hashlib

    return hashlib.sha256(bytecode).hexdigest()


def validate_hungarian_notation(name: str, type_str: str) -> bool:
    """
    Validate that a variable name follows Hungarian notation for its type.

    Hungarian Notation Rules:
        - Pointers: p prefix (pBuffer, pFunction)
        - Double pointers: pp prefix
        - DWORD/uint: dw prefix
        - WORD/ushort: w prefix
        - BYTE/byte: b prefix
        - BOOL/bool: b or is prefix
        - HANDLE: h prefix
        - Arrays: a or arr prefix
        - Strings: sz or str prefix
        - Counters: c or n prefix

    Args:
        name: Variable name to validate
        type_str: Type string

    Returns:
        True if valid Hungarian notation, False otherwise
    """
    if not name or not type_str:
        return False

    type_lower = type_str.lower()
    name_lower = name.lower()

    # Pointer check
    if "*" in type_str or "ptr" in type_lower:
        if type_str.count("*") >= 2 or "**" in type_str:
            return name_lower.startswith("pp")
        return name_lower.startswith("p")

    # Handle types
    if "handle" in type_lower or type_str.startswith("H"):
        return name_lower.startswith("h")

    # DWORD/uint
    if type_lower in ("dword", "uint", "ulong", "unsigned int", "unsigned long"):
        return name_lower.startswith("dw") or name_lower.startswith("n")

    # WORD/ushort
    if type_lower in ("word", "ushort", "unsigned short"):
        return name_lower.startswith("w")

    # BYTE/byte
    if type_lower in ("byte", "uchar", "unsigned char"):
        return name_lower.startswith("b")

    # Boolean
    if type_lower in ("bool", "boolean"):
        return name_lower.startswith("b") or name_lower.startswith("is")

    # Default - assume valid for unknown types
    return True


def validate_batch_renames(renames: dict) -> bool:
    """
    Validate batch rename parameters.

    Args:
        renames: Dictionary of old_name -> new_name pairs

    Returns:
        True if valid, False otherwise
    """
    if not renames or not isinstance(renames, dict):
        return False

    for old_name, new_name in renames.items():
        if not isinstance(old_name, str) or not isinstance(new_name, str):
            return False
        if not old_name or not new_name:
            return False

    return True


def validate_batch_comments(comments: list) -> bool:
    """
    Validate batch comment parameters.

    Args:
        comments: List of {address, comment} dictionaries

    Returns:
        True if valid, False otherwise
    """
    if not comments or not isinstance(comments, list):
        return False

    for item in comments:
        if not isinstance(item, dict):
            return False
        if "address" not in item or "comment" not in item:
            return False

    return True


def validate_program_path(path: str) -> bool:
    """
    Validate a Ghidra program path.

    Args:
        path: Program path string

    Returns:
        True if valid, False otherwise
    """
    if not path or not isinstance(path, str):
        return False

    # Check for path traversal attempts
    if ".." in path:
        return False

    return True


@mcp.tool()
def validate_data_type_exists(type_name: str, program: str = None) -> str:
    """
    Check if a data type exists in Ghidra before attempting type operations.

    This is a pre-check tool to prevent server 500 errors when setting variable types.
    Use this before calling set_local_variable_type() or batch_set_variable_types().

    Args:
        type_name: The data type name to validate (e.g., "int", "double", "MyStruct", "byte *")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with validation results:
        {
            "exists": true/false,
            "type_name": "double",
            "category": "builtin",
            "size": 8,
            "message": "Data type exists and is valid"
        }

    Examples:
        # Check if type exists before setting
        result = validate_data_type_exists("double")
        if result["exists"]:
            set_local_variable_type("0x401000", "local_c", "double")

        # Check custom struct
        validate_data_type_exists("UnitAny")
    """
    params = {"type_name": type_name}
    return safe_get_json("validate_data_type_exists", params, program=program)


@mcp.tool()
def get_data_type_size(type_name: str, program: str = None) -> str:
    """
    Get the size in bytes of a data type.

    Useful for validating type compatibility before type operations.

    Args:
        type_name: The data type name (e.g., "int", "double", "MyStruct")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with size information:
        {
            "type_name": "double",
            "size": 8,
            "category": "builtin"
        }

    Example:
        size_info = get_data_type_size("double")
        # Returns: {"type_name": "double", "size": 8, "category": "builtin"}
    """
    params = {"type_name": type_name}
    return safe_get_json("get_data_type_size", params, program=program)


def _convert_escaped_newlines(text: str) -> str:
    """Convert escaped newlines (\\n) to actual newlines"""
    if not text:
        return text
    return text.replace("\\n", "\n")


def parse_address_list(addresses: str, param_name: str = "addresses") -> list[str]:
    """
    Parse comma-separated or JSON array of hex addresses with validation.

    Args:
        addresses: Comma-separated addresses or JSON array string
        param_name: Parameter name for error messages (default: "addresses")

    Returns:
        List of validated hex addresses

    Raises:
        GhidraValidationError: If addresses format is invalid or contains invalid hex addresses
    """
    import json

    addr_list = []
    if addresses.startswith("["):
        try:
            addr_list = json.loads(addresses)
        except json.JSONDecodeError as e:
            raise GhidraValidationError(
                f"Invalid JSON array format for {param_name}: {e}"
            )
    else:
        addr_list = [addr.strip() for addr in addresses.split(",") if addr.strip()]

    # Validate all addresses
    for addr in addr_list:
        if not validate_hex_address(addr):
            raise GhidraValidationError(f"Invalid hex address format: {addr}")

    return addr_list


# Performance and caching utilities
from typing import Callable, TypeVar, Any, Optional

T = TypeVar("T")


def cache_key(*args: Any, **kwargs: Any) -> str:
    """
    Generate a cache key from function arguments.

    Returns:
        MD5 hash of serialized arguments
    """
    import json
    import hashlib

    key_data = {"args": args, "kwargs": kwargs}
    return hashlib.md5(
        json.dumps(key_data, sort_keys=True, default=str).encode()
    ).hexdigest()


def cached_request(
    cache_duration: int = 300,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to cache HTTP requests for specified duration.

    Args:
        cache_duration: Cache time-to-live in seconds (default: 300 = 5 minutes)

    Returns:
        Decorated function with caching capability
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        cache: dict[str, tuple[T, float]] = {}

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            if not ENABLE_CACHING:
                return func(*args, **kwargs)

            key = cache_key(*args, **kwargs)
            now = time.time()

            # Check cache
            if key in cache:
                result, timestamp = cache[key]
                if now - timestamp < cache_duration:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return result
                else:
                    del cache[key]  # Expired

            # Execute and cache
            result = func(*args, **kwargs)
            cache[key] = (result, now)

            # Simple cache cleanup (keep only most recent items)
            if len(cache) > CACHE_SIZE:
                oldest_key = min(cache.keys(), key=lambda k: cache[k][1])
                del cache[oldest_key]

            return result

        return wrapper

    return decorator


def safe_get_uncached(endpoint: str, params: dict = None, retries: int = 3) -> list:
    """
    Perform a GET request WITHOUT caching (for stateful queries like get_current_address).
    Uses UDS transport when available, falls back to TCP.

    Args:
        endpoint: The API endpoint to call
        params: Optional query parameters
        retries: Number of retry attempts for server errors

    Returns:
        List of strings representing the response
    """
    if params is None:
        params = {}

    timeout = get_timeout_for_endpoint(endpoint)

    # Try UDS transport first
    sock = get_active_socket()
    if sock:
        for attempt in range(retries):
            try:
                start_time = time.time()
                text, status = uds_request(sock, "GET", endpoint, params=params, timeout=timeout)
                duration = time.time() - start_time
                logger.info(f"UDS GET {endpoint} took {duration:.2f}s (attempt {attempt + 1})")
                if status == 200:
                    return text.splitlines()
                elif status >= 500 and attempt < retries - 1:
                    time.sleep(2**attempt)
                    continue
                else:
                    return [f"Error {status}: {text.strip()}"]
            except (OSError, ConnectionError) as e:
                logger.warning(f"UDS request failed: {e}, invalidating cache")
                invalidate_socket_cache()
                break  # Fall through to TCP
            except Exception as e:
                logger.error(f"UDS error: {e}")
                if attempt < retries - 1:
                    continue
                return [f"Error: {e}"]

    # TCP fallback
    if not validate_server_url(ghidra_server_url):
        logger.error(f"Invalid or unsafe server URL: {ghidra_server_url}")
        return ["Error: Invalid server URL - only local addresses allowed"]

    url = urljoin(ghidra_server_url, endpoint)

    for attempt in range(retries):
        try:
            start_time = time.time()
            response = session.get(url, params=params, timeout=timeout)
            response.encoding = "utf-8"
            duration = time.time() - start_time
            logger.info(f"TCP GET {endpoint} took {duration:.2f}s (attempt {attempt + 1})")
            if response.ok:
                return response.text.splitlines()
            elif response.status_code == 404:
                return [f"Endpoint not found: {endpoint}"]
            elif response.status_code >= 500:
                if attempt < retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise GhidraConnectionError(f"Server error: {response.status_code}")
            else:
                return [f"Error {response.status_code}: {response.text.strip()}"]
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                continue
            return [f"Timeout connecting to Ghidra server after {retries} attempts"]
        except requests.exceptions.RequestException as e:
            return [f"Request failed: {str(e)}"]
        except GhidraConnectionError:
            raise
        except Exception as e:
            return [f"Unexpected error: {str(e)}"]

    return ["Unexpected error in safe_get_uncached"]


@cached_request(cache_duration=180)  # 3-minute cache for GET requests
def safe_get(endpoint: str, params: dict = None, retries: int = 3, program: str = None) -> list:
    """
    Perform a cached GET request. Uses UDS when available, falls back to TCP.
    Delegates to safe_get_uncached (caching is handled by the decorator).
    """
    return safe_get_uncached(endpoint, params, retries)


def safe_get_json(endpoint: str, params: dict = None, retries: int = 3, program: str = None) -> str:
    """
    Perform a GET request for JSON endpoints. Uses UDS when available, falls back to TCP.
    Returns the raw response text as a single string instead of splitting into lines.
>>>>>>> 80327dc (feat: add UDS transport, multi-instance bridge, and upstream tools)
    """
    if params is None:
        params = {}
    if program:
        params["program"] = program

    timeout = get_timeout_for_endpoint(endpoint)

    # Try UDS transport first
    sock = get_active_socket()
    if sock:
        for attempt in range(retries):
            try:
                start_time = time.time()
                text, status = uds_request(sock, "GET", endpoint, params=params, timeout=timeout)
                duration = time.time() - start_time
                logger.info(f"UDS GET {endpoint} took {duration:.2f}s (attempt {attempt + 1})")
                if status == 200:
                    return text
                elif status == 404:
                    return f'{{"error": "Endpoint not found: {endpoint}"}}'
                elif status >= 500 and attempt < retries - 1:
                    time.sleep(2**attempt)
                    continue
                else:
                    return f'{{"error": "HTTP {status}: {text.strip()}"}}'
            except (OSError, ConnectionError) as e:
                logger.warning(f"UDS request failed, falling back to TCP: {e}")
                invalidate_socket_cache()
                break
            except Exception as e:
                if attempt < retries - 1:
                    continue
                return f'{{"error": "{e}"}}'

    # TCP fallback
    if not validate_server_url(ghidra_server_url):
        logger.error(f"Invalid or unsafe server URL: {ghidra_server_url}")
        return '{"error": "Invalid server URL - only local addresses allowed"}'

    url = urljoin(ghidra_server_url, endpoint)

    for attempt in range(retries):
        try:
            start_time = time.time()
            response = session.get(url, params=params, timeout=timeout)
            response.encoding = "utf-8"
            duration = time.time() - start_time
            logger.info(f"TCP GET {endpoint} took {duration:.2f}s (attempt {attempt + 1})")
            if response.ok:
                return response.text
            elif response.status_code == 404:
                return f'{{"error": "Endpoint not found: {endpoint}"}}'
            elif response.status_code >= 500 and attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            else:
                return f'{{"error": "HTTP {response.status_code}: {response.text.strip()}"}}'
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                continue
            return f'{{"error": "Timeout connecting to Ghidra server after {retries} attempts"}}'
        except requests.exceptions.RequestException as e:
            return f'{{"error": "Request failed: {str(e)}"}}'

    return '{"error": "Unexpected error in safe_get_json"}'


def safe_post_json(endpoint: str, data: dict, retries: int = 3, program: str = None) -> str:
    """
<<<<<<< HEAD
    Perform a JSON POST request with enhanced error handling and retry logic.

    Args:
        endpoint: The API endpoint to call
        data: Data to send as JSON
        retries: Number of retry attempts for server errors
        program: Optional program name for multi-binary targeting

    Returns:
        String response from the server
=======
    Perform a JSON POST request. Uses UDS when available, falls back to TCP.
    """
    timeout = calculate_dynamic_timeout(endpoint, data)

    # Try UDS transport first
    sock = get_active_socket()
    if sock:
        for attempt in range(retries):
            try:
                start_time = time.time()
                text, status = uds_request(sock, "POST", endpoint, json_data=data, timeout=timeout)
                duration = time.time() - start_time
                logger.info(f"UDS POST {endpoint} took {duration:.2f}s (attempt {attempt + 1})")
                if status == 200:
                    return text.strip()
                elif status == 404:
                    return f"Error: Endpoint {endpoint} not found"
                elif status >= 500 and attempt < retries - 1:
                    time.sleep(1)
                    continue
                else:
                    return f"Error: HTTP {status} - {text}"
            except (OSError, ConnectionError) as e:
                logger.warning(f"UDS request failed, falling back to TCP: {e}")
                invalidate_socket_cache()
                break
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(1)
                    continue
                return f"Error: Request failed - {str(e)}"

    # TCP fallback
    if not validate_server_url(ghidra_server_url):
        logger.error(f"Invalid or unsafe server URL: {ghidra_server_url}")
        return "Error: Invalid server URL - only local addresses allowed"

    url = urljoin(ghidra_server_url, endpoint)
>>>>>>> 80327dc (feat: add UDS transport, multi-instance bridge, and upstream tools)
    headers = {"Connection": "close"}

    for attempt in range(retries):
        try:
            start_time = time.time()
            response = session.post(url, json=data, headers=headers, timeout=timeout)
            response.encoding = "utf-8"
            duration = time.time() - start_time
            logger.info(f"TCP POST {endpoint} took {duration:.2f}s (attempt {attempt + 1})")
            if response.ok:
                return response.text.strip()
            elif response.status_code == 404:
                return f"Error: Endpoint {endpoint} not found"
            elif response.status_code >= 500 and attempt < retries - 1:
                time.sleep(1)
                continue
            else:
                return f"Error: HTTP {response.status_code} - {response.text}"
        except requests.RequestException as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return f"Error: Request failed - {str(e)}"

    return "Error: Maximum retries exceeded"


def safe_post(endpoint: str, data: dict | str, retries: int = 3, program: str = None) -> str:
    """
<<<<<<< HEAD
    Perform a POST request with enhanced error handling and retry logic.

    Args:
        endpoint: The API endpoint to call
        data: Data to send (dict or string)
        retries: Number of retry attempts for server errors
        program: Optional program name for multi-binary targeting

    Returns:
        String response from the server
=======
    Perform a POST request (form-encoded or raw). Uses UDS when available, falls back to TCP.
    """
    timeout = get_timeout_for_endpoint(endpoint)

    # Try UDS transport first
    sock = get_active_socket()
    if sock:
        for attempt in range(retries):
            try:
                start_time = time.time()
                text, status = uds_request(sock, "POST", endpoint, form_data=data, timeout=timeout)
                duration = time.time() - start_time
                logger.info(f"UDS POST {endpoint} took {duration:.2f}s (attempt {attempt + 1})")
                if status == 200:
                    return text.strip()
                elif status == 404:
                    return f"Endpoint not found: {endpoint}"
                elif status >= 500 and attempt < retries - 1:
                    time.sleep(2**attempt)
                    continue
                else:
                    return f"Error {status}: {text.strip()}"
            except (OSError, ConnectionError) as e:
                logger.warning(f"UDS request failed, falling back to TCP: {e}")
                invalidate_socket_cache()
                break
            except Exception as e:
                if attempt < retries - 1:
                    continue
                return f"Unexpected error: {str(e)}"

    # TCP fallback
    if not validate_server_url(ghidra_server_url):
        logger.error(f"Invalid or unsafe server URL: {ghidra_server_url}")
        return "Error: Invalid server URL - only local addresses allowed"

    url = urljoin(ghidra_server_url, endpoint)
    if program:
        url += f"?program={program}"

    for attempt in range(retries):
        try:
            start_time = time.time()
            if isinstance(data, dict):
                response = session.post(url, data=data, timeout=timeout)
            else:
                response = session.post(url, data=data.encode("utf-8"), timeout=timeout)
            response.encoding = "utf-8"
            duration = time.time() - start_time
            logger.info(f"TCP POST {endpoint} took {duration:.2f}s (attempt {attempt + 1})")
            if response.ok:
                return response.text.strip()
            elif response.status_code == 404:
                return f"Endpoint not found: {endpoint}"
            elif response.status_code >= 500 and attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            else:
                return f"Error {response.status_code}: {response.text.strip()}"
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                continue
            return f"Timeout connecting to Ghidra server after {retries} attempts"
        except requests.exceptions.RequestException as e:
            return f"Request failed: {str(e)}"

    return "Unexpected error in safe_post"


def make_request(
    url: str,
    method: str = "GET",
    params: dict = None,
    data: str = None,
    retries: int = 3,
    program: str = None,
) -> str:
    """
    Perform an HTTP request. Uses UDS when available, falls back to TCP.

    Args:
        url: Full URL to request (not just endpoint)
        method: HTTP method ("GET" or "POST")
        params: Query parameters for GET requests
        data: Raw data string for POST requests (already JSON-encoded)
        retries: Number of retry attempts for server errors
<<<<<<< HEAD
        program: Optional program name for multi-binary targeting

    Returns:
        String response from the server (typically JSON)
=======
>>>>>>> 80327dc (feat: add UDS transport, multi-instance bridge, and upstream tools)
    """
    if params is None:
        params = {}
    if program:
        params["program"] = program

    timeout = REQUEST_TIMEOUT

    # Try UDS transport first — extract endpoint path from URL
    sock = get_active_socket()
    if sock:
        endpoint = urlparse(url).path
        for attempt in range(retries):
            try:
                start_time = time.time()
                if method.upper() == "POST":
                    # data is already JSON-encoded string
                    text, status = uds_request(sock, "POST", endpoint, form_data=data, timeout=timeout)
                else:
                    text, status = uds_request(sock, "GET", endpoint, params=params, timeout=timeout)
                duration = time.time() - start_time
                logger.info(f"UDS {method} {endpoint} took {duration:.2f}s (attempt {attempt + 1})")
                if status == 200:
                    return text
                elif status == 404:
                    return f'{{"error": "Endpoint not found: {endpoint}"}}'
                elif status >= 500 and attempt < retries - 1:
                    time.sleep(2**attempt)
                    continue
                else:
                    return f'{{"error": "HTTP {status}: {text.strip()}"}}'
            except (OSError, ConnectionError) as e:
                logger.warning(f"UDS request failed, falling back to TCP: {e}")
                invalidate_socket_cache()
                break
            except Exception as e:
                if attempt < retries - 1:
                    continue
                return f'{{"error": "{e}"}}'

    # TCP fallback
    if not validate_server_url(url):
        logger.error(f"Invalid or unsafe server URL: {url}")
        return '{"error": "Invalid server URL - only local addresses allowed"}'

    for attempt in range(retries):
        try:
            start_time = time.time()
            if method.upper() == "POST":
                headers = {"Content-Type": "application/json"}
                response = session.post(url, data=data, headers=headers, timeout=timeout)
            else:
                response = session.get(url, params=params, timeout=timeout)
            response.encoding = "utf-8"
            duration = time.time() - start_time
            logger.info(f"TCP {method} {url} took {duration:.2f}s (attempt {attempt + 1})")
            if response.ok:
                return response.text
            elif response.status_code == 404:
                return f'{{"error": "Endpoint not found: {url}"}}'
            elif response.status_code >= 500 and attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            else:
                return f'{{"error": "HTTP {response.status_code}: {response.text.strip()}"}}'
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                continue
            return f'{{"error": "Timeout connecting to Ghidra server after {retries} attempts"}}'
        except requests.exceptions.RequestException as e:
            return f'{{"error": "Request failed: {str(e)}"}}'

    return '{"error": "Unexpected error in make_request"}'


@mcp.tool()
def list_functions(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List all function names in the program with pagination.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of functions to return (default: 100)
        program: Optional program name to query (e.g., "D2Client.dll").
                 If not specified, uses the currently active program.

    Returns:
        List of function names with pagination information
    """
    params = {"offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("list_functions", params)


@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List all namespace/class names in the program with pagination.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of classes to return (default: 100)
        program: Optional program name for multi-program support

    Returns:
        List of namespace/class names with pagination information
    """
    params = {"offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("list_classes", params)


# TODO: Future improvement - consolidate Java endpoints into single /decompile_unified endpoint
# Currently we have: /decompile, /decompile_function, /force_decompile, /force_decompile_by_name
# This would require rebuilding and redeploying the Ghidra plugin.


@mcp.tool()
def decompile_function(
    name: str = None,
    address: str = None,
    force: bool = False,
    timeout: int = None,
    program: str = None,
    offset: int = 0,
    limit: int = None,
) -> str:
    """
    Decompile a function by name or address and return the decompiled C code.

    Args:
        name: Function name to decompile (either name or address required)
        address: Function address in hex format (e.g., "0x6fb6aef0")
        force: Force fresh decompilation, clearing cache (default: False). Use after changing signatures, types, or storage.
        timeout: Timeout in seconds (default: 45s)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.
        offset: Line number to start from for pagination (0-indexed, default: 0)
        limit: Max lines to return. If None, returns all. Use 100-200 for large functions.

    Returns:
        Decompiled C pseudocode. With pagination, includes metadata header with total lines and range.
    """
    if not name and not address:
        raise GhidraValidationError("Either 'name' or 'address' parameter is required")

    # Apply custom timeout if specified
    original_timeout = None
    if timeout:
        original_timeout = ENDPOINT_TIMEOUTS.get("decompile_function", 45)
        ENDPOINT_TIMEOUTS["decompile_function"] = timeout
        ENDPOINT_TIMEOUTS["force_decompile"] = timeout
        ENDPOINT_TIMEOUTS["force_decompile_by_name"] = timeout

    try:
        if name:
            # Look up function address by name first
            search_params = {"query": name, "offset": 0, "limit": 10}
            if program:
                search_params["program"] = program
            search_result = safe_get("search_functions", search_params)
            func_address = None
            for line in search_result:
                # Parse "FunctionName @ 0x12345678" format
                if f"{name} @" in line or line.startswith(f"{name} "):
                    parts = line.split("@")
                    if len(parts) >= 2:
                        func_address = parts[-1].strip()
                        break

            if not func_address:
                return f"Error: Function '{name}' not found"

            if force:
                result = safe_post(
                    "force_decompile", {"function_address": func_address}
                )
            else:
                params = {"address": func_address}
                if program:
                    params["program"] = program
                if timeout:
                    params["timeout"] = str(timeout)
                result = safe_get("decompile_function", params)
        else:
            address = sanitize_address(address)
            if not validate_hex_address(address):
                raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

            if force:
                result = safe_post("force_decompile", {"function_address": address})
            else:
                # Use GET for cached decompilation (faster)
                params = {"address": address}
                if program:
                    params["program"] = program
                if timeout:
                    params["timeout"] = str(timeout)
                result = safe_get("decompile_function", params)

        # Convert list result to string if needed (safe_get returns list)
        if isinstance(result, list):
            result = "\n".join(result)

        # Apply pagination if offset or limit specified
        if offset > 0 or limit is not None:
            lines = result.split("\n")
            total_lines = len(lines)

            # Apply offset and limit
            end_idx = len(lines) if limit is None else min(offset + limit, len(lines))
            paginated_lines = lines[offset:end_idx]

            # Build pagination metadata header
            has_more = end_idx < total_lines
            metadata = f"/* PAGINATION: lines {offset + 1}-{end_idx} of {total_lines}"
            if has_more:
                metadata += f" (use offset={end_idx} for next chunk)"
            metadata += " */\n\n"

            result = metadata + "\n".join(paginated_lines)

        return result
    finally:
        # Restore original timeout
        if original_timeout:
            ENDPOINT_TIMEOUTS["decompile_function"] = original_timeout
            ENDPOINT_TIMEOUTS["force_decompile"] = original_timeout
            ENDPOINT_TIMEOUTS["force_decompile_by_name"] = original_timeout




@mcp.tool()
def rename_function(old_name: str, new_name: str, program: str = None) -> str:
    """
    Rename a function by its current name to a new user-defined name.

    Args:
        old_name: Current name of the function to rename
        new_name: New name for the function
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message indicating the result of the rename operation
    """
    return safe_post("rename_function", {"oldName": old_name, "newName": new_name}, program=program)


@mcp.tool()
def rename_data(address: str, new_name: str, program: str = None) -> str:
    """
    Rename a data label at the specified address.

    IMPORTANT: This tool only works for DEFINED data (data with an existing symbol/type).
    For undefined memory addresses, use create_label() or rename_or_label() instead.

    What is "defined data"?
    - Data that has been typed (e.g., dword, struct, array)
    - Data created via apply_data_type() or Ghidra's "D" key
    - Data with existing symbols in the Symbol Tree

    If you get an error like "No defined data at address", use:
    - create_label(address, name) for undefined addresses
    - rename_or_label(address, name) for automatic detection (recommended)

    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")
                Accepts addresses with or without 0x prefix
        new_name: New name for the data label (must be valid C identifier)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        str: Success or failure message indicating the result of the rename operation

    Raises:
        GhidraValidationError: If address format is invalid or name is invalid

    See Also:
        - create_label(): Create label at undefined address
        - rename_or_label(): Automatically detect and use correct method
        - apply_data_type(): Define data type before renaming
    """
    # Sanitize and validate address
    address = sanitize_address(address)
    if not validate_hex_address(address):
        raise GhidraValidationError(
            f"Invalid hexadecimal address format: {address}. "
            f"Expected format: 0x followed by hex digits (e.g., '0x401000')."
        )

    # Validate new name format
    if not new_name or not new_name.strip():
        raise GhidraValidationError("Data name cannot be empty.")

    new_name = new_name.strip()
    if not new_name[0].isalpha() and new_name[0] != "_":
        raise GhidraValidationError(
            f"Invalid data name '{new_name}'. "
            f"Names must start with a letter or underscore."
        )

    if not all(c.isalnum() or c == "_" for c in new_name):
        raise GhidraValidationError(
            f"Invalid data name '{new_name}'. "
            f"Names can only contain letters, numbers, and underscores."
        )

    response = safe_post("rename_data", {"address": address, "newName": new_name}, program=program)

    # Provide actionable error messages
    if "no defined data" in response.lower():
        return (
            f"Error: No defined data at {address}. "
            f"This address may be undefined memory. "
            f"Try: create_label('{address}', '{new_name}') instead, or "
            f"use rename_or_label('{address}', '{new_name}') for automatic detection."
        )
    elif "success" in response.lower() or "renamed" in response.lower():
        return f"Successfully renamed data at {address} to '{new_name}'"
    elif "error" in response.lower() or "failed" in response.lower():
        return f"{response}\nTry: rename_or_label('{address}', '{new_name}') for automatic handling."
    else:
        return f"Rename operation completed: {response}"


def _check_if_data_defined(address: str) -> bool:
    """
    Internal helper: Check if address has a defined data symbol.

    Args:
        address: Hex address to check

    Returns:
        True if data is defined, False if undefined
    """
    try:
        import json

        result = safe_post_json(
            "analyze_data_region",
            {
                "address": address,
                "max_scan_bytes": 16,
                "include_xref_map": False,
                "include_assembly_patterns": False,
                "include_boundary_detection": False,
            },
        )

        if result and not result.startswith("Error"):
            data = json.loads(result)
            current_type = data.get("current_type", "undefined")
            # If current_type is "undefined", it's not a defined data item
            return current_type != "undefined"
    except Exception as e:
        logger.warning(f"Failed to check if data defined at {address}: {e}")

    return False


@mcp.tool()
def get_function_labels(name: str, offset: int = 0, limit: int = 20, program: str = None) -> list:
    """
    Get all labels within the specified function by name.

    Args:
        name: Function name to search for labels within
        offset: Pagination offset (default: 0)
        limit: Maximum number of labels to return (default: 20)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        List of labels found within the specified function
    """
    return safe_get(
        "get_function_labels", {"name": name, "offset": offset, "limit": limit}, program=program
    )


@mcp.tool()
def rename_label(address: str, old_name: str, new_name: str, program: str = None) -> str:
    """
    Rename an existing label at the specified address.

    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        old_name: Current label name to rename
        new_name: New name for the label
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message indicating the result of the rename operation
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_post(
        "rename_label", {"address": address, "old_name": old_name, "new_name": new_name}, program=program
    )


@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List all memory segments in the program with pagination.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of segments to return (default: 100)
        program: Optional program name for multi-program support

    Returns:
        List of memory segments with their addresses, names, and properties
    """
    params = {"offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("list_segments", params)


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List imported symbols in the program with pagination.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of imports to return (default: 100)
        program: Optional program name for multi-program support

    Returns:
        List of imported symbols with their names and addresses
    """
    params = {"offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("list_imports", params)


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List exported functions/symbols with pagination.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of exports to return (default: 100)
        program: Optional program name for multi-program support

    Returns:
        List of exported functions/symbols with their names and addresses
    """
    params = {"offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("list_exports", params)


@mcp.tool()
def list_external_locations(
    offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    List all external locations (imports, ordinal imports, external functions, etc).

    External locations represent functions or data imported from external DLLs.
    This includes ordinal-based imports like "Ordinal_123" that can be renamed
    to proper function names for ordinal linkage restoration.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of external locations to return (default: 100)
        program: Optional program name to query (if not provided, uses current program)

    Returns:
        List of external locations with DLL name, label, and address
    """
    params = {"offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("list_external_locations", params)


@mcp.tool()
def get_external_location(
    address: str, dll_name: str = None, program: str = None
) -> dict:
    """
    Get details of a specific external location.

    Args:
        address: Memory address of the external location (e.g., "0x6fb7e218")
        dll_name: Optional DLL name to search in (if not provided, searches all DLLs)
        program: Optional program name to query (if not provided, uses current program)

    Returns:
        Dictionary with external location details (DLL, label, address)
    """
    params = {"address": address}
    if dll_name:
        params["dll_name"] = dll_name
    if program:
        params["program"] = program
    return safe_get("get_external_location", params)


@mcp.tool()
def rename_external_location(address: str, new_name: str, program: str = None) -> str:
    """
    Rename an external location (e.g., change Ordinal_123 to a real function name).

    This tool is essential for fixing broken ordinal-based imports when DLL
    function names change. Use it to rename ordinal imports to their correct
    function names for ordinal linkage restoration.

    Args:
        address: Memory address of the external location (e.g., "0x6fb7e218")
        new_name: New name for the external location (e.g., "sgptDataTables")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success message with old and new names, or error message

    Example:
        Rename "Ordinal_100" to actual function name:
        rename_external_location("0x6fb7e218", "sgptDataTables")
    """
    address = sanitize_address(address)
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")
    params = {"address": address, "new_name": new_name}
    return safe_post("rename_external_location", params, program=program)


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List all non-global namespaces in the program with pagination.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of namespaces to return (default: 100)
        program: Optional program name for multi-program support

    Returns:
        List of namespace names and their hierarchical paths
    """
    params = {"offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("list_namespaces", params)


@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List defined data labels and their values with pagination.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of data items to return (default: 100)
        program: Optional program name for multi-program support

    Returns:
        List of data labels with their addresses, names, and values
    """
    params = {"offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("list_data_items", params)


@mcp.tool()
def list_data_items_by_xrefs(
    offset: int = 0, limit: int = 100, format: str = "json", program: str = None
) -> str:
    """
    List defined data items sorted by cross-reference count (most referenced first).

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        format: "json" (default) or "text" for human-readable output
        program: Optional program name for multi-program support

    Returns:
        Sorted list of data items with address, name, type, size, and xref count.
    """
    if format not in ["text", "json"]:
        raise GhidraValidationError("format must be 'text' or 'json'")

    params = {"offset": offset, "limit": limit, "format": format}
    if program:
        params["program"] = program
    # Use safe_get_json since this endpoint returns JSON (not line-based text)
    result = safe_get_json("list_data_items_by_xrefs", params)
    return result



@mcp.tool()
def rename_variables(
    function_address: str, variable_renames: dict, backend: str = "auto", program: str = None
) -> str:
    """
    Rename one or more variables in a function with automatic backend selection.

    Args:
        function_address: Function address in hex format (e.g., "0x401000")
        variable_renames: Dict of {"old_name": "new_name"} pairs
        backend: "auto" (default, picks batch or progressive by count), "batch", or "progressive"
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with success status, variables_renamed count, variables_failed count, backend_used, and errors.
    """
    import json

    validate_hex_address(function_address)

    if not variable_renames:
        return json.dumps(
            {
                "success": True,
                "variables_renamed": 0,
                "variables_failed": 0,
                "backend_used": "none",
                "message": "No variables to rename",
            }
        )

    num_variables = len(variable_renames)

    # Determine backend strategy
    if backend == "auto":
        if num_variables <= 10:
            actual_backend = "batch"
        else:
            actual_backend = "progressive"
    elif backend in ["batch", "progressive"]:
        actual_backend = backend
    else:
        raise GhidraValidationError(
            f"Invalid backend: {backend}. Must be 'auto', 'batch', or 'progressive'"
        )

    logger.info(
        f"rename_variables: {num_variables} variables, backend={actual_backend}"
    )

    # Execute based on selected backend
    if actual_backend == "batch":
        try:
            payload = {
                "function_address": function_address,
                "variable_renames": variable_renames,
            }
            result_json = safe_post_json("batch_rename_variables", payload, program=program)
            result = json.loads(result_json)
            result["backend_used"] = "batch"
            return json.dumps(result, indent=2)

        except Exception as e:
            error_msg = str(e)
            if "timeout" in error_msg.lower() or "connection" in error_msg.lower():
                # Timeout detected - fallback to progressive if auto mode
                if backend == "auto":
                    logger.warning(
                        f"Batch backend timed out, falling back to progressive"
                    )
                    return _rename_variables_progressive_internal(
                        function_address, variable_renames, program=program
                    )

            # Non-timeout error or explicit batch mode - return error
            return json.dumps(
                {
                    "success": False,
                    "variables_renamed": 0,
                    "variables_failed": num_variables,
                    "backend_used": "batch",
                    "errors": [{"error": error_msg}],
                },
                indent=2,
            )

    else:  # progressive
        return _rename_variables_progressive_internal(
            function_address, variable_renames, program=program
        )


def _rename_variables_progressive_internal(
    function_address: str,
    variable_renames: dict,
    chunk_size: int = 5,
    retry_attempts: int = 3,
    program: str = None,
) -> str:
    """
    Internal progressive chunking implementation with retry logic.

    This handles large functions that timeout with batch operations by breaking
    variable renames into smaller chunks and retrying failed chunks.
    """
    import json
    import time

    variables_list = list(variable_renames.items())
    total_variables = len(variables_list)

    results = {
        "success": True,
        "total_variables": total_variables,
        "variables_renamed": 0,
        "variables_failed": 0,
        "backend_used": "progressive",
        "chunks_processed": 0,
        "chunks_failed": 0,
        "chunk_size": chunk_size,
        "failed_variables": [],
        "errors": [],
    }

    # Process variables in chunks
    for i in range(0, total_variables, chunk_size):
        chunk = dict(variables_list[i : i + chunk_size])
        chunk_num = (i // chunk_size) + 1
        total_chunks = (total_variables + chunk_size - 1) // chunk_size

        logger.info(
            f"Processing chunk {chunk_num}/{total_chunks} with {len(chunk)} variables"
        )

        # Attempt to rename this chunk with retries
        chunk_success = False
        last_error = None

        for attempt in range(retry_attempts):
            try:
                payload = {
                    "function_address": function_address,
                    "variable_renames": chunk,
                }

                result_json = safe_post_json("batch_rename_variables", payload, program=program)
                result = json.loads(result_json)

                if result.get("success"):
                    results["variables_renamed"] += result.get(
                        "variables_renamed", len(chunk)
                    )
                    results["variables_failed"] += result.get("variables_failed", 0)

                    if result.get("errors"):
                        results["errors"].extend(result["errors"])
                        for error in result["errors"]:
                            results["failed_variables"].append(error.get("old_name"))

                    chunk_success = True
                    results["chunks_processed"] += 1
                    break
                else:
                    last_error = result.get("error", "Unknown error")

            except Exception as e:
                last_error = str(e)
                if attempt < retry_attempts - 1:
                    wait_time = 2**attempt  # Exponential backoff
                    logger.warning(
                        f"Chunk {chunk_num} failed (attempt {attempt + 1}/{retry_attempts}), retrying in {wait_time}s..."
                    )
                    time.sleep(wait_time)
                else:
                    logger.error(
                        f"Chunk {chunk_num} failed after {retry_attempts} attempts"
                    )

        if not chunk_success:
            results["chunks_failed"] += 1
            results["success"] = False
            for old_name in chunk.keys():
                results["failed_variables"].append(old_name)
                results["errors"].append(
                    {
                        "old_name": old_name,
                        "error": f"Chunk timeout after {retry_attempts} attempts: {last_error}",
                    }
                )
            results["variables_failed"] += len(chunk)

    return json.dumps(results, indent=2)


@mcp.tool()
def get_function_by_address(address: str, program: str = None) -> str:
    """
    Get a function by its address.

    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")
        program: Optional program name to query (if not provided, uses current program)

    Returns:
        Function information including name, signature, and address range
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    params = {"address": address}
    if program:
        params["program"] = program
    return "\n".join(safe_get("get_function_by_address", params))


@mcp.tool()
def get_current_selection() -> dict:
    """
    Get the current selection context - both address and function information.

    Returns information about what is currently selected by the user in Ghidra's
    CodeBrowser, including both the cursor address and the containing function
    (if applicable).

    Args:
        None

    Returns:
        Dictionary containing:
        - address: Current cursor/selection address in hex format
        - function: Information about the currently selected function (name, address)
                    or None if not in a function

    Examples:
        # Get current selection
        selection = get_current_selection()
        print(f"Address: {selection['address']}")
        print(f"Function: {selection['function']}")

        # Use in workflow
        if selection['function']:
            print(f"In function: {selection['function']['name']}")
        else:
            print(f"Not in a function, at address: {selection['address']}")
    """
    result = {
        "address": "\n".join(safe_get_uncached("get_current_address")),
        "function": "\n".join(safe_get_uncached("get_current_function")),
    }
    return result


@mcp.tool()
def disassemble_function(
    address: str,
    program: str = None,
    offset: int = 0,
    limit: int = None,
    filter_mnemonics: str = None,
) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.

    Args:
        address: Function address in hex format (e.g., "0x1400010a0")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.
        offset: Instruction index to start from for pagination (0-indexed, default: 0)
        limit: Max instructions to return. If None, returns all. Use 100-200 for large functions.
        filter_mnemonics: Comma-separated mnemonics to filter (e.g., "CALL,JMP"). Applied before pagination.

    Returns:
        List of assembly instructions. With pagination, first element is metadata with total count.
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    params = {"address": address}
    if program:
        params["program"] = program
    result = safe_get("disassemble_function", params)

    # Apply mnemonic filter if specified (before pagination)
    if filter_mnemonics:
        mnemonics = [m.strip().upper() for m in filter_mnemonics.split(",")]
        result = [
            line
            for line in result
            if any(mnem in line.upper() for mnem in mnemonics)
        ]

    # Apply pagination if offset or limit specified
    if offset > 0 or limit is not None:
        total_instructions = len(result)

        # Apply offset and limit
        end_idx = len(result) if limit is None else min(offset + limit, len(result))
        paginated = result[offset:end_idx]

        # Add pagination metadata as first element
        has_more = end_idx < total_instructions
        metadata = f"/* PAGINATION: instructions {offset + 1}-{end_idx} of {total_instructions}"
        if has_more:
            metadata += f" (use offset={end_idx} for next chunk)"
        metadata += " */"

        return [metadata] + paginated

    return result


@mcp.tool()
def set_decompiler_comment(address: str, comment: str, program: str = None) -> str:
    """
    Set a comment for a given address in the function pseudocode.

    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")
        comment: Comment text to add to the decompiled pseudocode
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message indicating the result of the comment operation
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_post("set_decompiler_comment", {"address": address, "comment": comment}, program=program)


@mcp.tool()
def set_disassembly_comment(address: str, comment: str, program: str = None) -> str:
    """
    Set a comment for a given address in the function disassembly.

    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")
        comment: Comment text to add to the assembly disassembly
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message indicating the result of the comment operation
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_post(
        "set_disassembly_comment", {"address": address, "comment": comment}, program=program
    )


@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str, program: str = None) -> str:
    """
    Rename a function by its address.

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
                         Accepts addresses with or without 0x prefix
        new_name: New name for the function (must be valid C identifier)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        str: Success or failure message indicating the result of the rename operation

    Raises:
        GhidraValidationError: If address or name format is invalid, or function not found
    """
    # Sanitize and validate address
    function_address = sanitize_address(function_address)
    if not validate_hex_address(function_address):
        raise GhidraValidationError(
            f"Invalid hexadecimal address format: {function_address}. "
            f"Expected format: 0x followed by hex digits (e.g., '0x401000'). "
            f"Use search_functions_by_name() to find functions by name."
        )

    # Validate new name format
    if not new_name or not new_name.strip():
        raise GhidraValidationError("Function name cannot be empty.")

    new_name = new_name.strip()
    if not new_name[0].isalpha() and new_name[0] != "_":
        raise GhidraValidationError(
            f"Invalid function name '{new_name}'. "
            f"Names must start with a letter or underscore."
        )

    if not all(c.isalnum() or c == "_" for c in new_name):
        raise GhidraValidationError(
            f"Invalid function name '{new_name}'. "
            f"Names can only contain letters, numbers, and underscores."
        )

    # Verify function exists at this address
    func_check = safe_get("get_function_by_address", {"address": function_address}, program=program)
    if not func_check or any(
        "Error" in str(line) or "not found" in str(line).lower() for line in func_check
    ):
        raise GhidraValidationError(
            f"No function found at address {function_address}. "
            f"Use get_function_by_address() to verify the address, or "
            f"list_functions() to see all available functions."
        )

    result = safe_post(
        "rename_function_by_address",
        {"function_address": function_address, "new_name": new_name},
        program=program,
    )

    # Provide clear success/failure messages
    if "success" in result.lower() or "renamed" in result.lower():
        return f"Successfully renamed function at {function_address} to '{new_name}'"
    elif "error" in result.lower() or "failed" in result.lower():
        return f"{result}\nVerify function exists: get_function_by_address('{function_address}')"

    return result


@mcp.tool()
def set_function_prototype(
    function_address: str,
    prototype: str,
    calling_convention: str = None,
    timeout: int = None,
    program: str = None,
) -> str:
    """
    Set a function's prototype and optionally its calling convention.

    Args:
        function_address: Function address in hex format (e.g., "0x1400010a0")
        prototype: C function declaration (e.g., "int main(int argc, char* argv[])")
        calling_convention: Optional convention (e.g., "__cdecl", "__stdcall", "__fastcall")
        timeout: Optional timeout in seconds (default: 45s)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message. Use force decompile afterward to see updated output.
    """
    # Sanitize and validate address
    function_address = sanitize_address(function_address)
    if not validate_hex_address(function_address):
        raise GhidraValidationError(
            f"Invalid hexadecimal address format: {function_address}. "
            f"Expected format: 0x followed by hex digits (e.g., '0x401000')."
        )

    # Validate prototype is not empty
    if not prototype or not prototype.strip():
        raise GhidraValidationError(
            "Function prototype cannot be empty. "
            "Valid examples:\n"
            "  - 'dword myFunction(void)' (no parameters)\n"
            "  - 'int calculate(int x, int y)' (with parameters)\n"
            "  - 'void * allocate(uint size)' (returns pointer)\n"
            "Note: Use 'dword' not 'uint', 'byte' not 'BYTE' for Ghidra consistency"
        )

    # Verify function exists
    func_check = safe_get("get_function_by_address", {"address": function_address}, program=program)
    if not func_check or any(
        "Error" in str(line) or "not found" in str(line).lower() for line in func_check
    ):
        raise GhidraValidationError(
            f"No function found at address {function_address}. "
            f"Use get_function_by_address() to verify the address."
        )

    # Apply custom timeout if specified
    if timeout:
        original_timeout = ENDPOINT_TIMEOUTS.get("set_function_prototype", 45)
        ENDPOINT_TIMEOUTS["set_function_prototype"] = timeout

    try:
        data = {"function_address": function_address, "prototype": prototype.strip()}
        if calling_convention:
            data["calling_convention"] = calling_convention.strip()

        result = safe_post_json("set_function_prototype", data, program=program)

        # Provide actionable error messages
        if "success" in result.lower():
            # v3.0.1: Pass through server response (includes old prototype) and append usage hint
            msg = result.rstrip()
            msg += f"\nUse: get_decompiled_code('{function_address}', refresh_cache=True) to see changes"
            return msg
        elif "invalid calling convention" in result.lower():
            return (
                f"{result}\n"
                f"Use list_calling_conventions() to see available conventions.\n"
                f"Note: Don't specify calling convention in both prototype AND calling_convention parameter."
            )
        elif "server error 500" in result.lower():
            return (
                f"{result}\n"
                f"Common causes:\n"
                f"  1. Using 'uint' instead of 'dword' (use Ghidra types)\n"
                f"  2. Specifying calling convention twice (in prototype AND parameter)\n"
                f"  3. Invalid type names (check with validate_data_type_exists())\n"
                f"Valid example: 'dword myFunction(void)' without calling_convention parameter"
            )
        elif "error" in result.lower() or "failed" in result.lower():
            return (
                f"{result}\n"
                f"Verify prototype syntax is valid C (e.g., 'int func(int x)').\n"
                f"Use Ghidra types: dword (not uint), ushort (not USHORT), byte (not BYTE)"
            )

        return result
    finally:
        # Restore original timeout
        if timeout:
            ENDPOINT_TIMEOUTS["set_function_prototype"] = original_timeout


@mcp.tool()
def list_calling_conventions(program: str = None) -> str:
    """
    List all available calling conventions in the current Ghidra program.

    This tool is useful for debugging and verifying which calling conventions
    are loaded, especially after adding custom conventions to x86win.cspec.

    Args:
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        List of available calling convention names

    Example:
        conventions = list_calling_conventions()
        print(conventions)
        # Output: Available Calling Conventions (7):
        #         - __stdcall
        #         - __cdecl
        #         - __fastcall
        #         - __thiscall
        #         - __d2call
        #         - __d2regcall
        #         - __d2mixcall
    """
    return safe_get("list_calling_conventions", program=program)


@mcp.tool()
def set_local_variable_type(
    function_address: str, variable_name: str, new_type: str, program: str = None
) -> str:
    """
    Set a local variable's type.

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
        variable_name: Name of the local variable to modify
        new_type: New data type for the variable (e.g., "int", "char*", "MyStruct")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message indicating the result of the type change
    """
    if not validate_hex_address(function_address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {function_address}")

    return safe_post(
        "set_local_variable_type",
        {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type,
        },
        program=program,
    )


@mcp.tool()
def set_function_no_return(function_address: str, no_return: bool, program: str = None) -> str:
    """
    Set a function's "No Return" attribute to control flow analysis.

    This tool controls whether Ghidra treats a function as non-returning (like exit(), abort(), etc.).
    When a function is marked as non-returning:
    - Call sites are treated as terminators (CALL_TERMINATOR)
    - The decompiler doesn't show code execution continuing after the call
    - Control flow analysis treats the call like a RET instruction

    Use this to:
    - Fix incorrect flow overrides where functions actually return
    - Mark error handlers that never return (ExitProcess, TerminateThread, etc.)
    - Improve decompilation accuracy by correcting control flow assumptions

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x6fabbf92")
        no_return: true to mark as non-returning, false to mark as returning
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message with the function's old and new state

    Example:
        # Fix TriggerFatalError that actually returns
        set_function_no_return("0x6fabbf92", False)

        # Mark ExitApplication as non-returning
        set_function_no_return("0x6fab3664", True)
    """
    if not validate_hex_address(function_address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {function_address}")

    return safe_post(
        "set_function_no_return",
        {
            "function_address": function_address,
            "no_return": str(
                no_return
            ).lower(),  # Convert boolean to string for HTTP form data
        },
        program=program,
    )


@mcp.tool()
def set_variable_storage(
    function_address: str, variable_name: str, storage: str, program: str = None
) -> str:
    """
    Set custom storage for a local variable or parameter, overriding Ghidra's automatic detection.

    Args:
        function_address: Function address in hex (e.g., "0x6fb6aef0")
        variable_name: Name of variable to modify (e.g., "unaff_EBP")
        storage: Storage spec: "Stack[-0x10]:4", "EBP:4", "register:EBP", or "EAX:4"
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success message with old and new storage details. Use force decompile afterward to see changes.
    """
    if not validate_hex_address(function_address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {function_address}")

    if not variable_name or not variable_name.strip():
        raise GhidraValidationError("Variable name cannot be empty")

    if not storage or not storage.strip():
        raise GhidraValidationError("Storage specification cannot be empty")

    return safe_post(
        "set_variable_storage",
        {
            "function_address": function_address,
            "variable_name": variable_name,
            "storage": storage,
        },
        program=program,
    )


@mcp.tool()
def run_script(script_path: str, args: str = "", program: str = None) -> str:
    """
    Run a Ghidra script programmatically (v1.7.0).

    Executes Java (.java) or Python (.py) Ghidra scripts to automate complex
    analysis tasks that aren't covered by existing MCP tools.

    **Common Use Cases:**
    - Run custom analysis scripts
    - Execute batch processing workflows
    - Apply domain-specific reverse engineering techniques
    - Automate repetitive manual tasks

    Args:
        script_path: Absolute path to the script file (.java or .py)
        args: Optional JSON string of arguments (not yet fully implemented)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Script execution result or error message

    Example:
        # Run the EBP register reuse fix script
        run_script("C:/Users/user/ghidra-mcp/FixEBPRegisterReuse.py")

        # Run a custom analysis script
        run_script("/path/to/my_custom_analysis.java")

    Note:
        - Script must be a valid Ghidra script with proper annotations
        - The script runs in the context of the currently loaded program
        - Use list_scripts() to see available scripts
    """
    if not script_path or not script_path.strip():
        raise GhidraValidationError("Script path cannot be empty")

    return safe_post("run_script", {"script_path": script_path, "args": args}, program=program)


@mcp.tool()
def list_scripts(filter: str = "", program: str = None) -> str:
    """
    List available Ghidra scripts (v1.7.0).

    Returns a JSON list of all Ghidra scripts available in the script directories,
    optionally filtered by name.

    Args:
        filter: Optional filter string to match script names (case-sensitive substring match)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON object with array of script information:
        {
          "scripts": [
            {
              "name": "FixEBPRegisterReuse.py",
              "path": "/full/path/to/script.py",
              "provider": "PythonScriptProvider"
            },
            ...
          ]
        }

    Example:
        # List all scripts
        list_scripts()

        # Find EBP-related scripts
        list_scripts("EBP")

        # Find Python scripts
        list_scripts(".py")
    """
    params = {}
    if filter:
        params["filter"] = filter

    return safe_get_json("list_scripts", params, program=program)


@mcp.tool()
def get_xrefs_to(
    address: str, offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    Get all references to the specified address (xref to).

    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        program: Optional program name to query (e.g., "D2Client.dll").
                 If not specified, uses the currently active program.

    Returns:
        List of references to the specified address
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    params = {"address": address, "offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("get_xrefs_to", params)


@mcp.tool()
def get_xrefs_from(
    address: str, offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    Get all references from the specified address (xref from).

    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        program: Optional program name to query (e.g., "D2Client.dll").
                 If not specified, uses the currently active program.

    Returns:
        List of references from the specified address
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    params = {"address": address, "offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("get_xrefs_from", params)


@mcp.tool()
def get_function_xrefs(
    name: str, offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    Get all references to the specified function by name.

    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        program: Optional program name to query (e.g., "D2Client.dll").
                 If not specified, uses the currently active program.

    Returns:
        List of references to the specified function
    """
    params = {"name": name, "offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("get_function_xrefs", params)


@mcp.tool()
def list_strings(
    offset: int = 0, limit: int = 100, filter: str = None, program: str = None
) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 100)
        filter: Optional filter to match within string content
        program: Optional program name for multi-program support

    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    if program:
        params["program"] = program
    return safe_get("list_strings", params)


@mcp.tool()
def get_function_jump_targets(
    name: str, offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    Get all jump target addresses from a function's disassembly.

    Analyzes the disassembly of a specified function and extracts all addresses
    that are targets of conditional and unconditional jump instructions (JMP, JE, JNE, JZ, etc.).

    Args:
        name: Function name to analyze for jump targets
        offset: Pagination offset (default: 0)
        limit: Maximum number of jump targets to return (default: 100)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        List of jump target addresses found in the function's disassembly
    """
    return safe_get(
        "get_function_jump_targets", {"name": name, "offset": offset, "limit": limit}, program=program
    )


@mcp.tool()
def create_label(address: str, name: str, program: str = None) -> str:
    """
    Create a new label at the specified address.

    This tool creates labels at any memory address, including undefined memory.
    Use this for addresses without defined data types.

    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
                Accepts addresses with or without 0x prefix
        name: Name for the new label (must be valid C identifier)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        str: Success or failure message indicating the result of the label creation

    Raises:
        GhidraValidationError: If address or name format is invalid

    Examples:
        # Create a label at undefined memory
        create_label("0x401000", "start_routine")

        # Create a label at data location
        create_label("0x403000", "global_config")

    See Also:
        - rename_data(): Rename existing defined data
        - rename_or_label(): Automatically detect and use correct method
        - batch_create_labels(): Create multiple labels efficiently
    """
    # Sanitize and validate address
    address = sanitize_address(address)
    if not validate_hex_address(address):
        raise GhidraValidationError(
            f"Invalid hexadecimal address format: {address}. "
            f"Expected format: 0x followed by hex digits (e.g., '0x401000')."
        )

    # Validate name format
    if not name or not name.strip():
        raise GhidraValidationError("Label name cannot be empty.")

    name = name.strip()
    if not name[0].isalpha() and name[0] != "_":
        raise GhidraValidationError(
            f"Invalid label name '{name}'. "
            f"Names must start with a letter or underscore."
        )

    if not all(c.isalnum() or c == "_" for c in name):
        raise GhidraValidationError(
            f"Invalid label name '{name}'. "
            f"Names can only contain letters, numbers, and underscores."
        )

    result = safe_post("create_label", {"address": address, "name": name}, program=program)

    # Provide actionable error messages
    if "success" in result.lower() or "created" in result.lower():
        return f"Successfully created label '{name}' at {address}"
    elif "already exists" in result.lower():
        return (
            f"{result}\n"
            f"Try: rename_label('{address}', old_name, '{name}') to rename existing label."
        )
    elif "error" in result.lower() or "failed" in result.lower():
        return (
            f"{result}\nVerify address is valid: get_function_by_address('{address}')"
        )

    return result


@mcp.tool()
def batch_create_labels(labels: list, program: str = None) -> str:
    """
    Create multiple labels in a single atomic operation (v1.5.1).

    This tool creates multiple labels in one transaction, dramatically reducing API calls
    and preventing user interruption hooks from triggering repeatedly. This is the
    preferred method for creating multiple labels during function documentation.

    Performance impact:
    - Reduces N API calls to 1 call
    - Prevents interruption after each label creation
    - Atomic transaction ensures all-or-nothing semantics

    Args:
        labels: List of label objects, each with "address" and "name" fields
                Example: [{"address": "0x6faeb266", "name": "begin_slot_processing"},
                         {"address": "0x6faeb280", "name": "loop_check_slot_active"}]
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON string with success status, counts, and any errors:
        {"success": true, "labels_created": 5, "labels_skipped": 1, "labels_failed": 0}
    """
    if not labels or not isinstance(labels, list):
        raise GhidraValidationError("labels must be a non-empty list")

    # Validate each label entry
    for i, label in enumerate(labels):
        if not isinstance(label, dict):
            raise GhidraValidationError(f"Label at index {i} must be a dictionary")

        if "address" not in label or "name" not in label:
            raise GhidraValidationError(
                f"Label at index {i} must have 'address' and 'name' fields"
            )

        if not validate_hex_address(label["address"]):
            raise GhidraValidationError(
                f"Invalid hexadecimal address at index {i}: {label['address']}"
            )

    return safe_post_json("batch_create_labels", {"labels": labels}, program=program)


@mcp.tool()
def rename_or_label(address: str, name: str, program: str = None) -> str:
    """
    Intelligently rename data or create label at an address (server-side detection).

    This tool automatically detects whether the address contains defined data or
    undefined bytes and chooses the appropriate operation server-side. This is
    more efficient than rename_data_smart as the detection happens in Ghidra
    without additional API calls.

    Use this tool when you're unsure whether data is defined or undefined, or when
    you want guaranteed reliability with minimal round-trips.

    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")
        name: Name for the data/label
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message with details about the operation performed
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_post("rename_or_label", {"address": address, "name": name}, program=program)


@mcp.tool()
def delete_label(address: str, name: str = None, program: str = None) -> str:
    """
    Delete a label at the specified address.

    This tool removes labels from memory addresses. Useful for cleaning up
    orphan labels after applying array types that consume multiple addresses.

    Args:
        address: Memory address in hex format (e.g., "0x6ff86c64")
                 Accepts addresses with or without 0x prefix
        name: Optional specific label name to delete. If not provided,
              deletes all labels at the address.
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with deletion results:
        {
          "success": true,
          "deleted_count": 1,
          "deleted_names": ["g_pData_6ff86c64"]
        }

    Examples:
        # Delete specific label by name
        delete_label("0x6ff86c64", "g_pData_6ff86c64")

        # Delete all labels at address
        delete_label("0x6ff86c64")

    See Also:
        - batch_delete_labels(): Delete multiple labels efficiently
        - create_label(): Create new labels
        - rename_or_label(): Rename or create labels
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    params = {"address": address}
    if name:
        params["name"] = name

    return safe_post("delete_label", params, program=program)


@mcp.tool()
def batch_delete_labels(labels: list, program: str = None) -> str:
    """
    Delete multiple labels in a single atomic operation.

    Args:
        labels: List of label dicts, each with "address" (required) and optional "name".
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with labels_deleted, labels_skipped, and errors_count.
    """
    if not isinstance(labels, list):
        raise GhidraValidationError("labels must be a list")

    if len(labels) == 0:
        raise GhidraValidationError("labels list cannot be empty")

    for i, label in enumerate(labels):
        if not isinstance(label, dict):
            raise GhidraValidationError(f"Label at index {i} must be a dictionary")

        if "address" not in label:
            raise GhidraValidationError(f"Label at index {i} must have 'address' field")

        if not validate_hex_address(label["address"]):
            raise GhidraValidationError(
                f"Invalid hexadecimal address at index {i}: {label['address']}"
            )

    return safe_post_json("batch_delete_labels", {"labels": labels}, program=program)


@mcp.tool()
def get_function_callees(
    name: str, offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    Get all functions called by the specified function (callees).

    This tool analyzes a function and returns all functions that it calls directly.
    Useful for understanding what functionality a function depends on.

    Args:
        name: Function name to analyze for callees
        offset: Pagination offset (default: 0)
        limit: Maximum number of callees to return (default: 100)
        program: Optional program name for multi-program support

    Returns:
        List of functions called by the specified function
    """
    params = {"name": name, "offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("get_function_callees", params)


@mcp.tool()
def get_function_callers(
    name: str, offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    Get all functions that call the specified function (callers).

    This tool finds all functions that call the specified function, helping to
    understand the function's usage throughout the program.

    Args:
        name: Function name to find callers for
        offset: Pagination offset (default: 0)
        limit: Maximum number of callers to return (default: 100)
        program: Optional program name for multi-program support

    Returns:
        List of functions that call the specified function
    """
    params = {"name": name, "offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("get_function_callers", params)


@mcp.tool()
def get_function_call_graph(
    name: str, depth: int = 2, direction: str = "both", program: str = None
) -> list:
    """
    Get a call graph subgraph centered on the specified function.

    This tool generates a localized call graph showing the relationships between
    a function and its callers/callees up to a specified depth.

    Args:
        name: Function name to center the graph on
        depth: Maximum depth to traverse (default: 2)
        direction: Direction to traverse ("callers", "callees", "both")
        program: Optional program name for multi-program support

    Returns:
        List of call graph relationships in the format "caller -> callee"
    """
    params = {"name": name, "depth": depth, "direction": direction}
    if program:
        params["program"] = program
    return safe_get("get_function_call_graph", params)


@mcp.tool()
def get_full_call_graph(
    format: str = "edges", limit: int = 500, program: str = None
) -> list:
    """
    Get the complete call graph for the entire program.

    This tool generates a comprehensive call graph showing all function call
    relationships in the program. Can be output in different formats.

    Args:
        format: Output format ("edges", "adjacency", "dot", "mermaid")
        limit: Maximum number of relationships to return (default: 500)
        program: Optional program name for multi-program support

    Returns:
        Complete call graph in the specified format
    """
    params = {"format": format, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("get_full_call_graph", params)


@mcp.tool()
def list_data_types(
    category: str = None, offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    List all data types available in the program with optional category filtering.

    This tool enumerates all data types defined in the program's data type manager,
    including built-in types, user-defined structs, enums, and imported types.

    Args:
        category: Optional category filter (e.g., "builtin", "struct", "enum", "pointer")
        offset: Pagination offset (default: 0)
        limit: Maximum number of data types to return (default: 100)
        program: Optional program name to query (if not provided, uses current program)

    Returns:
        List of data types with their names, categories, and sizes
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    if program:
        params["program"] = program
    return safe_get("list_data_types", params)


@mcp.tool()
def search_data_types(pattern: str, offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    Search for data types by pattern matching against type names.

    This tool searches all data types in the program and returns those matching
    the specified pattern. The search is case-insensitive and matches against
    type names, categories, and full paths.

    Args:
        pattern: Search pattern (case-insensitive substring match)
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        List of matching data types with their names, categories, and sizes

    Example:
        # Search for all integer types
        search_data_types(pattern="int", limit=20)

        # Search for pointer types
        search_data_types(pattern="ptr", limit=10)
    """
    params = {"pattern": pattern, "offset": offset, "limit": limit}
    return safe_get("search_data_types", params, program=program)


@mcp.tool()
def create_struct(name: str, fields: list, program: str = None) -> str:
    """
    Create a new structure data type with specified fields.

    Args:
        name: Name for the new structure (must be unique)
        fields: List of field dicts, each with "name" (str), "type" (str), and optional "offset" (int).
                Supported types: int, uint, long, dword, ushort, word, short, char, byte, uchar,
                float, double, void*, typename[count] (arrays), or any custom struct/enum name.
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success message with structure name, field count, and total size.
    """
    return safe_post_json("create_struct", {"name": name, "fields": fields}, program=program)


@mcp.tool()
def create_enum(name: str, values: dict, size: int = 4, program: str = None) -> str:
    """
    Create a new enumeration data type with name-value pairs.

    This tool creates an enumeration type that can be applied to memory locations
    to provide meaningful names for numeric values.

    Args:
        name: Name for the new enumeration
        values: Dictionary of name-value pairs (e.g., {"OPTION_A": 0, "OPTION_B": 1})
        size: Size of the enum in bytes (1, 2, 4, or 8, default: 4)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success/failure message with created enumeration details

    Example:
        values = {"STATE_IDLE": 0, "STATE_RUNNING": 1, "STATE_STOPPED": 2}
    """
    return safe_post_json("create_enum", {"name": name, "values": values, "size": size}, program=program)


@mcp.tool()
def apply_data_type(address: str, type_name: str, clear_existing: bool = True, program: str = None) -> str:
    """
    Apply a specific data type at the given memory address.

    This tool applies a data type definition to a memory location, which helps
    in interpreting the raw bytes as structured data during analysis.

    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        type_name: Name of the data type to apply (e.g., "int", "MyStruct", "DWORD")
        clear_existing: Whether to clear existing data/code at the address (default: True)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success/failure message with details about the applied data type
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    logger.info(
        f"apply_data_type called with: address={address}, type_name={type_name}, clear_existing={clear_existing}"
    )
    data = {
        "address": address,
        "type_name": type_name,
        "clear_existing": clear_existing,
    }
    logger.info(f"Data being sent: {data}")
    result = safe_post_json("apply_data_type", data, program=program)
    logger.info(f"Result received: {result}")
    return result


@mcp.tool()
def check_connection() -> str:
    """
    Check if the Ghidra plugin is running and accessible.

    Returns:
        Connection status message
    """
    try:
        response = session.get(
            urljoin(ghidra_server_url, "check_connection"), timeout=REQUEST_TIMEOUT
        )
        if response.ok:
            return response.text.strip()
        else:
            return f"Connection failed: HTTP {response.status_code}"
    except Exception as e:
        return f"Connection failed: {str(e)}"


@mcp.tool()
def get_version() -> str:
    """
    Get version information about the GhidraMCP plugin and Ghidra.

    Returns detailed version information including:
    - Plugin version
    - Plugin name
    - Ghidra version
    - Java version
    - Endpoint count
    - Implementation status

    Returns:
        JSON string with version information
    """
    return "\n".join(safe_get("get_version"))


@mcp.tool()
def get_metadata(program: str = None) -> str:
    """
    Get metadata about the current program/database.

    Returns program information including name, architecture, base address,
    entry points, and other relevant metadata.

    Args:
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON string with program metadata
    """
    return "\n".join(safe_get("get_metadata", program=program))


@mcp.tool()
def get_function_count(program: str = None) -> str:
    """
    Return the total number of functions in the loaded program.

    Quickly retrieve the function count without listing all functions.
    Useful for estimating analysis scope or monitoring analysis progress.

    Args:
        program: Optional program name for multi-binary projects

    Returns:
        JSON with function_count and program name
    """
    params = {}
    if program:
        params["program"] = program
    return safe_get_json("get_function_count", params)


@mcp.tool()
def list_globals(
    offset: int = 0, limit: int = 100, filter: str = None, program: str = None
) -> list:
    """
    List matching globals in the database (paginated, filtered).

    Lists global variables and symbols in the program with optional filtering.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of globals to return (default: 100)
        filter: Optional filter to match global names (default: None)
        program: Optional program name for multi-program support

    Returns:
        List of global variables/symbols with their details
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    if program:
        params["program"] = program
    return safe_get("list_globals", params)


@mcp.tool()
def rename_global_variable(old_name: str, new_name: str, program: str = None) -> str:
    """
    Rename a global variable.

    Changes the name of a global variable or symbol in the program.

    Args:
        old_name: Current name of the global variable
        new_name: New name for the global variable
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success/failure message
    """
    return safe_post(
        "rename_global_variable", {"old_name": old_name, "new_name": new_name}, program=program
    )


@mcp.tool()
def get_entry_points(program: str = None) -> list:
    """
    Get all entry points in the database.

    Returns all program entry points including the main entry point and any
    additional entry points defined in the program.

    Args:
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        List of entry points with their addresses and names
    """
    return safe_get("get_entry_points", program=program)


# Data Type Analysis and Management Tools


@mcp.tool()
def get_enum_values(enum_name: str, program: str = None) -> list:
    """
    Get all values and names in an enumeration.

    Args:
        enum_name: Name of the enumeration to query
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        List of all enumeration values with their names and numeric values
    """
    return safe_get("get_enum_values", {"enum_name": enum_name}, program=program)


@mcp.tool()
def search_byte_patterns(pattern: str, mask: str = None, program: str = None) -> list:
    """
    Search for byte patterns with optional wildcards (e.g., 'E8 ?? ?? ?? ??').
    Useful for finding shellcode, API calls, or specific instruction sequences.

    **IMPLEMENTED in v1.7.1** - Searches all initialized memory blocks for matching byte sequences.
    Supports wildcard patterns using '??' for any byte. Returns up to 1000 matches.

    Args:
        pattern: Hexadecimal pattern to search for (e.g., "E8 ?? ?? ?? ??")
        mask: Optional mask for wildcards (use ? for wildcards)
        program: Optional program name for multi-binary projects

    Returns:
        List of addresses where the pattern was found

    Example:
        search_byte_patterns("E8 ?? ?? ?? ??")  # Find all CALL instructions
        search_byte_patterns("558BEC")  # Find standard function prologue
        search_byte_patterns("44324c4f44", program="Game.dll")  # Search in specific binary
    """
    params = {"pattern": pattern}
    if mask:
        params["mask"] = mask
    if program:
        params["program"] = program
    return safe_get("search_byte_patterns", params)


@mcp.tool()
def delete_data_type(type_name: str, program: str = None) -> str:
    """
    Delete a data type from the program.

    This tool removes a data type (struct, enum, typedef, etc.) from the program's
    data type manager. The type cannot be deleted if it's currently being used.

    Args:
        type_name: Name of the data type to delete
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message with details
    """
    if not type_name or not isinstance(type_name, str):
        raise GhidraValidationError("Type name is required and must be a string")

    return safe_post_json("delete_data_type", {"type_name": type_name}, program=program)


@mcp.tool()
def consolidate_duplicate_types(base_type_name: str, auto_delete: bool = False, program: str = None) -> str:
    """
    Find and consolidate duplicate state-based types into an identity-based type.

    Args:
        base_type_name: Base identity-based type name (e.g., "GameObject")
        auto_delete: If True, delete state-based variants. If False (default), only report duplicates.
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with duplicates found, deleted (if auto_delete), warnings, and recommendations.
    """
    import json
    import re

    if not base_type_name or not isinstance(base_type_name, str):
        raise GhidraValidationError("Base type name is required and must be a string")

    # State-based prefixes to detect
    state_prefixes = [
        "Initialized",
        "Allocated",
        "Created",
        "Updated",
        "Processed",
        "Deleted",
        "Modified",
        "Constructed",
        "Freed",
        "Destroyed",
        "Copied",
        "Cloned",
        "Active",
        "Pending",
        "Ready",
    ]

    # Search for all types matching base name pattern
    types_result = search_data_types(base_type_name, program=program)
    types_data = (
        json.loads(types_result) if isinstance(types_result, str) else types_result
    )

    # Find base type info
    base_type_info = None
    duplicates_found = []

    for type_entry in types_data:
        type_name = type_entry.split("|")[0].strip()

        # Exact match is our base type
        if type_name == base_type_name:
            base_type_info = type_entry
        # Check if it's a state-based variant
        else:
            for prefix in state_prefixes:
                if type_name.startswith(prefix) and type_name.endswith(base_type_name):
                    duplicates_found.append(type_name)
                    break

    # Build result
    result = {
        "base_type": base_type_name,
        "base_type_exists": base_type_info is not None,
        "duplicates_found": duplicates_found,
        "duplicates_deleted": [],
        "warnings": [],
        "action_required": False,
        "recommendations": [],
    }

    if not base_type_info:
        result["warnings"].append(
            f"Base type '{base_type_name}' does not exist - cannot consolidate"
        )
        result["action_required"] = True
        return json.dumps(result)

    if not duplicates_found:
        result["recommendations"].append(
            f"No state-based duplicates found for {base_type_name} - type naming is correct"
        )
        return json.dumps(result)

    # Extract size from base type info
    base_size_match = re.search(r"(\d+) bytes", base_type_info)
    if base_size_match:
        result["base_type_size"] = int(base_size_match.group(1))

    # If auto_delete is True, attempt to delete duplicates
    if auto_delete:
        for duplicate in duplicates_found:
            try:
                delete_result = delete_data_type(duplicate, program=program)
                if "error" not in delete_result.lower():
                    result["duplicates_deleted"].append(duplicate)
                else:
                    result["warnings"].append(
                        f"{duplicate} could not be deleted: {delete_result}"
                    )
                    result["action_required"] = True
            except Exception as e:
                result["warnings"].append(f"Failed to delete {duplicate}: {str(e)}")
                result["action_required"] = True
    else:
        result["action_required"] = True
        result["recommendations"].append(
            "Run consolidate_duplicate_types() with auto_delete=True after updating function prototypes"
        )

    # Add recommendations for manual cleanup
    if result["action_required"]:
        for duplicate in duplicates_found:
            if duplicate not in result["duplicates_deleted"]:
                result["recommendations"].append(
                    f"Update function prototypes: replace '{duplicate} *' with '{base_type_name} *' using set_function_prototype()"
                )
        result["recommendations"].append(
            f"After updating all references, re-run: consolidate_duplicate_types('{base_type_name}', auto_delete=True)"
        )

    return json.dumps(result)


@mcp.tool()
def modify_struct_field(
    struct_name: str, field_name: str, new_type: str = None, new_name: str = None, program: str = None
) -> str:
    """
    Modify a field in an existing structure.

    This tool allows changing the type and/or name of a field in an existing structure.
    At least one of new_type or new_name must be provided.

    Args:
        struct_name: Name of the structure to modify
        field_name: Name of the field to modify
        new_type: New data type for the field (optional)
        new_name: New name for the field (optional)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message with details
    """
    if not struct_name or not isinstance(struct_name, str):
        raise GhidraValidationError("Structure name is required and must be a string")
    if not field_name or not isinstance(field_name, str):
        raise GhidraValidationError("Field name is required and must be a string")
    if not new_type and not new_name:
        raise GhidraValidationError(
            "At least one of new_type or new_name must be provided"
        )

    data = {"struct_name": struct_name, "field_name": field_name}
    if new_type:
        data["new_type"] = new_type
    if new_name:
        data["new_name"] = new_name

    return safe_post_json("modify_struct_field", data, program=program)


@mcp.tool()
def add_struct_field(
    struct_name: str, field_name: str, field_type: str, offset: int = -1, program: str = None
) -> str:
    """
    Add a new field to an existing structure.

    This tool adds a new field to an existing structure at the specified offset
    or at the end if no offset is provided.

    Args:
        struct_name: Name of the structure to modify
        field_name: Name of the new field
        field_type: Data type of the new field
        offset: Offset to insert the field at (-1 for end, default: -1)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message with details
    """
    if not struct_name or not isinstance(struct_name, str):
        raise GhidraValidationError("Structure name is required and must be a string")
    if not field_name or not isinstance(field_name, str):
        raise GhidraValidationError("Field name is required and must be a string")
    if not field_type or not isinstance(field_type, str):
        raise GhidraValidationError("Field type is required and must be a string")

    data = {
        "struct_name": struct_name,
        "field_name": field_name,
        "field_type": field_type,
        "offset": offset,
    }

    return safe_post_json("add_struct_field", data, program=program)


@mcp.tool()
def remove_struct_field(struct_name: str, field_name: str, program: str = None) -> str:
    """
    Remove a field from an existing structure.

    This tool removes a field from an existing structure by name.

    Args:
        struct_name: Name of the structure to modify
        field_name: Name of the field to remove
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message with details
    """
    if not struct_name or not isinstance(struct_name, str):
        raise GhidraValidationError("Structure name is required and must be a string")
    if not field_name or not isinstance(field_name, str):
        raise GhidraValidationError("Field name is required and must be a string")

    return safe_post_json(
        "remove_struct_field", {"struct_name": struct_name, "field_name": field_name}, program=program
    )


@mcp.tool()
def create_array_type(base_type: str, length: int, name: str = None, program: str = None) -> str:
    """
    Create an array data type.

    This tool creates a new array data type based on an existing base type
    with the specified length.

    Args:
        base_type: Name of the base data type for the array
        length: Number of elements in the array
        name: Optional name for the array type
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message with created array type details
    """
    if not base_type or not isinstance(base_type, str):
        raise GhidraValidationError("Base type is required and must be a string")
    if not isinstance(length, int) or length <= 0:
        raise GhidraValidationError("Length must be a positive integer")

    data = {"base_type": base_type, "length": length}
    if name:
        data["name"] = name

    return safe_post_json("create_array_type", data, program=program)


@mcp.tool()
def analyze_data_region(
    address: str,
    max_scan_bytes: int = 1024,
    include_xref_map: bool = True,
    include_assembly_patterns: bool = True,
    include_boundary_detection: bool = True,
    program: str = None,
) -> str:
    """
    Comprehensive single-call analysis of a data region (boundaries, xrefs, stride, classification).

    Args:
        address: Starting address in hex format (e.g., "0x6fb835b8")
        max_scan_bytes: Maximum bytes to scan for boundary detection (default: 1024)
        include_xref_map: Include byte-by-byte xref mapping (default: True)
        include_assembly_patterns: Include assembly pattern analysis (default: True)
        include_boundary_detection: Detect data region boundaries (default: True)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with start/end address, xref map, classification hint, stride, and boundary info.
    """
    import json

    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hex address format: {address}")

    if not isinstance(max_scan_bytes, int) or max_scan_bytes <= 0:
        raise GhidraValidationError("max_scan_bytes must be a positive integer")

    data = {
        "address": address,
        "max_scan_bytes": max_scan_bytes,
        "include_xref_map": include_xref_map,
        "include_assembly_patterns": include_assembly_patterns,
        "include_boundary_detection": include_boundary_detection,
    }

    result = safe_post_json("analyze_data_region", data, program=program)

    # Format the JSON response for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result


@mcp.tool()
def inspect_memory_content(
    address: str, length: int = 64, detect_strings: bool = True, program: str = None
) -> str:
    """
    Read raw memory bytes and provide hex/ASCII representation with string detection hints.

    This tool helps prevent misidentification of strings as numeric data by:
    - Reading actual byte content in hex and ASCII format
    - Detecting printable ASCII characters and null terminators
    - Calculating string likelihood score
    - Suggesting appropriate data types (char[N] for strings, etc.)

    Args:
        address: Memory address in hex format (e.g., "0x6fb7ffbc")
        length: Number of bytes to read (default: 64)
        detect_strings: Enable string detection heuristics (default: True)
        program: Optional program name for multi-program support

    Returns:
        JSON string with memory inspection results:
        {
          "address": "0x6fb7ffbc",
          "bytes_read": 64,
          "hex_dump": "4A 75 6C 79 00 ...",
          "ascii_repr": "July\\0...",
          "printable_count": 4,
          "printable_ratio": 0.80,
          "null_terminator_at": 4,
          "max_consecutive_printable": 4,
          "is_likely_string": true,
          "detected_string": "July",
          "suggested_type": "char[5]",
          "string_length": 5
        }
    """
    import json

    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hex address format: {address}")

    if not isinstance(length, int) or length <= 0 or length > 4096:
        raise GhidraValidationError("length must be a positive integer <= 4096")

    params = {
        "address": address,
        "length": length,
        "detect_strings": str(detect_strings).lower(),
    }
    if program:
        params["program"] = program

    result = "\n".join(safe_get("inspect_memory_content", params))

    # Try to format as JSON for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result


@mcp.tool()
def get_bulk_xrefs(addresses: str, program: str = None) -> str:
    """
    Get cross-references for multiple addresses in a single batch request.

    This tool retrieves xrefs for multiple addresses simultaneously, dramatically
    reducing the number of network round-trips required for byte-by-byte analysis.

    Args:
        addresses: Comma-separated list of hex addresses (e.g., "0x6fb835b8,0x6fb835b9,0x6fb835ba")
                  or JSON array string (e.g., '["0x6fb835b8", "0x6fb835b9"]')
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON string with xref mappings:
        {
          "0x6fb835b8": [{"from": "0x6fb6cae9", "type": "DATA"}],
          "0x6fb835b9": [],
          "0x6fb835ba": [],
          "0x6fb835bc": [{"from": "0x6fb6c9fe", "type": "READ"}]
        }
    """
    import json

    # Parse input - support both comma-separated and JSON array
    addr_list = []
    if addresses.startswith("["):
        try:
            addr_list = json.loads(addresses)
        except:
            raise GhidraValidationError("Invalid JSON array format for addresses")
    else:
        addr_list = [addr.strip() for addr in addresses.split(",")]

    # Validate all addresses
    for addr in addr_list:
        if not validate_hex_address(addr):
            raise GhidraValidationError(f"Invalid hex address format: {addr}")

    data = {"addresses": addr_list}
    result = safe_post_json("get_bulk_xrefs", data, program=program)

    # Format the JSON response for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result


@mcp.tool()
def detect_array_bounds(
    address: str,
    analyze_loop_bounds: bool = True,
    analyze_indexing: bool = True,
    max_scan_range: int = 2048,
    program: str = None,
) -> str:
    """
    Automatically detect array/table size and element boundaries.

    This tool analyzes assembly patterns including loop bounds, array indexing,
    and comparison checks to determine the true size of arrays and tables.

    Args:
        address: Starting address of array/table in hex format (e.g., "0x6fb835d4")
        analyze_loop_bounds: Analyze loop CMP instructions for bounds (default: True)
        analyze_indexing: Analyze array indexing patterns for stride (default: True)
        max_scan_range: Maximum bytes to scan for table end (default: 2048)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON string with array analysis:
        {
          "probable_element_size": 12,
          "probable_element_count": 4,
          "total_bytes": 48,
          "confidence": "high|medium|low",
          "evidence": [
            {"type": "loop_bound", "address": "0x6fb6a023", "instruction": "CMP ECX, 4"},
            {"type": "stride_pattern", "stride": 12, "occurrences": 8},
            {"type": "boundary", "address": "0x6fb83604", "reason": "comparison_limit"}
          ],
          "loop_functions": ["ProcessTimedSpellEffect..."],
          "indexing_patterns": ["[base + index*12]", "LEA EDX, [EAX*3 + base]"]
        }
    """
    import json

    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hex address format: {address}")

    if not isinstance(max_scan_range, int) or max_scan_range <= 0:
        raise GhidraValidationError("max_scan_range must be a positive integer")

    data = {
        "address": address,
        "analyze_loop_bounds": analyze_loop_bounds,
        "analyze_indexing": analyze_indexing,
        "max_scan_range": max_scan_range,
    }

    result = safe_post_json("detect_array_bounds", data, program=program)

    # Format the JSON response for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result


@mcp.tool()
def get_assembly_context(
    xref_sources: str,
    context_instructions: int = 5,
    include_patterns: str = "LEA,MOV,CMP,IMUL,ADD,SUB",
    program: str = None,
) -> str:
    """
    Get assembly instructions with context for multiple xref source addresses.

    This tool retrieves assembly context around xref instructions to understand
    access patterns, data types, and usage context without manual disassembly.

    Args:
        xref_sources: Comma-separated xref source addresses (e.g., "0x6fb6cae9,0x6fb6c9fe")
                     or JSON array string
        context_instructions: Number of instructions before/after to include (default: 5)
        include_patterns: Comma-separated instruction types to highlight (default: "LEA,MOV,CMP,IMUL,ADD,SUB")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON string with assembly context:
        [
          {
            "xref_from": "0x6fb6cae9",
            "instruction": "MOV EDX, [0x6fb835b8]",
            "access_size": 4,
            "access_type": "READ",
            "context_before": ["0x6fb6cae4: PUSH EBX", ...],
            "context_after": ["0x6fb6caef: ADD EDX, EBX", ...],
            "pattern_detected": "array_index_check|dword_access|structure_field"
          }
        ]
    """
    import json

    # Parse input
    addr_list = []
    if xref_sources.startswith("["):
        try:
            addr_list = json.loads(xref_sources)
        except:
            raise GhidraValidationError("Invalid JSON array format for xref_sources")
    else:
        addr_list = [addr.strip() for addr in xref_sources.split(",")]

    # Validate all addresses
    for addr in addr_list:
        if not validate_hex_address(addr):
            raise GhidraValidationError(f"Invalid hex address format: {addr}")

    if not isinstance(context_instructions, int) or context_instructions < 0:
        raise GhidraValidationError(
            "context_instructions must be a non-negative integer"
        )

    pattern_list = [p.strip() for p in include_patterns.split(",")]

    data = {
        "xref_sources": addr_list,
        "context_instructions": context_instructions,
        "include_patterns": pattern_list,
    }

    result = safe_post_json("get_assembly_context", data, program=program)

    # Format the JSON response for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result


# ============================================================================
# FIELD-LEVEL ANALYSIS TOOLS (v1.4.0)
# ============================================================================


@mcp.tool()
def analyze_struct_field_usage(
    address: str, struct_name: str = None, max_functions: int = 10, program: str = None
) -> str:
    """
    Analyze how structure fields are accessed in decompiled code.

    This tool decompiles all functions that reference a structure and extracts usage patterns
    for each field, including variable names, access types, and purposes. This enables
    generating descriptive field names based on actual usage rather than generic placeholders.

    Args:
        address: Address of the structure instance in hex format (e.g., "0x6fb835b8")
        struct_name: Name of the structure type (optional - can be inferred if null)
        max_functions: Maximum number of referencing functions to analyze (default: 10)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON string with field usage analysis:
        {
          "struct_address": "0x6fb835b8",
          "struct_name": "ConfigData",
          "struct_size": 28,
          "functions_analyzed": 5,
          "field_usage": {
            "0": {
              "field_name": "dwResourceType",
              "field_type": "dword",
              "offset": 0,
              "size": 4,
              "access_count": 12,
              "suggested_names": ["resourceType", "dwType", "nResourceId"],
              "usage_patterns": ["conditional_check", "assignment"]
            },
            ...
          }
        }
    """
    import json

    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hex address format: {address}")

    # Validate parameter bounds (must match Java constants)
    if not isinstance(max_functions, int) or max_functions < 1 or max_functions > 100:
        raise GhidraValidationError("max_functions must be between 1 and 100")

    data = {"address": address, "max_functions": max_functions}
    if struct_name:
        data["struct_name"] = struct_name

    result = safe_post_json("analyze_struct_field_usage", data, program=program)

    # Format the JSON response for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result


@mcp.tool()
def get_field_access_context(
    struct_address: str, field_offset: int, num_examples: int = 5, program: str = None
) -> str:
    """
    Get assembly/decompilation context for specific field offsets.

    This tool retrieves specific usage examples for a field at a given offset within a structure,
    including the assembly instructions, reference types, and containing functions. Useful for
    understanding how a particular field is accessed and what its purpose might be.

    Args:
        struct_address: Address of the structure instance in hex format (e.g., "0x6fb835b8")
        field_offset: Offset of the field within the structure (e.g., 4 for second DWORD)
        num_examples: Number of usage examples to return (default: 5)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON string with field access contexts:
        {
          "struct_address": "0x6fb835b8",
          "field_offset": 4,
          "field_address": "0x6fb835bc",
          "examples": [
            {
              "access_address": "0x6fb6cae9",
              "ref_type": "DATA_READ",
              "assembly": "MOV EDX, [0x6fb835bc]",
              "function_name": "ProcessResource",
              "function_address": "0x6fb6ca00"
            },
            ...
          ]
        }
    """
    import json

    if not validate_hex_address(struct_address):
        raise GhidraValidationError(f"Invalid hex address format: {struct_address}")

    # Validate parameter bounds (must match Java constants: MAX_FIELD_OFFSET=65536, MAX_FIELD_EXAMPLES=50)
    if not isinstance(field_offset, int) or field_offset < 0 or field_offset > 65536:
        raise GhidraValidationError("field_offset must be between 0 and 65536")

    if not isinstance(num_examples, int) or num_examples < 1 or num_examples > 50:
        raise GhidraValidationError("num_examples must be between 1 and 50")

    data = {
        "struct_address": struct_address,
        "field_offset": field_offset,
        "num_examples": num_examples,
    }

    result = safe_post_json("get_field_access_context", data, program=program)

    # Format the JSON response for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result


@mcp.tool()
def batch_set_comments(
    function_address: str,
    decompiler_comments: list = None,
    disassembly_comments: list = None,
    plate_comment: str = None,
    program: str = None,
) -> str:
    """
    Set multiple comments in a single operation (v1.5.0).
    Reduces API calls from 10+ to 1 for typical function documentation.

    Args:
        function_address: Function address for plate comment
        decompiler_comments: List of {"address": "0x...", "comment": "..."} for PRE_COMMENT
        disassembly_comments: List of {"address": "0x...", "comment": "..."} for EOL_COMMENT
        plate_comment: Function header summary comment
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with success status and counts of comments set
    """
    validate_hex_address(function_address)

    # Convert escaped newlines in plate comment
    if plate_comment:
        plate_comment = _convert_escaped_newlines(plate_comment)

    payload = {
        "function_address": function_address,
        "decompiler_comments": decompiler_comments or [],
        "disassembly_comments": disassembly_comments or [],
        "plate_comment": plate_comment,
    }

    return safe_post_json("batch_set_comments", payload, program=program)


@mcp.tool()
def clear_function_comments(
    function_address: str,
    clear_plate: bool = True,
    clear_pre: bool = True,
    clear_eol: bool = True,
    program: str = None,
) -> str:
    """
    Clear all comments (plate, PRE, EOL) within a function's address range (v3.0.1).
    Useful for cleaning up stale comments before re-documenting a function.

    Args:
        function_address: Function address in hex format (e.g., "0x401000")
        clear_plate: Clear the plate (header) comment (default: True)
        clear_pre: Clear all PRE_COMMENT (decompiler) comments (default: True)
        clear_eol: Clear all EOL_COMMENT (disassembly) comments (default: True)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with counts of comments cleared per type
    """
    validate_hex_address(function_address)

    payload = {
        "function_address": function_address,
        "clear_plate": clear_plate,
        "clear_pre": clear_pre,
        "clear_eol": clear_eol,
    }

    return safe_post_json("clear_function_comments", payload, program=program)


@mcp.tool()
def get_plate_comment(address: str, program: str = None) -> str:
    """
    Get function plate (header) comment.
    This retrieves the comment that appears above the function in both disassembly and decompiler views.

    Args:
        address: Function address in hex format (e.g., "0x401000")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with address and comment, or null if no comment exists
    """
    validate_hex_address(address)

    params = {"address": address}
    return safe_get_json("get_plate_comment", params, program=program)


@mcp.tool()
def set_plate_comment(function_address: str, comment: str, program: str = None) -> str:
    """
    Set function plate (header) comment (v1.5.0).
    This comment appears above the function in both disassembly and decompiler views.

    Args:
        function_address: Function address in hex format (e.g., "0x401000")
        comment: Function header summary comment
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message
    """
    validate_hex_address(function_address)

    # Convert escaped newlines to actual newlines
    comment = _convert_escaped_newlines(comment)

    params = {"function_address": function_address, "comment": comment}
    result = safe_post("set_plate_comment", params, program=program)

    # Verify plate comment was applied by decompiling the function
    # This works around a Ghidra decompiler cache race condition where
    # plate comments may not immediately appear in decompilation output
    if "Success" in result:
        try:
            # Wait brief moment for cache to settle
            import time

            time.sleep(0.3)

            # Decompile by address and check for plate comment
            decompile_params = {"address": function_address}
            if program:
                decompile_params["program"] = program
            decompiled = safe_get("decompile_function", decompile_params)
            if isinstance(decompiled, list):
                decompiled = "\n".join(decompiled)

            # If plate comment shows as "/* null */", retry once
            if "/* null */" in decompiled:
                logger.warning(
                    f"Plate comment cache miss detected at {function_address}, retrying..."
                )
                time.sleep(0.5)  # Longer wait before retry
                result = safe_post("set_plate_comment", params, program=program)

                # Verify retry succeeded
                time.sleep(0.3)
                decompiled = safe_get(
                    "decompile_function", decompile_params
                )
                if isinstance(decompiled, list):
                    decompiled = "\n".join(decompiled)
                if "/* null */" in decompiled:
                    result += " (WARNING: Plate comment may require additional retry - cache persistence issue)"
        except Exception as e:
            logger.debug(f"Could not verify plate comment: {e}")

    return result


@mcp.tool()
def get_function_variables(function_name: str = None, function_address: str = None, program: str = None) -> str:
    """
    List all variables in a function including parameters and locals (v1.5.0).

    Args:
        function_name: Name of the function (either name or address required)
        function_address: Address of the function in hex (e.g., "0x401000") - alternative to name
        program: Optional program name to query (if not provided, uses current program)

    Returns:
        JSON with function variables including names, types, storage locations,
        and is_phantom flag indicating decompiler artifacts
    """
    if not function_name and not function_address:
        return '{"error": "Either function_name or function_address is required"}'

    params = {}
    if function_name:
        validate_function_name(function_name)
        params["function_name"] = function_name
    if function_address:
        validate_hex_address(function_address)
        params["function_address"] = function_address
    if program:
        params["program"] = program
    return safe_get_json("get_function_variables", params)


@mcp.tool()
def batch_rename_function_components(
    function_address: str,
    function_name: str = None,
    parameter_renames: dict = None,
    local_renames: dict = None,
    return_type: str = None,
    program: str = None,
) -> str:
    """
    Rename function and all its components atomically (v1.5.0).
    Combines multiple rename operations into a single transaction.

    Args:
        function_address: Function address in hex format
        function_name: New name for the function (optional)
        parameter_renames: Dict of {"old_name": "new_name"} for parameters
        local_renames: Dict of {"old_name": "new_name"} for local variables
        return_type: New return type (optional)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with success status and counts of renamed components
    """
    validate_hex_address(function_address)

    payload = {
        "function_address": function_address,
        "function_name": function_name,
        "parameter_renames": parameter_renames or {},
        "local_renames": local_renames or {},
        "return_type": return_type,
    }

    return safe_post_json("batch_rename_function_components", payload, program=program)


@mcp.tool()
def get_valid_data_types(category: str = None, program: str = None) -> str:
    """
    Get list of valid Ghidra data type strings (v1.5.0).
    Helps construct proper type definitions for create_struct and other type operations.

    Args:
        category: Optional category filter (not currently used)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with lists of builtin_types and windows_types
    """
    params = {"category": category} if category else {}
    return safe_get("get_valid_data_types", params, program=program)


@mcp.tool()
def analyze_function_completeness(function_address: str, compact: bool = True, program: str = None) -> str:
    """
    Analyze how completely a function has been documented.
    Checks names, prototypes, comments, undefined variables, Hungarian notation, and type quality.

    Args:
        function_address: Function address in hex format.
        compact: If True (default), returns only scores and issue counts (~300 bytes).
                 If False, returns full issue arrays and workflow recommendations (~20KB).
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with completeness_score (0-100), effective_score, all_deductions_unfixable,
        has_renameable_variables, and issue counts (compact) or full issue arrays (verbose).
    """
    validate_hex_address(function_address)

    params = {"function_address": function_address}
    if compact:
        params["compact"] = "true"
    return safe_get_json("analyze_function_completeness", params, program=program)


@mcp.tool()
def analyze_for_documentation(function_address: str, program: str = None) -> str:
    """
    Composite endpoint for RE documentation workflow. Single call returns decompiled code,
    classification, callees (with ordinal/thunk flags), parameters and locals with
    pre-analysis (needs_type, needs_rename, suggested_type, suggested_prefix),
    DAT global count, and compact completeness score.

    Args:
        function_address: Function address in hex format (e.g., "0x6FAB1234")
        program: Optional program name for multi-program support

    Returns:
        JSON with all data needed to document one function in a single response.
    """
    validate_hex_address(function_address)
    params = {"function_address": function_address}
    if program:
        params["program"] = program
    return safe_get_json("analyze_for_documentation", params)


@mcp.tool()
def batch_apply_documentation(
    address: str,
    name: str = None,
    prototype: str = None,
    calling_convention: str = None,
    variable_types: dict = None,
    variable_renames: dict = None,
    plate_comment: str = None,
    decompiler_comments: list = None,
    disassembly_comments: list = None,
    goto: bool = False,
    score: bool = True,
    program: str = None,
) -> str:
    """
    Apply all documentation to a function in a single call.
    Executes in order: rename -> prototype -> variable_types -> variable_renames -> comments -> score.
    Each step is independent; failures in one step don't block subsequent steps.

    Args:
        address: Function address in hex format (e.g., "0x6FDB2C70"). Required.
        name: New function name. Omit to skip rename.
        prototype: Full function signature (e.g., "void* __stdcall GetItemDataRecord(int nItemCode)").
        calling_convention: Override calling convention (e.g., "__stdcall", "__fastcall").
        variable_types: Dict of {variable_name: new_type} for storage types.
        variable_renames: Dict of {old_name: new_name} for variable renames.
        plate_comment: Function header comment.
        decompiler_comments: List of {"address": "0x...", "comment": "..."} for PRE_COMMENTs.
        disassembly_comments: List of {"address": "0x...", "comment": "..."} for EOL_COMMENTs.
        goto: If true, navigate CodeBrowser to this function before applying.
        score: If true (default), include completeness analysis after changes.
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with per-step success/failure results and optional completeness score.
    """
    validate_hex_address(address)

    payload = {"address": address, "goto": goto, "score": score}
    if name is not None:
        payload["name"] = name
    if prototype is not None:
        payload["prototype"] = prototype
    if calling_convention is not None:
        payload["calling_convention"] = calling_convention
    if variable_types is not None:
        payload["variable_types"] = variable_types
    if variable_renames is not None:
        payload["variable_renames"] = variable_renames
    if plate_comment is not None:
        payload["plate_comment"] = plate_comment
    if decompiler_comments is not None:
        payload["decompiler_comments"] = decompiler_comments
    if disassembly_comments is not None:
        payload["disassembly_comments"] = disassembly_comments

    return safe_post_json("batch_apply_documentation", payload, program=program)


@mcp.tool()
def batch_analyze_completeness(addresses: list[str], program: str = None) -> str:
    """
    Analyze completeness for multiple functions in a single call.
    Returns all completeness scores, deductions, and recommendations at once,
    avoiding the overhead of individual analyze_function_completeness calls.

    Args:
        addresses: List of hex addresses (e.g., ["0x10001000", "0x10002000"])
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with results array containing completeness data for each function
    """
    if not addresses:
        return '{"error": "addresses list cannot be empty"}'
    for addr in addresses:
        validate_hex_address(addr)

    return safe_post_json("batch_analyze_completeness", {"addresses": addresses}, program=program)


@mcp.tool()
def find_next_undefined_function(
    start_address: str = None,
    criteria: str = "name_pattern",
    pattern: str = "FUN_",
    direction: str = "ascending",
    program: str = None,
) -> str:
    """
    Find the next function needing analysis (v1.5.0).
    Intelligently searches for functions matching specified criteria.

    Args:
        start_address: Starting address for search (default: program min address)
        criteria: Search criteria (default: "name_pattern")
        pattern: Name pattern to match (default: "FUN_")
        direction: Search direction "ascending" or "descending" (default: "ascending")
        program: Optional program name to query (if not provided, uses current program)

    Returns:
        JSON with found function details or {"found": false}
    """
    if start_address:
        validate_hex_address(start_address)

    params = {
        "start_address": start_address,
        "criteria": criteria,
        "pattern": pattern,
        "direction": direction,
    }
    if program:
        params["program"] = program
    return safe_get_json("find_next_undefined_function", params)


@mcp.tool()
def batch_set_variable_types(function_address: str, variable_types: dict, program: str = None) -> str:
    """
    Set types for multiple variables in a single operation (v1.5.0).

    Args:
        function_address: Function address in hex format
        variable_types: Dict of {"variable_name": "type_name"}
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with success status and count of variables typed
    """
    validate_hex_address(function_address)

    payload = {
        "function_address": function_address,
        "variable_types": variable_types or {},
    }

    return safe_post_json("batch_set_variable_types", payload, program=program)


# ========== HIGH PRIORITY: WORKFLOW ENHANCEMENTS (v1.6.0) ==========
# NOTE: batch_rename_variables() and rename_variables_progressive() have been
# removed in favor of the unified rename_variables() tool.
# Use rename_variables(function_address, variable_renames, backend="auto") instead.


@mcp.tool()
def set_parameter_type(
    function_address: str, parameter_name: str, new_type: str, program: str = None
) -> str:
    """
    Change a parameter's data type to improve decompilation quality.

    This tool updates a function parameter's type from a primitive type to a structure
    pointer or other complex type. Critical for improving decompilation readability when
    parameters are actually pointers to structures but Ghidra infers them as int or void*.

    Args:
        function_address: Function address in hex format
        parameter_name: Name of the parameter to modify
        new_type: New data type (e.g., "MyStruct *", "int *", "char *")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message with details
    """
    validate_hex_address(function_address)

    payload = {
        "function_address": function_address,
        "parameter_name": parameter_name,
        "new_type": new_type,
    }

    return safe_post_json("set_parameter_type", payload, program=program)


@mcp.tool()
def analyze_function_complete(
    name: str,
    include_xrefs: bool = True,
    include_callees: bool = True,
    include_callers: bool = True,
    include_disasm: bool = True,
    include_variables: bool = True,
    program: Optional[str] = None,
) -> str:
    """
    Comprehensive function analysis in a single call (v1.6.0).

    Replaces 5+ individual calls with one efficient operation, dramatically
    reducing network round-trips during function documentation.

    Args:
        name: Function name to analyze
        include_xrefs: Include cross-references to function
        include_callees: Include functions this function calls
        include_callers: Include functions that call this function
        include_disasm: Include disassembly listing
        include_variables: Include parameter and local variable info
        program: Optional program name for multi-program support

    Returns:
        JSON with complete function analysis:
        {
          "decompiled_code": "void foo() { ... }",
          "xrefs": [{"from": "0x...", "type": "CALL"}],
          "callees": [{"name": "bar", "address": "0x..."}],
          "callers": [{"name": "main", "address": "0x..."}],
          "disassembly": [{"address": "0x...", "instruction": "MOV EAX, ..."}],
          "variables": {"parameters": [...], "locals": [...]}
        }
    """
    params = {
        "name": name,
        "include_xrefs": include_xrefs,
        "include_callees": include_callees,
        "include_callers": include_callers,
        "include_disasm": include_disasm,
        "include_variables": include_variables,
    }
    if program:
        params["program"] = program
    return safe_get_json("analyze_function_complete", params)


@mcp.tool()
def search_functions_enhanced(
    name_pattern: str = None,
    min_xrefs: int = None,
    max_xrefs: int = None,
    calling_convention: str = None,
    has_custom_name: bool = None,
    regex: bool = False,
    sort_by: str = "address",
    offset: int = 0,
    limit: int = 100,
    program: str = None,
) -> str:
    """
    Enhanced function search with filtering and sorting.

    Args:
        name_pattern: Function name pattern (substring or regex)
        min_xrefs: Minimum cross-reference count
        max_xrefs: Maximum cross-reference count
        calling_convention: Filter by calling convention
        has_custom_name: True=user-named only, False=FUN_* only
        regex: Enable regex pattern matching
        sort_by: "address" (default), "name", or "xref_count"
        offset: Pagination offset
        limit: Maximum results to return
        program: Optional program name. Defaults to active program.

    Returns:
        JSON with total count and results array (name, address, xref_count, calling_convention).
    """
    params = {
        "name_pattern": name_pattern,
        "min_xrefs": min_xrefs,
        "max_xrefs": max_xrefs,
        "calling_convention": calling_convention,
        "has_custom_name": has_custom_name,
        "regex": regex,
        "sort_by": sort_by,
        "offset": offset,
        "limit": limit,
        "program": program,
    }
    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    return safe_get_json("search_functions_enhanced", params)


@mcp.tool()
def disassemble_bytes(
    start_address: str,
    end_address: str = None,
    length: int = None,
    restrict_to_execute_memory: bool = True,
    program: str = None,
) -> str:
    """
    Disassemble undefined bytes into instructions at a specific address range.

    Args:
        start_address: Starting address in hex format (e.g., "0x6fb4ca14")
        end_address: Optional ending address in hex (exclusive)
        length: Optional length in bytes (alternative to end_address). Auto-detects if neither given.
        restrict_to_execute_memory: Restrict to executable memory (default: True)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with success status, address range, and bytes_disassembled count.
    """
    if not validate_hex_address(start_address):
        raise GhidraValidationError(f"Invalid start address format: {start_address}")

    if end_address and not validate_hex_address(end_address):
        raise GhidraValidationError(f"Invalid end address format: {end_address}")

    data = {
        "start_address": start_address,
        "end_address": end_address,
        "length": length,
        "restrict_to_execute_memory": restrict_to_execute_memory,
    }

    # Remove None values
    data = {k: v for k, v in data.items() if v is not None}

    return safe_post_json("disassemble_bytes", data, program=program)


@mcp.tool()
def save_program(program: str = None) -> str:
    """
    Save the current program in Ghidra.

    Saves all pending changes to the Ghidra project database.
    Call this before exiting Ghidra to ensure no work is lost.

    Args:
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with save status.
    """
    return safe_post_json("save_program", {}, program=program)


@mcp.tool()
def exit_ghidra() -> str:
    """
    Save and exit Ghidra gracefully.

    Saves the current program, then closes Ghidra. Use this instead of
    killing the process to ensure all changes are persisted.

    Returns:
        JSON with save and exit status.
    """
    return safe_post_json("exit_ghidra", {})


@mcp.tool()
def delete_function(address: str, program: str = None) -> str:
    """
    Delete a function at the specified address.

    Removes the function definition at the given address. Useful for
    deleting degenerate 1-byte stub functions so they can be recreated
    properly with create_function.

    Args:
        address: Address of the function entry point in hex format (e.g., "0x08011d34")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with deletion result including the name of the deleted function.

    Examples:
        delete_function("0x08011d34")
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid address format: {address}")

    return safe_post_json("delete_function", {"address": address}, program=program)


@mcp.tool()
def create_function(
    address: str, name: str = None, disassemble_first: bool = True, program: str = None
) -> str:
    """
    Create a function at the specified address.

    Args:
        address: Starting address in hex format (e.g., "0x6ff56791")
        name: Optional function name (if omitted, auto-generates FUN_ name)
        disassemble_first: If true, disassemble bytes before creating function (default: True)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with success status, address, function name, and entry point.
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid address format: {address}")

    data = {"address": address, "name": name, "disassemble_first": disassemble_first}

    # Remove None values
    data = {k: v for k, v in data.items() if v is not None}

    return safe_post_json("create_function", data, program=program)


@mcp.tool()
def create_memory_block(
    name: str,
    address: str,
    size: int,
    read: bool = True,
    write: bool = True,
    execute: bool = False,
    volatile: bool = False,
    comment: str = None,
    program: str = None,
) -> str:
    """
    Create an uninitialized memory block at the specified address.

    Useful for defining peripheral MMIO regions, memory-mapped hardware
    registers, or other address ranges that Ghidra doesn't know about.

    Args:
        name: Name for the memory block (e.g., "GPIOA", "USART1")
        address: Start address in hex format (e.g., "0x40020000")
        size: Size in bytes (e.g., 0x400 for 1KB)
        read: Allow read access (default: True)
        write: Allow write access (default: True)
        execute: Allow execute access (default: False)
        volatile: Mark as volatile memory (default: False)
        comment: Optional description for the block
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with block creation result including name, address range,
        size, and permissions.

    Examples:
        create_memory_block("GPIOA", "0x40020000", 0x400)
        create_memory_block("USART1", "0x40011000", 0x400, comment="USART1 registers")
        create_memory_block("FLASH", "0x08000000", 0x80000, execute=True, write=False)
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid address format: {address}")

    data = {
        "name": name,
        "address": address,
        "size": size,
        "read": read,
        "write": write,
        "execute": execute,
        "volatile": volatile,
    }
    if comment is not None:
        data["comment"] = comment

    return safe_post_json("create_memory_block", data, program=program)


# ========== SCRIPT GENERATION (v1.9.0) ==========


# ========== SCRIPT LIFECYCLE MANAGEMENT (v1.9.1) ==========


@mcp.tool()
def save_ghidra_script(
    script_name: str, script_content: str, overwrite: bool = False, backup: bool = True
) -> str:
    """
    Save a Ghidra script to disk in the ghidra_scripts/ directory.

    This tool enables saving generated scripts (from generate_ghidra_script)
    to the local ghidra_scripts/ directory where Ghidra can discover and run them.

    Args:
        script_name: Name for script without .java extension (e.g., "DocumentFunctions")
                    Must be alphanumeric + underscore only
        script_content: Full Java script content to save
        overwrite: Whether to overwrite if exists (default: False)
        backup: Create backup if overwriting (default: True)

    Returns:
        JSON with save status:
        {
            "success": true,
            "script_path": "ghidra_scripts/DocumentFunctions.java",
            "file_size": 2048,
            "backup_path": "ghidra_scripts/DocumentFunctions.java.backup",
            "message": "Script saved successfully"
        }

    Example:
        # Generate a script
        result = generate_ghidra_script("Document all functions", "document_functions")
        script_content = result["script_content"]

        # Save it to disk
        save_result = save_ghidra_script("DocumentFunctions", script_content)
        print(f"Saved to: {save_result['script_path']}")

        # Can now run it in Ghidra via Script Manager
    """
    import os
    import json

    if not script_name or not isinstance(script_name, str):
        raise GhidraValidationError("script_name is required and must be a string")

    if not script_content or not isinstance(script_content, str):
        raise GhidraValidationError("script_content is required and must be a string")

    # Validate script name (alphanumeric + underscore only)
    if not all(c.isalnum() or c == "_" for c in script_name):
        raise GhidraValidationError(
            "script_name must be alphanumeric or underscore only"
        )

    # Build path — use ~/ghidra_scripts/ so scripts land where Ghidra's
    # script manager and run_ghidra_script/run_script search
    script_dir = os.path.join(os.path.expanduser("~"), "ghidra_scripts")
    script_file = f"{script_name}.java"
    script_path = os.path.join(script_dir, script_file)

    # Create directory if needed
    try:
        os.makedirs(script_dir, exist_ok=True)
    except Exception as e:
        raise GhidraValidationError(f"Could not create ghidra_scripts directory: {e}")

    # Check if file exists and overwrite setting
    if os.path.exists(script_path) and not overwrite:
        raise GhidraValidationError(
            f"Script {script_name} already exists. Use overwrite=True to replace."
        )

    # Backup if needed
    backup_path = None
    if os.path.exists(script_path) and backup:
        backup_path = f"{script_path}.backup"
        try:
            import shutil

            shutil.copy2(script_path, backup_path)
        except Exception as e:
            logger.warning(f"Could not create backup: {e}")
            backup_path = None

    # Write script
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        file_size = os.path.getsize(script_path)
    except Exception as e:
        raise GhidraValidationError(f"Could not write script file: {e}")

    # Return success response
    response = {
        "success": True,
        "script_name": script_name,
        "script_path": script_path,
        "file_size": file_size,
        "message": "Script saved successfully",
    }

    if backup_path:
        response["backup_path"] = backup_path

    return json.dumps(response, indent=2)


@mcp.tool()
def list_ghidra_scripts(
    filter_pattern: str = None, include_metadata: bool = True
) -> str:
    """
    List all Ghidra scripts in the ghidra_scripts/ directory.

    Args:
        filter_pattern: Optional regex pattern to filter scripts
        include_metadata: Include file size, modified date, LOC (default: True)

    Returns:
        JSON with script list:
        {
            "total_scripts": 5,
            "scripts": [
                {
                    "name": "DocumentFunctions",
                    "filename": "DocumentFunctions.java",
                    "path": "/path/to/ghidra_scripts/DocumentFunctions.java",
                    "size": 2048,
                    "modified": "2025-01-10T14:30:00Z",
                    "lines_of_code": 45
                },
                ...
            ]
        }

    Example:
        # List all scripts
        result = list_ghidra_scripts()
        for script in result["scripts"]:
            print(f"{script['name']}: {script['size']} bytes")

        # List scripts matching pattern
        result = list_ghidra_scripts(filter_pattern="Document.*")
    """
    import os
    import json
    from datetime import datetime

    script_dir = os.path.join(os.path.expanduser("~"), "ghidra_scripts")
    scripts = []

    # Create directory if missing
    if not os.path.exists(script_dir):
        os.makedirs(script_dir, exist_ok=True)

    try:
        # Scan directory for .java files
        for filename in sorted(os.listdir(script_dir)):
            if not filename.endswith(".java"):
                continue

            filepath = os.path.join(script_dir, filename)
            script_name = filename[:-5]  # Remove .java extension

            # Apply filter if provided
            if filter_pattern:
                import re

                if not re.search(filter_pattern, script_name):
                    continue

            script_info = {"name": script_name, "filename": filename, "path": filepath}

            if include_metadata:
                try:
                    # Get file stats
                    stat_info = os.stat(filepath)
                    script_info["size"] = stat_info.st_size
                    modified = datetime.fromtimestamp(stat_info.st_mtime)
                    script_info["modified"] = modified.isoformat() + "Z"

                    # Count lines of code (rough estimate)
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        script_info["lines_of_code"] = len(f.readlines())
                except Exception as e:
                    logger.warning(f"Could not get metadata for {filename}: {e}")

            scripts.append(script_info)

    except Exception as e:
        raise GhidraValidationError(f"Could not list scripts: {e}")

    response = {"total_scripts": len(scripts), "scripts": scripts}

    return json.dumps(response, indent=2)


@mcp.tool()
def get_ghidra_script(script_name: str) -> str:
    """
    Get full content of a Ghidra script.

    Args:
        script_name: Name of script to retrieve (without .java extension)

    Returns:
        Full script content as string

    Example:
        # Retrieve a script before running it
        content = get_ghidra_script("DocumentFunctions")
        print(content)  # View the source

        # Can be used to modify and re-save
    """
    import os

    if not script_name or not isinstance(script_name, str):
        raise GhidraValidationError("script_name is required")

    script_dir = os.path.join(os.path.expanduser("~"), "ghidra_scripts")
    script_path = os.path.join(script_dir, f"{script_name}.java")

    if not os.path.exists(script_path):
        raise GhidraValidationError(f"Script not found: {script_name}")

    try:
        with open(script_path, "r", encoding="utf-8") as f:
            content = f.read()
        return content
    except Exception as e:
        raise GhidraValidationError(f"Could not read script: {e}")


@mcp.tool()
def run_ghidra_script(
    script_name: str,
    args: str = None,
    timeout_seconds: int = 300,
    capture_output: bool = True,
    program: str = None,
) -> str:
    """
    Run a Ghidra script by name and capture all output including errors.

    Args:
        script_name: Script name (e.g., "MyScript.java") or absolute path
        args: Optional space-separated arguments passed via getScriptArgs()
        timeout_seconds: Max execution time in seconds (default: 300)
        capture_output: Capture console output (default: True)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with success status, script path, execution time, and console output.
    """
    import json

    if not script_name or not isinstance(script_name, str):
        raise GhidraValidationError("script_name is required")

    payload = {
        "script_name": script_name,
        "timeout_seconds": timeout_seconds,
        "capture_output": capture_output,
    }
    if args:
        payload["args"] = args

    result = safe_post_json("run_ghidra_script", payload, program=program)

    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result


@mcp.tool()
def run_script_inline(code: str, args: str = None, program: str = None) -> str:
    """
    Execute an inline Java snippet as a Ghidra script.

    Sends Java source code directly to Ghidra for immediate execution
    without needing a script file on disk. The code should be a complete
    GhidraScript class.

    Args:
        code: Complete Java source code (must contain a class extending GhidraScript)
        args: Optional space-separated arguments passed to the script
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Script execution output including console output and any errors.

    Example:
        run_script_inline('''
        import ghidra.app.script.GhidraScript;
        public class InlineTask extends GhidraScript {
            @Override
            public void run() throws Exception {
                println("Functions: " + currentProgram.getFunctionManager().getFunctionCount());
            }
        }
        ''')
    """
    if not code or not isinstance(code, str):
        raise GhidraValidationError("code parameter is required")

    data = {"code": code}
    if args:
        data["args"] = args

    return safe_post_json("run_script_inline", data, program=program)


@mcp.tool()
def update_ghidra_script(
    script_name: str, new_content: str, keep_backup: bool = True
) -> str:
    """
    Update an existing Ghidra script with new content.

    This enables iterative script improvement: generate → test → analyze errors → fix → test again.

    Args:
        script_name: Script to update
        new_content: New script content
        keep_backup: Save previous version as backup (default: True)

    Returns:
        JSON with update status:
        {
            "success": true,
            "script_name": "DocumentFunctions",
            "previous_version_backup": "ghidra_scripts/DocumentFunctions.java.backup",
            "lines_changed": 15,
            "size_delta": 512,
            "message": "Script updated successfully"
        }

    Example - Iterative Improvement:
        # Get current script
        script = get_ghidra_script("DocumentFunctions")

        # Make improvements
        improved = improve_script(script, error_message)

        # Update it
        result = update_ghidra_script("DocumentFunctions", improved)

        # Verify improvement
        run_result = run_ghidra_script("DocumentFunctions")
    """
    import os
    import json

    if not script_name or not isinstance(script_name, str):
        raise GhidraValidationError("script_name is required")

    if not new_content or not isinstance(new_content, str):
        raise GhidraValidationError("new_content is required")

    script_dir = os.path.join(os.path.expanduser("~"), "ghidra_scripts")
    script_path = os.path.join(script_dir, f"{script_name}.java")

    if not os.path.exists(script_path):
        raise GhidraValidationError(f"Script not found: {script_name}")

    # Get old content for comparison
    try:
        with open(script_path, "r", encoding="utf-8") as f:
            old_content = f.read()
        old_size = len(old_content)
    except Exception as e:
        raise GhidraValidationError(f"Could not read existing script: {e}")

    # Create backup if requested
    backup_path = None
    if keep_backup:
        backup_path = f"{script_path}.backup"
        try:
            import shutil

            shutil.copy2(script_path, backup_path)
        except Exception as e:
            logger.warning(f"Could not create backup: {e}")

    # Write new content
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        new_size = len(new_content)
    except Exception as e:
        raise GhidraValidationError(f"Could not update script: {e}")

    # Calculate changes
    size_delta = new_size - old_size
    lines_changed = sum(
        1 for a, b in zip(old_content.split("\n"), new_content.split("\n")) if a != b
    )

    response = {
        "success": True,
        "script_name": script_name,
        "lines_changed": lines_changed,
        "size_delta": size_delta,
        "message": "Script updated successfully",
    }

    if backup_path:
        response["previous_version_backup"] = backup_path

    return json.dumps(response, indent=2)


@mcp.tool()
def delete_ghidra_script(
    script_name: str, confirm: bool = False, archive: bool = True
) -> str:
    """
    Delete a Ghidra script safely with automatic backup.

    Requires explicit confirmation to prevent accidental deletion.

    Args:
        script_name: Script to delete
        confirm: Must be True to actually delete (prevents accidents)
        archive: Create archive/backup before deletion (default: True)

    Returns:
        JSON with deletion status:
        {
            "success": true,
            "script_name": "DocumentFunctions",
            "deleted": true,
            "archive_location": "ghidra_scripts/.archive/DocumentFunctions.java",
            "message": "Script deleted and archived"
        }

    Example:
        # Delete a script (requires explicit confirmation)
        result = delete_ghidra_script("DocumentFunctions", confirm=True)
        print(result["archive_location"])  # Where backup was saved
    """
    import os
    import json

    if not script_name or not isinstance(script_name, str):
        raise GhidraValidationError("script_name is required")

    if not confirm:
        raise GhidraValidationError(
            "confirm=True required for safety (prevents accidents)"
        )

    script_dir = os.path.join(os.path.expanduser("~"), "ghidra_scripts")
    script_path = os.path.join(script_dir, f"{script_name}.java")

    if not os.path.exists(script_path):
        raise GhidraValidationError(f"Script not found: {script_name}")

    # Archive if requested
    archive_path = None
    if archive:
        try:
            archive_dir = os.path.join("ghidra_scripts", ".archive")
            os.makedirs(archive_dir, exist_ok=True)
            archive_path = os.path.join(archive_dir, f"{script_name}.java")
            import shutil

            shutil.copy2(script_path, archive_path)
        except Exception as e:
            logger.warning(f"Could not archive script: {e}")
            # Don't fail deletion if archive fails

    # Delete the script
    try:
        os.remove(script_path)
    except Exception as e:
        raise GhidraValidationError(f"Could not delete script: {e}")

    response = {
        "success": True,
        "script_name": script_name,
        "deleted": True,
        "message": "Script deleted successfully",
    }

    if archive_path:
        response["archive_location"] = archive_path

    return json.dumps(response, indent=2)


# ==================== PROGRAM MANAGEMENT TOOLS ====================


@mcp.tool()
def list_open_programs() -> str:
    """
    List all currently open programs in Ghidra.

    Returns information about each open program including:
    - name: The program name
    - path: Project path to the program
    - is_current: Whether this is the active program
    - executable_path: Original file path
    - language: Processor language/architecture
    - compiler: Compiler specification
    - image_base: Base address
    - memory_size: Total memory size in bytes
    - function_count: Number of functions

    Use this to see what modules/binaries are loaded and which one
    is currently active for MCP tool operations.

    Returns:
        JSON with list of open programs and current program name

    Example:
        programs = list_open_programs()
        # Returns: {"programs": [...], "count": 2, "current_program": "Game.exe"}
    """
    url = f"{ghidra_server_url}/list_open_programs"
    return make_request(url, method="GET")


@mcp.tool()
def get_current_program_info() -> str:
    """
    Get detailed information about the currently active program.

    Returns comprehensive metadata including:
    - name, path, executable_path, executable_format
    - language, compiler, address_size
    - image_base, min_address, max_address
    - memory_size, memory_block_count
    - function_count, symbol_count, data_type_count
    - creation_date

    This is the program that all MCP tools will operate on.

    Returns:
        JSON with detailed program information

    Example:
        info = get_current_program_info()
        # Returns: {"name": "Game.exe", "language": "x86:LE:32:default", ...}
    """
    url = f"{ghidra_server_url}/get_current_program_info"
    return make_request(url, method="GET")


@mcp.tool()
def switch_program(name: str) -> str:
    """
    Switch the default program for tools that don't specify an explicit program.

    Sets which program is used when a tool call omits the `program` parameter.
    For deterministic multi-binary workflows, prefer passing `program=` explicitly
    to each tool call instead of relying on switch_program.

    Args:
        name: Name of the program to switch to. Can be:
              - Exact program name (e.g., "D2Client.dll")
              - Partial path match (e.g., "Client")

    Returns:
        JSON with success status and the switched program info

    Raises:
        GhidraValidationError: If program name not provided or not found

    Example:
        # For parallel multi-binary, pass program= explicitly:
        funcs_a = list_functions(program="D2Client.dll")
        funcs_b = list_functions(program="D2Common.dll")

        # switch_program sets the fallback default (not needed with explicit program=):
        switch_program("D2Client.dll")
        funcs = list_functions()  # Uses D2Client.dll as default
    """
    if not name:
        raise GhidraValidationError("Program name is required")

    url = f"{ghidra_server_url}/switch_program"
    params = {"name": name}
    return make_request(url, method="GET", params=params)


@mcp.tool()
def list_project_files(folder: str = None) -> str:
    """
    List all files in the current Ghidra project.

    Shows the contents of the project, including both folders
    and program files. Use this to discover what binaries are
    available to open.

    Args:
        folder: Optional folder path to list (e.g., "/subfolder").
                Defaults to root folder if not specified.

    Returns:
        JSON with project name, folders, and files in the specified location.
        Each file includes: name, path, content_type, version, is_read_only

    Example:
        # List root folder
        files = list_project_files()

        # List a subfolder
        files = list_project_files("/dlls")
    """
    url = f"{ghidra_server_url}/list_project_files"
    params = {}
    if folder:
        params["folder"] = folder
    return make_request(url, method="GET", params=params)


@mcp.tool()
def open_program(path: str, auto_analyze: bool = False) -> str:
    """
    Open a program from the current Ghidra project.

    Opens a binary file that exists in the Ghidra project and
    sets it as the current program for MCP operations. If the
    program is already open, simply switches to it.

    Args:
        path: Project path to the program (e.g., "/Game.exe" or "/dlls/D2Client.dll")
              Use list_project_files() to see available paths.
        auto_analyze: If True, automatically trigger Ghidra's auto-analysis after
                      opening the program. This runs all configured analyzers.
                      Default: False.

    Returns:
        JSON with success status, program name, auto_analyzed flag, and basic info

    Raises:
        GhidraValidationError: If path not provided or file not found

    Example:
        # Open a program from project
        result = open_program("/D2Client.dll")

        # Open and auto-analyze
        result = open_program("/D2Client.dll", auto_analyze=True)
    """
    if not path:
        raise GhidraValidationError("Program path is required")

    url = f"{ghidra_server_url}/open_program"
    params = {"path": path}
    if auto_analyze:
        params["auto_analyze"] = "true"
    return make_request(url, method="GET", params=params)


# ====================================================================================
# MEMORY OPERATIONS - Read and search raw memory bytes
# ====================================================================================


@mcp.tool()
def read_memory(address: str, length: int = 256, program: str = None) -> str:
    """
    Read raw bytes from memory at the specified address.

    Reads binary data directly from the program's memory space. Useful for:
    - Examining data structures at specific addresses
    - Reading string data that wasn't auto-detected
    - Verifying patch locations before modification
    - Extracting embedded resources or constants

    Args:
        address: Memory address to read from (hex string, e.g., "0x401000")
        length: Number of bytes to read (default: 256, max recommended: 4096)
        program: Optional program name for multi-binary projects

    Returns:
        JSON with address, bytes (hex string), ASCII representation, and length

    Example:
        # Read 64 bytes at address
        data = read_memory("0x401000", 64)
        # Returns: {"address": "0x401000", "bytes": "4d5a9000...", "ascii": "MZ...", "length": 64}

        # Read from specific program in multi-binary project
        data = read_memory("0x10001000", 128, program="Game.dll")
    """
    if not address:
        raise GhidraValidationError("Address is required")
    
    url = f"{ghidra_server_url}/read_memory"
    params = {"address": address, "length": length}
    if program:
        params["program"] = program
    return make_request(url, method="GET", params=params)


@mcp.tool()
def search_memory_strings(
    query: str, 
    min_length: int = 4,
    encoding: str = "ascii",
    program: str = None
) -> str:
    """
    Search for string patterns in program memory.

    Searches for strings matching the query pattern. More flexible than
    list_strings() as it can find strings that weren't auto-detected
    during initial analysis.

    Args:
        query: String or regex pattern to search for
        min_length: Minimum string length to consider (default: 4)
        encoding: String encoding - "ascii", "utf8", "utf16" (default: "ascii")
        program: Optional program name for multi-binary projects

    Returns:
        JSON with matching strings, their addresses, and context

    Example:
        # Find error messages
        results = search_memory_strings("error")
        
        # Find version strings
        results = search_memory_strings("v1\\.[0-9]+")
        
        # Find Unicode strings
        results = search_memory_strings("Player", encoding="utf16")
    """
    if not query:
        raise GhidraValidationError("Query string is required")
    
    url = f"{ghidra_server_url}/search_strings"
    params = {
        "query": query,
        "min_length": min_length,
        "encoding": encoding
    }
    if program:
        params["program"] = program
    return make_request(url, method="GET", params=params)


# ====================================================================================
# UI NAVIGATION & CURSOR TOOLS - Interactive Ghidra session support
# ====================================================================================


@mcp.tool()
def get_current_address() -> str:
    """
    Get the current cursor/selection address in Ghidra's listing view.

    Returns the address where the user's cursor is currently positioned
    in the Ghidra UI. Useful for:
    - Understanding user's current focus
    - Building context-aware suggestions
    - Coordinating between manual and automated analysis

    Returns:
        JSON with current address and containing function (if any)

    Example:
        location = get_current_address()
        # Returns: {"address": "0x401234", "function": "main", "in_function": true}
    """
    url = f"{ghidra_server_url}/get_current_address"
    return make_request(url, method="GET")


@mcp.tool()
def get_current_function() -> str:
    """
    Get information about the function at the current cursor position.

    Returns details about the function containing the cursor, including
    its name, address range, signature, and basic metrics.

    Returns:
        JSON with function details or null if cursor is not in a function

    Example:
        func = get_current_function()
        # Returns: {"name": "main", "entry": "0x401000", "signature": "int main(int, char**)", ...}
    """
    url = f"{ghidra_server_url}/get_current_function"
    return make_request(url, method="GET")


@mcp.tool()
def set_bookmark(
    address: str,
    category: str = "Analysis",
    comment: str = "",
    bookmark_type: str = "Note",
    program: str = None
) -> str:
    """
    Set a bookmark at the specified address.

    Creates a bookmark to mark interesting locations for later review.
    Bookmarks persist with the program and are visible in Ghidra's
    Bookmark window.

    Args:
        address: Address to bookmark (hex string)
        category: Bookmark category for organization (default: "Analysis")
        comment: Descriptive comment for the bookmark
        bookmark_type: Type of bookmark - "Note", "Warning", "Error", "Info" (default: "Note")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON confirmation of bookmark creation

    Example:
        # Mark an interesting function
        set_bookmark("0x401000", "Crypto", "Possible encryption routine")

        # Flag suspicious code
        set_bookmark("0x402000", "Malware", "Anti-debug check", bookmark_type="Warning")
    """
    if not address:
        raise GhidraValidationError("Address is required")

    url = f"{ghidra_server_url}/set_bookmark"
    if program:
        url += f"?program={program}"
    params = {
        "address": address,
        "category": category,
        "comment": comment,
        "type": bookmark_type
    }
    return make_request(url, method="POST", data=json.dumps(params))


@mcp.tool()
def delete_bookmark(address: str, category: str = None, program: str = None) -> str:
    """
    Delete a bookmark at the specified address.

    Removes a previously created bookmark. Can optionally filter by
    category to delete only specific bookmarks.

    Args:
        address: Address of the bookmark to delete
        category: Optional category filter (deletes all if not specified)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON confirmation of deletion

    Example:
        delete_bookmark("0x401000")
        delete_bookmark("0x401000", category="Analysis")
    """
    if not address:
        raise GhidraValidationError("Address is required")

    url = f"{ghidra_server_url}/delete_bookmark"
    params = {"address": address}
    if category:
        params["category"] = category
    return make_request(url, method="POST", data=json.dumps(params), program=program)


# ====================================================================================
# CONTROL FLOW & ANALYSIS TOOLS - Deep function analysis and complexity metrics
# ====================================================================================


@mcp.tool()
def analyze_control_flow(function_name: str, program: str = None) -> str:
    """
    Analyze the control flow structure of a function.

    Returns detailed control flow information including:
    - Basic block count and boundaries
    - Control flow edges (jumps, branches, calls)
    - Cyclomatic complexity
    - Loop detection
    - Unreachable code detection

    Args:
        function_name: Name of function to analyze
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with control flow graph data and complexity metrics

    Example:
        cfg = analyze_control_flow("decrypt_data")
        # Returns: {
        #   "function": "decrypt_data",
        #   "basic_blocks": 15,
        #   "edges": 22,
        #   "cyclomatic_complexity": 8,
        #   "loops": [{"start": "0x401050", "end": "0x401080"}],
        #   "blocks": [{"start": "0x401000", "end": "0x401020", "type": "entry"}, ...]
        # }
    """
    if not function_name:
        raise GhidraValidationError("Function name is required")

    url = f"{ghidra_server_url}/analyze_control_flow"
    params = {"function_name": function_name}
    if program:
        params["program"] = program
    return make_request(url, method="GET", params=params)


@mcp.tool()
def find_dead_code(function_name: str = None, program: str = None) -> str:
    """
    Find unreachable/dead code blocks in a function or entire program.

    Identifies code that cannot be reached through normal execution flow,
    which may indicate:
    - Compiler artifacts
    - Obfuscation/anti-analysis
    - Legacy/removed features
    - Bugs in the original code

    Args:
        function_name: Optional function to analyze. If not provided, scans entire program.
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with list of unreachable code blocks and their addresses

    Example:
        dead = find_dead_code("main")
        # Returns: {"dead_blocks": [{"address": "0x401500", "size": 32, "reason": "unreachable"}]}
    """
    url = f"{ghidra_server_url}/find_dead_code"
    params = {}
    if function_name:
        params["function_name"] = function_name
    return make_request(url, method="GET", params=params, program=program)


@mcp.tool()
def find_anti_analysis_techniques(program: str = None) -> str:
    """
    Detect anti-analysis and anti-debugging techniques in the binary.

    Scans for common techniques used to hinder reverse engineering:
    - IsDebuggerPresent checks
    - Timing checks (rdtsc)
    - Exception-based detection
    - VM/sandbox detection
    - Self-modifying code indicators
    - API obfuscation

    Args:
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with detected techniques, their locations, and severity

    Example:
        techniques = find_anti_analysis_techniques()
        # Returns: {
        #   "techniques": [
        #     {"type": "debugger_check", "address": "0x401000", "method": "IsDebuggerPresent"},
        #     {"type": "timing_check", "address": "0x401100", "method": "rdtsc"}
        #   ],
        #   "severity": "medium"
        # }
    """
    url = f"{ghidra_server_url}/find_anti_analysis_techniques"
    return make_request(url, method="GET", program=program)


@mcp.tool()
def batch_decompile(functions: str, program: str = None) -> str:
    """
    Decompile multiple functions at once for bulk analysis.

    Efficiently decompiles a list of functions, useful for:
    - Comparing related functions
    - Extracting code patterns
    - Bulk documentation generation

    Args:
        functions: Comma-separated list of function names or addresses
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with decompiled code for each function

    Example:
        code = batch_decompile("init_player,update_player,render_player")
        # Returns: {"functions": [{"name": "init_player", "code": "void init_player()..."}, ...]}
    """
    if not functions:
        raise GhidraValidationError("Function list is required")

    url = f"{ghidra_server_url}/batch_decompile"
    params = {"functions": functions}
    if program:
        params["program"] = program
    return make_request(url, method="GET", params=params)


@mcp.tool()
def get_function_metrics(function_name: str = None, address: str = None, program: str = None) -> str:
    """
    Get complexity metrics for a function.

    Returns quantitative metrics useful for:
    - Identifying complex functions needing review
    - Prioritizing reverse engineering effort
    - Comparing function implementations across versions

    Args:
        function_name: Name of function to analyze
        address: Or address of function (alternative to name)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with metrics:
        - instruction_count: Total instructions
        - basic_block_count: Number of basic blocks
        - cyclomatic_complexity: McCabe complexity metric
        - call_count: Number of function calls made
        - string_count: Number of string references
        - local_variable_count: Stack variables

    Example:
        metrics = get_function_metrics("decrypt_packet")
        # Returns: {"cyclomatic_complexity": 12, "instruction_count": 156, ...}
    """
    if not function_name and not address:
        raise GhidraValidationError("Either function_name or address is required")

    # Use find_similar_functions with limit=1 to get metrics for single function
    url = f"{ghidra_server_url}/find_similar_functions"
    params = {"limit": 1}
    if function_name:
        params["target_function"] = function_name
    elif address:
        params["target_function"] = address
    if program:
        params["program"] = program
    return make_request(url, method="GET", params=params)


# ====================================================================================
# CROSS-VERSION MATCHING TOOLS - Accelerate function documentation propagation
# ====================================================================================


@mcp.tool()
def compare_programs_documentation() -> str:
    """
    Compare documentation status across all open programs.

    Returns documented vs undocumented function counts for each open program,
    helping identify documentation gaps and prioritize work.

    Returns:
        JSON with program comparison:
        {
          "programs": [
            {
              "name": "D2Client.dll",
              "path": "/LoD/1.07/D2Client.dll",
              "is_current": true,
              "total_functions": 5372,
              "documented": 5350,
              "undocumented": 22,
              "documentation_percent": 99.6
            },
            {
              "name": "D2Client.dll",
              "path": "/LoD/1.11/D2Client.dll",
              "is_current": false,
              "total_functions": 5912,
              "documented": 3500,
              "undocumented": 2412,
              "documentation_percent": 59.2
            }
          ],
          "count": 2
        }

    Example:
        # Quick check of documentation gaps
        result = compare_programs_documentation()
        # Shows which versions need the most work
    """
    url = f"{ghidra_server_url}/compare_programs_documentation"
    return make_request(url, method="GET")


@mcp.tool()
def find_undocumented_by_string(address: str, program: str = None) -> str:
    """
    Find undocumented (FUN_*) functions that reference a given string address.

    This is a filtered version of get_xrefs_to that only returns FUN_* functions,
    making it easy to identify undocumented functions that can be named based on
    string anchor context.

    Args:
        address: Address of the string to find references to (e.g., "0x6fb86c18")
        program: Optional program name for multi-program support

    Returns:
        JSON with undocumented functions:
        {
          "string_address": "0x6fb86c18",
          "undocumented_functions": [
            {
              "name": "FUN_6fadecd0",
              "address": "6fadecd0",
              "ref_address": "6fadecfe",
              "ref_type": "DATA"
            }
          ],
          "undocumented_count": 1,
          "documented_count": 1,
          "total_referencing_functions": 2
        }

    Example:
        # Find panel.cpp string and get undocumented functions
        list_strings(filter="panel.cpp")  # Returns address 0x6fb86c18
        result = find_undocumented_by_string("0x6fb86c18")
        # Now document each FUN_* function
    """
    if not address:
        raise GhidraValidationError("String address is required")

    url = f"{ghidra_server_url}/find_undocumented_by_string"
    params = {"address": address}
    if program:
        params["program"] = program
    return make_request(url, method="GET", params=params)


@mcp.tool()
def batch_string_anchor_report(pattern: str = ".cpp", program: str = None) -> str:
    """
    Generate a report of source file strings and their undocumented functions.

    Args:
        pattern: String pattern to match (default: ".cpp"). Other useful patterns: ".h", "Error", "Assert"
        program: Optional program name for multi-program support

    Returns:
        JSON with anchors (string, address, undocumented/documented function lists), total counts.
    """
    url = f"{ghidra_server_url}/batch_string_anchor_report"
    params = {"pattern": pattern}
    if program:
        params["program"] = program
    return make_request(url, method="GET", params=params)


# ====================================================================================
# FUNCTION HASH INDEX - Cross-binary documentation propagation
# ====================================================================================


@mcp.tool()
def get_function_hash(address: str, program: str = None) -> str:
    """
    Compute a normalized opcode hash for a function (address-independent, for cross-binary matching).

    Args:
        address: Function address in hex format (e.g., "0x6FAB1234")
        program: Optional program name for multi-program support

    Returns:
        JSON with function name, address, hash, instruction count, size, and program.
    """
    if not address:
        raise GhidraValidationError("Function address is required")

    url = f"{ghidra_server_url}/get_function_hash"
    params = {"address": address}
    if program:
        params["program"] = program
    return make_request(url, method="GET", params=params)


@mcp.tool()
def get_bulk_function_hashes(
    offset: int = 0, limit: int = 100, filter: str = None, program: str = None
) -> str:
    """
    Get normalized opcode hashes for multiple functions efficiently.

    This is the bulk version of get_function_hash(), designed for building
    a function hash index across an entire binary.

    Args:
        offset: Number of functions to skip (for pagination)
        limit: Maximum number of functions to return (default: 100, max: 1000)
        filter: Filter functions - "documented" (has custom name),
                "undocumented" (FUN_* names), or None for all
        program: Optional program name for multi-program support

    Returns:
        JSON with array of function hashes:
        {
            "program": "D2Client.dll",
            "functions": [
                {"name": "ProcessUnit", "address": "0x...", "hash": "...", ...},
                ...
            ],
            "offset": 0,
            "limit": 100,
            "returned": 100,
            "total_matching": 5432
        }

    Example:
        # Get all documented functions
        result = get_bulk_function_hashes(filter="documented")

        # Paginate through all functions
        result = get_bulk_function_hashes(offset=0, limit=500)
        result = get_bulk_function_hashes(offset=500, limit=500)
    """
    url = f"{ghidra_server_url}/get_bulk_function_hashes"
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    if program:
        params["program"] = program
    return make_request(url, method="GET", params=params)


# ====================================================================================
# FUZZY FUNCTION MATCHING & DIFF - Cross-compiler function comparison
# ====================================================================================


@mcp.tool()
def get_function_signature(address: str, program: str = None) -> str:
    """
    Get a function's feature signature for fuzzy matching.

    Extracts a compiler-agnostic feature vector including callee names,
    string constants, immediate values, basic block structure, and numeric
    metrics. For ARM binaries, prologue/epilogue instructions are stripped
    to focus on function logic rather than ABI conventions.

    Args:
        address: Function address in hex format (e.g., "0x08011d34")
        program: Optional program name for multi-program support

    Returns:
        JSON with feature vector:
        {
            "function_name": "HAL_GPIO_Init",
            "address": "0x08011d34",
            "instruction_count": 87,
            "basic_block_count": 12,
            "callee_names": ["HAL_RCC_GetHCLKFreq", ...],
            "string_constants": ["GPIO error", ...],
            "immediate_values": [0x10, 0x20, ...],
            "basic_block_hashes": ["a1b2c3...", ...],
            "prologue_stripped": true,
            "epilogue_stripped": true
        }
    """
    if not address:
        raise GhidraValidationError("Function address is required")

    params = {"address": address}
    if program:
        params["program"] = program
    return safe_get("get_function_signature", params)


@mcp.tool()
def find_similar_functions_fuzzy(
    address: str,
    target_program: str,
    source_program: str = None,
    threshold: float = 0.7,
    limit: int = 20,
) -> str:
    """
    Find functions in a target binary that are similar to a given source function using fuzzy matching.

    Args:
        address: Source function address in hex format (e.g., "0x08011d34")
        target_program: Name of the target program to search in (required)
        source_program: Name of the source program (default: current program)
        threshold: Minimum similarity score 0.0-1.0 (default: 0.7)
        limit: Maximum number of matches to return (default: 20)

    Returns:
        JSON with ranked matches including names, addresses, and similarity scores.
    """
    if not address:
        raise GhidraValidationError("Function address is required")
    if not target_program:
        raise GhidraValidationError("target_program is required")

    params = {
        "address": address,
        "target_program": target_program,
        "threshold": threshold,
        "limit": limit,
    }
    if source_program:
        params["source_program"] = source_program
    return safe_get("find_similar_functions_fuzzy", params)


@mcp.tool()
def bulk_fuzzy_match(
    source_program: str,
    target_program: str,
    threshold: float = 0.7,
    offset: int = 0,
    limit: int = 50,
    filter: str = None,
) -> str:
    """
    Find the best fuzzy match for each source function in a target binary (paginated).

    Args:
        source_program: Name of the source program (required)
        target_program: Name of the target program (required)
        threshold: Minimum similarity score 0.0-1.0 (default: 0.7)
        offset: Skip this many source functions for pagination (default: 0)
        limit: Process this many source functions per call (default: 50)
        filter: "named" (only documented), "unnamed" (only FUN_*), or None for all

    Returns:
        JSON with best match per source function including names, addresses, and similarity scores.
    """
    if not source_program:
        raise GhidraValidationError("source_program is required")
    if not target_program:
        raise GhidraValidationError("target_program is required")

    params = {
        "source_program": source_program,
        "target_program": target_program,
        "threshold": threshold,
        "offset": offset,
        "limit": limit,
    }
    if filter:
        params["filter"] = filter
    return safe_get("bulk_fuzzy_match", params)


@mcp.tool()
def diff_functions(
    address_a: str,
    address_b: str,
    program_a: str = None,
    program_b: str = None,
) -> str:
    """
    Compute a structured instruction-level diff between two functions.

    Args:
        address_a: First function address in hex (e.g., "0x08011d34")
        address_b: Second function address in hex (e.g., "0x0800a234")
        program_a: Program name for function A (default: current program)
        program_b: Program name for function B (default: same as program_a)

    Returns:
        JSON with similarity score, prologue/body/epilogue diffs, and call/string differences.
    """
    if not address_a:
        raise GhidraValidationError("address_a is required")
    if not address_b:
        raise GhidraValidationError("address_b is required")

    params = {
        "address_a": address_a,
        "address_b": address_b,
    }
    if program_a:
        params["program_a"] = program_a
    if program_b:
        params["program_b"] = program_b
    return safe_get("diff_functions", params)


@mcp.tool()
def get_function_documentation(address: str, program: str = None) -> str:
    """
    Export all documentation for a function (name, prototype, comments, labels, hash) for cross-binary propagation.

    Args:
        address: Function address in hex format (e.g., "0x6FAB1234")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with hash, function name, return type, calling convention, plate comment,
        parameters, local variables, comments/labels with relative offsets, and completeness score.
    """
    if not address:
        raise GhidraValidationError("Function address is required")

    url = f"{ghidra_server_url}/get_function_documentation"
    params = {"address": address}
    return make_request(url, method="GET", params=params, program=program)


@mcp.tool()
def apply_function_documentation(
    target_address: str,
    function_name: str = None,
    return_type: str = None,
    calling_convention: str = None,
    plate_comment: str = None,
    parameters: list = None,
    comments: list = None,
    labels: list = None,
    program: str = None,
) -> str:
    """
    Apply exported documentation to a target function. Comments and labels use relative offsets.

    Args:
        target_address: Address of function to document (required)
        function_name: New name for the function
        return_type: Return type (e.g., "int", "void *")
        calling_convention: Calling convention (e.g., "__fastcall")
        plate_comment: Function header comment
        parameters: List of parameter dicts [{"ordinal": 0, "name": "...", "type": "..."}]
        comments: List of comment dicts [{"relative_offset": 10, "eol_comment": "..."}]
        labels: List of label dicts [{"relative_offset": 20, "name": "loop_start"}]
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with success status and changes_applied count.
    """
    if not target_address:
        raise GhidraValidationError("target_address is required")

    import json

    # Build JSON body
    body = {
        "target_address": target_address,
    }
    if function_name:
        body["function_name"] = function_name
    if return_type:
        body["return_type"] = return_type
    if calling_convention:
        body["calling_convention"] = calling_convention
    if plate_comment:
        body["plate_comment"] = plate_comment
    if parameters:
        body["parameters"] = parameters
    if comments:
        body["comments"] = comments
    if labels:
        body["labels"] = labels

    url = f"{ghidra_server_url}/apply_function_documentation"
    return make_request(url, method="POST", data=json.dumps(body), program=program)


# ====================================================================================
# FUNCTION HASH INDEX MANAGEMENT - High-level tools for cross-binary documentation
# ====================================================================================

import json
import os
from pathlib import Path
from datetime import datetime

# Default index file location
FUNCTION_HASH_INDEX_FILE = "function_hash_index.json"


@mcp.tool()
def build_function_hash_index(
    programs: list = None,
    filter: str = "documented",
    index_file: str = None,
    merge: bool = True,
) -> str:
    """
    Build or update a function hash index from one or more programs for cross-binary doc propagation.

    Args:
        programs: List of program paths to scan (e.g., ["/D2Client.dll"]). None = current program.
        filter: "documented" (custom names only), "undocumented" (FUN_* only), or "all"
        index_file: Path to save index JSON (default: function_hash_index.json)
        merge: If True, merge with existing index; if False, replace

    Returns:
        JSON with programs scanned, functions indexed, unique hashes, and duplicates found.
    """
    index_path = index_file or FUNCTION_HASH_INDEX_FILE

    # Load existing index if merging
    existing_index = {
        "version": "1.0",
        "hash_algorithm": "normalized_opcodes_sha256",
        "functions": {},
    }
    if merge and os.path.exists(index_path):
        try:
            with open(index_path, "r") as f:
                existing_index = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load existing index: {e}")

    index = existing_index
    programs_scanned = 0
    functions_indexed = 0

    # Get current program info for reference
    try:
        current_info = json.loads(
            make_request(f"{ghidra_server_url}/get_current_program_info")
        )
        current_program = current_info.get("name", "Unknown")
    except:
        current_program = "Unknown"

    # If no programs specified, just scan current program
    if not programs:
        programs_to_scan = [None]  # None means current program
    else:
        programs_to_scan = programs

    for program_path in programs_to_scan:
        try:
            # Switch to program if specified
            if program_path:
                result = json.loads(
                    make_request(
                        f"{ghidra_server_url}/open_program",
                        params={"path": program_path},
                    )
                )
                if "error" in result:
                    logger.warning(f"Could not open {program_path}: {result['error']}")
                    continue
                program_name = result.get("name", program_path)
            else:
                program_name = current_program

            # Get all function hashes (paginate through all)
            offset = 0
            batch_size = 500

            while True:
                result = json.loads(
                    make_request(
                        f"{ghidra_server_url}/get_bulk_function_hashes",
                        params={
                            "offset": offset,
                            "limit": batch_size,
                            "filter": filter,
                        },
                    )
                )

                if "error" in result:
                    logger.warning(
                        f"Error getting hashes from {program_name}: {result['error']}"
                    )
                    break

                functions = result.get("functions", [])
                if not functions:
                    break

                for func in functions:
                    hash_val = func["hash"]
                    func_name = func["name"]
                    func_addr = func["address"]
                    has_custom = func.get("has_custom_name", False)

                    # Get completeness score for documented functions
                    completeness = 0
                    if has_custom:
                        try:
                            comp_result = json.loads(
                                make_request(
                                    f"{ghidra_server_url}/analyze_function_completeness",
                                    params={"address": func_addr},
                                )
                            )
                            completeness = comp_result.get("completeness_score", 0)
                        except:
                            pass

                    instance = {
                        "program": program_name,
                        "address": func_addr,
                        "name": func_name,
                        "completeness_score": completeness,
                        "indexed_at": datetime.now().isoformat(),
                    }

                    if hash_val not in index["functions"]:
                        # New hash - create entry
                        index["functions"][hash_val] = {
                            "canonical": instance if has_custom else None,
                            "instances": [instance],
                        }
                    else:
                        # Existing hash - add instance and potentially update canonical
                        entry = index["functions"][hash_val]

                        # Check if this instance already exists
                        existing = False
                        for i, inst in enumerate(entry["instances"]):
                            if (
                                inst["program"] == program_name
                                and inst["address"] == func_addr
                            ):
                                # Update existing instance
                                entry["instances"][i] = instance
                                existing = True
                                break

                        if not existing:
                            entry["instances"].append(instance)

                        # Update canonical if this is better documented
                        if has_custom:
                            if entry["canonical"] is None:
                                entry["canonical"] = instance
                            elif completeness > entry["canonical"].get(
                                "completeness_score", 0
                            ):
                                entry["canonical"] = instance

                    functions_indexed += 1

                offset += batch_size
                if len(functions) < batch_size:
                    break

            programs_scanned += 1

        except Exception as e:
            logger.warning(f"Error processing program {program_path}: {e}")

    # Count unique hashes and duplicates
    unique_hashes = len(index["functions"])
    duplicates = sum(
        1 for entry in index["functions"].values() if len(entry["instances"]) > 1
    )

    # Save index
    try:
        with open(index_path, "w") as f:
            json.dump(index, f, indent=2)
    except Exception as e:
        return json.dumps(
            {
                "error": f"Could not save index: {str(e)}",
                "programs_scanned": programs_scanned,
                "functions_indexed": functions_indexed,
            }
        )

    return json.dumps(
        {
            "success": True,
            "programs_scanned": programs_scanned,
            "functions_indexed": functions_indexed,
            "unique_hashes": unique_hashes,
            "duplicates_found": duplicates,
            "index_file": index_path,
        }
    )


@mcp.tool()
def lookup_function_by_hash(
    address: str = None, hash: str = None, index_file: str = None, program: str = None
) -> str:
    """
    Look up a function in the hash index to find matches across binaries.

    Given either a function address (will compute hash) or a hash directly,
    searches the index for all instances of matching functions.

    Args:
        address: Function address to look up (computes hash automatically)
        hash: Direct hash value to look up (alternative to address)
        index_file: Path to index file (default: function_hash_index.json)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with lookup results:
        {
            "found": true,
            "hash": "a1b2c3d4...",
            "canonical": {
                "program": "D2Client.dll 1.13d",
                "address": "0x6fab1234",
                "name": "UNITS_GetUnitX",
                "completeness_score": 95
            },
            "instances": [...],
            "total_instances": 5
        }

    Example:
        # Look up current function
        result = lookup_function_by_hash(address="0x6FAB1234")

        # If found, get the canonical documentation
        if result["found"] and result["canonical"]:
            docs = get_function_documentation(result["canonical"]["address"])
    """
    if not address and not hash:
        raise GhidraValidationError("Either address or hash must be provided")

    index_path = index_file or FUNCTION_HASH_INDEX_FILE

    # Load index
    if not os.path.exists(index_path):
        return json.dumps({"error": f"Index file not found: {index_path}"})

    try:
        with open(index_path, "r") as f:
            index = json.load(f)
    except Exception as e:
        return json.dumps({"error": f"Could not load index: {str(e)}"})

    # Get hash if address provided
    if address and not hash:
        try:
            req_params = {"address": address}
            if program:
                req_params["program"] = program
            result = json.loads(
                make_request(
                    f"{ghidra_server_url}/get_function_hash",
                    params=req_params,
                )
            )
            if "error" in result:
                return json.dumps(result)
            hash = result["hash"]
        except Exception as e:
            return json.dumps({"error": f"Could not compute hash: {str(e)}"})

    # Look up in index
    if hash not in index.get("functions", {}):
        return json.dumps(
            {
                "found": False,
                "hash": hash,
                "message": "No matching functions found in index",
            }
        )

    entry = index["functions"][hash]
    return json.dumps(
        {
            "found": True,
            "hash": hash,
            "canonical": entry.get("canonical"),
            "instances": entry.get("instances", []),
            "total_instances": len(entry.get("instances", [])),
        }
    )


@mcp.tool()
def propagate_documentation(
    source_address: str = None,
    source_hash: str = None,
    target_programs: list = None,
    dry_run: bool = False,
    index_file: str = None,
) -> str:
    """
    Propagate documentation from a source function to all matching functions (same hash) across binaries.

    Args:
        source_address: Address of source function (will export its documentation)
        source_hash: Hash to look up canonical source in index (alternative to source_address)
        target_programs: List of program names to propagate to (None = all in index)
        dry_run: If True, only report what would be changed without applying
        index_file: Path to index file (default: function_hash_index.json)

    Returns:
        JSON with targets updated/skipped counts and per-target details.
    """
    if not source_address and not source_hash:
        raise GhidraValidationError(
            "Either source_address or source_hash must be provided"
        )

    index_path = index_file or FUNCTION_HASH_INDEX_FILE

    # Get source documentation
    if source_address:
        try:
            docs = json.loads(
                make_request(
                    f"{ghidra_server_url}/get_function_documentation",
                    params={"address": source_address},
                )
            )
            if "error" in docs:
                return json.dumps(docs)
            source_hash = docs["hash"]
            source_info = {
                "program": docs["source_program"],
                "address": docs["source_address"],
                "name": docs["function_name"],
            }
        except Exception as e:
            return json.dumps(
                {"error": f"Could not get source documentation: {str(e)}"}
            )
    else:
        # Look up canonical from index
        lookup_result = json.loads(
            lookup_function_by_hash(hash=source_hash, index_file=index_path)
        )
        if not lookup_result.get("found") or not lookup_result.get("canonical"):
            return json.dumps(
                {"error": "Source hash not found or has no canonical documentation"}
            )

        canonical = lookup_result["canonical"]
        # Need to switch to source program and get documentation
        try:
            make_request(
                f"{ghidra_server_url}/switch_program",
                params={"name": canonical["program"]},
            )
            docs = json.loads(
                make_request(
                    f"{ghidra_server_url}/get_function_documentation",
                    params={"address": canonical["address"]},
                )
            )
            if "error" in docs:
                return json.dumps(docs)
            source_info = {
                "program": canonical["program"],
                "address": canonical["address"],
                "name": canonical["name"],
            }
        except Exception as e:
            return json.dumps(
                {"error": f"Could not get canonical documentation: {str(e)}"}
            )

    # Load index to find all instances
    try:
        with open(index_path, "r") as f:
            index = json.load(f)
    except Exception as e:
        return json.dumps({"error": f"Could not load index: {str(e)}"})

    if source_hash not in index.get("functions", {}):
        return json.dumps({"error": f"Hash {source_hash} not found in index"})

    instances = index["functions"][source_hash].get("instances", [])

    results = {
        "success": True,
        "source": source_info,
        "targets_updated": 0,
        "targets_skipped": 0,
        "dry_run": dry_run,
        "details": [],
    }

    for instance in instances:
        target_program = instance["program"]
        target_address = instance["address"]

        # Skip source
        if (
            target_program == source_info["program"]
            and target_address == source_info["address"]
        ):
            results["details"].append(
                {
                    "program": target_program,
                    "address": target_address,
                    "status": "skipped",
                    "reason": "source function",
                }
            )
            results["targets_skipped"] += 1
            continue

        # Check target program filter
        if target_programs and target_program not in target_programs:
            results["details"].append(
                {
                    "program": target_program,
                    "address": target_address,
                    "status": "skipped",
                    "reason": "not in target_programs filter",
                }
            )
            results["targets_skipped"] += 1
            continue

        if dry_run:
            results["details"].append(
                {
                    "program": target_program,
                    "address": target_address,
                    "status": "would_update",
                    "current_name": instance.get("name", "unknown"),
                }
            )
            results["targets_updated"] += 1
        else:
            try:
                # Switch to target program
                switch_result = json.loads(
                    make_request(
                        f"{ghidra_server_url}/switch_program",
                        params={"name": target_program},
                    )
                )
                if "error" in switch_result:
                    results["details"].append(
                        {
                            "program": target_program,
                            "address": target_address,
                            "status": "error",
                            "reason": switch_result["error"],
                        }
                    )
                    results["targets_skipped"] += 1
                    continue

                # Apply documentation
                apply_result = json.loads(
                    make_request(
                        f"{ghidra_server_url}/apply_function_documentation",
                        method="POST",
                        data=json.dumps(
                            {
                                "target_address": target_address,
                                "function_name": docs.get("function_name"),
                                "return_type": docs.get("return_type"),
                                "calling_convention": docs.get("calling_convention"),
                                "plate_comment": docs.get("plate_comment"),
                                "parameters": docs.get("parameters"),
                                "comments": docs.get("comments"),
                                "labels": docs.get("labels"),
                            }
                        ),
                    )
                )

                if "error" in apply_result:
                    results["details"].append(
                        {
                            "program": target_program,
                            "address": target_address,
                            "status": "error",
                            "reason": apply_result["error"],
                        }
                    )
                    results["targets_skipped"] += 1
                else:
                    results["details"].append(
                        {
                            "program": target_program,
                            "address": target_address,
                            "status": "updated",
                            "changes": apply_result.get("changes_applied", 0),
                        }
                    )
                    results["targets_updated"] += 1

            except Exception as e:
                results["details"].append(
                    {
                        "program": target_program,
                        "address": target_address,
                        "status": "error",
                        "reason": str(e),
                    }
                )
                results["targets_skipped"] += 1

    return json.dumps(results)


# ==========================================================================
# SERVER CONNECTION TOOLS
# ==========================================================================


@mcp.tool()
def connect_server() -> str:
    """
    Connect to the configured Ghidra shared server.

    Establishes connection using GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT,
    GHIDRA_SERVER_USER, and GHIDRA_SERVER_PASSWORD environment variables.

    Returns:
        JSON with connection status, host, port, and user.
    """
    return safe_post_json("server/connect", {})


@mcp.tool()
def disconnect_server() -> str:
    """
    Disconnect from the Ghidra shared server.

    Returns:
        JSON with disconnect status.
    """
    return safe_post_json("server/disconnect", {})


@mcp.tool()
def server_status() -> str:
    """
    Get the current Ghidra server connection status.

    Returns:
        JSON with connected state, host, port, user, and last error if any.
    """
    return safe_get_json("server/status", {})


@mcp.tool()
def list_repositories() -> str:
    """
    List available repositories on the connected Ghidra server.

    Requires an active server connection (use connect_server first).

    Returns:
        JSON with list of repository names and count.
    """
    return safe_get_json("server/repositories", {})


@mcp.tool()
def create_repository(name: str) -> str:
    """
    Create a new repository on the connected Ghidra server.

    Args:
        name: Name of the new repository to create.

    Returns:
        JSON with creation status and repository name.
    """
    return safe_post_json("server/repository/create", {"name": name})


# ==========================================================================
# PROJECT LIFECYCLE TOOLS
# ==========================================================================


@mcp.tool()
def create_project(parent_dir: str, name: str) -> str:
    """
    Create a new Ghidra project in the specified directory.

    Creates a new .gpr project file and opens it as the current project.

    Args:
        parent_dir: Absolute path to the directory where the project will be created.
        name: Name of the new project (no extension needed).

    Returns:
        JSON with creation status, name, and directory.

    Example:
        result = create_project("/projects", "MyAnalysis")
    """
    return safe_post_json("create_project", {"parentDir": parent_dir, "name": name})


@mcp.tool()
def open_project(project_path: str) -> str:
    """
    Open an existing Ghidra project.

    Args:
        project_path: Path to the .gpr file or directory containing it.
                      Examples: "/projects/MyProject.gpr" or "/projects/MyProject"

    Returns:
        JSON with open status and project name.
    """
    return safe_get_json("open_project", {"path": project_path})


@mcp.tool()
def close_project() -> str:
    """
    Close the currently open Ghidra project.

    Closes all open programs and releases the project lock.

    Returns:
        JSON with close status.
    """
    return safe_post_json("close_project", {})


@mcp.tool()
def delete_project(project_path: str) -> str:
    """
    Delete a Ghidra project from disk.

    WARNING: This permanently deletes the project files. The project
    will be closed first if it is currently open.

    Args:
        project_path: Path to the .gpr file or project directory.

    Returns:
        JSON with deletion status.
    """
    return safe_post_json("delete_project", {"projectPath": project_path})


@mcp.tool()
def list_projects(search_dir: str = None) -> str:
    """
    List Ghidra projects found in a directory tree.

    Scans up to 3 directory levels deep for .gpr files.

    Args:
        search_dir: Directory to search. Defaults to user home directory.

    Returns:
        JSON with list of projects: name, path, active (bool), count.
    """
    params = {}
    if search_dir:
        params["searchDir"] = search_dir
    return safe_get_json("list_projects", params)


# ==========================================================================
# PROJECT & TOOL MANAGEMENT (FrontEnd)
# ==========================================================================


@mcp.tool()
def project_info() -> str:
    """
    Get detailed information about the current Ghidra project.

    Returns project name, shared/server status, open programs, running tools,
    and whether CodeBrowser is active. Works from the FrontEnd (Project Manager)
    without needing CodeBrowser open.

    Returns:
        JSON with project name, shared status, server info, file count,
        open programs, running tools, and codebrowser_active flag.
    """
    return safe_get_json("project/info", {})


@mcp.tool()
def list_running_tools() -> str:
    """
    List all currently running Ghidra tool windows.

    Shows each tool's name, instance, whether it has a ProgramManager
    (i.e. is a CodeBrowser), and what programs are open in it.

    Returns:
        JSON with tools array and count.
    """
    return safe_get_json("tool/running_tools", {})


@mcp.tool()
def launch_codebrowser(path: str = None) -> str:
    """
    Open a file in CodeBrowser, launching a new CodeBrowser if needed.

    If a CodeBrowser is already running, opens the file in it.
    If no CodeBrowser is running, launches a new one.
    If no path is specified, launches an empty CodeBrowser.

    Args:
        path: Project path to the file to open (e.g., "/LoD/1.00/D2Common.dll").
              Optional - omit to launch empty CodeBrowser.

    Returns:
        JSON with success status and tool/program details.
    """
    params = {}
    if path:
        params["path"] = path
    return safe_post_json("tool/launch_codebrowser", params)


@mcp.tool()
def goto_address(address: str, program: str = None) -> str:
    """
    Navigate the CodeBrowser listing and decompiler to a specific address.

    Finds the running CodeBrowser and uses GoToService to move the cursor
    to the specified address, updating both the listing and decompiler views.

    Args:
        address: Memory address in hex format (e.g., "0x6FD81234")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with success status, navigated address, and containing function (if any).
    """
    return safe_post_json("tool/goto_address", {"address": address}, program=program)


@mcp.tool()
def authenticate_server(username: str = None, password: str = "") -> str:
    """
    Register credentials for Ghidra server authentication.

    Bypasses the GUI password dialog by registering a programmatic authenticator.
    Once registered, all subsequent server operations (connecting to shared projects,
    version control, etc.) use these credentials automatically.

    Args:
        username: Server username. Optional - defaults to Ghidra's saved username
                  or the system user if not specified.
        password: Server password. Required.

    Returns:
        JSON with success status and registered username.
    """
    params = {"password": password}
    if username:
        params["username"] = username
    return safe_post_json("server/authenticate", params)


# ==========================================================================
# PROJECT ORGANIZATION TOOLS
# ==========================================================================


@mcp.tool()
def create_folder(path: str) -> str:
    """
    Create a folder in the current Ghidra project.

    Creates all intermediate folders in the path if they don't exist.

    Args:
        path: Folder path to create (e.g., "/dlls/x64" or "analysis").

    Returns:
        JSON with creation status and path.
    """
    return safe_post_json("create_folder", {"path": path})


@mcp.tool()
def move_file(file_path: str, dest_folder: str) -> str:
    """
    Move a file within the current Ghidra project.

    Args:
        file_path: Current path of the file in the project (e.g., "/Game.exe").
        dest_folder: Destination folder path (e.g., "/archived").

    Returns:
        JSON with move status, from, and to paths.
    """
    return safe_post_json("move_file", {"filePath": file_path, "destFolder": dest_folder})


@mcp.tool()
def move_folder(source_path: str, dest_path: str) -> str:
    """
    Move a folder within the current Ghidra project.

    Args:
        source_path: Current path of the folder (e.g., "/old_dlls").
        dest_path: Destination parent folder path (e.g., "/archive").

    Returns:
        JSON with move status.
    """
    return safe_post_json("move_folder", {"sourcePath": source_path, "destPath": dest_path})


@mcp.tool()
def delete_file(file_path: str) -> str:
    """
    Delete a file from the current Ghidra project.

    WARNING: This permanently removes the file from the project.
    The file will be closed first if it is currently open.

    Args:
        file_path: Project path of the file to delete (e.g., "/temp/Game.exe").

    Returns:
        JSON with deletion status.
    """
    return safe_post_json("delete_file", {"filePath": file_path})


# ==========================================================================
# VERSION CONTROL TOOLS
# ==========================================================================


@mcp.tool()
def checkout_file(repo: str, path: str, exclusive: bool = True) -> str:
    """
    Check out a file from a Ghidra shared server repository for exclusive editing.

    Checks the file's current checkout status first. If already checked out,
    returns the existing checkout info instead of failing.

    Args:
        repo: Repository name (e.g., "MyProject").
        path: File path within the repository (e.g., "/Game.exe").
        exclusive: If True (default), check out exclusively for editing.

    Returns:
        JSON with checkout status.
    """
    # Check current status first to avoid errors on already-checked-out files
    folder = path.rsplit("/", 1)[0] if "/" in path else "/"
    if not folder:
        folder = "/"
    status = safe_get_json("server/checkouts", {"path": folder})
    try:
        status_data = json.loads(status) if isinstance(status, str) else status
        checkouts = status_data.get("checkouts", [])
        for co in checkouts:
            if co.get("path") == path and co.get("is_checked_out"):
                return json.dumps({
                    "status": "already_checked_out",
                    "path": path,
                    "exclusive": co.get("is_checked_out_exclusive", False),
                    "user": co.get("checkout_user", "unknown")
                })
    except (json.JSONDecodeError, AttributeError):
        pass  # Fall through to attempt checkout

    return safe_post_json("server/version_control/checkout", {
        "path": path, "exclusive": str(exclusive).lower()
    })


@mcp.tool()
def checkin_file(repo: str, path: str, comment: str, keep_checked_out: bool = False) -> str:
    """
    Check in a file to a Ghidra shared server repository.

    Args:
        repo: Repository name.
        path: File path within the repository.
        comment: Check-in comment describing the changes.
        keep_checked_out: If True, file remains checked out after check-in.

    Returns:
        JSON with check-in status.
    """
    return safe_post_json("server/version_control/checkin", {
        "path": path, "comment": comment,
        "keepCheckedOut": str(keep_checked_out).lower()
    })


@mcp.tool()
def undo_checkout(repo: str, path: str) -> str:
    """
    Undo a checkout, discarding any local changes to the file.

    Args:
        repo: Repository name.
        path: File path within the repository.

    Returns:
        JSON with undo status.
    """
    return safe_post_json("server/version_control/undo_checkout", {"path": path})


@mcp.tool()
def add_to_version_control(repo: str, path: str, comment: str) -> str:
    """
    Add a file to version control on the Ghidra server for the first time.

    Args:
        repo: Repository name where the file will be added.
        path: File path within the repository.
        comment: Initial version comment.

    Returns:
        JSON with status and next steps.
    """
    return safe_post_json("server/version_control/add", {
        "repo": repo, "path": path, "comment": comment
    })


# ==========================================================================
# VERSION HISTORY TOOLS
# ==========================================================================


@mcp.tool()
def get_version_history(repo: str, path: str) -> str:
    """
    Get the version history of a file in a Ghidra server repository.

    Args:
        repo: Repository name.
        path: File path within the repository.

    Returns:
        JSON with list of versions: version number, user, comment, date.
    """
    return safe_get_json("server/version_history", {"repo": repo, "path": path})


@mcp.tool()
def get_checkouts(path: str = "/") -> str:
    """
    List all checked-out files in a project folder, including server-side checkouts.

    Recursively scans the folder for both locally checked-out files and
    server-side checkouts by other users. This is the recommended way to
    see who has files locked on the shared server.

    Args:
        path: Folder path within the project (e.g., "/LoD/1.08").
              Defaults to "/" (entire project).

    Returns:
        JSON with list of checked-out files. Each entry includes local checkout
        status and server_checkouts array with checkout_id, user, and version.
    """
    return safe_get_json("server/checkouts", {"path": path})


# ==========================================================================
# ADMIN TOOLS
# ==========================================================================


@mcp.tool()
def terminate_checkout(path: str) -> str:
    """
    Forcibly terminate all checkouts on a single file.

    Terminates both local and server-side checkouts for the specified file.
    Use get_checkouts first to see which files have active checkouts.

    Args:
        path: File path within the project (e.g., "/LoD/1.08/D2Common.dll").

    Returns:
        JSON with termination status and count of terminated checkouts.
    """
    return safe_post_json("server/admin/terminate_checkout", {"path": path})


@mcp.tool()
def terminate_all_checkouts(path: str = "/") -> str:
    """
    Forcibly terminate ALL checkouts in a folder recursively.

    Scans all files in the folder (and subfolders) for server-side checkouts
    and terminates them all in one call. Use this to bulk-clear checkout locks
    on an entire version folder.

    Args:
        path: Folder path within the project (e.g., "/LoD/1.08").
              Defaults to "/" (entire project).

    Returns:
        JSON with summary: files_with_checkouts, checkouts_terminated, and
        per-file details.
    """
    return safe_post_json("server/admin/terminate_all_checkouts", {"path": path})


@mcp.tool()
def list_server_users() -> str:
    """
    Admin: list all users registered on the Ghidra server.

    Requires server admin privileges and active connection.

    Returns:
        JSON with list of users: name, is_admin, count.
    """
    return safe_get_json("server/admin/users", {})


@mcp.tool()
def set_user_permissions(repo: str, user: str, access_level: int) -> str:
    """
    Admin: set a user's access level for a repository.

    Requires server admin privileges.

    Args:
        repo: Repository name.
        user: Username to update.
        access_level: Access level (0=no_access, 1=read_only, 2=read_write, 3=admin).

    Returns:
        JSON with permission update status.
    """
    return safe_post_json("server/admin/set_permissions", {
        "repo": repo, "user": user, "accessLevel": str(access_level)
    })


# ==========================================================================
# ANALYSIS CONTROL TOOLS
# ==========================================================================


@mcp.tool()
def list_analyzers(program: str = None) -> str:
    """
    List all available analyzers for the current program.

    Shows each analyzer's name, description, enabled state, and priority.

    Args:
        program: Optional program name for multi-binary analysis.

    Returns:
        JSON with list of analyzers and their current configuration.

    Example:
        analyzers = list_analyzers()
        # Returns: {"analyzers": [{"name": "ASCII Strings", "enabled": true, ...}], "count": N}
    """
    params = {}
    if program:
        params["program"] = program
    return safe_get_json("list_analyzers", params)


@mcp.tool()
def configure_analyzer(analyzer_name: str, enabled: bool = None, program: str = None) -> str:
    """
    Enable or disable a specific analyzer for a program.

    Changes take effect on the next call to run_analysis.

    Args:
        analyzer_name: Name of the analyzer to configure (from list_analyzers).
        enabled: True to enable, False to disable. Required.
        program: Optional program name for multi-binary analysis.

    Returns:
        JSON with configuration status.

    Example:
        # Disable demangling to speed up analysis
        configure_analyzer("Demangler GNU", enabled=False)
    """
    data = {"name": analyzer_name}
    if enabled is not None:
        data["enabled"] = str(enabled).lower()
    if program:
        data["program"] = program
    return safe_post_json("configure_analyzer", data)


@mcp.tool()
def run_analysis(program: str = None) -> str:
    """
    Run auto-analysis on the current program.

    Triggers Ghidra's full auto-analysis pipeline. This may take a while
    for large binaries. Use list_analyzers/configure_analyzer to control
    which analyzers run before calling this.

    Args:
        program: Optional program name for multi-binary analysis.

    Returns:
        JSON with analysis result: success, duration_ms, total_functions, new_functions.

    Example:
        result = run_analysis()
        # Returns: {"success": true, "duration_ms": 12500, "total_functions": 847, ...}
    """
    data = {}
    if program:
        data["program"] = program
    return safe_post_json("run_analysis", data)


# ==========================================================================
# NEWLY EXPOSED HEADLESS ENDPOINTS (previously headless-only, now bridged)
# ==========================================================================


@mcp.tool()
def list_functions_enhanced(
    program: str = None,
    offset: int = 0,
    limit: int = 100
) -> str:
    """
    List functions with enhanced metadata including thunk and external flags.

    Args:
        program: Optional program name for multi-binary analysis.
        offset: Pagination offset.
        limit: Maximum results to return.

    Returns:
        JSON array of functions with name, address, isThunk, isExternal fields.
    """
    params = {"offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get_json("list_functions_enhanced", params)


# ========== DATA TYPE MANAGEMENT ==========


@mcp.tool()
def create_typedef(name: str, base_type: str, program: str = None) -> str:
    """
    Create a typedef (type alias) data type.

    Args:
        name: Name for the new typedef (e.g., "pUnit")
        base_type: Base type to alias (e.g., "UnitAny *", "int", "DWORD")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success message with typedef details or error message
    """
    return safe_post_json("create_typedef", {"name": name, "baseType": base_type}, program=program)


@mcp.tool()
def create_union(name: str, fields: list, program: str = None) -> str:
    """
    Create a union data type with specified fields.

    Unions store all fields at the same memory offset (overlapping), unlike structs.

    Args:
        name: Name for the new union (must be unique)
        fields: List of field definitions as dictionaries with:
                - name (required): Field name
                - type (required): Field data type (e.g., "int", "float", "char[16]")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success message with union details or error message

    Examples:
        fields = [
            {"name": "asInt", "type": "int"},
            {"name": "asFloat", "type": "float"},
            {"name": "asBytes", "type": "byte[4]"}
        ]
        result = create_union("NumberVariant", fields)
    """
    return safe_post_json("create_union", {"name": name, "fields": fields}, program=program)


@mcp.tool()
def create_pointer_type(base_type: str, name: str = None, program: str = None) -> str:
    """
    Create a pointer data type wrapping a base type.

    Args:
        base_type: Base type to create pointer for (e.g., "int", "UnitAny", "void")
        name: Optional custom name for the pointer type
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success message with pointer type details or error message
    """
    data = {"baseType": base_type}
    if name:
        data["name"] = name
    return safe_post_json("create_pointer_type", data, program=program)


@mcp.tool()
def clone_data_type(source_type: str, new_name: str, program: str = None) -> str:
    """
    Clone an existing data type with a new name.

    Creates a copy of an existing struct, enum, union, or other data type.
    Useful for creating variants of complex types without recreating them.

    Args:
        source_type: Name of the existing data type to clone
        new_name: Name for the cloned type (must be unique)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success message with cloned type details or error message
    """
    return safe_post_json(
        "clone_data_type", {"sourceType": source_type, "newName": new_name}, program=program
    )


@mcp.tool()
def create_data_type_category(category_path: str, program: str = None) -> str:
    """
    Create a new category (folder) in the data type manager.

    Categories organize data types into a hierarchy, similar to folders.

    Args:
        category_path: Category path to create (e.g., "/MyTypes/Structures")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success message or error message
    """
    return safe_post_json(
        "create_data_type_category", {"categoryPath": category_path}, program=program
    )


@mcp.tool()
def list_data_type_categories(
    offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    List all data type categories (folders) in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of categories to return (default: 100)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        List of category paths in the data type manager
    """
    return safe_get(
        "list_data_type_categories", {"offset": offset, "limit": limit}, program=program
    )


@mcp.tool()
def move_data_type_to_category(type_name: str, category_path: str, program: str = None) -> str:
    """
    Move an existing data type to a different category.

    Args:
        type_name: Name of the data type to move
        category_path: Target category path (e.g., "/MyTypes/Structures")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success message or error message
    """
    return safe_post_json(
        "move_data_type_to_category",
        {"typeName": type_name, "categoryPath": category_path},
        program=program,
    )


@mcp.tool()
def get_struct_layout(struct_name: str, program: str = None) -> str:
    """
    Get the detailed field layout of a structure data type.

    Returns a formatted view showing each field's offset, size, type, and name.
    Useful for visualizing struct organization.

    Args:
        struct_name: Name of the structure to inspect
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Formatted struct layout with offset, size, type, and name for each field
    """
    return safe_get_json("get_struct_layout", {"structName": struct_name}, program=program)


@mcp.tool()
def import_data_types(source: str, format: str = "gdt", program: str = None) -> str:
    """
    Import data types from an external source file.

    Args:
        source: Path to the data type source file (e.g., a .gdt file)
        format: Import format (default: "gdt")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Import results or error message
    """
    return safe_post_json(
        "import_data_types", {"source": source, "format": format}, program=program
    )


# ========== VALIDATION & PRE-FLIGHT ==========


@mcp.tool()
def validate_data_type(address: str, type_name: str, program: str = None) -> str:
    """
    Validate whether a data type can be applied at a specific memory address.

    Pre-flight check before apply_data_type(). Checks memory availability,
    alignment, and type compatibility.

    Args:
        address: Memory address to check (e.g., "0x401000")
        type_name: Data type name to validate (e.g., "MyStruct", "int")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with validation results including compatibility and any warnings
    """
    return safe_get_json(
        "validate_data_type", {"address": address, "typeName": type_name}, program=program
    )


@mcp.tool()
def validate_function_prototype(
    function_address: str, prototype: str, calling_convention: str = None, program: str = None
) -> str:
    """
    Validate a function prototype before applying it.

    Pre-flight check before set_function_prototype(). Validates syntax,
    calling convention, and parameter types without modifying anything.

    Args:
        function_address: Address of the function to validate against
        prototype: Prototype string (e.g., "int __stdcall MyFunc(int a, char *b)")
        calling_convention: Optional calling convention to validate
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with validation results, any syntax errors, and warnings
    """
    params = {"functionAddress": function_address, "prototype": prototype}
    if calling_convention:
        params["callingConvention"] = calling_convention
    return safe_get_json("validate_function_prototype", params, program=program)


@mcp.tool()
def can_rename_at_address(address: str, program: str = None) -> str:
    """
    Check what can be renamed at a given address.

    Determines whether the address contains a function, data, or undefined bytes,
    and suggests which rename tool to use. Use this before renaming to avoid errors.

    Args:
        address: Memory address to check (e.g., "0x401000")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with rename type ("function", "defined_data", or "undefined"),
        current name, and suggested tool to use
    """
    return safe_get_json("can_rename_at_address", {"address": address}, program=program)


# ========== DECOMPILATION ==========


@mcp.tool()
def force_decompile(address: str, program: str = None) -> str:
    """
    Force fresh decompilation of a function, bypassing the cache.

    Use this after renaming variables, changing types, or modifying function
    signatures to see updated decompiled output.

    Args:
        address: Memory address of the function (e.g., "0x401000")
        program: Optional program name for multi-program support

    Returns:
        Freshly decompiled C pseudocode
    """
    params = {"address": address}
    if program:
        params["program"] = program
    return safe_get_json("force_decompile", params)


@mcp.tool()
def clear_instruction_flow_override(address: str, program: str = None) -> str:
    """
    Clear a flow override on an instruction at the given address.

    Repairs Ghidra's overly-aggressive noreturn classification, allowing code
    after the instruction to be reanalyzed and included in functions.

    Args:
        address: Address of the instruction with the flow override (e.g., "0x401000")
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or error message
    """
    return safe_post_json(
        "clear_instruction_flow_override", {"address": address}, program=program
    )


# ========== LISTING & BOOKMARKS ==========


@mcp.tool()
def list_bookmarks(
    category: str = None, address: str = None, offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    List bookmarks in the program.

    Bookmarks are user-set markers for tracking analysis progress. This complements
    set_bookmark and delete_bookmark by allowing you to query existing bookmarks.

    Args:
        category: Optional filter by bookmark category
        address: Optional filter by specific address
        offset: Pagination offset (default: 0)
        limit: Maximum number of bookmarks to return (default: 100)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        List of bookmarks with address, category, comment, and type
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    if address:
        params["address"] = address
    return safe_get("list_bookmarks", params, program=program)


# ========== SECURITY ANALYSIS ==========


@mcp.tool()
def analyze_api_call_chains(program: str = None) -> str:
    """
    Identify suspicious API call chain patterns for threat detection.

    Scans functions for known threat patterns including process injection,
    persistence mechanisms, credential theft, network operations, and
    ransomware-like file operations. Returns matched patterns with severity levels.

    Args:
        program: Optional program name for multi-program support

    Returns:
        JSON with detected threat patterns, matched functions, and severity levels
    """
    params = {}
    if program:
        params["program"] = program
    return safe_get_json("analyze_api_call_chains", params)


@mcp.tool()
def detect_malware_behaviors(program: str = None) -> str:
    """
    Analyze functions for malware behavior indicators.

    Scans for 10 categories of suspicious behavior: code injection, keylogging,
    screen capture, privilege escalation, defense evasion, lateral movement,
    data exfiltration, cryptographic operations, process manipulation, and more.

    Args:
        program: Optional program name for multi-program support

    Returns:
        JSON with detected behaviors, risk scores, and matched API patterns
    """
    params = {}
    if program:
        params["program"] = program
    return safe_get_json("detect_malware_behaviors", params)


@mcp.tool()
def extract_iocs_with_context(program: str = None) -> str:
    """
    Extract Indicators of Compromise (IOCs) from program string data.

    Identifies IPv4 addresses, URLs, domains, emails, registry keys, file paths,
    Bitcoin addresses, and MD5/SHA256 hashes. Includes confidence scoring and
    the containing function for each IOC.

    Args:
        program: Optional program name for multi-program support

    Returns:
        JSON with IOC type, value, address, containing function, and confidence score
    """
    params = {}
    if program:
        params["program"] = program
    return safe_get_json("extract_iocs_with_context", params)


# ========== GUI-ONLY ANALYSIS ==========


@mcp.tool()
def suggest_field_names(address: str, size: int = None, program: str = None) -> str:
    """
    Get AI-assisted field name suggestions for a structure at an address.

    Analyzes structure fields and generates name suggestions based on
    field types and usage patterns.

    Args:
        address: Address of the structure instance
        size: Optional structure size in bytes
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with field offset, type, current name, and suggested names
    """
    params = {"address": address}
    if size:
        params["size"] = size
    return safe_get_json("suggest_field_names", params, program=program)


@mcp.tool()
def apply_data_classification(
    address: str, classification: str, type_definition: dict = None, program: str = None
) -> str:
    """
    Apply data type classification at an address with naming and comments in one atomic call.

    Combines type application, label creation, and commenting into a single transaction.
    Classifications: PRIMITIVE, STRUCTURE, ARRAY, ENUM.

    Args:
        address: Memory address to classify (e.g., "0x401000")
        classification: Classification type (PRIMITIVE, STRUCTURE, ARRAY, ENUM)
        type_definition: Optional type definition dict with details for the classification
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success message with applied classification details or error message
    """
    data = {"address": address, "classification": classification}
    if type_definition:
        data["type_definition"] = type_definition
    return safe_post_json("apply_data_classification", data, program=program)


@mcp.tool()
def analyze_call_graph(
    mode: str = "cycles", source: str = None, target: str = None, program: str = None
) -> str:
    """
    Analyze call graph relationships with advanced graph algorithms.

    Three analysis modes:
    - "cycles": Detect recursive call cycles using DFS
    - "path": Find shortest call path between two functions (requires source and target)
    - "strongly_connected": Identify strongly connected components

    Args:
        mode: Analysis mode ("cycles", "path", or "strongly_connected")
        source: Source function name (required for "path" mode)
        target: Target function name (required for "path" mode)
        program: Optional program name for multi-program support

    Returns:
        JSON with analysis results depending on mode
    """
    params = {"mode": mode}
    if source:
        params["source"] = source
    if target:
        params["target"] = target
    if program:
        params["program"] = program
    return safe_get_json("analyze_call_graph", params)


# ========== SERVER REPOSITORY BROWSING ==========


@mcp.tool()
def list_repository_files(repo: str, folder: str = "/") -> str:
    """
    List files in a Ghidra shared server repository folder.

    Requires an active server connection (use connect_server first).

    Args:
        repo: Repository name (e.g., "MyProject")
        folder: Folder path within the repository (default: "/")

    Returns:
        JSON with list of files and folders in the repository
    """
    return safe_get_json(
        "server/repository/files", {"repo": repo, "folder": folder}
    )


@mcp.tool()
def get_repository_file(repo: str, path: str) -> str:
    """
    Get metadata for a specific file in a Ghidra shared server repository.

    Requires an active server connection (use connect_server first).

    Args:
        repo: Repository name (e.g., "MyProject")
        path: File path within the repository (e.g., "/Game.exe")

    Returns:
        JSON with file metadata (name, version, size, checkout status, etc.)
    """
    return safe_get_json(
        "server/repository/file", {"repo": repo, "path": path}
    )


# ========== UDS INSTANCE MANAGEMENT ==========


@mcp.tool()
def list_instances() -> str:
    """
    List all running Ghidra instances discovered via Unix domain sockets.

    Returns JSON with each instance's project name, PID, open programs, and socket path.
    Also shows which instance is currently connected.
    Useful for multi-instance setups where multiple Ghidra processes are running.
    """
    instances = discover_instances()
    if not instances:
        return json.dumps({"instances": [], "note": "No UDS instances found. Falling back to TCP."})
    active = get_active_socket()
    for inst in instances:
        inst["connected"] = (inst["socket"] == active)
    return json.dumps({"instances": instances}, indent=2)


@mcp.tool()
def connect_instance(project: str) -> str:
    """
    Switch the MCP bridge to a different Ghidra instance by project name.

    Use list_instances() first to see available instances and their project names.
    After connecting, all subsequent MCP tool calls will be routed to the selected instance.

    Args:
        project: Project name (or substring) to connect to (e.g., "test-project")

    Returns:
        JSON with connection result
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
    # Invalidate request cache since we switched instances
    if hasattr(safe_get, "cache"):
        safe_get.cache.clear()
    return json.dumps({
        "connected": True,
        "project": match.get("project"),
        "socket": match["socket"],
        "pid": match.get("pid"),
    })


# ========== CONVENIENCE ALIASES ==========


@mcp.tool()
def get_decompiled_code(
    function_address: str, refresh_cache: bool = False, timeout: int = None
) -> str:
    """
    Get the decompiled C code for a function at the specified address.

    **DEPRECATED**: Use decompile_function(address=...) instead. This tool is maintained
    for backward compatibility but decompile_function() is the preferred unified tool.

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x401000")
        refresh_cache: If True, forces fresh decompilation (default: False)
        timeout: Optional timeout in seconds for this operation

    Returns:
        str: Decompiled C pseudocode as a string

    Note:
        This is a convenience wrapper around decompile_function().
        Prefer using: decompile_function(address="0x401000", force=True)
    """
    return decompile_function(
        address=function_address, force=refresh_cache, timeout=timeout
    )


@mcp.tool()
def get_disassembly(
    function_address: str,
    as_text: bool = False,
    filter_mnemonics: str = None,
    timeout: int = None,
) -> list[str] | str:
    """
    Get the disassembled assembly code for a function at the specified address.

    This is a simplified tool specifically designed for retrieving disassembly.
    Use this when you need the assembly instructions of a function for low-level analysis.

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x401000", "0x6fb6aef0")
                         Accepts addresses with or without 0x prefix
        as_text: If True, returns assembly as a single string with newlines; if False, returns list (default: False)
        filter_mnemonics: Optional comma-separated instruction mnemonics to filter by
                         (e.g., "CALL,JMP" shows only calls and jumps, "MOV" shows only moves)
                         Case-insensitive
        timeout: Optional timeout in seconds for this operation (overrides default)

    Returns:
        list[str] | str: List of assembly instructions (default) or single string with newlines if as_text=True
                        Each line contains: address, instruction, and optional comment

    Raises:
        GhidraValidationError: If address format is invalid or no function found

    Note:
        This returns the same information as disassemble_function() but with a simpler name.
        Use as_text=True for easier reading/display, or as_text=False (default) for programmatic parsing.
    """
    # Sanitize and validate address
    function_address = sanitize_address(function_address)
    if not validate_hex_address(function_address):
        raise GhidraValidationError(
            f"Invalid hexadecimal address format: {function_address}. "
            f"Expected format: 0x followed by hex digits (e.g., '0x401000'). "
            f"Use get_function_by_address() to verify the address."
        )

    # Verify function exists at this address
    func_check = safe_get("get_function_by_address", {"address": function_address})
    if not func_check or any(
        "Error" in str(line) or "not found" in str(line).lower() for line in func_check
    ):
        raise GhidraValidationError(
            f"No function found at address {function_address}. "
            f"Verify the address using get_function_by_address() or "
            f"use disassemble_bytes() to disassemble arbitrary memory regions."
        )

    # Apply custom timeout if specified
    if timeout:
        original_timeout = ENDPOINT_TIMEOUTS.get("disassemble_function", 30)
        ENDPOINT_TIMEOUTS["disassemble_function"] = timeout

    try:
        result = safe_get("disassemble_function", {"address": function_address})

        # Check for errors
        if not result or (len(result) == 1 and "Error" in result[0]):
            error_msg = result[0] if result else "Unknown error"
            raise GhidraValidationError(
                f"Failed to disassemble function at {function_address}: {error_msg}. "
                f"Try using get_function_by_address() to verify the function exists."
            )

        # Apply mnemonic filter if specified
        if filter_mnemonics:
            mnemonics = [m.strip().upper() for m in filter_mnemonics.split(",")]
            # Filter lines that contain any of the specified mnemonics
            result = [
                line
                for line in result
                if any(mnem in line.upper() for mnem in mnemonics)
            ]

            if not result:
                logger.warning(
                    f"No instructions matching '{filter_mnemonics}' found in function at {function_address}"
                )

        if as_text:
            return "\n".join(result)
        return result
    finally:
        # Restore original timeout
        if timeout:
            ENDPOINT_TIMEOUTS["disassemble_function"] = original_timeout


@mcp.tool()
def get_function_jump_target_addresses(
    name: str, offset: int = 0, limit: int = 100
) -> list:
    """
    Get all jump target addresses from a function's disassembly.

    This tool analyzes the disassembly of a specified function and extracts all addresses
    that are targets of conditional and unconditional jump instructions (JMP, JE, JNE, JZ, etc.).

    Args:
        name: Function name to analyze for jump targets
        offset: Pagination offset (default: 0)
        limit: Maximum number of jump targets to return (default: 100)

    Returns:
        List of jump target addresses found in the function's disassembly
    """
    return safe_get(
        "get_function_jump_targets", {"name": name, "offset": offset, "limit": limit}
    )


@mcp.tool()
def search_functions_by_name(
    query: str, offset: int = 0, limit: int = 100, program: str = None
) -> list:
    """
    Search for functions whose name contains the given substring.

    Args:
        query: Search string to match against function names
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of results to return (default: 100)
        program: Optional program name to query (e.g., "D2Client.dll").
                 If not specified, uses the currently active program.

    Returns:
        List of matching functions with their names and addresses
    """
    if not query:
        raise GhidraValidationError("query string is required")
    params = {"query": query, "offset": offset, "limit": limit}
    if program:
        params["program"] = program
    return safe_get("search_functions", params)


# ========== MAIN ==========


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument(
        "--ghidra-server",
        type=str,
        default=DEFAULT_GHIDRA_SERVER,
        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}",
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        help="Port to run MCP server on (only used for sse), default: 8089",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse"],
        help="Transport protocol for MCP, default: stdio",
    )
    parser.add_argument(
        "--profile",
        type=str,
        choices=list(TOOL_PROFILES.keys()),
        help="Load only tools for a specific workflow (e.g., 're' for reverse engineering)",
    )
    args = parser.parse_args()

    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server

    if args.profile:
        apply_tool_profile(mcp, args.profile)

    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8089

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(
                f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse"
            )
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()

# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
#     "psycopg2-binary>=2.9,<3",
# ]
# ///

import base64
import requests
import argparse
import logging
import time
import re
import json
import inspect
import threading
from urllib.parse import urljoin, urlparse
from typing import Optional, Any

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
    "upload_file": 120,  # 2 minutes - binary transfer to headless server
    "default": 30,  # 30 seconds for all other operations
}
MAX_RETRIES = 3
RETRY_BACKOFF_FACTOR = 0.5
CACHE_SIZE = 256
ENABLE_CACHING = True

# Tool profiles for reducing schema overhead in specialized workflows
TOOL_PROFILES = {
    "re": {
        "check_connection",
        "get_current_program_info",
        "get_metadata",
        "save_program",
        "exit_ghidra",
        "list_open_programs",
        "switch_program",
        "open_program",
        "search_functions_enhanced",
        "find_next_undefined_function",
        "decompile_function",
        "analyze_function_complete",
        "analyze_for_documentation",
        "get_function_variables",
        "get_function_callees",
        "get_function_callers",
        "batch_apply_documentation",
        "analyze_function_completeness",
        "batch_analyze_completeness",
        "batch_set_variable_types",
        "set_bookmark",
        "get_function_xrefs",
        "get_function_hash",
        "propagate_documentation",
        "build_function_hash_index",
        "run_ghidra_script",
        "run_script_inline",
        "rename_function_by_address",
        "set_function_prototype",
        "rename_variables",
        "batch_set_comments",
        "set_plate_comment",
        "set_local_variable_type",
        "rename_or_label",
        # Knowledge DB tools
        "store_function_knowledge",
        "query_knowledge_context",
        "store_ordinal_mapping",
        "get_ordinal_mapping",
        "export_system_knowledge",
    },
}


def apply_tool_profile(mcp_instance, profile_name):
    """Remove tools not in the specified profile from the MCP server."""
    if profile_name not in TOOL_PROFILES:
        raise ValueError(
            f"Unknown profile '{profile_name}'. Available: {list(TOOL_PROFILES.keys())}"
        )
    allowed = TOOL_PROFILES[profile_name]
    tool_mgr = getattr(mcp_instance, "_tool_manager", None)
    if tool_mgr is None:
        logger.warning("Could not access tool manager for profile filtering")
        return
    tools_dict = getattr(tool_mgr, "_tools", None)
    if tools_dict is None:
        logger.warning("Could not access tools dict for profile filtering")
        return
    all_tools = list(tools_dict.keys())
    removed = 0
    for name in all_tools:
        if name not in allowed:
            del tools_dict[name]
            removed += 1
    logger.info(
        f"Profile '{profile_name}': kept {len(allowed)} tools, removed {removed}"
    )


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

# Load .env file if present (for KNOWLEDGE_DB_*, GHIDRA_SERVER_URL, etc.)
import os
from pathlib import Path

_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for line in _env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.split("#")[0].strip()  # strip inline comments
            if key and key not in os.environ:  # env vars take precedence
                os.environ[key] = value

# Configure enhanced logging
LOG_LEVEL = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url: env var > .env file > default
ghidra_server_url = os.getenv("GHIDRA_SERVER_URL", DEFAULT_GHIDRA_SERVER)


# ========== KNOWLEDGE DB (PostgreSQL at RE-Universe) ==========

# Optional psycopg2 for knowledge database connectivity
try:
    import psycopg2
    import psycopg2.pool
    import psycopg2.extras

    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False
    logger.warning("psycopg2 not installed - knowledge DB tools disabled")

# Knowledge DB configuration (configure via environment variables)
KNOWLEDGE_DB_HOST = os.getenv("KNOWLEDGE_DB_HOST", "localhost")
KNOWLEDGE_DB_PORT = int(os.getenv("KNOWLEDGE_DB_PORT", "5432"))
KNOWLEDGE_DB_NAME = os.getenv("KNOWLEDGE_DB_NAME", "bsim")
KNOWLEDGE_DB_USER = os.getenv("KNOWLEDGE_DB_USER", "")
KNOWLEDGE_DB_PASSWORD = os.getenv("KNOWLEDGE_DB_PASSWORD", "")
KNOWLEDGE_DB_TIMEOUT = float(os.getenv("KNOWLEDGE_DB_TIMEOUT", "2.0"))  # seconds
KNOWLEDGE_DB_READ_TIMEOUT = float(
    os.getenv("KNOWLEDGE_DB_READ_TIMEOUT", "0.5")
)  # seconds


class KnowledgeDB:
    """Connection pool + circuit breaker for the knowledge PostgreSQL database."""

    def __init__(self):
        self._pool = None
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._circuit_open = False
        self._max_failures = 3

    def _get_pool(self):
        if self._pool is not None:
            return self._pool
        with self._lock:
            if self._pool is not None:
                return self._pool
            if not HAS_PSYCOPG2:
                return None
            try:
                self._pool = psycopg2.pool.ThreadedConnectionPool(
                    minconn=1,
                    maxconn=5,
                    host=KNOWLEDGE_DB_HOST,
                    port=KNOWLEDGE_DB_PORT,
                    dbname=KNOWLEDGE_DB_NAME,
                    user=KNOWLEDGE_DB_USER,
                    password=KNOWLEDGE_DB_PASSWORD or None,
                    connect_timeout=int(KNOWLEDGE_DB_TIMEOUT),
                    options=f"-c statement_timeout={int(KNOWLEDGE_DB_READ_TIMEOUT * 1000)}",
                )
                logger.info(
                    f"Knowledge DB pool created: {KNOWLEDGE_DB_HOST}:{KNOWLEDGE_DB_PORT}/{KNOWLEDGE_DB_NAME}"
                )
                self._consecutive_failures = 0
                self._circuit_open = False
                return self._pool
            except Exception as e:
                logger.warning(f"Knowledge DB connection failed: {e}")
                return None

    def _record_failure(self):
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._max_failures:
            self._circuit_open = True
            logger.warning(
                "Knowledge DB circuit breaker OPEN - disabling for this session"
            )

    def _record_success(self):
        self._consecutive_failures = 0

    def execute_read(self, query, params=None):
        """Execute a read query. Returns rows as list of dicts, or None on failure."""
        if self._circuit_open or not HAS_PSYCOPG2:
            return None
        pool = self._get_pool()
        if not pool:
            return None
        conn = None
        try:
            conn = pool.getconn()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
            conn.rollback()  # read-only, release any locks
            self._record_success()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"Knowledge DB read failed: {e}")
            self._record_failure()
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            return None
        finally:
            if conn and pool:
                try:
                    pool.putconn(conn)
                except Exception:
                    pass

    def execute_write(self, query, params=None):
        """Execute a write query. Returns True on success, False on failure. Fire-and-forget."""
        if self._circuit_open or not HAS_PSYCOPG2:
            return False
        pool = self._get_pool()
        if not pool:
            return False
        conn = None
        try:
            conn = pool.getconn()
            with conn.cursor() as cur:
                cur.execute(query, params)
            conn.commit()
            self._record_success()
            return True
        except Exception as e:
            logger.warning(f"Knowledge DB write failed: {e}")
            self._record_failure()
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            return False
        finally:
            if conn and pool:
                try:
                    pool.putconn(conn)
                except Exception:
                    pass

    @property
    def available(self):
        return HAS_PSYCOPG2 and not self._circuit_open


# Global knowledge DB instance (lazy connection)
knowledge_db = KnowledgeDB()


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
FUNCTION_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def validate_server_url(url: str) -> bool:
    """Validate that the server URL is safe to use"""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False
        if parsed.hostname in ["localhost", "127.0.0.1", "::1"]:
            return True
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
    endpoint_name = endpoint.strip("/").split("/")[-1]
    return ENDPOINT_TIMEOUTS.get(endpoint_name, ENDPOINT_TIMEOUTS["default"])


def calculate_dynamic_timeout(endpoint: str, payload: dict = None) -> int:
    """
    Calculate timeout dynamically based on operation complexity.
    For batch operations, scales timeout based on the number of items being processed.
    """
    endpoint_name = endpoint.strip("/").split("/")[-1]
    base_timeout = ENDPOINT_TIMEOUTS.get(endpoint_name, ENDPOINT_TIMEOUTS["default"])

    if not payload:
        return base_timeout

    if endpoint_name == "batch_rename_variables":
        variable_count = len(payload.get("variable_renames", {}))
        per_variable_time = 25
        safety_multiplier = 1.5
        calculated_timeout = int(
            base_timeout + (variable_count * per_variable_time * safety_multiplier)
        )
        return min(calculated_timeout, 600)

    if endpoint_name == "batch_set_comments":
        comment_count = 0
        comment_count += len(payload.get("decompiler_comments", []))
        comment_count += len(payload.get("disassembly_comments", []))
        comment_count += 1 if payload.get("plate_comment") else 0
        calculated_timeout = int(base_timeout + (comment_count * 5 * 1.5))
        return min(calculated_timeout, 600)

    if endpoint_name == "batch_create_labels":
        label_count = len(payload.get("labels", []))
        calculated_timeout = int(base_timeout + (label_count * 2 * 1.5))
        return min(calculated_timeout, 600)

    return base_timeout


def validate_hex_address(address: str) -> bool:
    """Validate hexadecimal address format (0x-prefixed or segment:offset)"""
    if not address or not isinstance(address, str):
        return False
    return bool(
        HEX_ADDRESS_PATTERN.match(address) or SEGMENT_ADDRESS_PATTERN.match(address)
    )


def sanitize_address(address: str) -> str:
    """Normalize address format (handle with/without 0x prefix, case normalization)."""
    if not address:
        return address
    address = address.strip()
    if SEGMENT_ADDRESS_PATTERN.match(address):
        return address
    if not address.startswith(("0x", "0X")):
        address = "0x" + address
    return address.lower()


def validate_function_name(name: str) -> bool:
    """Validate function name format"""
    return bool(FUNCTION_NAME_PATTERN.match(name)) if name else False


def normalize_address(address: str) -> str:
    """Normalize address to standard format (0x prefix, no leading zeros)."""
    if not address:
        return address
    address = address.strip()
    if SEGMENT_ADDRESS_PATTERN.match(address):
        return address
    address = address.lower()
    if address.startswith(("0x", "0X")):
        address = address[2:]
    address = address.lstrip("0") or "0"
    return "0x" + address


def format_success_response(operation: str, result: dict = None, **kwargs) -> str:
    response = {"success": True, "operation": operation}
    if result is not None:
        response["result"] = result
    response.update(kwargs)
    return json.dumps(response)


def format_error_response(
    operation: str, error: str, error_code: str = None, **kwargs
) -> str:
    response = {"success": False, "operation": operation, "error": error}
    if error_code:
        response["error_code"] = error_code
    response.update(kwargs)
    return json.dumps(response)


def calculate_function_hash(bytecode: bytes) -> str:
    import hashlib
    return hashlib.sha256(bytecode).hexdigest()


def validate_hungarian_notation(name: str, type_str: str) -> bool:
    if not name or not type_str:
        return False
    type_lower = type_str.lower()
    name_lower = name.lower()
    if "*" in type_str or "ptr" in type_lower:
        if type_str.count("*") >= 2 or "**" in type_str:
            return name_lower.startswith("pp")
        return name_lower.startswith("p")
    if "handle" in type_lower or type_str.startswith("H"):
        return name_lower.startswith("h")
    if type_lower in ("dword", "uint", "ulong", "unsigned int", "unsigned long"):
        return name_lower.startswith("dw") or name_lower.startswith("n")
    if type_lower in ("word", "ushort", "unsigned short"):
        return name_lower.startswith("w")
    if type_lower in ("byte", "uchar", "unsigned char"):
        return name_lower.startswith("b")
    if type_lower in ("bool", "boolean"):
        return name_lower.startswith("b") or name_lower.startswith("is")
    return True


def validate_batch_renames(renames: dict) -> bool:
    if not renames or not isinstance(renames, dict):
        return False
    for old_name, new_name in renames.items():
        if not isinstance(old_name, str) or not isinstance(new_name, str):
            return False
        if not old_name or not new_name:
            return False
    return True


def validate_batch_comments(comments: list) -> bool:
    if not comments or not isinstance(comments, list):
        return False
    for item in comments:
        if not isinstance(item, dict):
            return False
        if "address" not in item or "comment" not in item:
            return False
    return True


def validate_program_path(path: str) -> bool:
    if not path or not isinstance(path, str):
        return False
    if ".." in path:
        return False
    return True


def _convert_escaped_newlines(text: str) -> str:
    """Convert escaped newlines (\\n) to actual newlines"""
    if not text:
        return text
    return text.replace("\\n", "\n")


def parse_address_list(addresses: str, param_name: str = "addresses") -> list[str]:
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
    for addr in addr_list:
        if not validate_hex_address(addr):
            raise GhidraValidationError(f"Invalid hex address format: {addr}")
    return addr_list


# Performance and caching utilities
from typing import Callable, TypeVar

T = TypeVar("T")


def cache_key(*args: Any, **kwargs: Any) -> str:
    import hashlib
    key_data = {"args": args, "kwargs": kwargs}
    return hashlib.md5(
        json.dumps(key_data, sort_keys=True, default=str).encode()
    ).hexdigest()


def cached_request(
    cache_duration: int = 300,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        cache: dict[str, tuple[T, float]] = {}

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            if not ENABLE_CACHING:
                return func(*args, **kwargs)
            key = cache_key(*args, **kwargs)
            now = time.time()
            if key in cache:
                result, timestamp = cache[key]
                if now - timestamp < cache_duration:
                    return result
                else:
                    del cache[key]
            result = func(*args, **kwargs)
            cache[key] = (result, now)
            if len(cache) > CACHE_SIZE:
                oldest_key = min(cache.keys(), key=lambda k: cache[k][1])
                del cache[oldest_key]
            return result

        return wrapper

    return decorator


def safe_get_uncached(endpoint: str, params: dict = None, retries: int = 3) -> list:
    if params is None:
        params = {}
    if not validate_server_url(ghidra_server_url):
        return ["Error: Invalid server URL - only local addresses allowed"]
    url = urljoin(ghidra_server_url, endpoint)
    timeout = get_timeout_for_endpoint(endpoint)
    for attempt in range(retries):
        try:
            response = session.get(url, params=params, timeout=timeout)
            response.encoding = "utf-8"
            if response.ok:
                return response.text.splitlines()
            elif response.status_code == 404:
                return [f"Endpoint not found: {endpoint}"]
            elif response.status_code >= 500:
                if attempt < retries - 1:
                    time.sleep(2**attempt)
                    continue
                else:
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


@cached_request(cache_duration=180)
def safe_get(
    endpoint: str, params: dict = None, retries: int = 3, program: str = None
) -> list:
    if params is None:
        params = {}
    if program:
        params["program"] = program
    if not validate_server_url(ghidra_server_url):
        return ["Error: Invalid server URL - only local addresses allowed"]
    url = urljoin(ghidra_server_url, endpoint)
    timeout = get_timeout_for_endpoint(endpoint)
    for attempt in range(retries):
        try:
            response = session.get(url, params=params, timeout=timeout)
            response.encoding = "utf-8"
            if response.ok:
                return response.text.splitlines()
            elif response.status_code == 404:
                return [f"Endpoint not found: {endpoint}"]
            elif response.status_code >= 500:
                if attempt < retries - 1:
                    time.sleep(2**attempt)
                    continue
                else:
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
    return ["Unexpected error in safe_get"]


def safe_get_json(
    endpoint: str, params: dict = None, retries: int = 3, program: str = None
) -> str:
    if params is None:
        params = {}
    if program:
        params["program"] = program
    if not validate_server_url(ghidra_server_url):
        return '{"error": "Invalid server URL - only local addresses allowed"}'
    url = urljoin(ghidra_server_url, endpoint)
    timeout = get_timeout_for_endpoint(endpoint)
    for attempt in range(retries):
        try:
            start_time = time.time()
            response = session.get(url, params=params, timeout=timeout)
            response.encoding = "utf-8"
            duration = time.time() - start_time
            logger.info(f"Request to {endpoint} took {duration:.2f}s (attempt {attempt + 1}/{retries})")
            if response.ok:
                return response.text
            elif response.status_code == 404:
                return f'{{"error": "Endpoint not found: {endpoint}"}}'
            elif response.status_code >= 500:
                if attempt < retries - 1:
                    time.sleep(2**attempt)
                    continue
                else:
                    return f'{{"error": "Server error {response.status_code} after {retries} attempts"}}'
            else:
                return f'{{"error": "HTTP {response.status_code}: {response.text.strip()}"}}'
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                continue
            return f'{{"error": "Timeout connecting to Ghidra server after {retries} attempts"}}'
        except requests.exceptions.RequestException as e:
            return f'{{"error": "Request failed: {str(e)}"}}'
        except Exception as e:
            return f'{{"error": "Unexpected error: {str(e)}"}}'
    return '{"error": "Unexpected error in safe_get_json"}'


def safe_post_json(
    endpoint: str, data: dict, retries: int = 3, program: str = None
) -> str:
    if not validate_server_url(ghidra_server_url):
        return "Error: Invalid server URL - only local addresses allowed"
    url = urljoin(ghidra_server_url, endpoint)
    if program:
        url += f"?program={program}"
    timeout = calculate_dynamic_timeout(endpoint, data)
    logger.info(f"Using dynamic timeout of {timeout}s for endpoint {endpoint} (payload items: {len(data)})")
    headers = {"Connection": "close"}
    for attempt in range(retries):
        try:
            start_time = time.time()
            logger.info(f"Sending JSON POST to {url} with data: {data}")
            response = session.post(url, json=data, headers=headers, timeout=timeout)
            response.encoding = "utf-8"
            duration = time.time() - start_time
            logger.info(f"JSON POST to {endpoint} took {duration:.2f}s (attempt {attempt + 1}/{retries}), status: {response.status_code}")
            if response.ok:
                return response.text.strip()
            elif response.status_code == 404:
                return f"Error: Endpoint {endpoint} not found"
            elif response.status_code >= 500:
                if attempt < retries - 1:
                    time.sleep(1)
                    continue
                else:
                    return f"Error: Server error {response.status_code} after {retries} attempts"
            else:
                return f"Error: HTTP {response.status_code} - {response.text}"
        except requests.RequestException as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            else:
                return f"Error: Request failed - {str(e)}"
    return "Error: Maximum retries exceeded"


def safe_post(
    endpoint: str, data: dict | str, retries: int = 3, program: str = None
) -> str:
    if not validate_server_url(ghidra_server_url):
        return "Error: Invalid server URL - only local addresses allowed"
    url = urljoin(ghidra_server_url, endpoint)
    if program:
        url += f"?program={program}"
    timeout = get_timeout_for_endpoint(endpoint)
    for attempt in range(retries):
        try:
            if isinstance(data, dict):
                response = session.post(url, json=data, timeout=timeout)
            else:
                response = session.post(url, data=data.encode("utf-8"), timeout=timeout)
            response.encoding = "utf-8"
            if response.ok:
                return response.text.strip()
            elif response.status_code == 404:
                return f"Endpoint not found: {endpoint}"
            elif response.status_code >= 500:
                if attempt < retries - 1:
                    time.sleep(2**attempt)
                    continue
                else:
                    raise GhidraConnectionError(f"Server error: {response.status_code}")
            else:
                return f"Error {response.status_code}: {response.text.strip()}"
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                continue
            return f"Timeout connecting to Ghidra server after {retries} attempts"
        except requests.exceptions.RequestException as e:
            return f"Request failed: {str(e)}"
        except GhidraConnectionError:
            raise
        except Exception as e:
            return f"Unexpected error: {str(e)}"
    return "Unexpected error in safe_post"


def make_request(
    url: str,
    method: str = "GET",
    params: dict = None,
    data: str = None,
    retries: int = 3,
    program: str = None,
) -> str:
    if params is None:
        params = {}
    if program:
        params["program"] = program
    if not validate_server_url(url):
        return '{"error": "Invalid server URL - only local addresses allowed"}'
    timeout = REQUEST_TIMEOUT
    for attempt in range(retries):
        try:
            if method.upper() == "POST":
                headers = {"Content-Type": "application/json"}
                response = session.post(url, data=data, headers=headers, timeout=timeout)
            else:
                response = session.get(url, params=params, timeout=timeout)
            response.encoding = "utf-8"
            if response.ok:
                return response.text
            elif response.status_code == 404:
                return f'{{"error": "Endpoint not found: {url}"}}'
            elif response.status_code >= 500:
                if attempt < retries - 1:
                    time.sleep(2**attempt)
                    continue
                else:
                    return f'{{"error": "Server error {response.status_code} after {retries} attempts"}}'
            else:
                return f'{{"error": "HTTP {response.status_code}: {response.text.strip()}"}}'
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                continue
            return f'{{"error": "Timeout connecting to Ghidra server after {retries} attempts"}}'
        except requests.exceptions.RequestException as e:
            return f'{{"error": "Request failed: {str(e)}"}}'
        except Exception as e:
            return f'{{"error": "Unexpected error: {str(e)}"}}'
    return '{"error": "Unexpected error in make_request"}'


# ===========================================================================
# DYNAMIC TOOL REGISTRATION FROM /mcp/schema
# ===========================================================================

# Set of tool names that are registered statically (complex bridge-only logic).
# These will NOT be overwritten by dynamic registration.
STATIC_TOOL_NAMES = {
    # Complex bridge-side logic
    "check_connection",
    "get_version",
    "decompile_function",
    "disassemble_function",
    "rename_variables",
    "rename_function_by_address",
    "set_function_prototype",
    "get_current_selection",
    "get_function_metrics",
    # Script lifecycle (local file I/O)
    "save_ghidra_script",
    "list_ghidra_scripts",
    "get_ghidra_script",
    "update_ghidra_script",
    "delete_ghidra_script",
    # Cross-binary hash/propagation (multi-call, file I/O)
    "build_function_hash_index",
    "lookup_function_by_hash",
    "propagate_documentation",
    # Knowledge DB tools (PostgreSQL)
    "store_function_knowledge",
    "query_knowledge_context",
    "store_ordinal_mapping",
    "get_ordinal_mapping",
    "export_system_knowledge",
}

# Schema type -> Python type annotation mapping
_SCHEMA_TYPE_MAP = {
    "string": str,
    "json": str,
    "integer": int,
    "boolean": bool,
    "number": float,
    "object": dict,
    "array": list,
    "any": str,
}


def _python_default(schema_type: str, default_str: str | None):
    """Convert a schema default string to a Python value."""
    if default_str is None:
        return inspect.Parameter.empty
    if schema_type == "integer":
        try:
            return int(default_str)
        except (ValueError, TypeError):
            return 0
    if schema_type == "boolean":
        return default_str.lower() == "true"
    if schema_type == "number":
        try:
            return float(default_str)
        except (ValueError, TypeError):
            return 0.0
    # string/json/object/array/any
    return default_str if default_str else None


def _make_tool_handler(tool_def: dict):
    """
    Create a handler function for a schema-defined tool with a proper signature
    so FastMCP can introspect parameter names and types.
    """
    path = tool_def["path"]
    method = tool_def["method"]
    params_schema = tool_def.get("params", [])

    # Build inspect.Parameter list for the function signature
    sig_params = []
    for p in params_schema:
        name = p["name"]
        ptype = _SCHEMA_TYPE_MAP.get(p.get("type", "string"), str)
        required = p.get("required", True)
        default_str = p.get("default")

        if required and default_str is None:
            default = inspect.Parameter.empty
            # Required params: use bare type annotation
            annotation = ptype
        else:
            default = _python_default(p.get("type", "string"), default_str)
            # Optional params: allow None
            if default is None or default is inspect.Parameter.empty:
                annotation = Optional[ptype]
                if default is inspect.Parameter.empty:
                    default = None
            else:
                annotation = ptype

        sig_params.append(
            inspect.Parameter(
                name,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=default,
                annotation=annotation,
            )
        )

    # Always add optional 'program' param if not already present
    param_names = {p["name"] for p in params_schema}
    if "program" not in param_names:
        sig_params.append(
            inspect.Parameter(
                "program",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=None,
                annotation=Optional[str],
            )
        )

    # Reorder the param names list so that params with default values are at the end of the list
    sig_params.sort(key=lambda x: x.default == inspect.Parameter.empty, reverse=True)

    sig = inspect.Signature(sig_params, return_annotation=str)

    # Separate query vs body params
    query_params = {p["name"] for p in params_schema if p.get("source") == "query"}
    body_params = {p["name"] for p in params_schema if p.get("source") == "body"}

    def handler(**kwargs):
        program = kwargs.pop("program", None)

        if method == "GET":
            # All params go as query string
            params = {k: v for k, v in kwargs.items() if v is not None}
            return safe_get_json(path.lstrip("/"), params, program=program)
        else:
            # POST: body params go in JSON body, query params in URL
            body_data = {}
            q_params = {}
            for k, v in kwargs.items():
                if v is None:
                    continue
                if k in body_params:
                    body_data[k] = v
                elif k in query_params:
                    q_params[k] = v
                else:
                    # Default: if method is POST and param source unknown, put in body
                    body_data[k] = v

            endpoint = path.lstrip("/")
            if q_params:
                # Append query params to endpoint URL
                from urllib.parse import urlencode
                endpoint += "?" + urlencode(q_params)

            return safe_post_json(endpoint, body_data, program=program)

    handler.__signature__ = sig
    return handler


def _register_schema_tools():
    """
    Fetch /mcp/schema from the Ghidra HTTP server and dynamically register
    all tools that don't have static implementations.
    """
    try:
        response = session.get(
            urljoin(ghidra_server_url, "mcp/schema"), timeout=10
        )
        if not response.ok:
            logger.warning(
                f"Could not fetch /mcp/schema (HTTP {response.status_code}). "
                f"Dynamic tools will not be available."
            )
            return 0

        schema = response.json()
        tools = schema.get("tools", [])
        registered = 0

        for tool_def in tools:
            path = tool_def.get("path", "")
            # Derive tool name from path: /list_functions -> list_functions
            tool_name = path.lstrip("/").replace("/", "_")

            # Skip tools with static implementations
            if tool_name in STATIC_TOOL_NAMES:
                logger.debug(f"Skipping static tool: {tool_name}")
                continue

            description = tool_def.get("description", f"Ghidra endpoint: {path}")
            handler = _make_tool_handler(tool_def)

            # Register with FastMCP
            mcp.tool(name=tool_name, description=description)(handler)
            registered += 1

        logger.info(f"Dynamically registered {registered} tools from /mcp/schema ({len(tools)} total in schema)")
        return registered

    except requests.exceptions.ConnectionError:
        logger.warning(
            "Could not connect to Ghidra server for schema discovery. "
            "Dynamic tools will not be available. Start Ghidra with the MCP plugin first."
        )
        return 0
    except Exception as e:
        logger.warning(f"Error during schema tool registration: {e}")
        return 0


# ===========================================================================
# STATIC TOOLS - Complex bridge-only logic that can't be auto-generated
# ===========================================================================


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

    Returns:
        JSON string with version information including plugin version,
        Ghidra version, Java version, and endpoint count.
    """
    return "\n".join(safe_get("get_version"))


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

    original_timeout = None
    if timeout:
        original_timeout = ENDPOINT_TIMEOUTS.get("decompile_function", 45)
        ENDPOINT_TIMEOUTS["decompile_function"] = timeout
        ENDPOINT_TIMEOUTS["force_decompile"] = timeout
        ENDPOINT_TIMEOUTS["force_decompile_by_name"] = timeout

    try:
        if name:
            search_params = {"query": name, "offset": 0, "limit": 10}
            if program:
                search_params["program"] = program
            search_result = safe_get("search_functions", search_params)
            func_address = None
            for line in search_result:
                if f"{name} @" in line or line.startswith(f"{name} "):
                    parts = line.split("@")
                    if len(parts) >= 2:
                        func_address = parts[-1].strip()
                        break
            if not func_address:
                return f"Error: Function '{name}' not found"
            if force:
                result = safe_post("force_decompile", {"function_address": func_address})
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
                params = {"address": address}
                if program:
                    params["program"] = program
                if timeout:
                    params["timeout"] = str(timeout)
                result = safe_get("decompile_function", params)

        if isinstance(result, list):
            result = "\n".join(result)

        # Apply pagination if offset or limit specified
        if offset > 0 or limit is not None:
            lines = result.split("\n")
            total_lines = len(lines)
            end_idx = len(lines) if limit is None else min(offset + limit, len(lines))
            paginated_lines = lines[offset:end_idx]
            has_more = end_idx < total_lines
            metadata = f"/* PAGINATION: lines {offset + 1}-{end_idx} of {total_lines}"
            if has_more:
                metadata += f" (use offset={end_idx} for next chunk)"
            metadata += " */\n\n"
            result = metadata + "\n".join(paginated_lines)

        return result
    finally:
        if original_timeout:
            ENDPOINT_TIMEOUTS["decompile_function"] = original_timeout
            ENDPOINT_TIMEOUTS["force_decompile"] = original_timeout
            ENDPOINT_TIMEOUTS["force_decompile_by_name"] = original_timeout


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

    if filter_mnemonics:
        mnemonics = [m.strip().upper() for m in filter_mnemonics.split(",")]
        result = [
            line for line in result if any(mnem in line.upper() for mnem in mnemonics)
        ]

    if offset > 0 or limit is not None:
        total_instructions = len(result)
        end_idx = len(result) if limit is None else min(offset + limit, len(result))
        paginated = result[offset:end_idx]
        has_more = end_idx < total_instructions
        metadata = f"/* PAGINATION: instructions {offset + 1}-{end_idx} of {total_instructions}"
        if has_more:
            metadata += f" (use offset={end_idx} for next chunk)"
        metadata += " */"
        return [metadata] + paginated

    return result


@mcp.tool()
def rename_variables(
    function_address: str,
    variable_renames: dict,
    backend: str = "auto",
    program: str = None,
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
    validate_hex_address(function_address)

    if not variable_renames:
        return json.dumps({
            "success": True, "variables_renamed": 0, "variables_failed": 0,
            "backend_used": "none", "message": "No variables to rename",
        })

    num_variables = len(variable_renames)

    if backend == "auto":
        actual_backend = "batch" if num_variables <= 10 else "progressive"
    elif backend in ["batch", "progressive"]:
        actual_backend = backend
    else:
        raise GhidraValidationError(f"Invalid backend: {backend}. Must be 'auto', 'batch', or 'progressive'")

    if actual_backend == "batch":
        try:
            payload = {"function_address": function_address, "variable_renames": variable_renames}
            result_json = safe_post_json("batch_rename_variables", payload, program=program)
            result = json.loads(result_json)
            result["backend_used"] = "batch"
            return json.dumps(result)
        except Exception as e:
            error_msg = str(e)
            if ("timeout" in error_msg.lower() or "connection" in error_msg.lower()) and backend == "auto":
                return _rename_variables_progressive_internal(function_address, variable_renames, program=program)
            return json.dumps({
                "success": False, "variables_renamed": 0, "variables_failed": num_variables,
                "backend_used": "batch", "errors": [{"error": error_msg}],
            })
    else:
        return _rename_variables_progressive_internal(function_address, variable_renames, program=program)


def _rename_variables_progressive_internal(
    function_address: str, variable_renames: dict, chunk_size: int = 5,
    retry_attempts: int = 3, program: str = None,
) -> str:
    variables_list = list(variable_renames.items())
    total_variables = len(variables_list)
    results = {
        "success": True, "total_variables": total_variables,
        "variables_renamed": 0, "variables_failed": 0,
        "backend_used": "progressive", "chunks_processed": 0,
        "chunks_failed": 0, "chunk_size": chunk_size,
        "failed_variables": [], "errors": [],
    }
    for i in range(0, total_variables, chunk_size):
        chunk = dict(variables_list[i : i + chunk_size])
        chunk_success = False
        last_error = None
        for attempt in range(retry_attempts):
            try:
                payload = {"function_address": function_address, "variable_renames": chunk}
                result_json = safe_post_json("batch_rename_variables", payload, program=program)
                result = json.loads(result_json)
                if result.get("success"):
                    results["variables_renamed"] += result.get("variables_renamed", len(chunk))
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
                    time.sleep(2**attempt)
        if not chunk_success:
            results["chunks_failed"] += 1
            results["success"] = False
            for old_name in chunk.keys():
                results["failed_variables"].append(old_name)
                results["errors"].append({
                    "old_name": old_name,
                    "error": f"Chunk timeout after {retry_attempts} attempts: {last_error}",
                })
            results["variables_failed"] += len(chunk)
    return json.dumps(results)


@mcp.tool()
def rename_function_by_address(
    function_address: str, new_name: str, program: str = None
) -> str:
    """
    Rename a function by its address.

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
        new_name: New name for the function (must be valid C identifier)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        Success or failure message indicating the result of the rename operation
    """
    function_address = sanitize_address(function_address)
    if not validate_hex_address(function_address):
        raise GhidraValidationError(
            f"Invalid address format: {function_address}. "
            f"Expected: hex (e.g., '0x401000') or segment:offset (e.g., 'mem:20de')."
        )
    if not new_name or not new_name.strip():
        raise GhidraValidationError("Function name cannot be empty.")
    new_name = new_name.strip()
    if not new_name[0].isalpha() and new_name[0] != "_":
        raise GhidraValidationError(f"Invalid function name '{new_name}'. Names must start with a letter or underscore.")
    if not all(c.isalnum() or c == "_" for c in new_name):
        raise GhidraValidationError(f"Invalid function name '{new_name}'. Names can only contain letters, numbers, and underscores.")

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
    function_address = sanitize_address(function_address)
    if not validate_hex_address(function_address):
        raise GhidraValidationError(f"Invalid address format: {function_address}.")
    if not prototype or not prototype.strip():
        raise GhidraValidationError("Function prototype cannot be empty.")

    # Verify function exists
    func_check = safe_get("get_function_by_address", {"address": function_address}, program=program)
    if not func_check or any(
        "Error" in str(line) or "not found" in str(line).lower() for line in func_check
    ):
        raise GhidraValidationError(f"No function found at address {function_address}.")

    original_timeout = None
    if timeout:
        original_timeout = ENDPOINT_TIMEOUTS.get("set_function_prototype", 45)
        ENDPOINT_TIMEOUTS["set_function_prototype"] = timeout

    try:
        data = {"function_address": function_address, "prototype": prototype.strip()}
        if calling_convention:
            data["calling_convention"] = calling_convention.strip()
        result = safe_post_json("set_function_prototype", data, program=program)

        if "success" in result.lower():
            msg = result.rstrip()
            msg += f"\nUse: get_decompiled_code('{function_address}', refresh_cache=True) to see changes"
            return msg
        elif "invalid calling convention" in result.lower():
            return f"{result}\nUse list_calling_conventions() to see available conventions."
        elif "server error 500" in result.lower():
            return (
                f"{result}\nCommon causes:\n"
                f"  1. Using 'uint' instead of 'dword' (use Ghidra types)\n"
                f"  2. Specifying calling convention twice\n"
                f"  3. Invalid type names (check with validate_data_type_exists())"
            )
        elif "error" in result.lower() or "failed" in result.lower():
            return f"{result}\nVerify prototype syntax is valid C."
        return result
    finally:
        if timeout and original_timeout is not None:
            ENDPOINT_TIMEOUTS["set_function_prototype"] = original_timeout


@mcp.tool()
def get_current_selection() -> dict:
    """
    Get the current selection context - both address and function information.

    Returns:
        Dictionary containing address and function info from Ghidra's CodeBrowser.
    """
    result = {
        "address": "\n".join(safe_get_uncached("get_current_address")),
        "function": "\n".join(safe_get_uncached("get_current_function")),
    }
    return result


@mcp.tool()
def get_function_metrics(
    function_name: str = None, address: str = None, program: str = None
) -> str:
    """
    Get complexity metrics for a function.

    Args:
        function_name: Name of function to analyze
        address: Or address of function (alternative to name)
        program: Optional program name (e.g., "D2Client.dll"). Defaults to active program.

    Returns:
        JSON with metrics: instruction_count, basic_block_count, cyclomatic_complexity, call_count, etc.
    """
    if not function_name and not address:
        raise GhidraValidationError("Either function_name or address is required")
    url = f"{ghidra_server_url}/find_similar_functions"
    params = {"limit": 1}
    if function_name:
        params["target_function"] = function_name
    elif address:
        params["target_function"] = address
    if program:
        params["program"] = program
    return make_request(url, method="GET", params=params)


# ========== SCRIPT LIFECYCLE MANAGEMENT ==========

@mcp.tool()
def save_ghidra_script(
    script_name: str, script_content: str, overwrite: bool = False, backup: bool = True
) -> str:
    """
    Save a Ghidra script to disk in the ghidra_scripts/ directory.

    Args:
        script_name: Name for script without .java extension (alphanumeric + underscore only)
        script_content: Full Java script content to save
        overwrite: Whether to overwrite if exists (default: False)
        backup: Create backup if overwriting (default: True)

    Returns:
        JSON with save status, script_path, file_size.
    """
    if not script_name or not isinstance(script_name, str):
        raise GhidraValidationError("script_name is required and must be a string")
    if not script_content or not isinstance(script_content, str):
        raise GhidraValidationError("script_content is required and must be a string")
    if not all(c.isalnum() or c == "_" for c in script_name):
        raise GhidraValidationError("script_name must be alphanumeric or underscore only")

    script_dir = os.path.join(os.path.expanduser("~"), "ghidra_scripts")
    script_file = f"{script_name}.java"
    script_path = os.path.join(script_dir, script_file)

    try:
        os.makedirs(script_dir, exist_ok=True)
    except Exception as e:
        raise GhidraValidationError(f"Could not create ghidra_scripts directory: {e}")

    if os.path.exists(script_path) and not overwrite:
        raise GhidraValidationError(f"Script {script_name} already exists. Use overwrite=True to replace.")

    backup_path = None
    if os.path.exists(script_path) and backup:
        backup_path = f"{script_path}.backup"
        try:
            import shutil
            shutil.copy2(script_path, backup_path)
        except Exception as e:
            logger.warning(f"Could not create backup: {e}")
            backup_path = None

    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        file_size = os.path.getsize(script_path)
    except Exception as e:
        raise GhidraValidationError(f"Could not write script file: {e}")

    response = {
        "success": True, "script_name": script_name, "script_path": script_path,
        "file_size": file_size, "message": "Script saved successfully",
    }
    if backup_path:
        response["backup_path"] = backup_path
    return json.dumps(response)


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
        JSON with total_scripts and scripts array.
    """
    from datetime import datetime

    script_dir = os.path.join(os.path.expanduser("~"), "ghidra_scripts")
    scripts = []

    if not os.path.exists(script_dir):
        os.makedirs(script_dir, exist_ok=True)

    try:
        for filename in sorted(os.listdir(script_dir)):
            if not filename.endswith(".java"):
                continue
            filepath = os.path.join(script_dir, filename)
            script_name = filename[:-5]
            if filter_pattern:
                if not re.search(filter_pattern, script_name):
                    continue
            script_info = {"name": script_name, "filename": filename, "path": filepath}
            if include_metadata:
                try:
                    stat_info = os.stat(filepath)
                    script_info["size"] = stat_info.st_size
                    modified = datetime.fromtimestamp(stat_info.st_mtime)
                    script_info["modified"] = modified.isoformat() + "Z"
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        script_info["lines_of_code"] = len(f.readlines())
                except Exception as e:
                    logger.warning(f"Could not get metadata for {filename}: {e}")
            scripts.append(script_info)
    except Exception as e:
        raise GhidraValidationError(f"Could not list scripts: {e}")

    return json.dumps({"total_scripts": len(scripts), "scripts": scripts})


@mcp.tool()
def get_ghidra_script(script_name: str) -> str:
    """
    Get full content of a Ghidra script.

    Args:
        script_name: Name of script to retrieve (without .java extension)

    Returns:
        Full script content as string
    """
    if not script_name or not isinstance(script_name, str):
        raise GhidraValidationError("script_name is required")
    script_dir = os.path.join(os.path.expanduser("~"), "ghidra_scripts")
    script_path = os.path.join(script_dir, f"{script_name}.java")
    if not os.path.exists(script_path):
        raise GhidraValidationError(f"Script not found: {script_name}")
    try:
        with open(script_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        raise GhidraValidationError(f"Could not read script: {e}")


@mcp.tool()
def update_ghidra_script(
    script_name: str, new_content: str, keep_backup: bool = True
) -> str:
    """
    Update an existing Ghidra script with new content.

    Args:
        script_name: Script to update
        new_content: New script content
        keep_backup: Save previous version as backup (default: True)

    Returns:
        JSON with update status, lines_changed, size_delta.
    """
    if not script_name or not isinstance(script_name, str):
        raise GhidraValidationError("script_name is required")
    if not new_content or not isinstance(new_content, str):
        raise GhidraValidationError("new_content is required")

    script_dir = os.path.join(os.path.expanduser("~"), "ghidra_scripts")
    script_path = os.path.join(script_dir, f"{script_name}.java")
    if not os.path.exists(script_path):
        raise GhidraValidationError(f"Script not found: {script_name}")

    try:
        with open(script_path, "r", encoding="utf-8") as f:
            old_content = f.read()
        old_size = len(old_content)
    except Exception as e:
        raise GhidraValidationError(f"Could not read existing script: {e}")

    backup_path = None
    if keep_backup:
        backup_path = f"{script_path}.backup"
        try:
            import shutil
            shutil.copy2(script_path, backup_path)
        except Exception as e:
            logger.warning(f"Could not create backup: {e}")

    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        new_size = len(new_content)
    except Exception as e:
        raise GhidraValidationError(f"Could not update script: {e}")

    lines_changed = sum(1 for a, b in zip(old_content.split("\n"), new_content.split("\n")) if a != b)
    response = {
        "success": True, "script_name": script_name, "lines_changed": lines_changed,
        "size_delta": new_size - old_size, "message": "Script updated successfully",
    }
    if backup_path:
        response["previous_version_backup"] = backup_path
    return json.dumps(response)


@mcp.tool()
def delete_ghidra_script(
    script_name: str, confirm: bool = False, archive: bool = True
) -> str:
    """
    Delete a Ghidra script safely with automatic backup.

    Args:
        script_name: Script to delete
        confirm: Must be True to actually delete (prevents accidents)
        archive: Create archive/backup before deletion (default: True)

    Returns:
        JSON with deletion status and archive location.
    """
    if not script_name or not isinstance(script_name, str):
        raise GhidraValidationError("script_name is required")
    if not confirm:
        raise GhidraValidationError("confirm=True required for safety (prevents accidents)")

    script_dir = os.path.join(os.path.expanduser("~"), "ghidra_scripts")
    script_path = os.path.join(script_dir, f"{script_name}.java")
    if not os.path.exists(script_path):
        raise GhidraValidationError(f"Script not found: {script_name}")

    archive_path = None
    if archive:
        try:
            archive_dir = os.path.join(script_dir, ".archive")
            os.makedirs(archive_dir, exist_ok=True)
            archive_path = os.path.join(archive_dir, f"{script_name}.java")
            import shutil
            shutil.copy2(script_path, archive_path)
        except Exception as e:
            logger.warning(f"Could not archive script: {e}")

    try:
        os.remove(script_path)
    except Exception as e:
        raise GhidraValidationError(f"Could not delete script: {e}")

    response = {
        "success": True, "script_name": script_name, "deleted": True,
        "message": "Script deleted successfully",
    }
    if archive_path:
        response["archive_location"] = archive_path
    return json.dumps(response)


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

    result = make_request(url, method="GET", params=params)

    if isinstance(result, str) and (
        "requires GUI mode" in result
        or "PluginTool not available" in result
        or "ProgramManager service not available" in result
    ):
        load_result = safe_post_json("load_program_from_project", {"path": path})

        if not auto_analyze:
            return load_result

        try:
            parsed = json.loads(load_result)
        except (TypeError, ValueError):
            return load_result

        if parsed.get("error") or not parsed.get("program"):
            return load_result

        parsed["analysis"] = json.loads(run_analysis(program=parsed["program"]))
        return json.dumps(parsed, indent=2)

    return result


@mcp.tool()
def load_program(file_path: str) -> str:
    """
    Load a program from a filesystem path visible to the Ghidra server.

    This is the headless-mode companion to open_program(). Use it when the
    binary already exists on the server filesystem, such as `/data/program.exe`
    in Docker deployments.

    Args:
        file_path: Absolute path to the binary on the Ghidra server host.

    Returns:
        JSON with load status and program name.
    """
    if not file_path:
        raise GhidraValidationError("File path is required")

    return safe_post_json("load_program", {"file": file_path})


@mcp.tool()
def close_program(name: str = None) -> str:
    """
    Close a loaded program.

    Args:
        name: Optional program name. If omitted, closes the current program.

    Returns:
        JSON with close status.
    """
    data = {}
    if name:
        data["name"] = name
    return safe_post_json("close_program", data)


@mcp.tool()
def load_program_from_project(path: str) -> str:
    """
    Load a program from the currently open Ghidra project.

    Args:
        path: Project path to the program (for example `/Game.exe`).

    Returns:
        JSON with load status and program name.
    """
    if not path:
        raise GhidraValidationError("Program path is required")

    return safe_post_json("load_program_from_project", {"path": path})


@mcp.tool()
def upload_binary(
    local_path: str,
    remote_filename: str = None,
    remote_dir: str = "/data/uploads",
    load: bool = True,
    analyze: bool = False,
    switch_to_program: bool = True,
) -> str:
    """
    Upload a local binary file to the Ghidra server and optionally load it.

    This is intended for headless/Docker workflows where the model only knows
    the path on its own filesystem and the server cannot directly access that
    path.

    Args:
        local_path: Local filesystem path to the binary on the MCP client host.
        remote_filename: Optional filename to use on the Ghidra server.
        remote_dir: Target directory on the Ghidra server. Defaults to `/data/uploads`.
        load: If True, load the uploaded binary after transfer.
        analyze: If True, run auto-analysis after loading.
        switch_to_program: If True, switch the current program to the uploaded one.

    Returns:
        JSON with upload details and optional load/analysis results.
    """
    if not local_path:
        raise GhidraValidationError("Local path is required")

    source = Path(local_path).expanduser().resolve()
    if not source.exists():
        raise GhidraValidationError(f"Local file not found: {source}")
    if not source.is_file():
        raise GhidraValidationError(f"Local path is not a file: {source}")

    file_bytes = source.read_bytes()
    upload_result = safe_post_json(
        "upload_file",
        {
            "filename": remote_filename or source.name,
            "directory": remote_dir,
            "content_base64": base64.b64encode(file_bytes).decode("ascii"),
            "overwrite": True,
        },
    )

    try:
        upload_data = json.loads(upload_result)
    except (TypeError, ValueError):
        return upload_result

    if upload_data.get("error"):
        return upload_result

    result = {
        "local_path": str(source),
        "uploaded": upload_data,
    }

    if not load:
        return json.dumps(result, indent=2)

    server_path = upload_data.get("path")
    load_result = load_program(server_path)
    try:
        load_data = json.loads(load_result)
    except (TypeError, ValueError):
        result["load"] = load_result
        return json.dumps(result, indent=2)

    result["load"] = load_data
    program_name = load_data.get("program")

    if program_name and switch_to_program:
        switch_result = switch_program(program_name)
        try:
            result["switch"] = json.loads(switch_result)
        except (TypeError, ValueError):
            result["switch"] = switch_result

    if program_name and analyze:
        analysis_result = run_analysis(program=program_name)
        try:
            result["analysis"] = json.loads(analysis_result)
        except (TypeError, ValueError):
            result["analysis"] = analysis_result

    return json.dumps(result, indent=2)


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
    return safe_get_json("find_similar_functions_fuzzy", params)


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
    return safe_get_json("bulk_fuzzy_match", params)


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

FUNCTION_HASH_INDEX_FILE = "function_hash_index.json"


@mcp.tool()
def build_function_hash_index(
    programs: list = None, filter: str = "documented",
    index_file: str = None, merge: bool = True,
) -> str:
    """
    Build or update a function hash index from one or more programs for cross-binary doc propagation.

    Args:
        programs: List of program paths to scan. None = current program.
        filter: "documented" (custom names only), "undocumented" (FUN_* only), or "all"
        index_file: Path to save index JSON (default: function_hash_index.json)
        merge: If True, merge with existing index; if False, replace

    Returns:
        JSON with programs scanned, functions indexed, unique hashes, and duplicates found.
    """
    index_path = index_file or FUNCTION_HASH_INDEX_FILE
    existing_index = {"version": "1.0", "hash_algorithm": "normalized_opcodes_sha256", "functions": {}}
    if merge and os.path.exists(index_path):
        try:
            with open(index_path, "r") as f:
                existing_index = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load existing index: {e}")

    index = existing_index
    programs_scanned = 0
    functions_indexed = 0

    try:
        current_info = json.loads(make_request(f"{ghidra_server_url}/get_current_program_info"))
        current_program = current_info.get("name", "Unknown")
    except Exception:
        current_program = "Unknown"

    programs_to_scan = programs if programs else [None]

    for program_path in programs_to_scan:
        try:
            if program_path:
                result = json.loads(make_request(f"{ghidra_server_url}/open_program", params={"path": program_path}))
                if "error" in result:
                    continue
                program_name = result.get("name", program_path)
            else:
                program_name = current_program

            offset = 0
            batch_size = 500
            while True:
                result = json.loads(make_request(
                    f"{ghidra_server_url}/get_bulk_function_hashes",
                    params={"offset": offset, "limit": batch_size, "filter": filter},
                ))
                if "error" in result:
                    break
                functions = result.get("functions", [])
                if not functions:
                    break

                for func in functions:
                    hash_val = func["hash"]
                    func_name = func["name"]
                    func_addr = func["address"]
                    has_custom = func.get("has_custom_name", False)

                    completeness = 0
                    if has_custom:
                        try:
                            comp_result = json.loads(make_request(
                                f"{ghidra_server_url}/analyze_function_completeness",
                                params={"address": func_addr},
                            ))
                            completeness = comp_result.get("completeness_score", 0)
                        except Exception:
                            pass

                    instance = {
                        "program": program_name, "address": func_addr,
                        "name": func_name, "completeness_score": completeness,
                        "indexed_at": datetime.now().isoformat(),
                    }

                    if hash_val not in index["functions"]:
                        index["functions"][hash_val] = {
                            "canonical": instance if has_custom else None,
                            "instances": [instance],
                        }
                    else:
                        entry = index["functions"][hash_val]
                        existing = False
                        for idx, inst in enumerate(entry["instances"]):
                            if inst["program"] == program_name and inst["address"] == func_addr:
                                entry["instances"][idx] = instance
                                existing = True
                                break
                        if not existing:
                            entry["instances"].append(instance)
                        if has_custom:
                            if entry["canonical"] is None:
                                entry["canonical"] = instance
                            elif completeness > entry["canonical"].get("completeness_score", 0):
                                entry["canonical"] = instance

                    functions_indexed += 1

                offset += batch_size
                if len(functions) < batch_size:
                    break
            programs_scanned += 1
        except Exception as e:
            logger.warning(f"Error processing program {program_path}: {e}")

    unique_hashes = len(index["functions"])
    duplicates = sum(1 for entry in index["functions"].values() if len(entry["instances"]) > 1)

    try:
        with open(index_path, "w") as f:
            json.dump(index, f, indent=2)
    except Exception as e:
        return json.dumps({
            "error": f"Could not save index: {str(e)}",
            "programs_scanned": programs_scanned, "functions_indexed": functions_indexed,
        })

    return json.dumps({
        "success": True, "programs_scanned": programs_scanned,
        "functions_indexed": functions_indexed, "unique_hashes": unique_hashes,
        "duplicates_found": duplicates, "index_file": index_path,
    })


@mcp.tool()
def lookup_function_by_hash(
    address: str = None, hash: str = None, index_file: str = None, program: str = None
) -> str:
    """
    Look up a function in the hash index to find matches across binaries.

    Args:
        address: Function address to look up (computes hash automatically)
        hash: Direct hash value to look up (alternative to address)
        index_file: Path to index file (default: function_hash_index.json)
        program: Optional program name. Defaults to active program.

    Returns:
        JSON with lookup results including canonical entry and all instances.
    """
    if not address and not hash:
        raise GhidraValidationError("Either address or hash must be provided")

    index_path = index_file or FUNCTION_HASH_INDEX_FILE
    if not os.path.exists(index_path):
        return json.dumps({"error": f"Index file not found: {index_path}"})

    try:
        with open(index_path, "r") as f:
            index = json.load(f)
    except Exception as e:
        return json.dumps({"error": f"Could not load index: {str(e)}"})

    if address and not hash:
        try:
            req_params = {"address": address}
            if program:
                req_params["program"] = program
            result = json.loads(make_request(f"{ghidra_server_url}/get_function_hash", params=req_params))
            if "error" in result:
                return json.dumps(result)
            hash = result["hash"]
        except Exception as e:
            return json.dumps({"error": f"Could not compute hash: {str(e)}"})

    if hash not in index.get("functions", {}):
        return json.dumps({"found": False, "hash": hash, "message": "No matching functions found in index"})

    entry = index["functions"][hash]
    return json.dumps({
        "found": True, "hash": hash, "canonical": entry.get("canonical"),
        "instances": entry.get("instances", []), "total_instances": len(entry.get("instances", [])),
    })


@mcp.tool()
def propagate_documentation(
    source_address: str = None, source_hash: str = None,
    target_programs: list = None, dry_run: bool = False, index_file: str = None,
) -> str:
    """
    Propagate documentation from a source function to all matching functions across binaries.

    Args:
        source_address: Address of source function
        source_hash: Hash to look up canonical source in index (alternative)
        target_programs: List of program names to propagate to (None = all in index)
        dry_run: If True, only report what would be changed
        index_file: Path to index file (default: function_hash_index.json)

    Returns:
        JSON with targets updated/skipped counts and per-target details.
    """
    if not source_address and not source_hash:
        raise GhidraValidationError("Either source_address or source_hash must be provided")

    index_path = index_file or FUNCTION_HASH_INDEX_FILE

    if source_address:
        try:
            docs = json.loads(make_request(
                f"{ghidra_server_url}/get_function_documentation",
                params={"address": source_address},
            ))
            if "error" in docs:
                return json.dumps(docs)
            source_hash = docs["hash"]
            source_info = {"program": docs["source_program"], "address": docs["source_address"], "name": docs["function_name"]}
        except Exception as e:
            return json.dumps({"error": f"Could not get source documentation: {str(e)}"})
    else:
        lookup_result = json.loads(lookup_function_by_hash(hash=source_hash, index_file=index_path))
        if not lookup_result.get("found") or not lookup_result.get("canonical"):
            return json.dumps({"error": "Source hash not found or has no canonical documentation"})
        canonical = lookup_result["canonical"]
        try:
            make_request(f"{ghidra_server_url}/switch_program", params={"name": canonical["program"]})
            docs = json.loads(make_request(
                f"{ghidra_server_url}/get_function_documentation",
                params={"address": canonical["address"]},
            ))
            if "error" in docs:
                return json.dumps(docs)
            source_info = {"program": canonical["program"], "address": canonical["address"], "name": canonical["name"]}
        except Exception as e:
            return json.dumps({"error": f"Could not get canonical documentation: {str(e)}"})

    try:
        with open(index_path, "r") as f:
            index = json.load(f)
    except Exception as e:
        return json.dumps({"error": f"Could not load index: {str(e)}"})

    if source_hash not in index.get("functions", {}):
        return json.dumps({"error": f"Hash {source_hash} not found in index"})

    instances = index["functions"][source_hash].get("instances", [])
    results = {"success": True, "source": source_info, "targets_updated": 0, "targets_skipped": 0, "dry_run": dry_run, "details": []}

    for instance in instances:
        target_program = instance["program"]
        target_address = instance["address"]

        if target_program == source_info["program"] and target_address == source_info["address"]:
            results["details"].append({"program": target_program, "address": target_address, "status": "skipped", "reason": "source function"})
            results["targets_skipped"] += 1
            continue

        if target_programs and target_program not in target_programs:
            results["details"].append({"program": target_program, "address": target_address, "status": "skipped", "reason": "not in target_programs filter"})
            results["targets_skipped"] += 1
            continue

        if dry_run:
            results["details"].append({"program": target_program, "address": target_address, "status": "would_update", "current_name": instance.get("name", "unknown")})
            results["targets_updated"] += 1
        else:
            try:
                switch_result = json.loads(make_request(f"{ghidra_server_url}/switch_program", params={"name": target_program}))
                if "error" in switch_result:
                    results["details"].append({"program": target_program, "address": target_address, "status": "error", "reason": switch_result["error"]})
                    results["targets_skipped"] += 1
                    continue

                apply_result = json.loads(make_request(
                    f"{ghidra_server_url}/apply_function_documentation",
                    method="POST",
                    data=json.dumps({
                        "target_address": target_address,
                        "function_name": docs.get("function_name"),
                        "return_type": docs.get("return_type"),
                        "calling_convention": docs.get("calling_convention"),
                        "plate_comment": docs.get("plate_comment"),
                        "parameters": docs.get("parameters"),
                        "comments": docs.get("comments"),
                        "labels": docs.get("labels"),
                    }),
                ))

                if "error" in apply_result:
                    results["details"].append({"program": target_program, "address": target_address, "status": "error", "reason": apply_result["error"]})
                    results["targets_skipped"] += 1
                else:
                    results["details"].append({"program": target_program, "address": target_address, "status": "updated", "changes": apply_result.get("changes_applied", 0)})
                    results["targets_updated"] += 1
            except Exception as e:
                results["details"].append({"program": target_program, "address": target_address, "status": "error", "reason": str(e)})
                results["targets_skipped"] += 1

    return json.dumps(results)


# ========== KNOWLEDGE DB TOOLS ==========


@mcp.tool()
def store_function_knowledge(
    address: str, binary_name: str, version: str, new_name: str,
    old_name: str = None, score: int = None, status: str = "complete",
    classification: str = None, iteration: int = None, strategy: str = None,
    plate_comment: str = None, prototype: str = None, deductions: str = None,
    game_system: str = None,
) -> str:
    """
    Store a documented function in the knowledge database.

    Args:
        address: Function address (e.g., "0x6fd81234")
        binary_name: Binary name (e.g., "D2Common.dll")
        version: Binary version (e.g., "1.00", "1.13d")
        new_name: New function name
        old_name: Original function name
        score: Completeness score 0-100
        status: Documentation status (complete, documented, needs_work, failed)
        classification: Function classification (thunk, leaf, worker, api)
        iteration: RE loop iteration number
        strategy: Selection strategy used
        plate_comment: Function plate comment / documentation
        prototype: Function prototype / signature
        deductions: JSON array of score deductions (as string)
        game_system: Game system classification (e.g., "inventory", "combat")

    Returns:
        JSON with success status
    """
    if not knowledge_db.available:
        return json.dumps({"available": False, "error": "Knowledge DB not available"})

    deductions_json = deductions if deductions else "[]"
    try:
        json.loads(deductions_json)
    except (json.JSONDecodeError, TypeError):
        deductions_json = "[]"

    success = knowledge_db.execute_write(
        """INSERT INTO documented_functions
           (address, binary_name, version, old_name, new_name, score, status,
            classification, iteration, strategy, plate_comment, prototype,
            deductions, game_system)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
           ON CONFLICT (address, binary_name, version)
           DO UPDATE SET
               new_name = EXCLUDED.new_name,
               score = EXCLUDED.score,
               status = EXCLUDED.status,
               classification = EXCLUDED.classification,
               iteration = EXCLUDED.iteration,
               strategy = EXCLUDED.strategy,
               plate_comment = EXCLUDED.plate_comment,
               prototype = EXCLUDED.prototype,
               deductions = EXCLUDED.deductions,
               game_system = COALESCE(EXCLUDED.game_system, documented_functions.game_system)
        """,
        (address, binary_name, version, old_name, new_name, score, status,
         classification, iteration, strategy, plate_comment, prototype, deductions_json, game_system),
    )

    if success:
        return json.dumps({"success": True, "stored": new_name})
    return json.dumps({"success": False, "error": "Write failed (logged)"})


@mcp.tool()
def query_knowledge_context(
    description: str = None, binary_name: str = None, version: str = None,
    game_system: str = None, limit: int = 10,
) -> str:
    """
    Query the knowledge database for context about functions.

    Args:
        description: Search text (function name, keyword, or description fragment)
        binary_name: Filter by binary name (e.g., "D2Common.dll")
        version: Filter by version (e.g., "1.00")
        game_system: Filter by game system (e.g., "inventory", "combat")
        limit: Maximum results to return (default 10)

    Returns:
        JSON with matching documented functions and their knowledge
    """
    if not knowledge_db.available:
        return json.dumps({"available": False, "error": "Knowledge DB not available"})

    conditions = []
    params = []

    if description:
        conditions.append(
            "(search_vector @@ plainto_tsquery('english', %s) OR "
            "new_name ILIKE %s OR plate_comment ILIKE %s)"
        )
        like_pattern = f"%{description}%"
        params.extend([description, like_pattern, like_pattern])

    if binary_name:
        conditions.append("binary_name = %s")
        params.append(binary_name)
    if version:
        conditions.append("version = %s")
        params.append(version)
    if game_system:
        conditions.append("game_system = %s")
        params.append(game_system)

    where_clause = " AND ".join(conditions) if conditions else "TRUE"
    params.append(min(limit, 50))

    query = f"""
        SELECT address, binary_name, version, old_name, new_name, score,
               status, classification, plate_comment, prototype, game_system
        FROM documented_functions
        WHERE {where_clause}
        ORDER BY score DESC NULLS LAST, updated_at DESC
        LIMIT %s
    """

    rows = knowledge_db.execute_read(query, params)
    if rows is None:
        return json.dumps({"available": False, "error": "Query failed"})
    return json.dumps({"success": True, "count": len(rows), "functions": rows}, default=str)


@mcp.tool()
def store_ordinal_mapping(
    ordinal: int, binary_name: str, version: str, function_name: str,
    calling_convention: str = None, parameter_count: int = None,
    source: str = "re_loop", confidence: float = 1.0, notes: str = None,
) -> str:
    """
    Store an ordinal-to-function-name mapping in the knowledge database.

    Args:
        ordinal: Ordinal number (e.g., 10375)
        binary_name: Binary name (e.g., "D2Common.dll")
        version: Binary version (e.g., "1.00")
        function_name: Resolved function name (e.g., "GetUnitPosition")
        calling_convention: Calling convention (e.g., "__stdcall")
        parameter_count: Number of parameters
        source: Origin of mapping ("re_loop", "community", "ida_export")
        confidence: Confidence 0.0-1.0 (default 1.0)
        notes: Additional notes

    Returns:
        JSON with success status
    """
    if not knowledge_db.available:
        return json.dumps({"available": False, "error": "Knowledge DB not available"})

    success = knowledge_db.execute_write(
        """INSERT INTO ordinal_mappings
           (ordinal, binary_name, version, function_name, calling_convention,
            parameter_count, source, confidence, notes)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT (ordinal, binary_name, version)
           DO UPDATE SET
               function_name = EXCLUDED.function_name,
               calling_convention = COALESCE(EXCLUDED.calling_convention, ordinal_mappings.calling_convention),
               parameter_count = COALESCE(EXCLUDED.parameter_count, ordinal_mappings.parameter_count),
               confidence = GREATEST(EXCLUDED.confidence, ordinal_mappings.confidence),
               notes = COALESCE(EXCLUDED.notes, ordinal_mappings.notes)
        """,
        (ordinal, binary_name, version, function_name, calling_convention,
         parameter_count, source, confidence, notes),
    )

    if success:
        return json.dumps({"success": True, "stored": f"Ordinal_{ordinal} -> {function_name}"})
    return json.dumps({"success": False, "error": "Write failed (logged)"})


@mcp.tool()
def get_ordinal_mapping(
    ordinal: int = None, binary_name: str = None, version: str = None,
    function_name: str = None,
) -> str:
    """
    Look up ordinal-to-function-name mappings from the knowledge database.

    Args:
        ordinal: Ordinal number to look up (e.g., 10375)
        binary_name: Filter by binary (e.g., "D2Common.dll")
        version: Filter by version (e.g., "1.00"). Omit to search all versions.
        function_name: Search by function name (partial match)

    Returns:
        JSON with matching ordinal mappings across all known versions
    """
    if not knowledge_db.available:
        return json.dumps({"available": False, "error": "Knowledge DB not available"})

    conditions = []
    params = []
    if ordinal is not None:
        conditions.append("ordinal = %s")
        params.append(ordinal)
    if binary_name:
        conditions.append("binary_name = %s")
        params.append(binary_name)
    if version:
        conditions.append("version = %s")
        params.append(version)
    if function_name:
        conditions.append("function_name ILIKE %s")
        params.append(f"%{function_name}%")

    if not conditions:
        return json.dumps({"success": False, "error": "At least one filter required"})

    where_clause = " AND ".join(conditions)
    query = f"""
        SELECT ordinal, binary_name, version, function_name,
               calling_convention, parameter_count, source, confidence, notes
        FROM ordinal_mappings
        WHERE {where_clause}
        ORDER BY binary_name, version, ordinal
        LIMIT 100
    """

    rows = knowledge_db.execute_read(query, params)
    if rows is None:
        return json.dumps({"available": False, "error": "Query failed"})
    return json.dumps({"success": True, "count": len(rows), "mappings": rows}, default=str)


@mcp.tool()
def export_system_knowledge(
    game_system: str = None, binary_name: str = None,
    version: str = None, format: str = "markdown",
) -> str:
    """
    Export documented knowledge for content creation (books, articles).

    Args:
        game_system: Filter by game system (e.g., "inventory", "combat", "all")
        binary_name: Filter by binary (e.g., "D2Common.dll")
        version: Filter by version (e.g., "1.00")
        format: Output format ("markdown" or "json")

    Returns:
        Formatted knowledge export
    """
    if not knowledge_db.available:
        return json.dumps({"available": False, "error": "Knowledge DB not available"})

    conditions = []
    params = []
    if game_system and game_system != "all":
        conditions.append("df.game_system = %s")
        params.append(game_system)
    if binary_name:
        conditions.append("df.binary_name = %s")
        params.append(binary_name)
    if version:
        conditions.append("df.version = %s")
        params.append(version)

    where_clause = " AND ".join(conditions) if conditions else "TRUE"
    query = f"""
        SELECT df.address, df.binary_name, df.version, df.new_name,
               df.score, df.classification, df.plate_comment, df.prototype,
               df.game_system,
               om.ordinal, om.calling_convention
        FROM documented_functions df
        LEFT JOIN ordinal_mappings om
            ON df.new_name = om.function_name
            AND df.binary_name = om.binary_name
            AND df.version = om.version
        WHERE {where_clause}
        ORDER BY df.game_system NULLS LAST, df.new_name
    """

    rows = knowledge_db.execute_read(query, params)
    if rows is None:
        return json.dumps({"available": False, "error": "Query failed"})

    if format == "json":
        return json.dumps({"success": True, "count": len(rows), "functions": rows}, default=str)

    # Markdown format grouped by game system
    systems = {}
    for row in rows:
        sys_name = row.get("game_system") or "Unclassified"
        systems.setdefault(sys_name, []).append(row)

    lines = ["# Diablo 2 Function Knowledge Export", ""]
    binary_label = binary_name or "All binaries"
    version_label = version or "all versions"
    lines.append(f"**Binary:** {binary_label} | **Version:** {version_label} | **Functions:** {len(rows)}")
    lines.append("")

    for sys_name, funcs in sorted(systems.items()):
        lines.append(f"## {sys_name.replace('_', ' ').title()}")
        lines.append("")
        for f in sorted(funcs, key=lambda x: x.get("new_name", "")):
            ordinal_str = f" (Ordinal {f['ordinal']})" if f.get("ordinal") else ""
            lines.append(f"### {f['new_name']}{ordinal_str}")
            if f.get("prototype"):
                lines.append(f"```c\n{f['prototype']}\n```")
            if f.get("plate_comment"):
                lines.append(f"{f['plate_comment']}")
            lines.append(f"*Address: {f['address']} | Score: {f.get('score', 'N/A')} | Type: {f.get('classification', 'N/A')}*")
            lines.append("")

    return "\n".join(lines)


# ========== MAIN ==========


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument(
        "--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}",
    )
    parser.add_argument(
        "--mcp-host", type=str, default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port", type=int,
        help="Port to run MCP server on (only used for sse), default: 8089",
    )
    parser.add_argument(
        "--transport", type=str, default="stdio", choices=["stdio", "sse"],
        help="Transport protocol for MCP, default: stdio",
    )
    parser.add_argument(
        "--profile", type=str, choices=list(TOOL_PROFILES.keys()),
        help="Load only tools for a specific workflow (e.g., 're' for reverse engineering)",
    )
    args = parser.parse_args()

    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server

    # Dynamic tool registration from Ghidra's /mcp/schema
    dynamic_count = _register_schema_tools()
    logger.info(f"Total tools: {dynamic_count} dynamic + {len(STATIC_TOOL_NAMES)} static")

    if args.profile:
        apply_tool_profile(mcp, args.profile)

    if args.transport == "sse":
        try:
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)
            mcp.settings.log_level = "INFO"
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8089
            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()

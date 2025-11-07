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
from urllib.parse import urljoin, urlparse

from mcp.server.fastmcp import FastMCP

# Performance optimization imports
from functools import lru_cache, wraps
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8089/"

# Enhanced configuration and state management
# HTTP request timeout (30s chosen for slow decompilation operations)
REQUEST_TIMEOUT = 30
DEFAULT_PAGINATION_LIMIT = 100

# Per-endpoint timeout configuration for expensive operations (v1.6.1)
ENDPOINT_TIMEOUTS = {
    'batch_rename_variables': 120,         # 2 minutes - variable renames trigger re-analysis (increased from 90s)
    'batch_set_comments': 120,             # 2 minutes - multiple comment operations (increased from 90s)
    'analyze_function_complete': 120,      # 2 minutes - comprehensive analysis with decompilation (increased from 90s)
    'batch_rename_function_components': 120, # 2 minutes - multiple rename operations (increased from 90s)
    'batch_set_variable_types': 90,        # 1.5 minutes - DataType lookups can be slow
    'analyze_data_region': 90,             # 1.5 minutes - complex data analysis
    'batch_create_labels': 60,             # 1 minute - creating multiple labels in transaction
    'set_plate_comment': 45,               # 45 seconds - plate comments can be lengthy
    'set_function_prototype': 45,          # 45 seconds - prototype changes trigger re-analysis
    'rename_function_by_address': 45,      # 45 seconds - function renames update xrefs
    'rename_variable': 30,                 # 30 seconds - single variable rename
    'rename_function': 45,                 # 45 seconds - function renames update xrefs
    'decompile_function': 45,              # 45 seconds - decompilation can be slow for large functions
    'disassemble_bytes': 120,              # 2 minutes - disassembly can be slow for large ranges
    'default': 30                          # 30 seconds for all other operations
}
# Maximum retry attempts for transient failures (3 attempts with exponential backoff)
MAX_RETRIES = 3
# Exponential backoff factor (0.5s, 1s, 2s, 4s sequence)
RETRY_BACKOFF_FACTOR = 0.5
# Cache size (256 entries ≈ 1MB memory footprint for typical requests)
CACHE_SIZE = 256
ENABLE_CACHING = True

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
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

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
HEX_ADDRESS_PATTERN = re.compile(r'^0x[0-9a-fA-F]+$')
FUNCTION_NAME_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

def validate_server_url(url: str) -> bool:
    """Validate that the server URL is safe to use"""
    try:
        parsed = urlparse(url)
        # Only allow HTTP/HTTPS protocols
        if parsed.scheme not in ['http', 'https']:
            return False
        # Only allow local addresses for security
        if parsed.hostname in ['localhost', '127.0.0.1', '::1']:
            return True
        # Allow private network ranges
        if parsed.hostname and (
            parsed.hostname.startswith('192.168.') or
            parsed.hostname.startswith('10.') or
            parsed.hostname.startswith('172.')
        ):
            return True
        return False
    except Exception:
        return False

def get_timeout_for_endpoint(endpoint: str) -> int:
    """Get the appropriate timeout for a specific endpoint"""
    # Extract endpoint name from URL path
    endpoint_name = endpoint.strip('/').split('/')[-1]
    return ENDPOINT_TIMEOUTS.get(endpoint_name, ENDPOINT_TIMEOUTS['default'])

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
    if not address.startswith(('0x', '0X')):
        address = '0x' + address
    
    # Normalize to lowercase
    return address.lower()

def validate_function_name(name: str) -> bool:
    """Validate function name format"""
    return bool(FUNCTION_NAME_PATTERN.match(name)) if name else False

def _convert_escaped_newlines(text: str) -> str:
    """Convert escaped newlines (\\n) to actual newlines"""
    if not text:
        return text
    return text.replace('\\n', '\n')

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
    if addresses.startswith('['):
        try:
            addr_list = json.loads(addresses)
        except json.JSONDecodeError as e:
            raise GhidraValidationError(f"Invalid JSON array format for {param_name}: {e}")
    else:
        addr_list = [addr.strip() for addr in addresses.split(',') if addr.strip()]

    # Validate all addresses
    for addr in addr_list:
        if not validate_hex_address(addr):
            raise GhidraValidationError(f"Invalid hex address format: {addr}")

    return addr_list


# Performance and caching utilities
from typing import Callable, TypeVar, Any

T = TypeVar('T')

def cache_key(*args: Any, **kwargs: Any) -> str:
    """
    Generate a cache key from function arguments.

    Returns:
        MD5 hash of serialized arguments
    """
    import json
    import hashlib
    key_data = {"args": args, "kwargs": kwargs}
    return hashlib.md5(json.dumps(key_data, sort_keys=True, default=str).encode()).hexdigest()

def cached_request(cache_duration: int = 300) -> Callable[[Callable[..., T]], Callable[..., T]]:
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

    Args:
        endpoint: The API endpoint to call
        params: Optional query parameters
        retries: Number of retry attempts for server errors

    Returns:
        List of strings representing the response
    """
    if params is None:
        params = {}

    # Validate server URL for security
    if not validate_server_url(ghidra_server_url):
        logger.error(f"Invalid or unsafe server URL: {ghidra_server_url}")
        return ["Error: Invalid server URL - only local addresses allowed"]

    url = urljoin(ghidra_server_url, endpoint)

    # Get endpoint-specific timeout
    timeout = get_timeout_for_endpoint(endpoint)
    logger.debug(f"Using timeout of {timeout}s for endpoint {endpoint}")

    for attempt in range(retries):
        try:
            start_time = time.time()
            response = session.get(url, params=params, timeout=timeout)
            response.encoding = 'utf-8'
            duration = time.time() - start_time

            logger.info(f"Request to {endpoint} took {duration:.2f}s (attempt {attempt + 1}/{retries})")

            if response.ok:
                return response.text.splitlines()
            elif response.status_code == 404:
                logger.warning(f"Endpoint not found: {endpoint}")
                return [f"Endpoint not found: {endpoint}"]
            elif response.status_code >= 500:
                # Server error - retry with exponential backoff
                if attempt < retries - 1:
                    wait_time = 2 ** attempt
                    logger.warning(f"Server error {response.status_code}, retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Server error after {retries} attempts: {response.status_code}")
                    raise GhidraConnectionError(f"Server error: {response.status_code}")
            else:
                logger.error(f"HTTP {response.status_code}: {response.text.strip()}")
                return [f"Error {response.status_code}: {response.text.strip()}"]

        except requests.exceptions.Timeout:
            logger.warning(f"Request timeout on attempt {attempt + 1}/{retries}")
            if attempt < retries - 1:
                continue
            return [f"Timeout connecting to Ghidra server after {retries} attempts"]
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return [f"Request failed: {str(e)}"]
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return [f"Unexpected error: {str(e)}"]

    return ["Unexpected error in safe_get_uncached"]


@cached_request(cache_duration=180)  # 3-minute cache for GET requests
def safe_get(endpoint: str, params: dict = None, retries: int = 3) -> list:
    """
    Perform a GET request with enhanced error handling and retry logic.

    Args:
        endpoint: The API endpoint to call
        params: Optional query parameters
        retries: Number of retry attempts for server errors

    Returns:
        List of strings representing the response
    """
    if params is None:
        params = {}

    # Validate server URL for security
    if not validate_server_url(ghidra_server_url):
        logger.error(f"Invalid or unsafe server URL: {ghidra_server_url}")
        return ["Error: Invalid server URL - only local addresses allowed"]

    url = urljoin(ghidra_server_url, endpoint)

    # Get endpoint-specific timeout
    timeout = get_timeout_for_endpoint(endpoint)
    logger.debug(f"Using timeout of {timeout}s for endpoint {endpoint}")

    for attempt in range(retries):
        try:
            start_time = time.time()
            response = session.get(url, params=params, timeout=timeout)
            response.encoding = 'utf-8'
            duration = time.time() - start_time

            logger.info(f"Request to {endpoint} took {duration:.2f}s (attempt {attempt + 1}/{retries})")

            if response.ok:
                return response.text.splitlines()
            elif response.status_code == 404:
                logger.warning(f"Endpoint not found: {endpoint}")
                return [f"Endpoint not found: {endpoint}"]
            elif response.status_code >= 500:
                # Server error - retry with exponential backoff
                if attempt < retries - 1:
                    wait_time = 2 ** attempt
                    logger.warning(f"Server error {response.status_code}, retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Server error after {retries} attempts: {response.status_code}")
                    raise GhidraConnectionError(f"Server error: {response.status_code}")
            else:
                logger.error(f"HTTP {response.status_code}: {response.text.strip()}")
                return [f"Error {response.status_code}: {response.text.strip()}"]

        except requests.exceptions.Timeout:
            logger.warning(f"Request timeout on attempt {attempt + 1}/{retries}")
            if attempt < retries - 1:
                continue
            return [f"Timeout connecting to Ghidra server after {retries} attempts"]
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return [f"Request failed: {str(e)}"]
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return [f"Unexpected error: {str(e)}"]

    return ["Unexpected error in safe_get"]


def safe_post_json(endpoint: str, data: dict, retries: int = 3) -> str:
    """
    Perform a JSON POST request with enhanced error handling and retry logic.

    Args:
        endpoint: The API endpoint to call
        data: Data to send as JSON
        retries: Number of retry attempts for server errors

    Returns:
        String response from the server
    """
    # Validate server URL for security
    if not validate_server_url(ghidra_server_url):
        logger.error(f"Invalid or unsafe server URL: {ghidra_server_url}")
        return "Error: Invalid server URL - only local addresses allowed"

    url = urljoin(ghidra_server_url, endpoint)

    # Get endpoint-specific timeout
    timeout = get_timeout_for_endpoint(endpoint)
    logger.debug(f"Using timeout of {timeout}s for endpoint {endpoint}")

    # Disable Keep-Alive for long-running operations to prevent connection timeout
    headers = {'Connection': 'close'}

    for attempt in range(retries):
        try:
            start_time = time.time()

            logger.info(f"Sending JSON POST to {url} with data: {data}")
            response = session.post(url, json=data, headers=headers, timeout=timeout)

            response.encoding = 'utf-8'
            duration = time.time() - start_time

            logger.info(f"JSON POST to {endpoint} took {duration:.2f}s (attempt {attempt + 1}/{retries}), status: {response.status_code}")
            
            if response.ok:
                return response.text.strip()
            elif response.status_code == 404:
                return f"Error: Endpoint {endpoint} not found"
            elif response.status_code >= 500:
                if attempt < retries - 1:  # Only log retry attempts for server errors
                    logger.warning(f"Server error {response.status_code} on attempt {attempt + 1}, retrying...")
                    time.sleep(1)  # Brief delay before retry
                    continue
                else:
                    return f"Error: Server error {response.status_code} after {retries} attempts"
            else:
                return f"Error: HTTP {response.status_code} - {response.text}"
                
        except requests.RequestException as e:
            if attempt < retries - 1:
                logger.warning(f"Request failed on attempt {attempt + 1}, retrying: {e}")
                time.sleep(1)
                continue
            else:
                logger.error(f"Request failed after {retries} attempts: {e}")
                return f"Error: Request failed - {str(e)}"

    return "Error: Maximum retries exceeded"

def safe_post(endpoint: str, data: dict | str, retries: int = 3) -> str:
    """
    Perform a POST request with enhanced error handling and retry logic.
    
    Args:
        endpoint: The API endpoint to call
        data: Data to send (dict or string)
        retries: Number of retry attempts for server errors
    
    Returns:
        String response from the server
    """
    # Validate server URL for security  
    if not validate_server_url(ghidra_server_url):
        logger.error(f"Invalid or unsafe server URL: {ghidra_server_url}")
        return "Error: Invalid server URL - only local addresses allowed"

    url = urljoin(ghidra_server_url, endpoint)

    # Get endpoint-specific timeout
    timeout = get_timeout_for_endpoint(endpoint)
    logger.debug(f"Using timeout of {timeout}s for endpoint {endpoint}")

    for attempt in range(retries):
        try:
            start_time = time.time()

            if isinstance(data, dict):
                logger.info(f"Sending POST to {url} with form data: {data}")
                response = session.post(url, data=data, timeout=timeout)
            else:
                logger.info(f"Sending POST to {url} with raw data: {data}")
                response = session.post(url, data=data.encode("utf-8"), timeout=timeout)

            response.encoding = 'utf-8'
            duration = time.time() - start_time

            logger.info(f"POST to {endpoint} took {duration:.2f}s (attempt {attempt + 1}/{retries}), status: {response.status_code}")
            
            if response.ok:
                return response.text.strip()
            elif response.status_code == 404:
                logger.warning(f"Endpoint not found: {endpoint}")
                return f"Endpoint not found: {endpoint}"
            elif response.status_code >= 500:
                # Server error - retry with exponential backoff
                if attempt < retries - 1:
                    wait_time = 2 ** attempt
                    logger.warning(f"Server error {response.status_code}, retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Server error after {retries} attempts: {response.status_code}")
                    raise GhidraConnectionError(f"Server error: {response.status_code}")
            else:
                logger.error(f"HTTP {response.status_code}: {response.text.strip()}")
                return f"Error {response.status_code}: {response.text.strip()}"
                
        except requests.exceptions.Timeout:
            logger.warning(f"POST timeout on attempt {attempt + 1}/{retries}")
            if attempt < retries - 1:
                continue
            return f"Timeout connecting to Ghidra server after {retries} attempts"
        except requests.exceptions.RequestException as e:
            logger.error(f"POST request failed: {str(e)}")
            return f"Request failed: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error in POST: {str(e)}")
            return f"Unexpected error: {str(e)}"
    
    return "Unexpected error in safe_post"

@mcp.tool()
def list_functions(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    
    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of functions to return (default: 100)
        
    Returns:
        List of function names with pagination information
    """
    return safe_get("functions", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    
    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of classes to return (default: 100)
        
    Returns:
        List of namespace/class names with pagination information
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str = None, address: str = None, force: bool = False) -> str:
    """
    Decompile a function by name or address and return the decompiled C code.

    Supports both normal decompilation and forced fresh decompilation (clearing cache).
    Essential after making changes that affect decompilation.

    **When to Use Force Decompilation:**
    - After changing function signatures or prototypes
    - After modifying variable storage
    - After updating data types used by the function
    - When decompilation seems stale or incorrect

    Args:
        name: Function name to decompile (either name or address required)
        address: Function address in hex format (e.g., "0x6fb6aef0") - alternative to name
        force: Force fresh decompilation, clearing cache and re-analyzing (default: False)

    Returns:
        Decompiled C code as a string

    Examples:
        # Decompile by function name
        code = decompile_function(name="main")

        # Decompile by address with forced re-analysis
        code = decompile_function(address="0x6fb6aef0", force=True)
    """
    if not name and not address:
        raise GhidraValidationError("Either 'name' or 'address' parameter is required")

    if name:
        endpoint = "force_decompile_by_name" if force else "decompile"
        return safe_post(endpoint, name if endpoint == "decompile" else {"name": name})
    else:
        if not validate_hex_address(address):
            raise GhidraValidationError(f"Invalid hexadecimal address: {address}")
        endpoint = "force_decompile"
        return safe_post(endpoint, {"function_address": address})

@mcp.tool()
def get_decompiled_code(function_address: str, refresh_cache: bool = False, timeout: int = None) -> str:
    """
    Get the decompiled C code for a function at the specified address.

    This is a simplified tool specifically designed for retrieving decompiled code.
    Use this when you need the pseudocode representation of a function for analysis.

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x401000", "0x6fb6aef0")
                         Accepts addresses with or without 0x prefix
        refresh_cache: If True, forces fresh decompilation by clearing the cache (default: False)
                      Use this after making changes to function signatures, variable types, or data types
        timeout: Optional timeout in seconds for this operation (overrides default 45s for large functions)

    Returns:
        str: Decompiled C pseudocode as a string

    Raises:
        GhidraValidationError: If address format is invalid or no function found at address

    Examples:
        # Get decompiled code for a function (uses cached decompilation)
        code = get_decompiled_code("0x401000")
        
        # Force fresh decompilation after making changes
        code = get_decompiled_code("0x6fb6aef0", refresh_cache=True)
        
        # Use custom timeout for very large function
        code = get_decompiled_code("0x401000", timeout=120)

    Performance Notes:
        - First call: ~100-500ms (depends on function complexity)
        - Cached calls: ~10-50ms
        - Use refresh_cache=True only when necessary
        - Ghidra internally caches decompilation results

    Troubleshooting:
        Decompilation may fail for functions with:
        - Complex or invalid control flow
        - Large NOP sleds or padding
        - External calls to unknown addresses
        - Stack frame analysis issues
        
        If decompilation fails, use get_disassembly() as an alternative to view assembly code.
        The error message will indicate the specific issue when possible.
        
        IMPORTANT: If you make changes to function signatures, data types, or structures,
        you MUST use refresh_cache=True to force re-decompilation. The decompiler caches
        results and will not automatically pick up changes. Changes that require refresh include:
        - Creating or applying new structure types (create_struct, apply_data_type)
        - Renaming global variables referenced by the function
        - Changing function prototypes or calling conventions
        - Modifying parameter or return types

    Note:
        If you need to decompile by function name instead of address, use decompile_function() tool.
    """
    # Sanitize and validate address
    function_address = sanitize_address(function_address)
    if not validate_hex_address(function_address):
        raise GhidraValidationError(
            f"Invalid hexadecimal address format: {function_address}. "
            f"Expected format: 0x followed by hex digits (e.g., '0x401000'). "
            f"Use get_function_by_address() to verify the address, or "
            f"search_functions_by_name() to find the function."
        )
    
    # Verify function exists at this address
    func_check = safe_get("get_function_by_address", {"address": function_address})
    if not func_check or any("Error" in str(line) or "not found" in str(line).lower() for line in func_check):
        raise GhidraValidationError(
            f"No function found at address {function_address}. "
            f"Verify the address using get_function_by_address() or "
            f"list_functions() to see all available functions."
        )
    
    # Apply custom timeout if specified
    if timeout:
        original_timeout = ENDPOINT_TIMEOUTS.get('decompile_function', 45)
        ENDPOINT_TIMEOUTS['decompile_function'] = timeout
        ENDPOINT_TIMEOUTS['force_decompile'] = timeout
    
    try:
        if refresh_cache:
            # Force fresh decompilation by clearing cache (uses POST)
            result = safe_post("force_decompile", {"function_address": function_address})
        else:
            # Get cached decompilation (much faster, uses GET)
            result = safe_get("decompile_function", {"address": function_address})
        
        # Convert list result to string if needed (safe_get returns list)
        if isinstance(result, list):
            result = '\n'.join(result)
        
        # Check for decompilation errors
        if result and "Error" in result:
            return (f"{result}\n\n"
                   f"Try: get_decompiled_code('{function_address}', refresh_cache=True) "
                   f"to force re-decompilation.")
        
        return result
    finally:
        # Restore original timeout
        if timeout:
            ENDPOINT_TIMEOUTS['decompile_function'] = original_timeout
            ENDPOINT_TIMEOUTS['force_decompile'] = original_timeout

@mcp.tool()
def get_disassembly(function_address: str, as_text: bool = False, 
                   filter_mnemonics: str = None, timeout: int = None) -> list[str] | str:
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

    Examples:
        # Get disassembly as a list (default)
        asm_lines = get_disassembly("0x401000")
        # Returns: ["0x401000: PUSH EBP", "0x401001: MOV EBP,ESP", ...]
        
        # Get disassembly as formatted text
        asm_text = get_disassembly("0x401000", as_text=True)
        # Returns: "0x401000: PUSH EBP\n0x401001: MOV EBP,ESP\n..."
        
        # Filter to show only CALL and JMP instructions
        calls_jumps = get_disassembly("0x401000", filter_mnemonics="CALL,JMP")
        # Returns: ["0x401005: CALL 0x402000", "0x40100a: JMP 0x401020", ...]
        
        # Show only MOV instructions as text
        movs = get_disassembly("0x401000", as_text=True, filter_mnemonics="MOV")

    Performance Notes:
        - Disassembly is cached by Ghidra
        - Filtering is done client-side after retrieval
        - Use filter_mnemonics to reduce output size for large functions

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
    if not func_check or any("Error" in str(line) or "not found" in str(line).lower() for line in func_check):
        raise GhidraValidationError(
            f"No function found at address {function_address}. "
            f"Verify the address using get_function_by_address() or "
            f"use disassemble_bytes() to disassemble arbitrary memory regions."
        )
    
    # Apply custom timeout if specified
    if timeout:
        original_timeout = ENDPOINT_TIMEOUTS.get('disassemble_function', 30)
        ENDPOINT_TIMEOUTS['disassemble_function'] = timeout
    
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
            mnemonics = [m.strip().upper() for m in filter_mnemonics.split(',')]
            # Filter lines that contain any of the specified mnemonics
            # Format is typically "address: mnemonic operands ; comment"
            result = [
                line for line in result 
                if any(mnem in line.upper() for mnem in mnemonics)
            ]
            
            if not result:
                logger.warning(f"No instructions matching '{filter_mnemonics}' found in function at {function_address}")
        
        if as_text:
            return "\n".join(result)
        return result
    finally:
        # Restore original timeout
        if timeout:
            ENDPOINT_TIMEOUTS['disassemble_function'] = original_timeout

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    
    Args:
        old_name: Current name of the function to rename
        new_name: New name for the function
        
    Returns:
        Success or failure message indicating the result of the rename operation
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
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
    if not new_name[0].isalpha() and new_name[0] != '_':
        raise GhidraValidationError(
            f"Invalid data name '{new_name}'. "
            f"Names must start with a letter or underscore."
        )
    
    if not all(c.isalnum() or c == '_' for c in new_name):
        raise GhidraValidationError(
            f"Invalid data name '{new_name}'. "
            f"Names can only contain letters, numbers, and underscores."
        )

    response = safe_post("renameData", {"address": address, "newName": new_name})

    # Provide actionable error messages
    if "no defined data" in response.lower():
        return (f"Error: No defined data at {address}. "
               f"This address may be undefined memory. "
               f"Try: create_label('{address}', '{new_name}') instead, or "
               f"use rename_or_label('{address}', '{new_name}') for automatic detection.")
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
        result = safe_post_json("analyze_data_region", {
            "address": address,
            "max_scan_bytes": 16,
            "include_xref_map": False,
            "include_assembly_patterns": False,
            "include_boundary_detection": False
        })

        if result and not result.startswith("Error"):
            data = json.loads(result)
            current_type = data.get("current_type", "undefined")
            # If current_type is "undefined", it's not a defined data item
            return current_type != "undefined"
    except Exception as e:
        logger.warning(f"Failed to check if data defined at {address}: {e}")

    return False


@mcp.tool()
def get_function_labels(name: str, offset: int = 0, limit: int = 20) -> list:
    """
    Get all labels within the specified function by name.
    
    Args:
        name: Function name to search for labels within
        offset: Pagination offset (default: 0)
        limit: Maximum number of labels to return (default: 20)
        
    Returns:
        List of labels found within the specified function
    """
    return safe_get("function_labels", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def rename_label(address: str, old_name: str, new_name: str) -> str:
    """
    Rename an existing label at the specified address.

    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        old_name: Current label name to rename
        new_name: New name for the label

    Returns:
        Success or failure message indicating the result of the rename operation
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_post("rename_label", {
        "address": address,
        "old_name": old_name,
        "new_name": new_name
    })

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    
    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of segments to return (default: 100)
        
    Returns:
        List of memory segments with their addresses, names, and properties
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    
    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of imports to return (default: 100)
        
    Returns:
        List of imported symbols with their names and addresses
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of exports to return (default: 100)

    Returns:
        List of exported functions/symbols with their names and addresses
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_external_locations(offset: int = 0, limit: int = 100) -> list:
    """
    List all external locations (imports, ordinal imports, external functions, etc).

    External locations represent functions or data imported from external DLLs.
    This includes ordinal-based imports like "Ordinal_123" that can be renamed
    to proper function names for ordinal linkage restoration.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of external locations to return (default: 100)

    Returns:
        List of external locations with DLL name, label, and address
    """
    return safe_get("list_external_locations", {"offset": offset, "limit": limit})

@mcp.tool()
def get_external_location(address: str, dll_name: str = None) -> dict:
    """
    Get details of a specific external location.

    Args:
        address: Memory address of the external location (e.g., "0x6fb7e218")
        dll_name: Optional DLL name to search in (if not provided, searches all DLLs)

    Returns:
        Dictionary with external location details (DLL, label, address)
    """
    params = {"address": address}
    if dll_name:
        params["dll_name"] = dll_name
    return safe_get("get_external_location", params)

@mcp.tool()
def rename_external_location(address: str, new_name: str) -> str:
    """
    Rename an external location (e.g., change Ordinal_123 to a real function name).

    This tool is essential for fixing broken ordinal-based imports when DLL
    function names change. Use it to rename ordinal imports to their correct
    function names for ordinal linkage restoration.

    Args:
        address: Memory address of the external location (e.g., "0x6fb7e218")
        new_name: New name for the external location (e.g., "sgptDataTables")

    Returns:
        Success message with old and new names, or error message

    Example:
        Rename "Ordinal_100" to actual function name:
        rename_external_location("0x6fb7e218", "sgptDataTables")
    """
    params = {"address": validate_hex_address(address), "new_name": new_name}
    return safe_post("rename_external_location", params)

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    
    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of namespaces to return (default: 100)
        
    Returns:
        List of namespace names and their hierarchical paths
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of data items to return (default: 100)

    Returns:
        List of data labels with their addresses, names, and values
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items_by_xrefs(offset: int = 0, limit: int = 100, format: str = "json") -> str:
    """
    List defined data items sorted by cross-reference count (v1.7.4).
    Returns data items with the most references first.

    This tool is ideal for identifying the most heavily-used data structures
    in a binary, helping prioritize which data items to analyze first.

    Args:
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of data items to return (default: 100)
        format: Output format - "text" for human-readable or "json" for structured data (default: "json")

    Returns:
        Sorted list of data items with xref counts. Items with the most xrefs appear first.

        JSON format returns:
        [
          {
            "address": "0x6fb835b8",
            "name": "DataTableName",
            "type": "pointer",
            "size": "4 bytes",
            "xref_count": 25
          },
          ...
        ]

        Text format returns:
        DataTableName @ 6fb835b8 [pointer] (4 bytes) - 25 xrefs
        ...

    Example:
        # Get top 50 most referenced data items as JSON
        list_data_items_by_xrefs(limit=50, format="json")

        # Get all data items sorted by xrefs (text format)
        list_data_items_by_xrefs(limit=10000, format="text")
    """
    if format not in ["text", "json"]:
        raise GhidraValidationError("format must be 'text' or 'json'")

    result = safe_get("list_data_items_by_xrefs", {"offset": offset, "limit": limit, "format": format})
    return result

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.

    Args:
        query: Search string to match against function names
        offset: Pagination offset for starting position (default: 0)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of matching functions with their names and addresses
    """
    if not query:
        raise GhidraValidationError("query string is required")
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    
    Args:
        function_name: Name of the function containing the variable
        old_name: Current name of the variable to rename
        new_name: New name for the variable
        
    Returns:
        Success or failure message indicating the result of the rename operation
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.

    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")

    Returns:
        Function information including name, signature, and address range
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return "\n".join(safe_get("get_function_by_address", {"address": address}))

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
        "function": "\n".join(safe_get_uncached("get_current_function"))
    }
    return result

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.

    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")

    Returns:
        List of assembly instructions with addresses and comments
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.

    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")
        comment: Comment text to add to the decompiled pseudocode

    Returns:
        Success or failure message indicating the result of the comment operation
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.

    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")
        comment: Comment text to add to the assembly disassembly

    Returns:
        Success or failure message indicating the result of the comment operation
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
                         Accepts addresses with or without 0x prefix
        new_name: New name for the function (must be valid C identifier)

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
    if not new_name[0].isalpha() and new_name[0] != '_':
        raise GhidraValidationError(
            f"Invalid function name '{new_name}'. "
            f"Names must start with a letter or underscore."
        )
    
    if not all(c.isalnum() or c == '_' for c in new_name):
        raise GhidraValidationError(
            f"Invalid function name '{new_name}'. "
            f"Names can only contain letters, numbers, and underscores."
        )
    
    # Verify function exists at this address
    func_check = safe_get("get_function_by_address", {"address": function_address})
    if not func_check or any("Error" in str(line) or "not found" in str(line).lower() for line in func_check):
        raise GhidraValidationError(
            f"No function found at address {function_address}. "
            f"Use get_function_by_address() to verify the address, or "
            f"list_functions() to see all available functions."
        )

    result = safe_post("rename_function_by_address", {
        "function_address": function_address, 
        "new_name": new_name
    })
    
    # Provide clear success/failure messages
    if "success" in result.lower() or "renamed" in result.lower():
        return f"Successfully renamed function at {function_address} to '{new_name}'"
    elif "error" in result.lower() or "failed" in result.lower():
        return f"{result}\nVerify function exists: get_function_by_address('{function_address}')"
    
    return result

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str, 
                          calling_convention: str = None, timeout: int = None) -> str:
    """
    Set a function's prototype and optionally its calling convention.

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
                         Accepts addresses with or without 0x prefix
        prototype: Function prototype string (e.g., "int main(int argc, char* argv[])")
                  Must be valid C function declaration syntax
        calling_convention: Optional calling convention (e.g., "__cdecl", "__stdcall", "__fastcall", "__thiscall")
                           Use list_calling_conventions() to see available conventions
        timeout: Optional timeout in seconds for this operation (default: 45s)

    Returns:
        str: Success or failure message indicating the result of the prototype update

    Raises:
        GhidraValidationError: If address format is invalid or function not found

    Examples:
        # Set basic function prototype
        set_function_prototype("0x401000", "int calculate(int x, int y)")
        
        # Set prototype with calling convention
        set_function_prototype("0x401000", "void __stdcall ProcessData(void* buffer, int size)", "__stdcall")
        
        # Set prototype with custom timeout
        set_function_prototype("0x401000", "void ComplexFunction(void)", timeout=90)

    Note:
        After changing a prototype, use get_decompiled_code() with refresh_cache=True 
        to see the updated decompilation.
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
            "Example: 'int calculate(int x, int y)'"
        )
    
    # Verify function exists
    func_check = safe_get("get_function_by_address", {"address": function_address})
    if not func_check or any("Error" in str(line) or "not found" in str(line).lower() for line in func_check):
        raise GhidraValidationError(
            f"No function found at address {function_address}. "
            f"Use get_function_by_address() to verify the address."
        )
    
    # Apply custom timeout if specified
    if timeout:
        original_timeout = ENDPOINT_TIMEOUTS.get('set_function_prototype', 45)
        ENDPOINT_TIMEOUTS['set_function_prototype'] = timeout

    try:
        data = {"function_address": function_address, "prototype": prototype.strip()}
        if calling_convention:
            data["calling_convention"] = calling_convention.strip()
            
        result = safe_post_json("set_function_prototype", data)
        
        # Provide actionable error messages
        if "success" in result.lower():
            msg = f"Successfully set prototype for function at {function_address}"
            if calling_convention:
                msg += f" with {calling_convention} calling convention"
            msg += f"\nUse: get_decompiled_code('{function_address}', refresh_cache=True) to see changes"
            return msg
        elif "invalid calling convention" in result.lower():
            return (f"{result}\n"
                   f"Use list_calling_conventions() to see available conventions.")
        elif "error" in result.lower() or "failed" in result.lower():
            return (f"{result}\n"
                   f"Verify prototype syntax is valid C (e.g., 'int func(int x)').")
        
        return result
    finally:
        # Restore original timeout
        if timeout:
            ENDPOINT_TIMEOUTS['set_function_prototype'] = original_timeout

@mcp.tool()
def list_calling_conventions() -> str:
    """
    List all available calling conventions in the current Ghidra program.

    This tool is useful for debugging and verifying which calling conventions
    are loaded, especially after adding custom conventions to x86win.cspec.

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
    return safe_get("list_calling_conventions")

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
        variable_name: Name of the local variable to modify
        new_type: New data type for the variable (e.g., "int", "char*", "MyStruct")

    Returns:
        Success or failure message indicating the result of the type change
    """
    if not validate_hex_address(function_address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {function_address}")

    return safe_post("set_local_variable_type", {
        "function_address": function_address,
        "variable_name": variable_name,
        "new_type": new_type
    })

@mcp.tool()
def set_function_no_return(function_address: str, no_return: bool) -> str:
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

    return safe_post("set_function_no_return", {
        "function_address": function_address,
        "no_return": str(no_return).lower()  # Convert boolean to string for HTTP form data
    })


@mcp.tool()
def set_variable_storage(function_address: str, variable_name: str, storage: str) -> str:
    """
    Set custom storage for a local variable or parameter (v1.7.0).

    This allows overriding Ghidra's automatic variable storage detection, which is
    crucial for fixing decompilation issues caused by compiler optimizations.

    **Use Cases:**
    - Fix register reuse issues (e.g., EBP used as local variable after PUSH EBP)
    - Correct variables misidentified as "unaff_" (unaffected registers)
    - Override incorrect automatic stack variable allocation
    - Force specific register or stack storage for variables

    **Common Register Reuse Pattern:**
    When a compiler pushes a register like EBP, then reuses it as a local variable:
    ```asm
    PUSH EBP        ; Save EBP
    CALL func       ; Returns value in EAX
    MOV EBP,EAX     ; Reuse EBP as local variable!
    TEST EBP,EBP    ; Use it
    ```

    Ghidra sees this as "unaff_EBP" and produces incorrect decompilation.
    Use this tool to create a proper local variable for the reused register.

    Args:
        function_address: Function address in hex (e.g., "0x6fb6aef0")
        variable_name: Name of variable to modify (e.g., "unaff_EBP")
        storage: Storage specification in one of these formats:
            - "Stack[-0x10]:4" - Stack location at offset -0x10, 4 bytes
            - "EBP:4" - EBP register, 4 bytes
            - "register:EBP" - EBP register (auto-sized)
            - "EAX:4" - EAX register, 4 bytes

    Returns:
        Success message with old and new storage details

    Example:
        # Fix EBP register reuse issue
        set_variable_storage(
            function_address="0x6fb6aef0",
            variable_name="unaff_EBP",
            storage="Stack[-0x4]:4"  # Move to stack to clarify it's a local var
        )

        # Then force re-decompilation to see the fix
        force_decompile("0x6fb6aef0")

    Note:
        After changing variable storage, use force_decompile() to see the updated
        decompilation with the new variable assignments.
    """
    if not validate_hex_address(function_address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {function_address}")

    if not variable_name or not variable_name.strip():
        raise GhidraValidationError("Variable name cannot be empty")

    if not storage or not storage.strip():
        raise GhidraValidationError("Storage specification cannot be empty")

    return safe_post("set_variable_storage", {
        "function_address": function_address,
        "variable_name": variable_name,
        "storage": storage
    })

@mcp.tool()
def run_script(script_path: str, args: str = "") -> str:
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

    return safe_post("run_script", {
        "script_path": script_path,
        "args": args
    })

@mcp.tool()
def list_scripts(filter: str = "") -> str:
    """
    List available Ghidra scripts (v1.7.0).

    Returns a JSON list of all Ghidra scripts available in the script directories,
    optionally filtered by name.

    Args:
        filter: Optional filter string to match script names (case-sensitive substring match)

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

    return safe_get("list_scripts", params)


@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")
    
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).

    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)

    Returns:
        List of references from the specified address
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 100, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 100)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def get_function_jump_target_addresses(name: str, offset: int = 0, limit: int = 100) -> list:
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
    return safe_get("function_jump_targets", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def create_label(address: str, name: str) -> str:
    """
    Create a new label at the specified address.

    This tool creates labels at any memory address, including undefined memory.
    Use this for addresses without defined data types.

    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
                Accepts addresses with or without 0x prefix
        name: Name for the new label (must be valid C identifier)

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
    if not name[0].isalpha() and name[0] != '_':
        raise GhidraValidationError(
            f"Invalid label name '{name}'. "
            f"Names must start with a letter or underscore."
        )
    
    if not all(c.isalnum() or c == '_' for c in name):
        raise GhidraValidationError(
            f"Invalid label name '{name}'. "
            f"Names can only contain letters, numbers, and underscores."
        )

    result = safe_post("create_label", {"address": address, "name": name})
    
    # Provide actionable error messages
    if "success" in result.lower() or "created" in result.lower():
        return f"Successfully created label '{name}' at {address}"
    elif "already exists" in result.lower():
        return (f"{result}\n"
               f"Try: rename_label('{address}', old_name, '{name}') to rename existing label.")
    elif "error" in result.lower() or "failed" in result.lower():
        return f"{result}\nVerify address is valid: get_function_by_address('{address}')"
    
    return result

@mcp.tool()
def batch_create_labels(labels: list) -> str:
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
            raise GhidraValidationError(f"Label at index {i} must have 'address' and 'name' fields")

        if not validate_hex_address(label["address"]):
            raise GhidraValidationError(f"Invalid hexadecimal address at index {i}: {label['address']}")

    return safe_post_json("batch_create_labels", {
        "labels": labels
    })

@mcp.tool()
def rename_or_label(address: str, name: str) -> str:
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

    Returns:
        Success or failure message with details about the operation performed
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_post("rename_or_label", {
        "address": address,
        "name": name
    })

@mcp.tool()
def get_function_callees(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all functions called by the specified function (callees).
    
    This tool analyzes a function and returns all functions that it calls directly.
    Useful for understanding what functionality a function depends on.
    
    Args:
        name: Function name to analyze for callees
        offset: Pagination offset (default: 0)
        limit: Maximum number of callees to return (default: 100)
        
    Returns:
        List of functions called by the specified function
    """
    return safe_get("function_callees", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_callers(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all functions that call the specified function (callers).
    
    This tool finds all functions that call the specified function, helping to
    understand the function's usage throughout the program.
    
    Args:
        name: Function name to find callers for
        offset: Pagination offset (default: 0)
        limit: Maximum number of callers to return (default: 100)
        
    Returns:
        List of functions that call the specified function
    """
    return safe_get("function_callers", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_call_graph(name: str, depth: int = 2, direction: str = "both") -> list:
    """
    Get a call graph subgraph centered on the specified function.
    
    This tool generates a localized call graph showing the relationships between
    a function and its callers/callees up to a specified depth.
    
    Args:
        name: Function name to center the graph on
        depth: Maximum depth to traverse (default: 2)
        direction: Direction to traverse ("callers", "callees", "both")
        
    Returns:
        List of call graph relationships in the format "caller -> callee"
    """
    return safe_get("function_call_graph", {"name": name, "depth": depth, "direction": direction})

@mcp.tool()
def get_full_call_graph(format: str = "edges", limit: int = 500) -> list:
    """
    Get the complete call graph for the entire program.
    
    This tool generates a comprehensive call graph showing all function call
    relationships in the program. Can be output in different formats.
    
    Args:
        format: Output format ("edges", "adjacency", "dot", "mermaid")
        limit: Maximum number of relationships to return (default: 500)
        
    Returns:
        Complete call graph in the specified format
    """
    return safe_get("full_call_graph", {"format": format, "limit": limit})

@mcp.tool()
def list_data_types(category: str = None, offset: int = 0, limit: int = 100) -> list:
    """
    List all data types available in the program with optional category filtering.
    
    This tool enumerates all data types defined in the program's data type manager,
    including built-in types, user-defined structs, enums, and imported types.
    
    Args:
        category: Optional category filter (e.g., "builtin", "struct", "enum", "pointer")
        offset: Pagination offset (default: 0)
        limit: Maximum number of data types to return (default: 100)
        
    Returns:
        List of data types with their names, categories, and sizes
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    return safe_get("list_data_types", params)

@mcp.tool()
def create_struct(name: str, fields: list) -> str:
    """
    Create a new structure data type with specified fields.

    This tool creates a custom structure definition that can be applied to memory
    locations. Fields should be specified as a list of dictionaries with 'name'
    and 'type' keys (offset is optional).

    IMPORTANT: The 'fields' parameter should be a Python list of dictionaries.
    The tool will automatically convert it to proper JSON format for the Ghidra endpoint.

    Supported field types:
    - Integers: int, uint, long, dword, ushort, word, short, char, byte, uchar
    - Floats: float, double
    - Pointers: void* (e.g., "void*" for void pointers)
    - Arrays: typename[count] (e.g., "char[16]" for 16-byte char array)
    - Custom: Any previously defined struct or enum name

    Args:
        name: Name for the new structure (must be unique)
        fields: List of field definitions as dictionaries with:
                - name (required): Field name (must be valid C identifier)
                - type (required): Field data type from supported list above
                - offset (optional): Explicit byte offset (fields auto-calculated if omitted)

    Returns:
        Success message with structure details (name, field count, total size)
        Error message if creation fails

    Examples:
        # Simple struct with basic types
        fields = [
            {"name": "id", "type": "uint"},
            {"name": "flags", "type": "ushort"},
            {"name": "reserved", "type": "ushort"}
        ]
        result = create_struct("MyStruct", fields)

        # Struct with pointers and arrays
        fields = [
            {"name": "dwType", "type": "uint"},
            {"name": "pData", "type": "void*"},
            {"name": "wX", "type": "ushort"},
            {"name": "wY", "type": "ushort"},
            {"name": "szName", "type": "char[16]"}
        ]
        result = create_struct("UnitAny", fields)

    Note:
        - Structure size is calculated based on field types and sizes
        - Fields are added sequentially unless explicit offsets are provided
        - Structure names must be unique (not previously defined)
        - Use apply_data_type tool to apply the struct to memory locations
    """
    return safe_post_json("create_struct", {"name": name, "fields": fields})

@mcp.tool()
def create_enum(name: str, values: dict, size: int = 4) -> str:
    """
    Create a new enumeration data type with name-value pairs.
    
    This tool creates an enumeration type that can be applied to memory locations
    to provide meaningful names for numeric values.
    
    Args:
        name: Name for the new enumeration
        values: Dictionary of name-value pairs (e.g., {"OPTION_A": 0, "OPTION_B": 1})
        size: Size of the enum in bytes (1, 2, 4, or 8, default: 4)
        
    Returns:
        Success/failure message with created enumeration details
        
    Example:
        values = {"STATE_IDLE": 0, "STATE_RUNNING": 1, "STATE_STOPPED": 2}
    """
    return safe_post_json("create_enum", {"name": name, "values": values, "size": size})

@mcp.tool()
def apply_data_type(address: str, type_name: str, clear_existing: bool = True) -> str:
    """
    Apply a specific data type at the given memory address.

    This tool applies a data type definition to a memory location, which helps
    in interpreting the raw bytes as structured data during analysis.

    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        type_name: Name of the data type to apply (e.g., "int", "MyStruct", "DWORD")
        clear_existing: Whether to clear existing data/code at the address (default: True)

    Returns:
        Success/failure message with details about the applied data type
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    logger.info(f"apply_data_type called with: address={address}, type_name={type_name}, clear_existing={clear_existing}")
    data = {
        "address": address,
        "type_name": type_name,
        "clear_existing": clear_existing
    }
    logger.info(f"Data being sent: {data}")
    result = safe_post_json("apply_data_type", data)
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
        response = session.get(urljoin(ghidra_server_url, "check_connection"), timeout=REQUEST_TIMEOUT)
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
def get_metadata() -> str:
    """
    Get metadata about the current program/database.
    
    Returns program information including name, architecture, base address,
    entry points, and other relevant metadata.
    
    Returns:
        JSON string with program metadata
    """
    return "\n".join(safe_get("get_metadata"))


@mcp.tool()
def list_globals(offset: int = 0, limit: int = 100, filter: str = None) -> list:
    """
    List matching globals in the database (paginated, filtered).
    
    Lists global variables and symbols in the program with optional filtering.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of globals to return (default: 100)
        filter: Optional filter to match global names (default: None)
        
    Returns:
        List of global variables/symbols with their details
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("list_globals", params)

@mcp.tool()
def rename_global_variable(old_name: str, new_name: str) -> str:
    """
    Rename a global variable.
    
    Changes the name of a global variable or symbol in the program.
    
    Args:
        old_name: Current name of the global variable
        new_name: New name for the global variable
        
    Returns:
        Success/failure message
    """
    return safe_post("rename_global_variable", {
        "old_name": old_name,
        "new_name": new_name
    })

@mcp.tool()
def get_entry_points() -> list:
    """
    Get all entry points in the database.
    
    Returns all program entry points including the main entry point and any
    additional entry points defined in the program.
    
    Returns:
        List of entry points with their addresses and names
    """
    return safe_get("get_entry_points")

# Data Type Analysis and Management Tools

@mcp.tool()
def get_enum_values(enum_name: str) -> list:
    """
    Get all values and names in an enumeration.

    Args:
        enum_name: Name of the enumeration to query

    Returns:
        List of all enumeration values with their names and numeric values
    """
    return safe_get("get_enum_values", {"enum_name": enum_name})




@mcp.tool()
def search_byte_patterns(pattern: str, mask: str = None) -> list:
    """
    Search for byte patterns with optional wildcards (e.g., 'E8 ?? ?? ?? ??').
    Useful for finding shellcode, API calls, or specific instruction sequences.

    **IMPLEMENTED in v1.7.1** - Searches all initialized memory blocks for matching byte sequences.
    Supports wildcard patterns using '??' for any byte. Returns up to 1000 matches.

    Args:
        pattern: Hexadecimal pattern to search for (e.g., "E8 ?? ?? ?? ??")
        mask: Optional mask for wildcards (use ? for wildcards)

    Returns:
        List of addresses where the pattern was found

    Example:
        search_byte_patterns("E8 ?? ?? ?? ??")  # Find all CALL instructions
        search_byte_patterns("558BEC")  # Find standard function prologue
    """
    params = {"pattern": pattern}
    if mask:
        params["mask"] = mask
    return safe_get("search_byte_patterns", params)




@mcp.tool()
def delete_data_type(type_name: str) -> str:
    """
    Delete a data type from the program.
    
    This tool removes a data type (struct, enum, typedef, etc.) from the program's
    data type manager. The type cannot be deleted if it's currently being used.
    
    Args:
        type_name: Name of the data type to delete
        
    Returns:
        Success or failure message with details
    """
    if not type_name or not isinstance(type_name, str):
        raise GhidraValidationError("Type name is required and must be a string")
    
    return safe_post_json("delete_data_type", {"type_name": type_name})

@mcp.tool()
def modify_struct_field(struct_name: str, field_name: str, new_type: str = None, new_name: str = None) -> str:
    """
    Modify a field in an existing structure.
    
    This tool allows changing the type and/or name of a field in an existing structure.
    At least one of new_type or new_name must be provided.
    
    Args:
        struct_name: Name of the structure to modify
        field_name: Name of the field to modify
        new_type: New data type for the field (optional)
        new_name: New name for the field (optional)
        
    Returns:
        Success or failure message with details
    """
    if not struct_name or not isinstance(struct_name, str):
        raise GhidraValidationError("Structure name is required and must be a string")
    if not field_name or not isinstance(field_name, str):
        raise GhidraValidationError("Field name is required and must be a string")
    if not new_type and not new_name:
        raise GhidraValidationError("At least one of new_type or new_name must be provided")
    
    data = {
        "struct_name": struct_name,
        "field_name": field_name
    }
    if new_type:
        data["new_type"] = new_type
    if new_name:
        data["new_name"] = new_name
    
    return safe_post_json("modify_struct_field", data)

@mcp.tool()
def add_struct_field(struct_name: str, field_name: str, field_type: str, offset: int = -1) -> str:
    """
    Add a new field to an existing structure.
    
    This tool adds a new field to an existing structure at the specified offset
    or at the end if no offset is provided.
    
    Args:
        struct_name: Name of the structure to modify
        field_name: Name of the new field
        field_type: Data type of the new field
        offset: Offset to insert the field at (-1 for end, default: -1)
        
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
        "offset": offset
    }
    
    return safe_post_json("add_struct_field", data)

@mcp.tool()
def remove_struct_field(struct_name: str, field_name: str) -> str:
    """
    Remove a field from an existing structure.
    
    This tool removes a field from an existing structure by name.
    
    Args:
        struct_name: Name of the structure to modify
        field_name: Name of the field to remove
        
    Returns:
        Success or failure message with details
    """
    if not struct_name or not isinstance(struct_name, str):
        raise GhidraValidationError("Structure name is required and must be a string")
    if not field_name or not isinstance(field_name, str):
        raise GhidraValidationError("Field name is required and must be a string")
    
    return safe_post_json("remove_struct_field", {
        "struct_name": struct_name,
        "field_name": field_name
    })

@mcp.tool()
def create_array_type(base_type: str, length: int, name: str = None) -> str:
    """
    Create an array data type.
    
    This tool creates a new array data type based on an existing base type
    with the specified length.
    
    Args:
        base_type: Name of the base data type for the array
        length: Number of elements in the array
        name: Optional name for the array type
        
    Returns:
        Success or failure message with created array type details
    """
    if not base_type or not isinstance(base_type, str):
        raise GhidraValidationError("Base type is required and must be a string")
    if not isinstance(length, int) or length <= 0:
        raise GhidraValidationError("Length must be a positive integer")
    
    data = {
        "base_type": base_type,
        "length": length
    }
    if name:
        data["name"] = name
    
    return safe_post_json("create_array_type", data)






@mcp.tool()
def analyze_data_region(
    address: str,
    max_scan_bytes: int = 1024,
    include_xref_map: bool = True,
    include_assembly_patterns: bool = True,
    include_boundary_detection: bool = True
) -> str:
    """
    Comprehensive single-call analysis of a data region.

    This tool performs complete data region analysis including boundary detection,
    byte-by-byte xref mapping, stride detection, and classification hints.
    Replaces 20-30 individual tool calls with one efficient batch operation.

    Args:
        address: Starting address in hex format (e.g., "0x6fb835b8")
        max_scan_bytes: Maximum bytes to scan for boundary detection (default: 1024)
        include_xref_map: Include detailed byte-by-byte xref mapping (default: True)
        include_assembly_patterns: Include assembly pattern analysis (default: True)
        include_boundary_detection: Detect data region boundaries (default: True)

    Returns:
        JSON string with comprehensive analysis:
        {
          "start_address": "0x6fb835b8",
          "end_address": "0x6fb835d4",
          "byte_span": 28,
          "xref_map": {"0x6fb835b8": [{"from": "0x6fb6cae9", "type": "DATA"}], ...},
          "unique_xref_addresses": ["0x6fb835b8", "0x6fb835bc", ...],
          "unique_xref_count": 5,
          "classification_hint": "STRUCTURE|ARRAY|PRIMITIVE",
          "stride_detected": 4,
          "next_boundary_address": "0x6fb835d4",
          "next_boundary_reason": "different_xref_set|named_label|end_of_data",
          "current_name": "DAT_6fb835b8",
          "current_type": "undefined"
        }
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
        "include_boundary_detection": include_boundary_detection
    }

    result = safe_post_json("analyze_data_region", data)

    # Format the JSON response for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result

@mcp.tool()
def inspect_memory_content(address: str, length: int = 64, detect_strings: bool = True) -> str:
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
        "detect_strings": str(detect_strings).lower()
    }

    result = "\n".join(safe_get("inspect_memory_content", params))

    # Try to format as JSON for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result

@mcp.tool()
def get_bulk_xrefs(addresses: str) -> str:
    """
    Get cross-references for multiple addresses in a single batch request.

    This tool retrieves xrefs for multiple addresses simultaneously, dramatically
    reducing the number of network round-trips required for byte-by-byte analysis.

    Args:
        addresses: Comma-separated list of hex addresses (e.g., "0x6fb835b8,0x6fb835b9,0x6fb835ba")
                  or JSON array string (e.g., '["0x6fb835b8", "0x6fb835b9"]')

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
    if addresses.startswith('['):
        try:
            addr_list = json.loads(addresses)
        except:
            raise GhidraValidationError("Invalid JSON array format for addresses")
    else:
        addr_list = [addr.strip() for addr in addresses.split(',')]

    # Validate all addresses
    for addr in addr_list:
        if not validate_hex_address(addr):
            raise GhidraValidationError(f"Invalid hex address format: {addr}")

    data = {"addresses": addr_list}
    result = safe_post_json("get_bulk_xrefs", data)

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
    max_scan_range: int = 2048
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
        "max_scan_range": max_scan_range
    }

    result = safe_post_json("detect_array_bounds", data)

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
    include_patterns: str = "LEA,MOV,CMP,IMUL,ADD,SUB"
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
    if xref_sources.startswith('['):
        try:
            addr_list = json.loads(xref_sources)
        except:
            raise GhidraValidationError("Invalid JSON array format for xref_sources")
    else:
        addr_list = [addr.strip() for addr in xref_sources.split(',')]

    # Validate all addresses
    for addr in addr_list:
        if not validate_hex_address(addr):
            raise GhidraValidationError(f"Invalid hex address format: {addr}")

    if not isinstance(context_instructions, int) or context_instructions < 0:
        raise GhidraValidationError("context_instructions must be a non-negative integer")

    pattern_list = [p.strip() for p in include_patterns.split(',')]

    data = {
        "xref_sources": addr_list,
        "context_instructions": context_instructions,
        "include_patterns": pattern_list
    }

    result = safe_post_json("get_assembly_context", data)

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
    address: str,
    struct_name: str = None,
    max_functions: int = 10
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

    data = {
        "address": address,
        "max_functions": max_functions
    }
    if struct_name:
        data["struct_name"] = struct_name

    result = safe_post_json("analyze_struct_field_usage", data)

    # Format the JSON response for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result

@mcp.tool()
def get_field_access_context(
    struct_address: str,
    field_offset: int,
    num_examples: int = 5
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
        "num_examples": num_examples
    }

    result = safe_post_json("get_field_access_context", data)

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
    plate_comment: str = None
) -> str:
    """
    Set multiple comments in a single operation (v1.5.0).
    Reduces API calls from 10+ to 1 for typical function documentation.

    Args:
        function_address: Function address for plate comment
        decompiler_comments: List of {"address": "0x...", "comment": "..."} for PRE_COMMENT
        disassembly_comments: List of {"address": "0x...", "comment": "..."} for EOL_COMMENT
        plate_comment: Function header summary comment

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
        "plate_comment": plate_comment
    }

    return safe_post_json("batch_set_comments", payload)

@mcp.tool()
def set_plate_comment(
    function_address: str,
    comment: str
) -> str:
    """
    Set function plate (header) comment (v1.5.0).
    This comment appears above the function in both disassembly and decompiler views.

    Args:
        function_address: Function address in hex format (e.g., "0x401000")
        comment: Function header summary comment

    Returns:
        Success or failure message
    """
    validate_hex_address(function_address)

    # Convert escaped newlines to actual newlines
    comment = _convert_escaped_newlines(comment)

    params = {"function_address": function_address, "comment": comment}
    result = safe_post("set_plate_comment", params)

    # Verify plate comment was applied by decompiling the function
    # This works around a Ghidra decompiler cache race condition where
    # plate comments may not immediately appear in decompilation output
    if "Success" in result:
        try:
            # Get function name to decompile
            func_info = safe_get("get_function_by_address", {"address": function_address})
            if "error" not in func_info.lower():
                import json
                func_data = json.loads(func_info)
                func_name = func_data.get("name", "")

                if func_name:
                    # Wait brief moment for cache to settle
                    import time
                    time.sleep(0.3)

                    # Decompile and check for plate comment
                    decompiled = safe_get("decompile_function", {"name": func_name})

                    # If plate comment shows as "/* null */", retry once
                    if "/* null */" in decompiled:
                        logger.warning(f"Plate comment cache miss detected at {function_address}, retrying...")
                        time.sleep(0.5)  # Longer wait before retry
                        result = safe_post("set_plate_comment", params)

                        # Verify retry succeeded
                        time.sleep(0.3)
                        decompiled = safe_get("decompile_function", {"name": func_name})
                        if "/* null */" in decompiled:
                            result += " (WARNING: Plate comment may require additional retry - cache persistence issue)"
        except Exception as e:
            logger.debug(f"Could not verify plate comment: {e}")

    return result

@mcp.tool()
def get_function_variables(
    function_name: str
) -> str:
    """
    List all variables in a function including parameters and locals (v1.5.0).

    Args:
        function_name: Name of the function

    Returns:
        JSON with function variables including names, types, and storage locations
    """
    validate_function_name(function_name)

    params = {"function_name": function_name}
    return safe_get("get_function_variables", params)

@mcp.tool()
def batch_rename_function_components(
    function_address: str,
    function_name: str = None,
    parameter_renames: dict = None,
    local_renames: dict = None,
    return_type: str = None
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

    Returns:
        JSON with success status and counts of renamed components
    """
    validate_hex_address(function_address)

    payload = {
        "function_address": function_address,
        "function_name": function_name,
        "parameter_renames": parameter_renames or {},
        "local_renames": local_renames or {},
        "return_type": return_type
    }

    return safe_post_json("batch_rename_function_components", payload)

@mcp.tool()
def get_valid_data_types(
    category: str = None
) -> str:
    """
    Get list of valid Ghidra data type strings (v1.5.0).
    Helps construct proper type definitions for create_struct and other type operations.

    Args:
        category: Optional category filter (not currently used)

    Returns:
        JSON with lists of builtin_types and windows_types
    """
    params = {"category": category} if category else {}
    return safe_get("get_valid_data_types", params)


@mcp.tool()
def analyze_function_completeness(
    function_address: str
) -> str:
    """
    Analyze how completely a function has been documented (v1.5.0).
    Checks for custom names, prototypes, comments, and undefined variables.

    Args:
        function_address: Function address in hex format

    Returns:
        JSON with completeness analysis including:
        - has_custom_name, has_prototype, has_calling_convention
        - has_plate_comment, undefined_variables
        - completeness_score (0-100)
    """
    validate_hex_address(function_address)

    params = {"function_address": function_address}
    return safe_get("analyze_function_completeness", params)

@mcp.tool()
def find_next_undefined_function(
    start_address: str = None,
    criteria: str = "name_pattern",
    pattern: str = "FUN_",
    direction: str = "ascending"
) -> str:
    """
    Find the next function needing analysis (v1.5.0).
    Intelligently searches for functions matching specified criteria.

    Args:
        start_address: Starting address for search (default: program min address)
        criteria: Search criteria (default: "name_pattern")
        pattern: Name pattern to match (default: "FUN_")
        direction: Search direction "ascending" or "descending" (default: "ascending")

    Returns:
        JSON with found function details or {"found": false}
    """
    if start_address:
        validate_hex_address(start_address)

    params = {
        "start_address": start_address,
        "criteria": criteria,
        "pattern": pattern,
        "direction": direction
    }
    return safe_get("find_next_undefined_function", params)

@mcp.tool()
def batch_set_variable_types(
    function_address: str,
    variable_types: dict
) -> str:
    """
    Set types for multiple variables in a single operation (v1.5.0).

    Args:
        function_address: Function address in hex format
        variable_types: Dict of {"variable_name": "type_name"}

    Returns:
        JSON with success status and count of variables typed
    """
    validate_hex_address(function_address)

    payload = {
        "function_address": function_address,
        "variable_types": variable_types or {}
    }

    return safe_post_json("batch_set_variable_types", payload)

# ========== HIGH PRIORITY: WORKFLOW ENHANCEMENTS (v1.6.0) ==========

@mcp.tool()
def batch_rename_variables(
    function_address: str,
    variable_renames: dict
) -> str:
    """
    Rename multiple variables in a function atomically (v1.6.0).

    This tool renames multiple local variables or parameters in a single
    transaction with partial success reporting.

    Args:
        function_address: Function address in hex format (e.g., "0x401000")
        variable_renames: Dict of {"old_name": "new_name"} pairs

    Returns:
        JSON with detailed results:
        {
          "success": true,
          "variables_renamed": 5,
          "variables_failed": 1,
          "errors": [{"old_name": "var1", "error": "Variable not found"}]
        }

    Example:
        batch_rename_variables("0x6fb385a0", {
            "param_1": "eventRecord",
            "local_4": "playerNode",
            "iVar1": "skillIndex"
        })
    """
    validate_hex_address(function_address)

    payload = {
        "function_address": function_address,
        "variable_renames": variable_renames or {}
    }

    return safe_post_json("batch_rename_variables", payload)




@mcp.tool()
def analyze_function_complete(
    name: str,
    include_xrefs: bool = True,
    include_callees: bool = True,
    include_callers: bool = True,
    include_disasm: bool = True,
    include_variables: bool = True
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
        "include_variables": include_variables
    }
    return safe_get("analyze_function_complete", params)

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
    limit: int = 100
) -> str:
    """
    Enhanced function search with filtering and sorting (v1.6.0).

    Provides powerful search capabilities to find functions matching
    multiple criteria, with support for regex patterns and sorting.

    Args:
        name_pattern: Function name pattern (substring or regex)
        min_xrefs: Minimum number of cross-references
        max_xrefs: Maximum number of cross-references
        calling_convention: Filter by calling convention
        has_custom_name: True=user-named only, False=default names (FUN_) only
        regex: Enable regex pattern matching
        sort_by: Sort order: "address"|"name"|"xref_count" (default: "address")
        offset: Pagination offset
        limit: Maximum results to return

    Returns:
        JSON with search results:
        {
          "total": 150,
          "offset": 0,
          "limit": 100,
          "results": [
            {
              "name": "ProcessPlayerSkillCooldowns",
              "address": "0x6fb385a0",
              "xref_count": 5,
              "calling_convention": "__cdecl"
            }
          ]
        }

    Example:
        # Find all FUN_ functions with 2+ xrefs, sorted by xref count
        search_functions_enhanced(
            name_pattern="FUN_",
            min_xrefs=2,
            sort_by="xref_count",
            limit=50
        )
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
        "limit": limit
    }
    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    return safe_get("search_functions_enhanced", params)

@mcp.tool()
def disassemble_bytes(
    start_address: str,
    end_address: str = None,
    length: int = None,
    restrict_to_execute_memory: bool = True
) -> str:
    """
    Disassemble a range of undefined bytes at a specific address (v1.7.1).

    This tool converts undefined bytes into disassembled instructions, which is
    essential after clearing flow overrides that previously hid code.

    Args:
        start_address: Starting address in hex format (e.g., "0x6fb4ca14")
        end_address: Optional ending address in hex format (exclusive)
        length: Optional length in bytes (alternative to end_address)
        restrict_to_execute_memory: If true, restricts to executable memory (default: True)

    Returns:
        JSON with disassembly result:
        {
          "success": true,
          "start_address": "0x6fb4ca14",
          "end_address": "0x6fb4ca28",
          "bytes_disassembled": 21,
          "message": "Successfully disassembled 21 byte(s)"
        }

    Example:
        # Disassemble 21 bytes at 0x6fb4ca14
        disassemble_bytes("0x6fb4ca14", length=21)

        # Disassemble range from 0x6fb4ca14 to 0x6fb4ca29 (exclusive)
        disassemble_bytes("0x6fb4ca14", end_address="0x6fb4ca29")

        # Auto-detect length (scan until existing code/data found)
        disassemble_bytes("0x6fb4ca14")

    Note:
        If neither end_address nor length is provided, the tool will automatically
        detect the range by scanning until it hits existing instructions or defined data.
    """
    if not validate_hex_address(start_address):
        raise GhidraValidationError(f"Invalid start address format: {start_address}")

    if end_address and not validate_hex_address(end_address):
        raise GhidraValidationError(f"Invalid end address format: {end_address}")

    data = {
        "start_address": start_address,
        "end_address": end_address,
        "length": length,
        "restrict_to_execute_memory": restrict_to_execute_memory
    }

    # Remove None values
    data = {k: v for k, v in data.items() if v is not None}

    return safe_post_json("disassemble_bytes", data)

# ========== SCRIPT GENERATION (v1.9.0) ==========


# ========== SCRIPT LIFECYCLE MANAGEMENT (v1.9.1) ==========

@mcp.tool()
def save_ghidra_script(
    script_name: str,
    script_content: str,
    overwrite: bool = False,
    backup: bool = True
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
    if not all(c.isalnum() or c == '_' for c in script_name):
        raise GhidraValidationError("script_name must be alphanumeric or underscore only")

    # Build path
    script_dir = "ghidra_scripts"
    script_file = f"{script_name}.java"
    script_path = os.path.join(script_dir, script_file)

    # Create directory if needed
    try:
        os.makedirs(script_dir, exist_ok=True)
    except Exception as e:
        raise GhidraValidationError(f"Could not create ghidra_scripts directory: {e}")

    # Check if file exists and overwrite setting
    if os.path.exists(script_path) and not overwrite:
        raise GhidraValidationError(f"Script {script_name} already exists. Use overwrite=True to replace.")

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
        with open(script_path, 'w', encoding='utf-8') as f:
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
        "message": "Script saved successfully"
    }

    if backup_path:
        response["backup_path"] = backup_path

    return json.dumps(response, indent=2)

@mcp.tool()
def list_ghidra_scripts(
    filter_pattern: str = None,
    include_metadata: bool = True
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

    script_dir = "ghidra_scripts"
    scripts = []

    # Create directory if missing
    if not os.path.exists(script_dir):
        os.makedirs(script_dir, exist_ok=True)

    try:
        # Scan directory for .java files
        for filename in sorted(os.listdir(script_dir)):
            if not filename.endswith('.java'):
                continue

            filepath = os.path.join(script_dir, filename)
            script_name = filename[:-5]  # Remove .java extension

            # Apply filter if provided
            if filter_pattern:
                import re
                if not re.search(filter_pattern, script_name):
                    continue

            script_info = {
                "name": script_name,
                "filename": filename,
                "path": filepath
            }

            if include_metadata:
                try:
                    # Get file stats
                    stat_info = os.stat(filepath)
                    script_info["size"] = stat_info.st_size
                    modified = datetime.fromtimestamp(stat_info.st_mtime)
                    script_info["modified"] = modified.isoformat() + "Z"

                    # Count lines of code (rough estimate)
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        script_info["lines_of_code"] = len(f.readlines())
                except Exception as e:
                    logger.warning(f"Could not get metadata for {filename}: {e}")

            scripts.append(script_info)

    except Exception as e:
        raise GhidraValidationError(f"Could not list scripts: {e}")

    response = {
        "total_scripts": len(scripts),
        "scripts": scripts
    }

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

    script_path = os.path.join("ghidra_scripts", f"{script_name}.java")

    if not os.path.exists(script_path):
        raise GhidraValidationError(f"Script not found: {script_name}")

    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    except Exception as e:
        raise GhidraValidationError(f"Could not read script: {e}")

@mcp.tool()
def run_ghidra_script(
    script_name: str,
    timeout_seconds: int = 300,
    capture_output: bool = True
) -> str:
    """
    Run a Ghidra script and capture all output including errors.

    This tool executes a Ghidra script via the REST API and captures:
    - Complete console output (all println statements)
    - Error messages with line numbers
    - Execution time and statistics
    - Exit code and status

    **Key Feature**: Full error capture enables automatic script debugging.
    AI can read error messages and automatically fix broken scripts.

    Args:
        script_name: Script name to execute (without .java extension)
        timeout_seconds: Max execution time (default: 5 minutes)
        capture_output: Capture console output (default: True)

    Returns:
        JSON with execution results:
        {
            "success": true/false,
            "script_name": "DocumentFunctions",
            "execution_time_seconds": 45.2,
            "console_output": "Processing...\nCompleted!",
            "exit_code": 0,
            "errors": [
                {
                    "type": "RuntimeException",
                    "message": "Function not found",
                    "line": 42
                }
            ],
            "warnings": [
                {
                    "type": "Warning",
                    "message": "Variable unused",
                    "line": 15
                }
            ]
        }

    Example - Basic Execution:
        result = run_ghidra_script("DocumentFunctions")
        print(result["console_output"])

    Example - Automatic Troubleshooting:
        result = run_ghidra_script("DocumentFunctions")
        if result["errors"]:
            # AI reads errors and fixes script
            fixed_script = ai_fix_script(result["errors"])
            update_ghidra_script("DocumentFunctions", fixed_script)
            # Re-run to verify fix
            result = run_ghidra_script("DocumentFunctions")
    """
    import json

    if not script_name or not isinstance(script_name, str):
        raise GhidraValidationError("script_name is required")

    # Call Java endpoint which handles actual execution
    payload = {
        "script_name": script_name,
        "timeout_seconds": timeout_seconds,
        "capture_output": capture_output
    }

    result = safe_post_json("run_ghidra_script", payload)

    # Parse and format response
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result

@mcp.tool()
def update_ghidra_script(
    script_name: str,
    new_content: str,
    keep_backup: bool = True
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

    script_path = os.path.join("ghidra_scripts", f"{script_name}.java")

    if not os.path.exists(script_path):
        raise GhidraValidationError(f"Script not found: {script_name}")

    # Get old content for comparison
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
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
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        new_size = len(new_content)
    except Exception as e:
        raise GhidraValidationError(f"Could not update script: {e}")

    # Calculate changes
    size_delta = new_size - old_size
    lines_changed = sum(1 for a, b in zip(old_content.split('\n'), new_content.split('\n')) if a != b)

    response = {
        "success": True,
        "script_name": script_name,
        "lines_changed": lines_changed,
        "size_delta": size_delta,
        "message": "Script updated successfully"
    }

    if backup_path:
        response["previous_version_backup"] = backup_path

    return json.dumps(response, indent=2)

@mcp.tool()
def delete_ghidra_script(
    script_name: str,
    confirm: bool = False,
    archive: bool = True
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
        raise GhidraValidationError("confirm=True required for safety (prevents accidents)")

    script_path = os.path.join("ghidra_scripts", f"{script_name}.java")

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
        "message": "Script deleted successfully"
    }

    if archive_path:
        response["archive_location"] = archive_path

    return json.dumps(response, indent=2)

# ========== MAIN ==========

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8089")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
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
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
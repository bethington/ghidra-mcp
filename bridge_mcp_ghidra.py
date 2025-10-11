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

# Per-endpoint timeout configuration for expensive operations
ENDPOINT_TIMEOUTS = {
    'document_function_complete': 120,     # 2 minutes - comprehensive atomic documentation
    'batch_rename_variables': 60,          # 1 minute - variable renames can trigger re-analysis
    'batch_set_comments': 45,              # 45 seconds - multiple comment operations
    'analyze_function_complete': 60,       # 1 minute - comprehensive analysis with decompilation
    'batch_decompile_functions': 90,       # 1.5 minutes - multiple decompilations
    'batch_rename_function_components': 60, # 1 minute - multiple rename operations
    'batch_set_variable_types': 60,        # 1 minute - DataType lookups can be slow
    'analyze_data_region': 60,             # 1 minute - complex data analysis
    'batch_decompile_xref_sources': 90,    # 1.5 minutes - multiple decompilations
    'create_and_apply_data_type': 45,      # 45 seconds - struct creation + application
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

def validate_function_name(name: str) -> bool:
    """Validate function name format"""
    return bool(FUNCTION_NAME_PATTERN.match(name)) if name else False

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

    for attempt in range(retries):
        try:
            start_time = time.time()

            logger.info(f"Sending JSON POST to {url} with data: {data}")
            response = session.post(url, json=data, timeout=timeout)

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
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    
    Args:
        name: Function name to decompile
        
    Returns:
        Decompiled C code as a string
    """
    return safe_post("decompile", name)

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
        new_name: New name for the data label

    Returns:
        Success or failure message indicating the result of the rename operation

    See Also:
        - create_label(): Create label at undefined address
        - rename_or_label(): Automatically detect and use correct method
        - apply_data_type(): Define data type before renaming
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    response = safe_post("renameData", {"address": address, "newName": new_name})

    # Validate response and provide clear success message
    if "success" in response.lower() or "renamed" in response.lower():
        return f"Successfully renamed data at {address} to '{new_name}'"
    elif "error" in response.lower() or "failed" in response.lower():
        return response  # Return original error message
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
def rename_data_smart(address: str, new_name: str) -> str:
    """
    Intelligently rename data at an address, automatically detecting if it's
    defined data or undefined bytes and using the appropriate method.

    This tool automatically chooses between rename_data (for defined symbols)
    and create_label (for undefined addresses) based on the current state.

    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")
        new_name: New name for the data label

    Returns:
        Success or failure message with details about the operation performed
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    # Check if data is defined
    is_defined = _check_if_data_defined(address)

    if is_defined:
        # Use rename_data endpoint for defined symbols
        logger.info(f"Address {address} has defined data, using rename_data")
        response = safe_post("renameData", {"address": address, "newName": new_name})

        if "success" in response.lower() or "renamed" in response.lower():
            return f"✓ Renamed defined data at {address} to '{new_name}'"
        else:
            return f"Rename data attempted: {response}"
    else:
        # Use create_label for undefined addresses
        logger.info(f"Address {address} is undefined, using create_label")
        response = safe_post("create_label", {"address": address, "name": new_name})

        if "success" in response.lower() or "created" in response.lower():
            return f"✓ Created label '{new_name}' at {address} (was undefined)"
        else:
            return f"Create label attempted: {response}"

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
def get_current_address() -> str:
    """
    Get the address currently selected by the user.

    Args:
        None

    Returns:
        Current cursor/selection address in hex format
    """
    return "\n".join(safe_get_uncached("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.

    Args:
        None

    Returns:
        Information about the currently selected function including name and address
    """
    return "\n".join(safe_get_uncached("get_current_function"))

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
        new_name: New name for the function

    Returns:
        Success or failure message indicating the result of the rename operation
    """
    if not validate_hex_address(function_address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {function_address}")

    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str, calling_convention: str = None) -> str:
    """
    Set a function's prototype and optionally its calling convention.

    Args:
        function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
        prototype: Function prototype string (e.g., "int main(int argc, char* argv[])")
        calling_convention: Optional calling convention (e.g., "__cdecl", "__stdcall", "__fastcall", "__thiscall")

    Returns:
        Success or failure message indicating the result of the prototype update
    """
    if not validate_hex_address(function_address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {function_address}")

    data = {"function_address": function_address, "prototype": prototype}
    if calling_convention:
        data["callingConvention"] = calling_convention
    return safe_post_json("set_function_prototype", data)

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

    This tool creates a user-defined label at the given address. The label will be
    visible in Ghidra's Symbol Tree and can be used for navigation and reference.

    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        name: Name for the new label

    Returns:
        Success/failure message
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_post("create_label", {
        "address": address,
        "name": name
    })

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
    locations. Fields should be specified as a list of dictionaries with 'name',
    'type', and optionally 'offset' keys.
    
    Args:
        name: Name for the new structure
        fields: List of field definitions, each with:
                - name: Field name
                - type: Field data type (e.g., "int", "char", "DWORD")
                - offset: Optional explicit offset (auto-calculated if omitted)
                
    Returns:
        Success/failure message with created structure details
        
    Example:
        fields = [
            {"name": "id", "type": "int"},
            {"name": "name", "type": "char[32]"},
            {"name": "flags", "type": "DWORD"}
        ]
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
def format_number_conversions(text: str, size: int = 4) -> str:
    """
    Convert a number (decimal, hexadecimal) to different representations.
    
    Takes a number in various formats and converts it to decimal, hexadecimal,
    binary, and other useful representations.
    
    Args:
        text: Number to convert (can be decimal like "123" or hex like "0x7B")
        size: Size in bytes for representation (1, 2, 4, or 8, default: 4)
        
    Returns:
        String with multiple number representations
    """
    return "\n".join(safe_get("convert_number", {"text": text, "size": size}))

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
def analyze_data_types(address: str, depth: int = 1) -> list:
    """
    Analyze data types at a given address with specified depth.

    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        depth: Analysis depth for following pointers and references (default: 1)

    Returns:
        Detailed analysis of data types at the specified address
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_get("analyze_data_types", {"address": address, "depth": depth})

@mcp.tool()
def create_union(name: str, fields: list) -> str:
    """
    Create a new union data type with specified fields.
    
    Args:
        name: Name for the new union
        fields: List of field definitions, each with:
                - name: Field name
                - type: Field data type (e.g., "int", "char", "DWORD")
                
    Returns:
        Success/failure message with created union details
        
    Example:
        fields = [
            {"name": "as_int", "type": "int"},
            {"name": "as_float", "type": "float"},
            {"name": "as_bytes", "type": "char[4]"}
        ]
    """
    import json
    fields_json = json.dumps(fields) if isinstance(fields, list) else str(fields)
    return safe_post("create_union", {"name": name, "fields": fields_json})

@mcp.tool()
def get_data_type_size(type_name: str) -> list:
    """
    Get the size and alignment information for a data type.

    Args:
        type_name: Name of the data type to query

    Returns:
        Size, alignment, and path information for the data type
    """
    return safe_get("get_type_size", {"type_name": type_name})

@mcp.tool()
def get_struct_layout(struct_name: str) -> list:
    """
    Get the detailed layout of a structure including field offsets.

    Args:
        struct_name: Name of the structure to analyze

    Returns:
        Detailed structure layout with field offsets, sizes, and types
    """
    return safe_get("get_struct_layout", {"struct_name": struct_name})

@mcp.tool()
def search_data_types(pattern: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for data types by name pattern.
    
    Args:
        pattern: Search pattern to match against data type names
        offset: Pagination offset (default: 0)
        limit: Maximum number of results to return (default: 100)
        
    Returns:
        List of matching data types with their details
    """
    return safe_get("search_data_types", {"pattern": pattern, "offset": offset, "limit": limit})

@mcp.tool()
def auto_create_struct_from_memory(address: str, size: int, name: str) -> str:
    """
    Automatically create a structure by analyzing memory layout at an address.

    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        size: Size in bytes to analyze (0 for automatic detection)
        name: Name for the new structure

    Returns:
        Success/failure message with created structure details
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_post("auto_create_struct", {"address": address, "size": size, "name": name})

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
def create_typedef(name: str, base_type: str) -> str:
    """
    Create a typedef (type alias) for an existing data type.
    
    Args:
        name: Name for the new typedef
        base_type: Name of the base data type to alias
        
    Returns:
        Success/failure message with typedef creation details
    """
    return safe_post("create_typedef", {"name": name, "base_type": base_type})

@mcp.tool()
def clone_data_type(source_type: str, new_name: str) -> str:
    """
    Clone/copy an existing data type with a new name.
    
    Args:
        source_type: Name of the source data type to clone
        new_name: Name for the cloned data type
        
    Returns:
        Success/failure message with cloning details
    """
    return safe_post("clone_data_type", {"source_type": source_type, "new_name": new_name})

@mcp.tool()
def validate_data_type(address: str, type_name: str) -> list:
    """
    Validate if a data type can be properly applied at a given address.

    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        type_name: Name of the data type to validate

    Returns:
        Validation results including memory availability, alignment, and conflicts
    """
    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hexadecimal address: {address}")

    return safe_get("validate_data_type", {"address": address, "type_name": type_name})

@mcp.tool()
def export_data_types(format: str = "c", category: str = None) -> list:
    """
    Export data types in various formats.

    Args:
        format: Export format ("c", "json", "summary") - default: "c"
        category: Optional category filter for data types

    Returns:
        Exported data types in the specified format
    """
    params = {"format": format}
    if category:
        params["category"] = category
    return safe_get("export_data_types", params)

@mcp.tool()
def import_data_types(source: str, format: str = "c") -> str:
    """
    [ROADMAP v2.0] Import data types from various sources.

    IMPLEMENTATION STATUS: Placeholder - Returns "Import functionality not yet implemented"
    PLANNED FOR: Version 2.0

    Planned functionality:
    - Parse C header files and extract struct/enum/typedef definitions
    - Import JSON-formatted type definitions
    - Support Ghidra Data Type Archive (.gdt) files
    - Handle type conflicts and dependencies
    - Validate imported types before applying
    - Batch import multiple types in single operation

    Related tool:
    - export_data_types(): Fully implemented - export types to C/JSON/summary formats

    Args:
        source: Source data containing type definitions (C header, JSON, etc.)
        format: Format of the source data ("c", "json") - default: "c"

    Returns:
        Currently: Placeholder message
        Future: Import results with success/failure counts and error details
    """
    return safe_post("import_data_types", {"source": source, "format": format})

# === MALWARE ANALYSIS TOOLS (ROADMAP - v2.0) ===
# NOTE: The following tools are planned for future implementation.
# They currently return placeholder responses from the Java plugin.
# Status: ROADMAP features targeted for v2.0 release

@mcp.tool()
def detect_crypto_constants() -> list:
    """
    [ROADMAP v2.0] Identify cryptographic constants and algorithms in the binary.

    IMPLEMENTATION STATUS: Placeholder - Returns "Not yet implemented"
    PLANNED FOR: Version 2.0

    Planned functionality:
    - Searches for known crypto constants like AES S-boxes, SHA constants
    - Identifies DES, AES, RSA, SHA, MD5 algorithm usage
    - Detects custom crypto implementations

    Returns:
        Currently: Placeholder message
        Future: List of potential crypto constants with algorithm identification
    """
    return safe_get("detect_crypto_constants")

@mcp.tool()
def search_byte_patterns(pattern: str, mask: str = None) -> list:
    """
    Search for byte patterns with optional masks (e.g., 'E8 ?? ?? ?? ??').
    Useful for finding shellcode, API calls, or specific instruction sequences.
    
    Args:
        pattern: Hexadecimal pattern to search for (e.g., "E8 ?? ?? ?? ??")
        mask: Optional mask for wildcards (use ? for wildcards)
        
    Returns:
        List of addresses where the pattern was found
    """
    params = {"pattern": pattern}
    if mask:
        params["mask"] = mask
    return safe_get("search_byte_patterns", params)

@mcp.tool()
def find_similar_functions(target_function: str, threshold: float = 0.8) -> list:
    """
    [ROADMAP v2.0] Find functions similar to target using structural analysis.

    IMPLEMENTATION STATUS: Placeholder - Returns "Not yet implemented"
    PLANNED FOR: Version 2.0

    Planned functionality:
    - Uses control flow graph comparison for similarity detection
    - Analyzes instruction patterns and basic block structures
    - Identifies code reuse, copied functions, and variants
    - Useful for finding malware variants and common code patterns

    Args:
        target_function: Name of the function to compare against
        threshold: Similarity threshold (0.0 to 1.0, higher = more similar)

    Returns:
        Currently: Placeholder message
        Future: List of similar functions with similarity scores
    """
    if not validate_function_name(target_function):
        raise GhidraValidationError(f"Invalid function name: {target_function}")

    return safe_get("find_similar_functions", {
        "target_function": target_function,
        "threshold": threshold
    })

@mcp.tool()
def analyze_control_flow(function_name: str) -> dict:
    """
    [ROADMAP v2.0] Analyze control flow complexity, cyclomatic complexity, and basic blocks.

    IMPLEMENTATION STATUS: Placeholder - Returns "Not yet implemented"
    PLANNED FOR: Version 2.0

    Planned functionality:
    - Calculates cyclomatic complexity (McCabe metric)
    - Identifies basic blocks and control flow paths
    - Detects complex branching patterns
    - Analyzes loop structures and nesting depth
    - Useful for identifying obfuscated or intentionally complex code

    Args:
        function_name: Name of the function to analyze

    Returns:
        Currently: Placeholder message
        Future: Dictionary with control flow analysis results (complexity scores, block counts, path analysis)
    """
    if not validate_function_name(function_name):
        raise GhidraValidationError(f"Invalid function name: {function_name}")

    return safe_get("analyze_control_flow", {"function_name": function_name})

@mcp.tool()
def find_anti_analysis_techniques() -> list:
    """
    [ROADMAP v2.0] Detect anti-analysis, anti-debugging, and evasion techniques.

    IMPLEMENTATION STATUS: Placeholder - Returns "Not yet implemented"
    PLANNED FOR: Version 2.0

    Planned functionality:
    - Detects anti-debugging checks (IsDebuggerPresent, CheckRemoteDebuggerPresent)
    - Identifies anti-VM techniques (CPUID checks, timing attacks)
    - Finds anti-disassembly patterns (opaque predicates, junk code)
    - Detects environment checks (sandbox detection, process enumeration)
    - Identifies code obfuscation techniques

    Returns:
        Currently: Placeholder message
        Future: List of detected evasion techniques with addresses, descriptions, and severity
    """
    return safe_get("find_anti_analysis_techniques")

@mcp.tool()
def extract_iocs() -> dict:
    """
    [ROADMAP v2.0] Extract Indicators of Compromise (IOCs) from the binary.

    IMPLEMENTATION STATUS: Placeholder - Returns "Not yet implemented"
    PLANNED FOR: Version 2.0

    Planned functionality:
    - Extracts IP addresses (IPv4 and IPv6)
    - Finds URLs and domain names
    - Identifies file paths (Windows, Linux, macOS)
    - Detects registry keys and values
    - Finds email addresses and cryptocurrency wallets
    - Identifies mutex names and named pipes

    Returns:
        Currently: Placeholder message
        Future: Dictionary of IOCs organized by type (ips, urls, files, registry, etc.)
    """
    return safe_get("extract_iocs")

@mcp.tool()
def batch_decompile_functions(function_names: list) -> dict:
    """
    Decompile multiple functions in a single request for better performance.
    
    Args:
        function_names: List of function names to decompile
        
    Returns:
        Dictionary mapping function names to their decompiled code
    """
    # Validate all function names
    for name in function_names:
        if not validate_function_name(name):
            raise GhidraValidationError(f"Invalid function name: {name}")
    
    return safe_get("batch_decompile", {"functions": ",".join(function_names)})

@mcp.tool()
def find_dead_code(function_name: str) -> list:
    """
    Identify potentially unreachable code blocks within a function.
    Useful for finding hidden functionality or dead code elimination.
    
    Args:
        function_name: Name of the function to analyze
        
    Returns:
        List of potentially unreachable code blocks with addresses
    """
    if not validate_function_name(function_name):
        raise GhidraValidationError(f"Invalid function name: {function_name}")
    
    return safe_get("find_dead_code", {"function_name": function_name})

@mcp.tool()
def analyze_function_complexity(function_name: str) -> dict:
    """
    Calculate various complexity metrics for a function.
    Includes cyclomatic complexity, lines of code, branch count, etc.
    
    Args:
        function_name: Name of the function to analyze
        
    Returns:
        Dictionary with complexity metrics
    """
    if not validate_function_name(function_name):
        raise GhidraValidationError(f"Invalid function name: {function_name}")
    
    return safe_get("analyze_function_complexity", {"function_name": function_name})

@mcp.tool()
def batch_rename_functions(renames: dict) -> dict:
    """
    Rename multiple functions atomically.
    
    Args:
        renames: Dictionary mapping old names to new names
        
    Returns:
        Dictionary with rename results and any errors
    """
    # Validate all function names
    for old_name, new_name in renames.items():
        if not validate_function_name(old_name):
            raise GhidraValidationError(f"Invalid old function name: {old_name}")
        if not validate_function_name(new_name):
            raise GhidraValidationError(f"Invalid new function name: {new_name}")
    
    return safe_get("batch_rename_functions", {"renames": str(renames)})

@mcp.tool()
def auto_decrypt_strings() -> list:
    """
    [ROADMAP v2.0] Automatically identify and attempt to decrypt common string obfuscation patterns.

    IMPLEMENTATION STATUS: Placeholder - Returns "Not yet implemented"
    PLANNED FOR: Version 2.0

    Planned functionality:
    - Detects XOR encoding patterns (single-byte and multi-byte keys)
    - Identifies Base64 encoded strings
    - Recognizes ROT13 and simple substitution ciphers
    - Finds stack strings (strings built character-by-character)
    - Attempts automatic decryption with common algorithms
    - Reports decryption confidence scores

    Returns:
        Currently: Placeholder message
        Future: List of decrypted strings with locations, decryption method, and confidence
    """
    return safe_get("decrypt_strings_auto")

@mcp.tool()
def analyze_api_call_chains() -> dict:
    """
    [ROADMAP v2.0] Identify and visualize suspicious Windows API call sequences used by malware.

    IMPLEMENTATION STATUS: Placeholder - Returns "Not yet implemented"
    PLANNED FOR: Version 2.0

    Planned functionality:
    - Detects process injection patterns (CreateRemoteThread, WriteProcessMemory)
    - Identifies persistence mechanisms (Registry, Scheduled Tasks, Services)
    - Finds privilege escalation sequences
    - Detects network communication patterns
    - Identifies file system manipulation chains
    - Analyzes API call order and dependencies

    Returns:
        Currently: Placeholder message
        Future: Dictionary of detected API call patterns with threat assessment, severity, and MITRE ATT&CK mappings
    """
    return safe_get("analyze_api_call_chains")

@mcp.tool()
def extract_iocs_with_context() -> dict:
    """
    [ROADMAP v2.0] Enhanced IOC extraction with analysis context and confidence scoring.

    IMPLEMENTATION STATUS: Placeholder - Returns "Not yet implemented"
    PLANNED FOR: Version 2.0

    Planned functionality:
    - Extracts IOCs with surrounding code context
    - Provides confidence scores based on usage patterns
    - Categorizes IOCs by purpose (C2, exfiltration, lateral movement)
    - Identifies how IOCs are constructed (hardcoded, dynamically built)
    - Links IOCs to function purposes and call chains
    - Detects obfuscated or encoded IOCs

    Returns:
        Currently: Placeholder message
        Future: Dictionary of IOCs with context, confidence scores, usage analysis, and categorization
    """
    return safe_get("extract_iocs_with_context")

@mcp.tool()
def detect_malware_behaviors() -> list:
    """
    [ROADMAP v2.0] Automatically detect common malware behaviors and techniques.

    IMPLEMENTATION STATUS: Placeholder - Returns "Not yet implemented"
    PLANNED FOR: Version 2.0

    Planned functionality:
    - Detects keylogging patterns
    - Identifies screen capture functionality
    - Finds credential harvesting code
    - Detects network beaconing patterns
    - Identifies ransomware behaviors (encryption, file enumeration)
    - Finds rootkit techniques (hooking, SSDT modification)
    - Maps behaviors to MITRE ATT&CK framework

    Returns:
        Currently: Placeholder message
        Future: List of detected behaviors with confidence scores, evidence, and MITRE ATT&CK IDs
    """
    return safe_get("detect_malware_behaviors")

# ===================================================================================
# NEW DATA STRUCTURE MANAGEMENT TOOLS
# ===================================================================================

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
def create_pointer_type(base_type: str, name: str = None) -> str:
    """
    Create a pointer data type.
    
    This tool creates a new pointer data type pointing to the specified base type.
    
    Args:
        base_type: Name of the base data type for the pointer
        name: Optional name for the pointer type
        
    Returns:
        Success or failure message with created pointer type details
    """
    if not base_type or not isinstance(base_type, str):
        raise GhidraValidationError("Base type is required and must be a string")
    
    data = {"base_type": base_type}
    if name:
        data["name"] = name
    
    return safe_post_json("create_pointer_type", data)

@mcp.tool()
def create_data_type_category(category_path: str) -> str:
    """
    Create a new data type category.
    
    This tool creates a new category for organizing data types.
    
    Args:
        category_path: Path for the new category (e.g., "MyTypes" or "MyTypes/SubCategory")
        
    Returns:
        Success or failure message with category creation details
    """
    if not category_path or not isinstance(category_path, str):
        raise GhidraValidationError("Category path is required and must be a string")
    
    return safe_post_json("create_data_type_category", {"category_path": category_path})

@mcp.tool()
def move_data_type_to_category(type_name: str, category_path: str) -> str:
    """
    Move a data type to a different category.
    
    This tool moves an existing data type to a specified category.
    
    Args:
        type_name: Name of the data type to move
        category_path: Target category path
        
    Returns:
        Success or failure message with move operation details
    """
    if not type_name or not isinstance(type_name, str):
        raise GhidraValidationError("Type name is required and must be a string")
    if not category_path or not isinstance(category_path, str):
        raise GhidraValidationError("Category path is required and must be a string")
    
    return safe_post_json("move_data_type_to_category", {
        "type_name": type_name,
        "category_path": category_path
    })

@mcp.tool()
def list_data_type_categories(offset: int = 0, limit: int = 100) -> str:
    """
    List all data type categories.
    
    This tool lists all available data type categories with pagination.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of categories to return (default: 100)
        
    Returns:
        List of data type categories
    """
    if not isinstance(offset, int) or offset < 0:
        raise GhidraValidationError("Offset must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise GhidraValidationError("Limit must be a positive integer")
    
    return "\n".join(safe_get("list_data_type_categories", {
        "offset": offset,
        "limit": limit
    }))

@mcp.tool()
def create_function_signature(name: str, return_type: str, parameters: str = None) -> str:
    """
    Create a function signature data type.

    This tool creates a new function signature data type that can be used
    for function pointers and type definitions.

    Args:
        name: Name for the function signature
        return_type: Return type of the function
        parameters: Optional JSON string describing parameters (e.g., '[{"name": "param1", "type": "int"}]')

    Returns:
        Success or failure message with function signature creation details
    """
    if not name or not isinstance(name, str):
        raise GhidraValidationError("Function name is required and must be a string")
    if not return_type or not isinstance(return_type, str):
        raise GhidraValidationError("Return type is required and must be a string")

    data = {
        "name": name,
        "return_type": return_type
    }
    if parameters:
        data["parameters"] = parameters

    return safe_post_json("create_function_signature", data)

# ============================================================================
# NEW HIGH-PERFORMANCE ANALYSIS TOOLS
# ============================================================================

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

@mcp.tool()
def batch_decompile_xref_sources(
    target_address: str,
    include_function_names: bool = True,
    include_usage_context: bool = True
) -> str:
    """
    Decompile all functions that reference a target address in one batch operation.

    This tool finds all functions containing xrefs to the target address and
    decompiles them, providing usage context and variable type hints.

    Args:
        target_address: Address being referenced (e.g., "0x6fb835b8")
        include_function_names: Include function name analysis (default: True)
        include_usage_context: Extract specific usage lines (default: True)

    Returns:
        JSON string with decompiled functions:
        [
          {
            "function_name": "ProcessTimedSpellEffect...",
            "function_address": "0x6fb6a000",
            "xref_address": "0x6fb6a023",
            "decompiled_code": "...",
            "usage_lines": [
              "pFVar4 = &FrameThresholdDataTable;",
              "if ((int)pFVar4->threshold < iVar3) break;"
            ],
            "variable_type_hints": {
              "threshold": "dword",
              "access_pattern": "structure_field"
            }
          }
        ]
    """
    import json

    if not validate_hex_address(target_address):
        raise GhidraValidationError(f"Invalid hex address format: {target_address}")

    data = {
        "target_address": target_address,
        "include_function_names": include_function_names,
        "include_usage_context": include_usage_context
    }

    result = safe_post_json("batch_decompile_xref_sources", data)

    # Format the JSON response for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result

def _verify_content_before_classification(address: str) -> dict:
    """
    Internal helper: Verify memory content before applying classification.

    This prevents misidentifying strings as numeric data by inspecting actual bytes.

    Args:
        address: Hex address to verify

    Returns:
        Dictionary with verification results:
        {
            "is_string": bool,
            "detected_string": str or None,
            "suggested_type": str or None,
            "printable_ratio": float,
            "recommendation": str
        }
    """
    import json

    try:
        # Use inspect_memory_content to check what the data actually contains
        result = inspect_memory_content(address, length=64, detect_strings=True)
        data = json.loads(result)

        verification = {
            "is_string": data.get("is_likely_string", False),
            "detected_string": data.get("detected_string"),
            "suggested_type": data.get("suggested_type"),
            "printable_ratio": float(data.get("printable_ratio", 0.0)),
            "recommendation": ""
        }

        if verification["is_string"]:
            verification["recommendation"] = (
                f"WARNING: Content appears to be a string (\"{verification['detected_string']}\"). "
                f"Consider using classification='STRING' with type '{verification['suggested_type']}' "
                f"instead of numeric types."
            )
        else:
            verification["recommendation"] = "Content verification passed: not a string."

        return verification

    except Exception as e:
        logger.warning(f"Content verification failed for {address}: {e}")
        return {
            "is_string": False,
            "detected_string": None,
            "suggested_type": None,
            "printable_ratio": 0.0,
            "recommendation": f"Content verification failed: {e}"
        }

@mcp.tool()
def create_and_apply_data_type(
    address: str,
    classification: str,
    name: str = None,
    comment: str = None,
    type_definition: str | dict = None
) -> str:
    """
    Apply data type, name, and comment in a single atomic operation.

    This tool combines create_struct + apply_data_type + rename_data + set_comment
    into one atomic operation, ensuring consistency and reducing round-trips.

    Args:
        address: Target address (e.g., "0x6fb835b8")
        classification: Data classification: "PRIMITIVE", "STRUCTURE", or "ARRAY"
        name: Name to apply (optional, only if meaningful)
        comment: Comment to apply (optional)
        type_definition: JSON string (NOT dict) with type definition:
                        For PRIMITIVE: '{\"type\": \"dword\"}'  # ← Note the quotes
                        For STRUCTURE: '{\"name\": \"StructName\", \"fields\": [...]}'
                        For ARRAY: '{\"element_type\": \"dword\", \"count\": 64}'
                                  or '{\"element_struct\": \"StructName\", \"count\": 10}'

                        IMPORTANT: Must be a JSON string, not a Python dict.
                        Use json.dumps() if constructing programmatically.

                        Example (CORRECT):
                            create_and_apply_data_type(
                                address=\"0x6fb835b8\",
                                classification=\"ARRAY\",
                                name=\"MyArray\",
                                type_definition='{\"element_type\": \"dword\", \"count\": 7}'  # JSON string
                            )

                        Example (INCORRECT):
                            type_definition={\"element_type\": \"dword\", \"count\": 7}  # Will fail validation

    Returns:
        Success message with all operations performed:
        \"Successfully applied classification at 0x6fb835b8:
         - Created structure: PreTableConfigData (28 bytes)
         - Applied data type: PreTableConfigData
         - Renamed to: PreFrameThresholdConfig
         - Added comment: 28-byte configuration structure...\"
    """
    import json

    if not validate_hex_address(address):
        raise GhidraValidationError(f"Invalid hex address format: {address}")

    valid_classifications = ["PRIMITIVE", "STRUCTURE", "ARRAY", "STRING"]
    if classification not in valid_classifications:
        raise GhidraValidationError(f"Classification must be one of: {', '.join(valid_classifications)}")

    # CONTENT VERIFICATION: Check for string misidentification
    # Only verify for PRIMITIVE and ARRAY (where misidentification is common)
    if classification in ["PRIMITIVE", "ARRAY"]:
        verification = _verify_content_before_classification(address)

        if verification["is_string"]:
            logger.warning(
                f"String detected at {address} but classification is {classification}. "
                f"Detected: \"{verification['detected_string']}\" "
                f"(printable ratio: {verification['printable_ratio']:.2f})"
            )
            logger.warning(verification["recommendation"])

            # Auto-correct to STRING classification if highly confident
            if verification["printable_ratio"] >= 0.8:
                logger.info(f"Auto-correcting classification from {classification} to STRING")
                classification = "STRING"
                # Override type_definition with detected string type
                if verification["suggested_type"]:
                    type_definition = json.dumps({"type": verification["suggested_type"]})

    data = {
        "address": address,
        "classification": classification
    }

    if name:
        data["name"] = name
    if comment:
        data["comment"] = comment
    if type_definition:
        try:
            if not isinstance(type_definition, str):
                raise GhidraValidationError(
                    "type_definition must be a JSON string (use json.dumps() if needed), "
                    f"got {type(type_definition).__name__}"
                )
            type_def = json.loads(type_definition)
            data["type_definition"] = type_def
        except json.JSONDecodeError as e:
            raise GhidraValidationError(f"Invalid JSON in type_definition: {str(e)}")

    return safe_post_json("apply_data_classification", data)

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
def suggest_field_names(
    struct_address: str,
    struct_size: int = 0
) -> str:
    """
    AI-assisted field name suggestions based on usage patterns and data types.

    This tool analyzes a structure's field types and generates suggested names following
    common naming conventions (Hungarian notation, camelCase, etc.). Useful for quickly
    generating descriptive names for structure fields based on their types.

    Args:
        struct_address: Address of the structure instance in hex format (e.g., "0x6fb835b8")
        struct_size: Size of the structure in bytes (optional - auto-detected if 0)

    Returns:
        JSON string with field name suggestions:
        {
          "struct_address": "0x6fb835b8",
          "struct_name": "ConfigData",
          "struct_size": 28,
          "suggestions": [
            {
              "offset": 0,
              "current_name": "field0",
              "field_type": "dword",
              "suggested_names": ["dwValue", "nCount", "dwFlags"],
              "confidence": "medium"
            },
            {
              "offset": 4,
              "current_name": "field1",
              "field_type": "pointer",
              "suggested_names": ["pData", "lpBuffer", "pNext"],
              "confidence": "high"
            },
            ...
          ]
        }
    """
    import json

    if not validate_hex_address(struct_address):
        raise GhidraValidationError(f"Invalid hex address format: {struct_address}")

    # Validate parameter bounds (must match Java constant: MAX_FIELD_OFFSET=65536)
    if not isinstance(struct_size, int) or struct_size < 0 or struct_size > 65536:
        raise GhidraValidationError("struct_size must be between 0 and 65536")

    data = {
        "struct_address": struct_address,
        "struct_size": struct_size
    }

    result = safe_post_json("suggest_field_names", data)

    # Format the JSON response for readability
    try:
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except:
        return result

# ========== v1.5.0: WORKFLOW OPTIMIZATION TOOLS ==========

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

    params = {"function_address": function_address, "comment": comment}
    return safe_post("set_plate_comment", params)

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
def validate_data_type(
    address: str,
    type_name: str
) -> str:
    """
    Validate if a data type can be applied at a given address (v1.5.0).
    Checks memory availability, size compatibility, and alignment.

    Args:
        address: Target address in hex format
        type_name: Name of the data type to validate

    Returns:
        JSON with validation results including memory availability and size checks
    """
    validate_hex_address(address)

    params = {"address": address, "type_name": type_name}
    return safe_get("validate_data_type", params)

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
def validate_function_prototype(
    function_address: str,
    prototype: str,
    calling_convention: str = None
) -> str:
    """
    Validate a function prototype before applying it (v1.6.0).

    Checks if a prototype string can be successfully parsed and applied
    without actually modifying the function. Reports specific issues.

    Args:
        function_address: Function address in hex format
        prototype: Function prototype to validate (e.g., "int foo(char* bar)")
        calling_convention: Optional calling convention

    Returns:
        JSON with validation results:
        {
          "valid": true|false,
          "errors": ["Can't resolve return type: BOOL"],
          "warnings": ["Parameter name 'new' is a C++ keyword"],
          "parsed_return_type": "int",
          "parsed_parameters": [{"name": "bar", "type": "char*"}]
        }
    """
    validate_hex_address(function_address)

    params = {
        "function_address": function_address,
        "prototype": prototype
    }
    if calling_convention:
        params["calling_convention"] = calling_convention

    return safe_get("validate_function_prototype", params)

@mcp.tool()
def validate_data_type_exists(type_name: str) -> str:
    """
    Check if a data type exists in Ghidra's type manager (v1.6.0).

    Args:
        type_name: Name of the data type to check (e.g., "DWORD", "MyStruct")

    Returns:
        JSON with validation results:
        {
          "exists": true|false,
          "type_category": "builtin"|"struct"|"typedef"|"pointer",
          "size": 4,
          "path": "/builtin/DWORD"
        }
    """
    return safe_get("validate_data_type_exists", {"type_name": type_name})

@mcp.tool()
def can_rename_at_address(address: str) -> str:
    """
    Check what kind of symbol exists at an address (v1.6.0).

    Determines whether address contains defined data, undefined bytes,
    or code, helping choose between rename_data, create_label, etc.

    Args:
        address: Memory address in hex format

    Returns:
        JSON with address analysis:
        {
          "can_rename_data": true|false,
          "type": "defined_data"|"undefined"|"code"|"invalid",
          "current_name": "DAT_6fb385a0"|"FUN_6fb385a0"|null,
          "suggested_operation": "rename_data"|"create_label"|"rename_function"
        }
    """
    validate_hex_address(address)
    return safe_get("can_rename_at_address", {"address": address})

# ========== MEDIUM PRIORITY: PERFORMANCE OPTIMIZATIONS (v1.6.0) ==========

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
def document_function_complete(
    function_address: str,
    new_name: str = None,
    prototype: str = None,
    calling_convention: str = None,
    variable_renames: dict = None,
    variable_types: dict = None,
    labels: list = None,
    plate_comment: str = None,
    decompiler_comments: list = None,
    disassembly_comments: list = None
) -> str:
    """
    Document a function completely in one atomic operation (v1.6.0).

    Combines rename, prototype, variables, labels, and comments into a
    single transaction. Either all changes succeed or all are rolled back.

    Replaces 15-20 individual MCP calls with one efficient operation.

    Args:
        function_address: Function address in hex format
        new_name: New function name (optional)
        prototype: Function prototype (optional)
        calling_convention: Calling convention (optional)
        variable_renames: Dict of {"old_name": "new_name"} (optional)
        variable_types: Dict of {"var_name": "type"} (optional)
        labels: List of {"address": "0x...", "name": "label"} (optional)
        plate_comment: Function header comment (optional)
        decompiler_comments: List of {"address": "0x...", "comment": "..."} (optional)
        disassembly_comments: List of {"address": "0x...", "comment": "..."} (optional)

    Returns:
        JSON with operation results:
        {
          "success": true,
          "function_renamed": true,
          "prototype_set": true,
          "variables_renamed": 5,
          "variables_typed": 3,
          "labels_created": 8,
          "comments_set": 25,
          "errors": []
        }

    Example:
        document_function_complete(
            function_address="0x6fb385a0",
            new_name="ProcessPlayerSkillCooldowns",
            prototype="void ProcessPlayerSkillCooldowns(void)",
            calling_convention="__cdecl",
            variable_renames={"param_1": "playerNode"},
            labels=[{"address": "0x6fb385c0", "name": "loop_next_player"}],
            plate_comment="Processes skill cooldowns for all players"
        )
    """
    validate_hex_address(function_address)

    payload = {
        "function_address": function_address,
        "new_name": new_name,
        "prototype": prototype,
        "calling_convention": calling_convention,
        "variable_renames": variable_renames or {},
        "variable_types": variable_types or {},
        "labels": labels or [],
        "plate_comment": plate_comment,
        "decompiler_comments": decompiler_comments or [],
        "disassembly_comments": disassembly_comments or []
    }

    return safe_post_json("document_function_complete", payload)

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
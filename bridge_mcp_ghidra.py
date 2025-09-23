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
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8089/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER


def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]


def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=30)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

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
    
    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")
        new_name: New name for the data label
        
    Returns:
        Success or failure message indicating the result of the rename operation
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

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
        return ["Error: query string is required"]
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
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    
    Args:
        None
        
    Returns:
        Information about the currently selected function including name and address
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
# Removed duplicate decompile_function - using the MCP tool version above

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    
    Args:
        address: Memory address in hex format (e.g., "0x1400010a0")
        
    Returns:
        List of assembly instructions with addresses and comments
    """
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
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    
    Args:
        function_address: Memory address of the function in hex format (e.g., "0x1400010a0")
        prototype: Function prototype string (e.g., "int main(int argc, char* argv[])")
        
    Returns:
        Success or failure message indicating the result of the prototype update
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

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
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
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
    return safe_post("create_label", {
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
def get_full_call_graph(format: str = "edges", limit: int = 1000) -> list:
    """
    Get the complete call graph for the entire program.
    
    This tool generates a comprehensive call graph showing all function call
    relationships in the program. Can be output in different formats.
    
    Args:
        format: Output format ("edges", "adjacency", "dot", "mermaid")
        limit: Maximum number of relationships to return (default: 1000)
        
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
    return safe_post("create_struct", {"name": name, "fields": fields})

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
    return safe_post("create_enum", {"name": name, "values": values, "size": size})

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
    return safe_post("apply_data_type", {
        "address": address, 
        "type_name": type_name,
        "clear_existing": clear_existing
    })

@mcp.tool()
def check_connection() -> str:
    """
    Check if the Ghidra plugin is running and accessible.
    
    Returns:
        Connection status message
    """
    try:
        response = requests.get(urljoin(ghidra_server_url, "check_connection"), timeout=30)
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
def convert_number(text: str, size: int = 4) -> str:
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
def mcp_ghidra_analyze_data_types(address: str, depth: int = 1) -> list:
    """
    Analyze data types at a given address with specified depth.
    
    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        depth: Analysis depth for following pointers and references (default: 1)
        
    Returns:
        Detailed analysis of data types at the specified address
    """
    return safe_get("analyze_data_types", {"address": address, "depth": depth})

@mcp.tool()
def mcp_ghidra_create_union(name: str, fields: list) -> str:
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
def mcp_ghidra_get_type_size(type_name: str) -> str:
    """
    Get the size and alignment information for a data type.
    
    Args:
        type_name: Name of the data type to query
        
    Returns:
        Size, alignment, and path information for the data type
    """
    return safe_get("get_type_size", {"type_name": type_name})

@mcp.tool()
def mcp_ghidra_get_struct_layout(struct_name: str) -> str:
    """
    Get the detailed layout of a structure including field offsets.
    
    Args:
        struct_name: Name of the structure to analyze
        
    Returns:
        Detailed structure layout with field offsets, sizes, and types
    """
    return safe_get("get_struct_layout", {"struct_name": struct_name})

@mcp.tool()
def mcp_ghidra_search_data_types(pattern: str, offset: int = 0, limit: int = 100) -> list:
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
def mcp_ghidra_auto_create_struct(address: str, size: int, name: str) -> str:
    """
    Automatically create a structure by analyzing memory layout at an address.
    
    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        size: Size in bytes to analyze (0 for automatic detection)
        name: Name for the new structure
        
    Returns:
        Success/failure message with created structure details
    """
    return safe_post("auto_create_struct", {"address": address, "size": size, "name": name})

@mcp.tool()
def mcp_ghidra_get_enum_values(enum_name: str) -> str:
    """
    Get all values and names in an enumeration.
    
    Args:
        enum_name: Name of the enumeration to query
        
    Returns:
        List of all enumeration values with their names and numeric values
    """
    return safe_get("get_enum_values", {"enum_name": enum_name})

@mcp.tool()
def mcp_ghidra_create_typedef(name: str, base_type: str) -> str:
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
def mcp_ghidra_clone_data_type(source_type: str, new_name: str) -> str:
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
def mcp_ghidra_validate_data_type(address: str, type_name: str) -> str:
    """
    Validate if a data type can be properly applied at a given address.
    
    Args:
        address: Target address in hex format (e.g., "0x1400010a0")
        type_name: Name of the data type to validate
        
    Returns:
        Validation results including memory availability, alignment, and conflicts
    """
    return safe_get("validate_data_type", {"address": address, "type_name": type_name})

@mcp.tool()
def mcp_ghidra_export_data_types(format: str = "c", category: str = None) -> str:
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
def mcp_ghidra_import_data_types(source: str, format: str = "c") -> str:
    """
    Import data types from various sources (placeholder for future implementation).
    
    Args:
        source: Source data containing type definitions
        format: Format of the source data ("c", "json") - default: "c"
        
    Returns:
        Import results and status
    """
    return safe_post("import_data_types", {"source": source, "format": format})

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
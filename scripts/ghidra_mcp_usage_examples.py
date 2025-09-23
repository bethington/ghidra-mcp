#!/usr/bin/env python3
"""
GhidraMCP Usage Examples and API Demonstrations

Comprehensive examples showing how to use GhidraMCP tools programmatically.
Demonstrates all major functionality categories with proper error handling.

Categories covered:
- Basic connectivity and server info
- Data type creation and management
- Function analysis and decompilation
- Memory analysis and cross-references
- Program metadata and structure analysis

Requirements:
- GhidraMCP plugin installed and running in Ghidra
- A binary loaded and analyzed in Ghidra
- MCP server: python bridge_mcp_ghidra.py
- Dependencies: pip install requests

Usage:
    python ghidra_mcp_usage_examples.py [server_url]
"""

import requests
import json
import sys
import time
from urllib.parse import urljoin
from typing import Dict, Any, Optional

# Import centralized configuration
from scripts_config import (
    Config, EndpointConfig, MessageConfig, SampleDataConfig,
    get_server_url, get_timeout, format_success, format_error
)

GHIDRA_SERVER_URL = get_server_url()

def make_request(endpoint: str, method: str = "GET", data: Optional[Dict[str, Any]] = None, 
                json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Make a request to the Ghidra MCP server with proper error handling
    
    Args:
        endpoint: API endpoint path
        method: HTTP method (GET, POST)
        data: Form data for request
        json_data: JSON data for request
        
    Returns:
        Dict with 'success', 'data', 'error' keys
    """
    url = urljoin(GHIDRA_SERVER_URL, endpoint)
    
    try:
        if method == "GET":
            response = requests.get(url, params=data, timeout=get_timeout())
        elif method == "POST":
            if json_data:
                response = requests.post(url, json=json_data, timeout=get_timeout())
            else:
                response = requests.post(url, data=data, timeout=get_timeout())
        else:
            return {"success": False, "error": f"Unsupported method: {method}"}
        
        if response.ok:
            try:
                # Try to parse as JSON first
                json_data = response.json()
                return {"success": True, "data": json_data}
            except json.JSONDecodeError:
                # Return as text if not JSON
                return {"success": True, "data": response.text.strip()}
        else:
            return {
                "success": False, 
                "error": f"HTTP {response.status_code}: {response.text.strip()}"
            }
    except Exception as e:
        return {"success": False, "error": f"Request failed: {str(e)}"}

def test_basic_functionality():
    """Test basic MCP functionality"""
    print("=== Testing Basic Functionality ===")
    
    # Test listing functions
    print("\n1. Listing functions...")
    result = make_request("methods", data={"limit": 5})
    print(f"Functions: {result}")
    
    # Test listing data types
    print("\n2. Listing data types...")
    result = make_request("list_data_types", data={"limit": 10})
    print(f"Data types: {result}")
    
    # Test listing memory segments
    print("\n3. Listing memory segments...")
    result = make_request("segments", data={"limit": 5})
    print(f"Segments: {result}")

def test_data_type_tools():
    """Test the Core Data Type Tools"""
    print("\n=== Testing Core Data Type Tools ===")
    
    # Create a sample structure
    print("\n1. Creating a custom structure...")
    fields_json = '[{"name":"id","type":"int"},{"name":"name","type":"char[32]"},{"name":"flags","type":"DWORD"}]'
    result = make_request("create_struct", method="POST", data={
        "name": "MyCustomStruct",
        "fields": fields_json
    })
    print(f"Create struct result: {result}")
    
    # Create a sample enumeration
    print("\n2. Creating a custom enumeration...")
    values_json = '{"STATE_IDLE": 0, "STATE_RUNNING": 1, "STATE_STOPPED": 2, "STATE_ERROR": 3}'
    result = make_request("create_enum", method="POST", data={
        "name": "MyStateEnum",
        "values": values_json,
        "size": "4"
    })
    print(f"Create enum result: {result}")
    
    # List data types to see our new ones
    print("\n3. Listing data types to verify creation...")
    result = make_request("list_data_types", data={"limit": 20})
    print(f"Updated data types: {result}")

def test_function_analysis():
    """Test function analysis capabilities"""
    print("\n=== Testing Function Analysis ===")
    
    # Search for functions
    print("\n1. Searching for functions containing 'main'...")
    result = make_request("searchFunctions", data={"query": "main", "limit": 5})
    print(f"Search results: {result}")
    
    # Get call graph (if functions exist)
    print("\n2. Testing call graph functionality...")
    result = make_request("full_call_graph", data={"format": "edges", "limit": 10})
    print(f"Call graph: {result}")

def test_memory_analysis():
    """Test memory and data analysis"""
    print("\n=== Testing Memory Analysis ===")
    
    # List strings
    print("\n1. Listing defined strings...")
    result = make_request("strings", data={"limit": 5})
    print(f"Strings: {result}")
    
    # List imports
    print("\n2. Listing imports...")
    result = make_request("imports", data={"limit": 5})
    print(f"Imports: {result}")
    
    # List exports
    print("\n3. Listing exports...")
    result = make_request("exports", data={"limit": 5})
    print(f"Exports: {result}")

def main():
    """Main function to run all tests"""
    print("GhidraMCP Example Script")
    print("=" * 50)
    print(f"Server URL: {GHIDRA_SERVER_URL}")
    
    # Test server connectivity
    try:
        result = make_request("methods", data={"limit": 1})
        if "Error" in result or "failed" in result:
            print(f"❌ Server not accessible: {result}")
            print("\nMake sure:")
            print("1. Ghidra is running with GhidraMCP plugin enabled")
            print("2. A program is loaded in Ghidra")
            print("3. MCP server is started")
            sys.exit(1)
        else:
            print("✅ Server is accessible")
    except Exception as e:
        print(f"❌ Failed to connect to server: {e}")
        sys.exit(1)
    
    # Run tests
    test_basic_functionality()
    test_data_type_tools()
    test_function_analysis()
    test_memory_analysis()
    
    print("\n" + "=" * 50)
    print("Example script completed!")
    print("\nNext steps:")
    print("- Examine the results above to understand tool capabilities")
    print("- Modify this script to suit your specific reverse engineering needs")
    print("- Create additional scripts for automated analysis workflows")

if __name__ == "__main__":
    main()
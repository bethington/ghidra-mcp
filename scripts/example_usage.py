#!/usr/bin/env python3
"""
Example MCP Tool Usage Script

This script demonstrates how to use the GhidraMCP tools programmatically.
It shows examples of the Core Data Type Tools and other functionality.

Requirements:
- GhidraMCP plugin installed and running in Ghidra
- MCP server started: python bridge_mcp_ghidra.py
- requests library: pip install requests
"""

import requests
import json
import sys
from urllib.parse import urljoin

# Default Ghidra MCP server URL
GHIDRA_SERVER_URL = "http://127.0.0.1:8089/"

def make_request(endpoint, method="GET", data=None):
    """Make a request to the Ghidra MCP server"""
    url = urljoin(GHIDRA_SERVER_URL, endpoint)
    try:
        if method == "GET":
            response = requests.get(url, params=data, timeout=10)
        else:
            response = requests.post(url, data=data, timeout=10)
        
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

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
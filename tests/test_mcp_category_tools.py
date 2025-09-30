#!/usr/bin/env python3
"""
Test the new MCP bridge tools for category management
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from bridge_mcp_ghidra import (
    mcp_ghidra_create_data_type_category,
    mcp_ghidra_list_data_type_categories,
    mcp_ghidra_move_data_type_to_category,
    mcp_ghidra_create_function_signature
)

def test_mcp_category_tools():
    """Test the new MCP category management tools"""
    print("🧪 Testing MCP Category Management Tools")
    print("=" * 50)
    
    # Test 1: Create category
    print("\n📁 Test 1: Create data type category")
    try:
        result = mcp_ghidra_create_data_type_category("TestMCPCategory")
        print(f"   ✅ Success: {result}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 2: List categories
    print("\n📋 Test 2: List data type categories")
    try:
        result = mcp_ghidra_list_data_type_categories(0, 20)
        print(f"   ✅ Success: {result[:200]}...")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 3: Create test struct (using HTTP directly)
    print("\n🏗️  Test 3: Create test structure")
    try:
        import requests
        response = requests.post("http://127.0.0.1:8089/create_struct", json={
            "name": "MCPTestStruct",
            "fields": [
                {"name": "id", "type": "int"},
                {"name": "name", "type": "char[16]"}
            ]
        })
        print(f"   ✅ Success: {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 4: Move struct to category
    print("\n📦 Test 4: Move structure to category")
    try:
        result = mcp_ghidra_move_data_type_to_category("MCPTestStruct", "TestMCPCategory")
        print(f"   ✅ Success: {result}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 5: Create function signature
    print("\n⚡ Test 5: Create function signature")
    try:
        result = mcp_ghidra_create_function_signature(
            "MCPTestFunction", 
            "int", 
            '[{"name": "param1", "type": "int"}, {"name": "param2", "type": "char*"}]'
        )
        print(f"   ✅ Success: {result}")
    except Exception as e:
        print(f"   ❌ Error: {e}")

if __name__ == "__main__":
    test_mcp_category_tools()
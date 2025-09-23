#!/usr/bin/env python3
"""
Diagnostic script for GhidraMCP struct/enum creation issues.

This script helps debug the "Structure name is required" error by testing
various request formats and providing detailed debugging information.

Usage:
    python debug_struct_creation.py
"""

import requests
import json
import sys


def debug_request(description, url, data=None, method='POST', content_type='application/json'):
    """Make a request with detailed debugging output."""
    print(f"\n{'='*60}")
    print(f"🔍 DEBUG: {description}")
    print(f"{'='*60}")
    
    print(f"URL: {url}")
    print(f"Method: {method}")
    print(f"Content-Type: {content_type}")
    
    if data:
        print(f"Data: {json.dumps(data, indent=2)}")
    
    try:
        if method == 'POST':
            if content_type == 'application/json':
                response = requests.post(url, json=data, 
                                       headers={'Content-Type': 'application/json'}, 
                                       timeout=10)
                print(f"Raw request body: {json.dumps(data)}")
            else:
                response = requests.post(url, data=data, timeout=10)
                print(f"Form data: {data}")
        else:
            response = requests.get(url, timeout=10)
        
        print(f"\n📤 REQUEST DETAILS:")
        print(f"   Headers sent: {dict(response.request.headers)}")
        print(f"   Body sent: {response.request.body}")
        
        print(f"\n📥 RESPONSE DETAILS:")
        print(f"   Status Code: {response.status_code}")
        print(f"   Response Headers: {dict(response.headers)}")
        print(f"   Response Body: {response.text}")
        
        # Analyze the response
        if response.status_code == 200:
            if 'successfully' in response.text.lower():
                print(f"\n✅ SUCCESS: Operation completed successfully!")
                return True
            elif 'required' in response.text.lower():
                print(f"\n❌ VALIDATION ERROR: {response.text}")
                return False
            else:
                print(f"\n⚠️  UNEXPECTED: Got 200 but unusual response")
                return False
        else:
            print(f"\n❌ HTTP ERROR: Status {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"\n❌ CONNECTION ERROR: Cannot connect to Ghidra MCP server")
        print("   Make sure:")
        print("   1. Ghidra is running")
        print("   2. GhidraMCP plugin is enabled")
        print("   3. MCP server is started")
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        return False


def main():
    """Run comprehensive debugging tests."""
    print("🔧 GHIDRA MCP STRUCT/ENUM CREATION DEBUGGER")
    print("This script helps diagnose 'Structure name is required' errors")
    
    base_url = "http://127.0.0.1:8089"
    
    # Test 1: Server connectivity
    connectivity = debug_request(
        "Server Connectivity Test",
        f"{base_url}/list_functions",
        method='GET'
    )
    
    if not connectivity:
        print("\n❌ Cannot connect to server. Please check your Ghidra setup.")
        return
    
    # Test 2: Valid struct creation
    debug_request(
        "Valid Struct Creation (should work)",
        f"{base_url}/create_struct",
        {
            "name": "DebugStruct1",
            "fields": [
                {"name": "field1", "type": "int"},
                {"name": "field2", "type": "char[16]"}
            ]
        }
    )
    
    # Test 3: Missing name (reproduces error)
    debug_request(
        "Missing Name (reproduces 'Structure name is required')",
        f"{base_url}/create_struct",
        {
            "fields": [
                {"name": "field1", "type": "int"}
            ]
        }
    )
    
    # Test 4: Empty name (reproduces error)
    debug_request(
        "Empty Name (reproduces 'Structure name is required')",
        f"{base_url}/create_struct",
        {
            "name": "",
            "fields": [
                {"name": "field1", "type": "int"}
            ]
        }
    )
    
    # Test 5: Form data instead of JSON (old way - reproduces error)
    debug_request(
        "Form Data Instead of JSON (reproduces error)",
        f"{base_url}/create_struct",
        {
            "name": "FormStruct",
            "fields": json.dumps([{"name": "field1", "type": "int"}])
        },
        content_type='application/x-www-form-urlencoded'
    )
    
    # Test 6: Valid enum creation
    debug_request(
        "Valid Enum Creation (should work)",
        f"{base_url}/create_enum",
        {
            "name": "DebugEnum1",
            "values": {
                "OPTION_A": 0,
                "OPTION_B": 1,
                "OPTION_C": 2
            },
            "size": 4
        }
    )
    
    # Test 7: Missing enum name
    debug_request(
        "Missing Enum Name (reproduces 'Enumeration name is required')",
        f"{base_url}/create_enum",
        {
            "values": {
                "OPTION_A": 0,
                "OPTION_B": 1
            }
        }
    )
    
    print(f"\n{'='*60}")
    print("🎯 DEBUGGING CONCLUSIONS:")
    print("='*60}")
    print("The 'Structure name is required' error occurs when:")
    print("1. ❌ No 'name' field in JSON request")
    print("2. ❌ Empty string for 'name' field")
    print("3. ❌ Using form data instead of JSON")
    print("4. ❌ Malformed JSON request")
    print()
    print("✅ SOLUTION: Make sure you're sending:")
    print("   - Content-Type: application/json")
    print("   - Valid JSON with 'name' field")
    print("   - Non-empty name value")
    print()
    print("📝 EXAMPLE WORKING REQUEST:")
    print("   POST http://127.0.0.1:8089/create_struct")
    print("   Content-Type: application/json")
    print("   {")
    print('     "name": "MyStruct",')
    print('     "fields": [')
    print('       {"name": "field1", "type": "int"}')
    print('     ]')
    print("   }")
    print(f"\n{'='*60}")


if __name__ == "__main__":
    main()
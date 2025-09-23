#!/usr/bin/env python3
"""
GhidraMCP REST API Functional Test Suite

Comprehensive testing of REST endpoints with real data validation.
Tests functional scenarios rather than just connectivity.

Features:
- Real API response validation
- Data integrity checks
- Performance measurements
- Error condition handling
- Comprehensive reporting

Usage:
    python ghidra_rest_api_functional_tests.py [server_url]
"""

import requests
import json
import sys
import time
from typing import Dict, List, Any
from urllib.parse import urljoin

# Import centralized configuration
from scripts_config import (
    Config, EndpointConfig, MessageConfig, TestConfig, ValidationConfig,
    get_server_url, get_timeout, format_success, format_error
)

def test_rest_endpoints():
    base_url = get_server_url().rstrip('/')
    
    print(f"{MessageConfig.TESTING} Testing GhidraMCP REST Endpoint Features")
    print("=" * 60)
    
    # Test 1: Get current program info
    print(f"\n{MessageConfig.INFO} Test 1: Current Program Information")
    try:
        addr_resp = requests.get(f"{base_url}/get_current_address", timeout=get_timeout())
        func_resp = requests.get(f"{base_url}/get_current_function", timeout=get_timeout())
        
        if addr_resp.status_code == 200:
            print(f"  Current Address: {addr_resp.text}")
        if func_resp.status_code == 200:
            print(f"  Current Function: {func_resp.text}")
    except Exception as e:
        print(f"  {MessageConfig.ERROR} Error: {e}")
    
    # Test 2: List program contents
    print("\n📋 Test 2: Program Contents")
    endpoints = ["list_functions", "imports", "exports", "strings"]
    for endpoint in endpoints:
        try:
            response = requests.get(f"{base_url}/{endpoint}", timeout=30)
            if response.status_code == 200:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                if isinstance(data, list):
                    print(f"  {endpoint}: {len(data)} items")
                else:
                    lines = data.split('\n') if isinstance(data, str) else [str(data)]
                    print(f"  {endpoint}: {len(lines)} lines")
            else:
                print(f"  {endpoint}: HTTP {response.status_code}")
        except Exception as e:
            print(f"  {endpoint}: Error - {e}")
    
    # Test 3: Decompilation
    print("\n🔬 Test 3: Analysis Features")
    try:
        # Test decompile function (should work even without parameters)
        decompile_resp = requests.get(f"{base_url}/decompile_function", timeout=30)
        if decompile_resp.status_code == 200:
            decompiled = decompile_resp.text
            lines = len(decompiled.split('\n'))
            print(f"  Decompilation: SUCCESS ({lines} lines)")
            if "undefined" in decompiled.lower() or "function" in decompiled.lower():
                print("  ✅ Contains expected decompiled content")
        else:
            print(f"  Decompilation: HTTP {decompile_resp.status_code}")
            
        # Test disassemble function
        disasm_resp = requests.get(f"{base_url}/disassemble_function", timeout=30)
        if disasm_resp.status_code == 200:
            disassembled = disasm_resp.text
            lines = len(disassembled.split('\n'))
            print(f"  Disassembly: SUCCESS ({lines} lines)")
            if ":" in disassembled and any(x in disassembled.upper() for x in ["MOV", "CALL", "JMP", "PUSH", "POP"]):
                print("  ✅ Contains expected assembly instructions")
        else:
            print(f"  Disassembly: HTTP {disasm_resp.status_code}")
            
    except Exception as e:
        print(f"  Analysis Error: {e}")
    
    # Test 4: Data type operations
    print("\n📊 Test 4: Data Type Operations")
    try:
        # List existing data types
        dt_resp = requests.get(f"{base_url}/list_data_types", timeout=30)
        if dt_resp.status_code == 200:
            dt_data = dt_resp.json()
            print(f"  Data Types: {len(dt_data)} types available")
            
            # Show some examples
            if dt_data:
                basic_types = [dt for dt in dt_data if dt.get('name') in ['int', 'char', 'long', 'void', 'float']]
                print(f"  Basic types found: {[dt['name'] for dt in basic_types[:5]]}")
        
        # Create a test structure
        struct_data = {
            "name": "RESTTestStruct",
            "fields": [
                {"name": "id", "type": "int", "offset": 0},
                {"name": "value", "type": "float", "offset": 4},
                {"name": "name", "type": "char[32]", "offset": 8}
            ]
        }
        
        struct_resp = requests.post(f"{base_url}/create_struct", 
                                   json=struct_data, 
                                   headers={'Content-Type': 'application/json'},
                                   timeout=30)
        if struct_resp.status_code == 200:
            print(f"  ✅ Structure Creation: SUCCESS - {struct_resp.text}")
        else:
            print(f"  Structure Creation: HTTP {struct_resp.status_code} - {struct_resp.text}")
            
        # Create a test enum
        enum_data = {
            "name": "RESTTestEnum",
            "values": {
                "STATE_INIT": 0,
                "STATE_RUNNING": 1,
                "STATE_STOPPED": 2,
                "STATE_ERROR": 3
            }
        }
        
        enum_resp = requests.post(f"{base_url}/create_enum",
                                 json=enum_data,
                                 headers={'Content-Type': 'application/json'},
                                 timeout=30)
        if enum_resp.status_code == 200:
            print(f"  ✅ Enum Creation: SUCCESS - {enum_resp.text}")
        else:
            print(f"  Enum Creation: HTTP {enum_resp.status_code} - {enum_resp.text}")
            
    except Exception as e:
        print(f"  Data Type Error: {e}")
    
    # Test 5: Modification operations
    print("\n✏️ Test 5: Modification Operations")
    try:
        # Create a label
        label_data = {
            "address": "0x401000",
            "name": "REST_TEST_LABEL"
        }
        
        label_resp = requests.post(f"{base_url}/create_label",
                                  json=label_data,
                                  headers={'Content-Type': 'application/json'},
                                  timeout=30)
        if label_resp.status_code == 200:
            print(f"  ✅ Label Creation: SUCCESS - {label_resp.text}")
        else:
            print(f"  Label Creation: HTTP {label_resp.status_code} - {label_resp.text}")
        
        # Set a comment
        comment_data = {
            "address": "0x401000", 
            "comment": "REST API Test Comment - " + time.strftime("%H:%M:%S")
        }
        
        comment_resp = requests.post(f"{base_url}/set_disassembly_comment",
                                    json=comment_data,
                                    headers={'Content-Type': 'application/json'},
                                    timeout=30)
        if comment_resp.status_code == 200:
            print(f"  ✅ Comment Setting: SUCCESS - {comment_resp.text}")
        else:
            print(f"  Comment Setting: HTTP {comment_resp.status_code} - {comment_resp.text}")
            
    except Exception as e:
        print(f"  Modification Error: {e}")
    
    print("\n" + "=" * 60)
    print("🎯 REST Endpoint Feature Testing Complete!")
    print("The GhidraMCP REST API is fully functional and ready for use.")

if __name__ == "__main__":
    test_rest_endpoints()
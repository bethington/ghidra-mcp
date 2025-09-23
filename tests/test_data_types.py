#!/usr/bin/env python3

import requests
import json
import time

def test_struct_creation():
    """Test struct creation with various field types."""
    print("\n🏗️ TESTING STRUCT CREATION")
    print("=" * 50)
    
    test_cases = [
        {
            "name": "Simple struct with basic types",
            "struct": {
                "name": f"SimpleStruct_{int(time.time())}",
                "fields": [
                    {"name": "id", "type": "int"},
                    {"name": "value", "type": "float"},
                    {"name": "flag", "type": "char"}
                ]
            }
        },
        {
            "name": "Struct with arrays and pointers",
            "struct": {
                "name": f"ComplexStruct_{int(time.time())}",
                "fields": [
                    {"name": "buffer", "type": "char[32]"},
                    {"name": "count", "type": "int"},
                    {"name": "next_ptr", "type": "void*"},
                    {"name": "data", "type": "double"}
                ]
            }
        },
        {
            "name": "Struct with Windows types",
            "struct": {
                "name": f"WindowsStruct_{int(time.time())}",
                "fields": [
                    {"name": "handle", "type": "HANDLE"},
                    {"name": "length", "type": "DWORD"},
                    {"name": "flags", "type": "WORD"},
                    {"name": "status", "type": "BYTE"}
                ]
            }
        }
    ]
    
    for test_case in test_cases:
        print(f"\n📋 {test_case['name']}")
        print("-" * 40)
        
        try:
            response = requests.post(
                "http://localhost:8089/create_struct",
                json=test_case["struct"],
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            print(f"   Request: {json.dumps(test_case['struct'], indent=2)}")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200 and "Successfully created" in response.text:
                print("   ✅ SUCCESS")
            else:
                print("   ❌ FAILED")
                
        except Exception as e:
            print(f"   ❌ ERROR: {e}")

def test_enum_creation():
    """Test enum creation with various value types."""
    print("\n🔢 TESTING ENUM CREATION")
    print("=" * 50)
    
    test_cases = [
        {
            "name": "Simple enum with sequential values",
            "enum": {
                "name": f"SimpleEnum_{int(time.time())}",
                "values": {
                    "OPTION_NONE": 0,
                    "OPTION_ONE": 1,
                    "OPTION_TWO": 2,
                    "OPTION_THREE": 3
                }
            }
        },
        {
            "name": "Status code enum with hex values",
            "enum": {
                "name": f"StatusEnum_{int(time.time())}",
                "values": {
                    "STATUS_OK": 0,
                    "STATUS_ERROR": 1,
                    "STATUS_WARNING": 2,
                    "STATUS_CRITICAL": 255
                }
            }
        },
        {
            "name": "Bitfield enum with power-of-2 values",
            "enum": {
                "name": f"FlagsEnum_{int(time.time())}",
                "values": {
                    "FLAG_NONE": 0,
                    "FLAG_READ": 1,
                    "FLAG_WRITE": 2,
                    "FLAG_EXECUTE": 4,
                    "FLAG_ALL": 7
                }
            }
        }
    ]
    
    for test_case in test_cases:
        print(f"\n📋 {test_case['name']}")
        print("-" * 40)
        
        try:
            response = requests.post(
                "http://localhost:8089/create_enum",
                json=test_case["enum"],
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            print(f"   Request: {json.dumps(test_case['enum'], indent=2)}")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200 and "Successfully created" in response.text:
                print("   ✅ SUCCESS")
            else:
                print("   ❌ FAILED")
                
        except Exception as e:
            print(f"   ❌ ERROR: {e}")

def test_union_creation():
    """Test union creation (if supported)."""
    print("\n🔄 TESTING UNION CREATION")
    print("=" * 50)
    
    # Check if union creation endpoint exists
    union_data = {
        "name": f"TestUnion_{int(time.time())}",
        "fields": [
            {"name": "as_int", "type": "int"},
            {"name": "as_float", "type": "float"},
            {"name": "as_bytes", "type": "char[4]"}
        ]
    }
    
    try:
        response = requests.post(
            "http://localhost:8089/create_union",
            json=union_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"   Request: {json.dumps(union_data, indent=2)}")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print("   ✅ UNION CREATION SUPPORTED")
        elif response.status_code == 404:
            print("   ⚠️  UNION CREATION NOT IMPLEMENTED")
        else:
            print("   ❌ FAILED")
            
    except Exception as e:
        print(f"   ❌ ERROR: {e}")

def test_data_type_application():
    """Test applying created data types to memory addresses."""
    print("\n📍 TESTING DATA TYPE APPLICATION")
    print("=" * 50)
    
    # Create a test struct first
    struct_name = f"ApplyTestStruct_{int(time.time())}"
    struct_data = {
        "name": struct_name,
        "fields": [
            {"name": "header", "type": "int"},
            {"name": "data", "type": "char[16]"}
        ]
    }
    
    try:
        # Create the struct
        response = requests.post(
            "http://localhost:8089/create_struct",
            json=struct_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200 and "Successfully created" in response.text:
            print(f"   ✅ Created test struct: {struct_name}")
            
            # Try to apply it to a memory address
            apply_data = {
                "address": "0x401000",  # Common executable address
                "type_name": struct_name
            }
            
            response = requests.post(
                "http://localhost:8089/apply_data_type",
                json=apply_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            print(f"   Apply Request: {json.dumps(apply_data, indent=2)}")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                print("   ✅ DATA TYPE APPLICATION SUCCESSFUL")
            else:
                print("   ⚠️  DATA TYPE APPLICATION FAILED (may be due to address not existing)")
        else:
            print(f"   ❌ Failed to create test struct: {response.text}")
            
    except Exception as e:
        print(f"   ❌ ERROR: {e}")

def test_validation_errors():
    """Test validation error handling."""
    print("\n⚠️  TESTING VALIDATION ERRORS")
    print("=" * 50)
    
    validation_tests = [
        {
            "name": "Struct without name",
            "url": "http://localhost:8089/create_struct",
            "data": {"fields": [{"name": "test", "type": "int"}]},
            "expected_error": "Structure name is required"
        },
        {
            "name": "Struct with empty name",
            "url": "http://localhost:8089/create_struct", 
            "data": {"name": "", "fields": [{"name": "test", "type": "int"}]},
            "expected_error": "Structure name is required"
        },
        {
            "name": "Enum without name",
            "url": "http://localhost:8089/create_enum",
            "data": {"values": {"A": 0, "B": 1}},
            "expected_error": "name is required"
        },
        {
            "name": "Struct without fields",
            "url": "http://localhost:8089/create_struct",
            "data": {"name": "EmptyStruct"},
            "expected_error": "fields"
        }
    ]
    
    for test in validation_tests:
        print(f"\n📋 {test['name']}")
        print("-" * 40)
        
        try:
            response = requests.post(
                test["url"],
                json=test["data"],
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            print(f"   Request: {json.dumps(test['data'])}")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if test["expected_error"].lower() in response.text.lower():
                print("   ✅ VALIDATION ERROR CORRECTLY CAUGHT")
            else:
                print("   ❌ UNEXPECTED RESPONSE")
                
        except Exception as e:
            print(f"   ❌ ERROR: {e}")

def check_server_connectivity():
    """Check if the Ghidra MCP server is running."""
    print("🔍 CHECKING SERVER CONNECTIVITY")
    print("=" * 50)
    
    try:
        response = requests.get("http://localhost:8089/list_functions", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running and responsive")
            return True
        else:
            print(f"⚠️  Server responded with status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server at localhost:8089")
        print("   Make sure Ghidra is running with the MCP plugin enabled")
        return False
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False

def main():
    print("🧪 COMPREHENSIVE DATA TYPE CREATION TEST")
    print("=" * 70)
    
    # Check connectivity first
    if not check_server_connectivity():
        print("\n❌ Cannot proceed without server connectivity")
        return
    
    # Run all tests
    test_struct_creation()
    test_enum_creation() 
    test_union_creation()
    test_data_type_application()
    test_validation_errors()
    
    print("\n" + "=" * 70)
    print("🎯 TEST SUMMARY")
    print("All data type creation functionality has been tested!")
    print("Check the results above for any issues that need attention.")

if __name__ == "__main__":
    main()
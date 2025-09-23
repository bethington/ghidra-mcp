#!/usr/bin/env python3

import requests
import json
import time

def test_union_creation():
    """Test union creation with proper JSON format."""
    print("🔄 TESTING UNION CREATION WITH JSON")
    print("=" * 50)
    
    # Test case: Union with overlapping data types
    union_name = f"TestUnion_{int(time.time())}"
    union_data = {
        "name": union_name,
        "fields": [
            {"name": "as_int", "type": "int"},
            {"name": "as_float", "type": "float"},
            {"name": "as_bytes", "type": "char[4]"},
            {"name": "as_short", "type": "short[2]"}
        ]
    }
    
    try:
        response = requests.post(
            "http://localhost:8089/create_union",
            json=union_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"Request JSON:")
        print(json.dumps(union_data, indent=2))
        print(f"\nStatus Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200 and "created successfully" in response.text:
            print("\n✅ SUCCESS: Union creation worked with JSON!")
            return True
        else:
            print(f"\n❌ FAILED: Got unexpected response")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ CONNECTION ERROR: Cannot connect to localhost:8089")
        print("   Make sure Ghidra is running with the MCP plugin enabled")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def test_union_validation():
    """Test union validation errors."""
    print("\n⚠️  TESTING UNION VALIDATION")
    print("=" * 50)
    
    validation_tests = [
        {
            "name": "Union without name",
            "data": {"fields": [{"name": "test", "type": "int"}]},
            "expected_error": "Union name is required"
        },
        {
            "name": "Union with empty name",
            "data": {"name": "", "fields": [{"name": "test", "type": "int"}]},
            "expected_error": "Union name is required"
        },
        {
            "name": "Union without fields",
            "data": {"name": "EmptyUnion"},
            "expected_error": "Fields"
        }
    ]
    
    for test in validation_tests:
        print(f"\n📋 {test['name']}")
        print("-" * 40)
        
        try:
            response = requests.post(
                "http://localhost:8089/create_union",
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

def check_server():
    """Check if server is running."""
    try:
        response = requests.get("http://localhost:8089/list_functions", timeout=5)
        return response.status_code == 200
    except:
        return False

def main():
    print("🧪 UNION CREATION TEST")
    print("=" * 60)
    
    if not check_server():
        print("❌ Server not accessible at localhost:8089")
        print("Make sure Ghidra is running with the MCP plugin")
        return
    
    print("✅ Server is running\n")
    
    # Test union creation
    success = test_union_creation()
    
    # Test validation
    test_union_validation()
    
    print("\n" + "=" * 60)
    if success:
        print("🎯 UNION CREATION: WORKING! ✅")
        print("Union creation with JSON is now fully functional!")
    else:
        print("⚠️  UNION CREATION: NEEDS ATTENTION")
        print("Check the output above for issues.")

if __name__ == "__main__":
    main()
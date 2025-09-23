#!/usr/bin/env python3

import requests
import json

def test_struct_creation():
    """Test struct creation with proper JSON format."""
    
    print("🧪 Testing struct creation with JSON...")
    
    # Test data for struct creation
    struct_data = {
        "name": "TestStruct",
        "fields": [
            {"name": "id", "type": "int"},
            {"name": "value", "type": "float"}
        ]
    }
    
    # Headers for JSON request
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        # Make the request
        response = requests.post(
            "http://localhost:8089/create_struct",
            json=struct_data,
            headers=headers,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Text: {response.text}")
        
        if response.status_code == 200:
            print("✅ SUCCESS: Struct creation worked!")
        else:
            print(f"❌ FAILED: Got status {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ CONNECTION ERROR: Cannot connect to localhost:8089")
        print("   Make sure Ghidra is running with the MCP plugin enabled")
    except Exception as e:
        print(f"❌ ERROR: {e}")

def test_enum_creation():
    """Test enum creation with proper JSON format."""
    
    print("\n🧪 Testing enum creation with JSON...")
    
    # Test data for enum creation
    enum_data = {
        "name": "TestEnum",
        "values": {
            "OPTION_A": 0,
            "OPTION_B": 1,
            "OPTION_C": 2
        }
    }
    
    # Headers for JSON request
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        # Make the request
        response = requests.post(
            "http://localhost:8089/create_enum",
            json=enum_data,
            headers=headers,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Text: {response.text}")
        
        if response.status_code == 200:
            print("✅ SUCCESS: Enum creation worked!")
        else:
            print(f"❌ FAILED: Got status {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ CONNECTION ERROR: Cannot connect to localhost:8089")
        print("   Make sure Ghidra is running with the MCP plugin enabled")
    except Exception as e:
        print(f"❌ ERROR: {e}")

def test_invalid_requests():
    """Test invalid requests to see validation errors."""
    
    print("\n🧪 Testing validation errors...")
    
    # Test 1: Missing name
    print("\n1. Testing missing struct name...")
    try:
        response = requests.post(
            "http://localhost:8089/create_struct",
            json={"fields": [{"name": "test", "type": "int"}]},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"   Status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 2: Empty name
    print("\n2. Testing empty struct name...")
    try:
        response = requests.post(
            "http://localhost:8089/create_struct",
            json={"name": "", "fields": [{"name": "test", "type": "int"}]},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"   Status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 3: Form data instead of JSON
    print("\n3. Testing form data instead of JSON...")
    try:
        response = requests.post(
            "http://localhost:8089/create_struct",
            data={"name": "TestStruct", "fields": "invalid"},
            timeout=10
        )
        print(f"   Status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")

if __name__ == "__main__":
    print("🔧 Direct Struct/Enum Creation Test")
    print("=" * 50)
    
    test_struct_creation()
    test_enum_creation()
    test_invalid_requests()
    
    print("\n" + "=" * 50)
    print("Test completed!")
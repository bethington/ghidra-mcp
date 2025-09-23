#!/usr/bin/env python3

import requests
import json
import time

def test_single_struct():
    """Test a single struct creation."""
    print("🏗️ Testing Struct Creation")
    struct_data = {
        "name": f"TestStruct_{int(time.time())}",
        "fields": [
            {"name": "id", "type": "int"},
            {"name": "name", "type": "char[64]"}
        ]
    }
    
    try:
        response = requests.post(
            "http://localhost:8089/create_struct",
            json=struct_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        return response.status_code == 200 and "Successfully created" in response.text
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_single_enum():
    """Test a single enum creation."""
    print("\n🔢 Testing Enum Creation")
    enum_data = {
        "name": f"TestEnum_{int(time.time())}",
        "values": {
            "FIRST": 1,
            "SECOND": 2,
            "THIRD": 3
        }
    }
    
    try:
        response = requests.post(
            "http://localhost:8089/create_enum",
            json=enum_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        return response.status_code == 200 and "Successfully created" in response.text
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_single_union():
    """Test a single union creation."""
    print("\n🔄 Testing Union Creation")
    union_data = {
        "name": f"TestUnion_{int(time.time())}",
        "fields": [
            {"name": "as_int", "type": "int"},
            {"name": "as_float", "type": "float"}
        ]
    }
    
    try:
        response = requests.post(
            "http://localhost:8089/create_union",
            json=union_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        return response.status_code == 200 and "successfully" in response.text
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    print("🧪 FOCUSED DATA TYPE CREATION TEST")
    print("=" * 50)
    
    results = []
    results.append(("Struct", test_single_struct()))
    results.append(("Enum", test_single_enum()))
    results.append(("Union", test_single_union()))
    
    print("\n" + "=" * 50)
    print("📊 RESULTS SUMMARY:")
    for name, success in results:
        status = "✅ WORKING" if success else "❌ FAILED"
        print(f"   {name}: {status}")
    
    working_count = sum(1 for _, success in results if success)
    print(f"\n🎯 Overall: {working_count}/3 data types working")

if __name__ == "__main__":
    main()
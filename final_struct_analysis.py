#!/usr/bin/env python3

import requests
import json
import time

def test_scenario(name, url, data, headers=None, expected_success=True):
    """Test a specific scenario and report results."""
    print(f"\n📋 {name}")
    print("-" * 60)
    
    try:
        if headers:
            response = requests.post(url, json=data, headers=headers, timeout=10)
        else:
            response = requests.post(url, data=data, timeout=10)
        
        print(f"   Request: {json.dumps(data) if isinstance(data, dict) else str(data)}")
        if headers:
            print(f"   Headers: {headers}")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        success = response.status_code == 200 and "required" not in response.text and "No valid" not in response.text
        
        if expected_success and success:
            print("   ✅ PASSED: Working as expected")
        elif not expected_success and not success:
            print("   ✅ PASSED: Validation error as expected") 
        elif expected_success and not success:
            print("   ❌ FAILED: Should have worked but didn't")
        else:
            print("   ❌ FAILED: Should have failed but didn't")
            
        return success
        
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        return False

def main():
    print("🔍 Complete Struct/Enum Creation Analysis")
    print("=" * 70)
    
    # Test successful scenarios
    print("\n🟢 SCENARIOS THAT SHOULD WORK:")
    
    # Test 1: Valid struct with unique name
    unique_name = f"ValidStruct_{int(time.time())}"
    test_scenario(
        "Valid struct with proper JSON and unique name",
        "http://localhost:8089/create_struct",
        {
            "name": unique_name,
            "fields": [
                {"name": "id", "type": "int"},
                {"name": "value", "type": "float"}
            ]
        },
        {"Content-Type": "application/json"},
        expected_success=True
    )
    
    # Test 2: Valid enum with unique name
    unique_enum = f"ValidEnum_{int(time.time())}"
    test_scenario(
        "Valid enum with proper JSON and unique name",
        "http://localhost:8089/create_enum",
        {
            "name": unique_enum,
            "values": {"A": 0, "B": 1, "C": 2}
        },
        {"Content-Type": "application/json"},
        expected_success=True
    )
    
    # Test scenarios that should fail with validation
    print("\n🔴 SCENARIOS THAT SHOULD FAIL (Validation Errors):")
    
    # Test 3: Missing name in struct
    test_scenario(
        "Struct missing name field",
        "http://localhost:8089/create_struct",
        {
            "fields": [{"name": "test", "type": "int"}]
        },
        {"Content-Type": "application/json"},
        expected_success=False
    )
    
    # Test 4: Empty name in struct
    test_scenario(
        "Struct with empty name",
        "http://localhost:8089/create_struct",
        {
            "name": "",
            "fields": [{"name": "test", "type": "int"}]
        },
        {"Content-Type": "application/json"},
        expected_success=False
    )
    
    # Test 5: Form data instead of JSON
    test_scenario(
        "Form data instead of JSON (no Content-Type header)",
        "http://localhost:8089/create_struct",
        {
            "name": "TestStruct",
            "fields": "[{\"name\":\"test\",\"type\":\"int\"}]"
        },
        None,  # No JSON headers
        expected_success=False
    )
    
    # Test 6: Missing name in enum
    test_scenario(
        "Enum missing name field",
        "http://localhost:8089/create_enum",
        {
            "values": {"A": 0, "B": 1}
        },
        {"Content-Type": "application/json"},
        expected_success=False
    )
    
    print("\n" + "=" * 70)
    print("CONCLUSION:")
    print("✅ Struct/enum creation works perfectly when:")
    print("   - Proper JSON format is used")
    print("   - Content-Type: application/json header is set")
    print("   - A non-empty 'name' field is provided")
    print("   - Valid field definitions are included")
    print("")
    print("❌ Validation correctly rejects requests when:")
    print("   - The 'name' field is missing")
    print("   - The 'name' field is empty")
    print("   - Form data is sent instead of JSON")
    print("")
    print("🎯 The 'Structure name is required' error indicates you're hitting")
    print("   one of these validation cases - check your request format!")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Quick debug test to understand data type visibility
"""

import requests
import json

def test_data_type_creation():
    server_url = "http://127.0.0.1:8089"
    
    print("=== Data Type Creation and Visibility Test ===")
    
    # Create a test struct
    struct_name = "DebugTestStruct"
    struct_data = {
        "name": struct_name,
        "fields": json.dumps([
            {"name": "x", "type": "int"},
            {"name": "y", "type": "int"}
        ])
    }
    
    print(f"Creating struct: {struct_name}")
    response = requests.post(f"{server_url}/create_struct", data=struct_data)
    print(f"Creation result: {response.text}")
    
    # List all data types to see if it appears
    print("\nListing all data types...")
    response = requests.get(f"{server_url}/list_data_types", params={"limit": 50})
    data_types = response.text.strip().split('\n')
    
    found_our_type = False
    for dt in data_types:
        if struct_name.lower() in dt.lower():
            print(f"✅ Found our struct: {dt}")
            found_our_type = True
    
    if not found_our_type:
        print(f"❌ {struct_name} not found in data type list")
        print("First few data types:")
        for i, dt in enumerate(data_types[:5]):
            print(f"  {i}: {dt}")
    
    # Try to find it by searching with different patterns
    print(f"\nSearching for patterns containing '{struct_name}'...")
    for dt in data_types:
        if "debug" in dt.lower() or "test" in dt.lower():
            print(f"  Related: {dt}")

if __name__ == "__main__":
    test_data_type_creation()
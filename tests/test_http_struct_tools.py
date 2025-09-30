#!/usr/bin/env python3
"""
Direct HTTP test for new data structure management functionality
"""
import requests
import json
import time

BASE_URL = "http://localhost:8089"

def test_data_structure_management():
    """Test all new data structure management endpoints directly"""
    print("🧪 TESTING NEW DATA STRUCTURE MANAGEMENT ENDPOINTS")
    print("=" * 60)
    
    # Test 1: Create a test structure for modification
    print("\n📝 Test 1: Creating test structure...")
    try:
        data = {
            "name": "TestStruct",
            "fields": [
                {"name": "field1", "type": "DWORD"},
                {"name": "field2", "type": "WORD"},
                {"name": "field3", "type": "BYTE"}
            ]
        }
        response = requests.post(f"{BASE_URL}/create_struct", json=data)
        print(f"✅ Create test structure ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Create test structure failed: {e}")
    
    time.sleep(1)
    
    # Test 2: Modify struct field type
    print("\n🔧 Test 2: Modifying struct field type...")
    try:
        data = {
            "struct_name": "TestStruct",
            "field_name": "field2",
            "new_type": "DWORD"
        }
        response = requests.post(f"{BASE_URL}/modify_struct_field", json=data)
        print(f"✅ Modify field type ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Modify field type failed: {e}")
    
    time.sleep(1)
    
    # Test 3: Modify struct field name
    print("\n🏷️  Test 3: Modifying struct field name...")
    try:
        data = {
            "struct_name": "TestStruct",
            "field_name": "field3",
            "new_name": "newField3"
        }
        response = requests.post(f"{BASE_URL}/modify_struct_field", json=data)
        print(f"✅ Modify field name ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Modify field name failed: {e}")
    
    time.sleep(1)
    
    # Test 4: Add new field to structure
    print("\n➕ Test 4: Adding new field to structure...")
    try:
        data = {
            "struct_name": "TestStruct",
            "field_name": "newField4",
            "field_type": "WORD",
            "offset": -1
        }
        response = requests.post(f"{BASE_URL}/add_struct_field", json=data)
        print(f"✅ Add new field ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Add new field failed: {e}")
    
    time.sleep(1)
    
    # Test 5: Create array type
    print("\n📋 Test 5: Creating array type...")
    try:
        data = {
            "base_type": "DWORD",
            "length": 10,
            "name": "DWORD_Array_10"
        }
        response = requests.post(f"{BASE_URL}/create_array_type", json=data)
        print(f"✅ Create array type ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Create array type failed: {e}")
    
    time.sleep(1)
    
    # Test 6: Create pointer type
    print("\n👉 Test 6: Creating pointer type...")
    try:
        data = {
            "base_type": "TestStruct",
            "name": "TestStruct_Ptr"
        }
        response = requests.post(f"{BASE_URL}/create_pointer_type", data=data)
        print(f"✅ Create pointer type ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Create pointer type failed: {e}")
    
    time.sleep(1)
    
    # Test 7: Check structure layout after modifications
    print("\n🔍 Test 7: Checking modified structure layout...")
    try:
        response = requests.get(f"{BASE_URL}/get_struct_layout?struct_name=TestStruct")
        print(f"✅ Structure layout ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Get structure layout failed: {e}")
    
    time.sleep(1)
    
    # Test 8: Remove field from structure
    print("\n➖ Test 8: Removing field from structure...")
    try:
        data = {
            "struct_name": "TestStruct",
            "field_name": "field1"
        }
        response = requests.post(f"{BASE_URL}/remove_struct_field", data=data)
        print(f"✅ Remove field ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Remove field failed: {e}")
    
    time.sleep(1)
    
    # Test 9: List data types to see our new types
    print("\n📋 Test 9: Listing data types...")
    try:
        response = requests.get(f"{BASE_URL}/search_data_types?pattern=Test")
        print(f"✅ Search data types ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Search data types failed: {e}")
    
    time.sleep(1)
    
    # Test 10: Delete the test structure (cleanup)
    print("\n🗑️  Test 10: Deleting test structure...")
    try:
        data = {"type_name": "TestStruct"}
        response = requests.post(f"{BASE_URL}/delete_data_type", data=data)
        print(f"✅ Delete structure ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Delete structure failed: {e}")
    
    time.sleep(1)
    
    # Test 11: Delete array type (cleanup)
    print("\n🗑️  Test 11: Deleting array type...")
    try:
        data = {"type_name": "DWORD_Array_10"}
        response = requests.post(f"{BASE_URL}/delete_data_type", data=data)
        print(f"✅ Delete array type ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ Delete array type failed: {e}")
    
    print("\n" + "=" * 60)
    print("🎉 DATA STRUCTURE MANAGEMENT ENDPOINT TESTING COMPLETE!")

if __name__ == "__main__":
    test_data_structure_management()
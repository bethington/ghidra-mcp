#!/usr/bin/env python3
"""
Test script for new data structure management functionality
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from bridge_mcp_ghidra import *
import time

def test_data_structure_management():
    """Test all new data structure management tools"""
    print("🧪 TESTING NEW DATA STRUCTURE MANAGEMENT TOOLS")
    print("=" * 60)
    
    # Test 1: Create a test structure for modification
    print("\n📝 Test 1: Creating test structure...")
    try:
        result = create_struct("TestStruct", [
            {"name": "field1", "type": "DWORD"},
            {"name": "field2", "type": "WORD"},
            {"name": "field3", "type": "BYTE"}
        ])
        print(f"✅ Create test structure: {result}")
    except Exception as e:
        print(f"❌ Create test structure failed: {e}")
    
    time.sleep(1)
    
    # Test 2: Modify struct field type
    print("\n🔧 Test 2: Modifying struct field type...")
    try:
        result = mcp_ghidra_modify_struct_field("TestStruct", "field2", "DWORD", None)
        print(f"✅ Modify field type: {result}")
    except Exception as e:
        print(f"❌ Modify field type failed: {e}")
    
    time.sleep(1)
    
    # Test 3: Modify struct field name
    print("\n🏷️  Test 3: Modifying struct field name...")
    try:
        result = mcp_ghidra_modify_struct_field("TestStruct", "field3", None, "newField3")
        print(f"✅ Modify field name: {result}")
    except Exception as e:
        print(f"❌ Modify field name failed: {e}")
    
    time.sleep(1)
    
    # Test 4: Add new field to structure
    print("\n➕ Test 4: Adding new field to structure...")
    try:
        result = mcp_ghidra_add_struct_field("TestStruct", "newField4", "WORD", -1)
        print(f"✅ Add new field: {result}")
    except Exception as e:
        print(f"❌ Add new field failed: {e}")
    
    time.sleep(1)
    
    # Test 5: Create array type
    print("\n📋 Test 5: Creating array type...")
    try:
        result = mcp_ghidra_create_array_type("DWORD", 10, "DWORD_Array_10")
        print(f"✅ Create array type: {result}")
    except Exception as e:
        print(f"❌ Create array type failed: {e}")
    
    time.sleep(1)
    
    # Test 6: Create pointer type
    print("\n👉 Test 6: Creating pointer type...")
    try:
        result = mcp_ghidra_create_pointer_type("TestStruct", "TestStruct_Ptr")
        print(f"✅ Create pointer type: {result}")
    except Exception as e:
        print(f"❌ Create pointer type failed: {e}")
    
    time.sleep(1)
    
    # Test 7: Remove field from structure
    print("\n➖ Test 7: Removing field from structure...")
    try:
        result = mcp_ghidra_remove_struct_field("TestStruct", "field1")
        print(f"✅ Remove field: {result}")
    except Exception as e:
        print(f"❌ Remove field failed: {e}")
    
    time.sleep(1)
    
    # Test 8: Verify structure layout after modifications
    print("\n🔍 Test 8: Checking modified structure layout...")
    try:
        result = mcp_ghidra_get_struct_layout("TestStruct")
        print(f"✅ Structure layout: {result}")
    except Exception as e:
        print(f"❌ Get structure layout failed: {e}")
    
    time.sleep(1)
    
    # Test 9: Delete the test structure (cleanup)
    print("\n🗑️  Test 9: Deleting test structure...")
    try:
        result = mcp_ghidra_delete_data_type("TestStruct")
        print(f"✅ Delete structure: {result}")
    except Exception as e:
        print(f"❌ Delete structure failed: {e}")
    
    time.sleep(1)
    
    # Test 10: Delete array type (cleanup)
    print("\n🗑️  Test 10: Deleting array type...")
    try:
        result = mcp_ghidra_delete_data_type("DWORD_Array_10")
        print(f"✅ Delete array type: {result}")
    except Exception as e:
        print(f"❌ Delete array type failed: {e}")
    
    print("\n" + "=" * 60)
    print("🎉 DATA STRUCTURE MANAGEMENT TESTING COMPLETE!")

if __name__ == "__main__":
    test_data_structure_management()
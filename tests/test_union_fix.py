#!/usr/bin/env python3
"""
Test the fixed union creation functionality directly via REST API
"""

import requests
import json
import time

def test_union_creation():
    """Test creating a union with the fixed endpoint"""
    
    print("🧪 Testing Fixed Union Creation")
    print("="*50)
    
    # Test data for union creation
    union_data = {
        "name": "TestUnion",
        "fields": [
            {"name": "as_int", "type": "int"},
            {"name": "as_float", "type": "float"},
            {"name": "as_bytes", "type": "char[4]"}
        ]
    }
    
    try:
        print("📡 Testing union creation endpoint...")
        response = requests.post(
            "http://localhost:8089/create_union",
            json=union_data,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Union created successfully: {result}")
            return True
        else:
            print(f"❌ Failed to create union: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Connection error: {e}")
        print("Make sure Ghidra with the GhidraMCP plugin is running")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_struct_creation():
    """Test struct creation for comparison"""
    
    print("\n📐 Testing Struct Creation for Comparison")
    print("="*50)
    
    struct_data = {
        "name": "TestStruct",
        "fields": [
            {"name": "id", "type": "int"},
            {"name": "value", "type": "float"},
            {"name": "name", "type": "char[32]"}
        ]
    }
    
    try:
        response = requests.post(
            "http://localhost:8089/create_struct",
            json=struct_data,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Struct created successfully: {result}")
            return True
        else:
            print(f"❌ Failed to create struct: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Connection error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def main():
    print("🔧 UNION FIX VERIFICATION TEST")
    print("="*60)
    
    # Wait for server to be ready
    print("⏳ Waiting for server to be ready...")
    time.sleep(2)
    
    struct_ok = test_struct_creation()
    union_ok = test_union_creation()
    
    print("\n" + "="*60)
    print("📊 FINAL RESULTS")
    print("="*60)
    print(f"Struct Creation: {'✅ WORKING' if struct_ok else '❌ FAILED'}")
    print(f"Union Creation:  {'✅ FIXED' if union_ok else '❌ STILL BROKEN'}")
    
    if union_ok:
        print("\n🎉 SUCCESS! Union creation has been fixed!")
    else:
        print("\n⚠️  Union creation still needs work.")

if __name__ == "__main__":
    main()
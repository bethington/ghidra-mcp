#!/usr/bin/env python3
"""
Debug test to understand the union JSON conversion issue
"""

import requests
import json

def test_create_enum():
    """Test enum creation to compare with union"""
    url = "http://localhost:8089/create_enum"
    
    data = {
        "name": "TestEnum",
        "values": {"OPTION_A": 0, "OPTION_B": 1},
        "size": 4
    }
    
    print("🔢 Testing Enum Creation")
    print(f"URL: {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(url, json=data, timeout=5)
        print(f"Status: {response.status_code}")
        
        if response.content:
            try:
                result = response.json()
                print(f"JSON: {result}")
                return True
            except:
                print(f"Text: {response.text}")
                return True
        else:
            print("Empty response")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_create_struct():
    url = "http://localhost:8089/create_struct"
    
    data = {
        "name": "TestStruct2",
        "fields": [
            {"name": "a", "type": "int"},
            {"name": "b", "type": "float"}
        ]
    }
    
    print("\n🏗️ Testing Struct Creation")
    print(f"URL: {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(url, json=data, timeout=5)
        print(f"Status: {response.status_code}")
        
        if response.content:
            try:
                result = response.json()
                print(f"JSON: {result}")
                return True
            except:
                print(f"Text: {response.text}")
                return True
        else:
            print("Empty response")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_create_union():
    url = "http://localhost:8089/create_union"
    
    data = {
        "name": "TestUnion2",
        "fields": [
            {"name": "as_int", "type": "int"},
            {"name": "as_float", "type": "float"}
        ]
    }
    
    print("\n🔄 Testing Union Creation")
    print(f"URL: {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(url, json=data, timeout=5)
        print(f"Status: {response.status_code}")
        
        if response.content:
            try:
                result = response.json()
                print(f"JSON: {result}")
                return True
            except:
                print(f"Text: {response.text}")
                return True
        else:
            print("Empty response")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("🔍 DIAGNOSTIC TEST - All Data Type Creation")
    print("="*60)
    
    enum_ok = test_create_enum()
    struct_ok = test_create_struct()
    union_ok = test_create_union()
    
    print("\n" + "="*60)
    print("📊 DIAGNOSTIC RESULTS")
    print("="*60)
    print(f"Enum:   {'✅' if enum_ok else '❌'}")
    print(f"Struct: {'✅' if struct_ok else '❌'}")
    print(f"Union:  {'✅' if union_ok else '❌'}")
    
    if enum_ok and struct_ok and not union_ok:
        print("\n⚠️  Union is the only one failing - JSON conversion issue likely")
    elif not union_ok:
        print("\n❌ Multiple endpoints failing - may be server issue")
    else:
        print("\n🎉 All working!")
        
    print("\nNOTE: If union still fails, the plugin may need to be reloaded in Ghidra")
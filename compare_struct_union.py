#!/usr/bin/env python3
"""
Test both struct and union creation to compare
"""

import requests
import json

def test_create_struct():
    url = "http://localhost:8089/create_struct"
    
    data = {
        "name": "SimpleStruct",
        "fields": [
            {"name": "x", "type": "int"},
            {"name": "y", "type": "int"}
        ]
    }
    
    print("🏗️ Testing Struct Creation")
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
        "name": "SimpleUnion",
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
    struct_ok = test_create_struct()
    union_ok = test_create_union()
    
    print("\n" + "="*50)
    print("📊 RESULTS")
    print("="*50)
    print(f"Struct: {'✅' if struct_ok else '❌'}")
    print(f"Union:  {'✅' if union_ok else '❌'}")
    
    if not union_ok and struct_ok:
        print("\n⚠️  Union still broken while struct works - check Java code")
    elif union_ok:
        print("\n🎉 Both struct and union working!")
    else:
        print("\n❌ Both failing - server issue")
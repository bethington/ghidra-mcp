#!/usr/bin/env python3
"""
Direct test of union creation using simple requests
"""

import requests
import json

def test_create_union():
    url = "http://localhost:8089/create_union"
    
    # Simple union data
    data = {
        "name": "SimpleUnion",
        "fields": [
            {"name": "as_int", "type": "int"},
            {"name": "as_float", "type": "float"}
        ]
    }
    
    print("🧪 Testing Union Creation")
    print(f"URL: {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    
    try:
        # Use simple post without JSON header first
        response = requests.post(url, json=data, timeout=5)
        print(f"Status: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        
        if response.content:
            print(f"Content: {response.content}")
            try:
                result = response.json()
                print(f"JSON: {result}")
            except:
                print(f"Text: {response.text}")
        else:
            print("Empty response")
            
    except Exception as e:
        print(f"Error: {e}")
        print(f"Error type: {type(e)}")

if __name__ == "__main__":
    test_create_union()
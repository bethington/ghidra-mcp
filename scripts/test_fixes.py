#!/usr/bin/env python3
"""
Test the specific endpoints we fixed to see if they now work
"""

import requests
import json

# Base URL for the REST API
BASE_URL = "http://127.0.0.1:8089"

def test_endpoint(method, path, description, expected_success=True):
    """Test a single endpoint and return result"""
    url = f"{BASE_URL}{path}"
    
    try:
        if method == "GET":
            response = requests.get(url, timeout=5)
        elif method == "POST":
            response = requests.post(url, json={}, timeout=5)
        else:
            return {"success": False, "error": f"Unsupported method: {method}"}
        
        success = response.status_code == 200
        
        return {
            "success": success,
            "status_code": response.status_code,
            "endpoint": f"{method} {path}",
            "description": description,
            "response_length": len(response.text) if response else 0
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "endpoint": f"{method} {path}",
            "description": description
        }

def main():
    print("🔍 Testing Fixed Endpoints")
    print("=" * 50)
    
    # Test the endpoints we specifically fixed
    endpoints_to_test = [
        ("GET", "/functions", "List functions (alias)"),
        ("POST", "/rename_function", "Rename function (alias)"),
        ("POST", "/rename_data", "Rename data (alias)"),  
        ("POST", "/rename_variable", "Rename variable (alias)"),
        ("GET", "/function_jump_target_addresses", "Function jump targets (alias)"),
        ("GET", "/readMemory", "Read memory (new endpoint)"),
        
        # Test original paths to confirm they still work
        ("GET", "/list_functions", "List functions (original)"),
        ("POST", "/rename_function_by_name", "Rename function (original)"),
        ("POST", "/rename_data_label", "Rename data (original)"),
        ("POST", "/rename_variable_in_function", "Rename variable (original)"),
        ("GET", "/get_function_jump_target_addresses", "Function jump targets (original)"),
    ]
    
    results = []
    
    for method, path, description in endpoints_to_test:
        result = test_endpoint(method, path, description)
        results.append(result)
        
        status = "✅" if result["success"] else "❌"
        print(f"{status} {result['endpoint']} - {description}")
        if not result["success"]:
            if "error" in result:
                print(f"    Error: {result['error']}")
            else:
                print(f"    Status: {result['status_code']}")
    
    print("\n" + "=" * 50)
    
    # Summary
    successful = sum(1 for r in results if r["success"])
    total = len(results)
    success_rate = (successful / total) * 100 if total > 0 else 0
    
    print(f"📊 RESULTS SUMMARY:")
    print(f"   Total endpoints tested: {total}")
    print(f"   Successful: {successful}")
    print(f"   Failed: {total - successful}")
    print(f"   Success rate: {success_rate:.1f}%")
    
    if successful == total:
        print("🎉 All fixes working perfectly!")
    elif successful > total // 2:
        print("👍 Most fixes working - some issues remain")
    else:
        print("🔧 Major issues still present - fixes may not be active")

if __name__ == "__main__":
    main()
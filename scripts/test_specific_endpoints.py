#!/usr/bin/env python3
"""
Quick test to identify which specific endpoints are still failing
and need implementation or aliases.
"""

import requests
import json

BASE_URL = "http://127.0.0.1:8089"

# Test the endpoints that were identified as "TRUE 404 FAILURES"
missing_endpoints = [
    ("GET", "/functions", "list_functions"),
    ("GET", "/function_jump_target_addresses", "get_function_jump_target_addresses"),  
    ("POST", "/rename_function", "rename_function"),
    ("POST", "/rename_variable", "rename_variable"),
    ("POST", "/rename_data", "rename_data"),
    ("GET", "/readMemory", "read_memory"),
]

# Test some of the path/method mismatches too
path_mismatches = [
    ("GET", "/list_globals", "list_globals"),
    ("GET", "/get_entry_points", "get_entry_points"),
    ("POST", "/rename_global_variable", "rename_global_variable"),
]

def test_endpoint(method, path, description):
    """Test a single endpoint"""
    url = f"{BASE_URL}{path}"
    
    try:
        if method == "GET":
            response = requests.get(url, timeout=3)
        elif method == "POST":
            # Send minimal POST data
            response = requests.post(url, json={}, timeout=3)
        else:
            return {"status": "unsupported_method", "method": method}
        
        return {
            "path": path,
            "method": method,
            "status_code": response.status_code,
            "working": response.status_code == 200,
            "response_length": len(response.text) if response.text else 0
        }
        
    except Exception as e:
        return {
            "path": path, 
            "method": method,
            "status_code": "error",
            "working": False,
            "error": str(e)
        }

def main():
    print("🔍 Testing Previously Missing Endpoints")
    print("=" * 50)
    
    results = {
        "missing": [],
        "path_issues": []
    }
    
    print("\n📍 Testing TRUE 404 FAILURES:")
    for method, path, desc in missing_endpoints:
        result = test_endpoint(method, path, desc)
        results["missing"].append(result)
        
        status_emoji = "✅" if result["working"] else "❌"
        print(f"  {status_emoji} {method} {path} -> {result['status_code']}")
    
    print("\n📍 Testing PATH/METHOD MISMATCHES:")
    for method, path, desc in path_mismatches:
        result = test_endpoint(method, path, desc)
        results["path_issues"].append(result)
        
        status_emoji = "✅" if result["working"] else "❌"
        print(f"  {status_emoji} {method} {path} -> {result['status_code']}")
    
    # Summary
    missing_working = sum(1 for r in results["missing"] if r["working"])
    path_working = sum(1 for r in results["path_issues"] if r["working"])
    
    print(f"\n" + "=" * 50)
    print(f"📊 RESULTS:")
    print(f"  Previously Missing: {missing_working}/{len(results['missing'])} now working")
    print(f"  Path Issues: {path_working}/{len(results['path_issues'])} now working")
    
    total_working = missing_working + path_working
    total_tested = len(results["missing"]) + len(results["path_issues"])
    
    if total_working == total_tested:
        print(f"🎉 All tested endpoints are now working!")
    elif total_working > 0:
        print(f"✨ Progress: {total_working}/{total_tested} endpoints fixed")
    else:
        print(f"⚠️  No endpoints working - plugin may need redeployment")

if __name__ == "__main__":
    main()
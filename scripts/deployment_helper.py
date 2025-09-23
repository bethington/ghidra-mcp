#!/usr/bin/env python3
"""
Helper script to guide through the Ghidra plugin deployment process
and verify that the updated plugin is working.
"""

import os
import requests
import time

BASE_URL = "http://127.0.0.1:8089"

def check_server_status():
    """Check if the Ghidra MCP server is running"""
    try:
        response = requests.get(f"{BASE_URL}/list_functions", timeout=3)
        return True, response.status_code
    except requests.exceptions.ConnectionError:
        return False, "Not running"
    except Exception as e:
        return False, str(e)

def test_fixed_endpoints():
    """Test the endpoints that were fixed"""
    fixed_endpoints = [
        ("GET", "/functions", "List functions"),
        ("GET", "/function_jump_target_addresses", "Function jump targets"),
        ("POST", "/rename_function", "Rename function"),
        ("POST", "/rename_variable", "Rename variable"),
        ("POST", "/rename_data", "Rename data"),
        ("GET", "/readMemory", "Read memory"),
    ]
    
    results = []
    
    for method, path, desc in fixed_endpoints:
        try:
            url = f"{BASE_URL}{path}"
            if method == "GET":
                response = requests.get(url, timeout=3)
            else:
                response = requests.post(url, json={}, timeout=3)
            
            working = response.status_code == 200
            results.append({
                "endpoint": f"{method} {path}",
                "description": desc,
                "status_code": response.status_code,
                "working": working
            })
        except Exception as e:
            results.append({
                "endpoint": f"{method} {path}",
                "description": desc,
                "status_code": "error",
                "working": False,
                "error": str(e)
            })
    
    return results

def main():
    plugin_zip = "../target/GhidraMCP-1.2.0.zip"
    
    print("🔧 Ghidra Plugin Deployment Helper")
    print("=" * 50)
    
    # Check if plugin ZIP exists
    if not os.path.exists(plugin_zip):
        print(f"❌ Plugin ZIP not found: {plugin_zip}")
        print("   Run 'mvn clean package assembly:single' first")
        return
    
    print(f"✅ Plugin ZIP found: {plugin_zip}")
    
    # Check current server status
    print("\n📡 Checking current server status...")
    running, status = check_server_status()
    
    if not running:
        print(f"❌ Ghidra MCP server not running: {status}")
        print("   Start Ghidra and open a project first")
        return
    
    print(f"✅ Server is running (status: {status})")
    
    # Test current endpoints
    print("\n🧪 Testing fixed endpoints...")
    results = test_fixed_endpoints()
    
    working_count = sum(1 for r in results if r["working"])
    total_count = len(results)
    
    print(f"\n📊 Current Status: {working_count}/{total_count} endpoints working")
    
    for result in results:
        status_emoji = "✅" if result["working"] else "❌"
        print(f"  {status_emoji} {result['endpoint']} -> {result['status_code']}")
    
    if working_count == total_count:
        print("\n🎉 All endpoints are working! Plugin is properly deployed.")
        return
    
    # Provide deployment instructions
    print("\n" + "=" * 50) 
    print("🚀 DEPLOYMENT REQUIRED")
    print("=" * 50)
    print(f"\nThe updated plugin needs to be installed in Ghidra:")
    print(f"\n1. In Ghidra: File → Install Extensions")
    print(f"2. Click the '+' button")
    print(f"3. Select: {os.path.abspath(plugin_zip)}")
    print(f"4. Restart Ghidra")
    print(f"5. Open a project")
    print(f"6. Verify plugin is enabled: File → Configure → Developer")
    print(f"\nThen run this script again to verify the fix!")
    
    print(f"\n📈 Expected improvement:")
    print(f"   Current: {working_count}/{total_count} endpoints working")
    print(f"   After deployment: {total_count}/{total_count} endpoints working")

if __name__ == "__main__":
    main()
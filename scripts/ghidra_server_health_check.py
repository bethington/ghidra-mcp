#!/usr/bin/env python3
"""
Ghidra MCP Server Health Checker

Comprehensive diagnostic tool to verify that GhidraMCP is ready for use.
Validates connectivity, plugin status, program state, and core functionality.

Usage:
    python ghidra_server_health_check.py [server_url]
    
Examples:
    python ghidra_server_health_check.py
    python ghidra_server_health_check.py http://127.0.0.1:8080/
"""

import sys
import requests
import time
from urllib.parse import urljoin
from typing import Dict, Any

# Import centralized configuration
from scripts_config import (
    Config, EndpointConfig, MessageConfig, get_server_url, 
    get_timeout, format_success, format_error
)

def check_server_status(server_url: str = None) -> Dict[str, Any]:
    if server_url is None:
        server_url = get_server_url()
    """Check comprehensive server status"""
    server_url = server_url.rstrip('/') + '/'
    status = {
        "server_url": server_url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "connectivity": False,
        "plugin_loaded": False,
        "program_loaded": False,
        "basic_functions": {},
        "ready_for_testing": False,
        "issues": []
    }
    
    print(f"🔍 Checking MCP test readiness for {server_url}")
    print("-" * 50)
    
    # Test 1: Basic connectivity
    print("1. Testing connectivity...", end=" ")
    try:
        response = requests.get(urljoin(server_url, "methods"), timeout=get_timeout())
        if response.ok:
            status["connectivity"] = True
            status["plugin_loaded"] = True
            print(f"{MessageConfig.SUCCESS} Connected")
            print(f"   Response: {response.text.strip()}")
        else:
            print(f"{MessageConfig.ERROR} HTTP {response.status_code}")
            status["issues"].append(f"Server returned HTTP {response.status_code}")
    except Exception as e:
        print(f"{MessageConfig.ERROR} {str(e)}")
        status["issues"].append(f"Connection failed: {str(e)}")
    
    if not status["connectivity"]:
        print("\n❌ Cannot proceed without server connectivity")
        return status
    
    # Test 2: Basic endpoints
    print("\n2. Testing basic endpoints...")
    basic_tests = [
        ("get_metadata", "GET", "get_metadata", {}),
        ("list_functions", "GET", "functions", {"limit": 1}),
        ("list_strings", "GET", "strings", {"limit": 1}),
        ("convert_number", "GET", "convert_number", {"text": "42", "size": 4})
    ]
    
    for test_name, method, endpoint, params in basic_tests:
        print(f"   {test_name}...", end=" ")
        try:
            if method == "GET":
                response = requests.get(urljoin(server_url, endpoint), params=params, timeout=30)
            else:
                response = requests.post(urljoin(server_url, endpoint), data=params, timeout=30)
            
            if response.ok:
                print("✅")
                status["basic_functions"][test_name] = True
                
                # Check for program content
                if test_name in ["list_functions", "list_strings"] and response.text.strip():
                    lines = response.text.strip().split('\n')
                    if lines and not lines[0].startswith("Error") and len(lines) > 0:
                        status["program_loaded"] = True
            else:
                print(f"❌ HTTP {response.status_code}")
                status["basic_functions"][test_name] = False
                status["issues"].append(f"{test_name} returned HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ {str(e)}")
            status["basic_functions"][test_name] = False
            status["issues"].append(f"{test_name} failed: {str(e)}")
    
    # Test 3: Data type operations
    print("\n3. Testing data type operations...")
    print("   list_data_types...", end=" ")
    try:
        response = requests.get(urljoin(server_url, "list_data_types"), params={"limit": 5}, timeout=30)
        if response.ok and response.text.strip():
            print("✅")
            status["basic_functions"]["data_types"] = True
        else:
            print("❌")
            status["basic_functions"]["data_types"] = False
    except Exception as e:
        print(f"❌ {str(e)}")
        status["basic_functions"]["data_types"] = False
    
    # Test 4: Analysis operations
    print("\n4. Testing analysis operations...")
    print("   get_current_address...", end=" ")
    try:
        response = requests.get(urljoin(server_url, "get_current_address"), timeout=30)
        if response.ok:
            print("✅")
            status["basic_functions"]["analysis"] = True
            if "No current location" not in response.text:
                print(f"   Current address: {response.text.strip()}")
            else:
                print("   No current location set (normal for headless)")
        else:
            print("❌")
            status["basic_functions"]["analysis"] = False
    except Exception as e:
        print(f"❌ {str(e)}")
        status["basic_functions"]["analysis"] = False
    
    # Overall assessment
    print("\n" + "=" * 50)
    print("ASSESSMENT SUMMARY")
    print("=" * 50)
    
    working_functions = sum(1 for v in status["basic_functions"].values() if v)
    total_functions = len(status["basic_functions"])
    
    print(f"✅ Connectivity: {'Yes' if status['connectivity'] else 'No'}")
    print(f"✅ Plugin loaded: {'Yes' if status['plugin_loaded'] else 'No'}")
    print(f"✅ Program loaded: {'Yes' if status['program_loaded'] else 'Unclear'}")
    print(f"✅ Basic functions: {working_functions}/{total_functions} working")
    
    # Determine readiness
    if status["connectivity"] and status["plugin_loaded"] and working_functions >= 3:
        status["ready_for_testing"] = True 
        print("\n🎉 STATUS: READY FOR TESTING")
        print("You can run the full test suite with:")
        print(f"  python run_mcp_tests.py --server {server_url}")
    else:
        print("\n⚠️  STATUS: NOT READY FOR TESTING")
        print("Issues to resolve:")
        for issue in status["issues"]:
            print(f"  - {issue}")
        
        print("\nSuggestions:")
        if not status["connectivity"]:
            print("  - Start Ghidra with the GhidraMCP plugin")
            print("  - Verify the server URL and port")
        if not status["program_loaded"]:
            print("  - Load and analyze a binary in Ghidra")
            print("  - Ensure the program has been analyzed")
    
    return status

def main():
    server_url = get_server_url()
    status = check_server_status(server_url)
    sys.exit(0 if status["ready_for_testing"] else 1)

if __name__ == "__main__":
    main()
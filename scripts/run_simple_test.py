#!/usr/bin/env python3
"""
Simple test runner to check MCP endpoint connectivity
"""

import sys
import subprocess
import requests

def check_server_availability(server_url):
    """Check if Ghidra server is available"""
    try:
        response = requests.get(f"{server_url}methods", timeout=5)
        if response.status_code == 200:
            methods = response.json()
            method_count = len(methods) if isinstance(methods, list) else "unknown"
            print(f"PASS Server is available: Found {method_count} methods")
            return True
        else:
            print(f"FAIL Server responded with error: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"FAIL Cannot connect to server: {str(e)}")
        return False

def run_endpoint_test(server_url):
    """Run the endpoint test"""
    try:
        cmd = [sys.executable, "test_mcp_tools_endpoints.py", server_url]
        result = subprocess.run(cmd, cwd=".", capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("PASS Endpoint tests completed successfully")
            return True
        else:
            print(f"FAIL Endpoint tests failed (code {result.returncode})")
            print("STDOUT:", result.stdout[:500])
            print("STDERR:", result.stderr[:500])
            return False
    except Exception as e:
        print(f"FAIL Error running endpoint tests: {str(e)}")
        return False

def main():
    server_url = "http://127.0.0.1:8089/"
    
    print("=" * 60)
    print("Simple MCP Test Runner")
    print(f"Server: {server_url}")
    print("=" * 60)
    
    # Check server availability
    print("Checking server availability...")
    if not check_server_availability(server_url):
        sys.exit(1)
    
    # Run endpoint tests
    print("Running endpoint tests...")
    if run_endpoint_test(server_url):
        print("SUCCESS: All tests passed!")
        sys.exit(0)
    else:
        print("FAILURE: Tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
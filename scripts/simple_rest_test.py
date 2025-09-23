#!/usr/bin/env python3
"""
Simple REST Endpoint Test for GhidraMCP

This script tests the key REST endpoints to verify the server is working correctly.
"""

import requests
import json
import sys
from typing import Dict, List, Tuple

class SimpleRESTTester:
    def __init__(self, server_url: str = "http://127.0.0.1:8089/"):
        self.server_url = server_url.rstrip('/') + '/'
        self.session = requests.Session()
        self.session.timeout = 10
        
    def test_endpoint(self, endpoint: str, method: str = "GET", data: dict = None) -> Tuple[bool, str, int]:
        """Test a single endpoint and return success status, response, and status code"""
        try:
            url = self.server_url + endpoint
            if method == "GET":
                response = self.session.get(url)
            elif method == "POST":
                response = self.session.post(url, json=data, headers={'Content-Type': 'application/json'})
            else:
                return False, f"Unsupported method: {method}", 0
                
            return True, str(response.text)[:200], response.status_code
        except Exception as e:
            return False, str(e), 0
    
    def run_tests(self):
        """Run a comprehensive set of REST endpoint tests"""
        print("🔍 Testing GhidraMCP REST Endpoints")
        print("=" * 50)
        
        # Core navigation endpoints
        nav_endpoints = [
            ("list_functions", "GET"),
            ("classes", "GET"),
            ("segments", "GET"),
            ("imports", "GET"),
            ("exports", "GET"),
            ("strings", "GET"),
            ("data", "GET"),
            ("namespaces", "GET")
        ]
        
        print("\n📋 Navigation Endpoints:")
        nav_passed = 0
        for endpoint, method in nav_endpoints:
            success, response, status = self.test_endpoint(endpoint, method)
            if success and status == 200:
                print(f"  ✅ {method} /{endpoint} - SUCCESS")
                nav_passed += 1
            else:
                print(f"  ❌ {method} /{endpoint} - FAILED ({status})")
        
        # Analysis endpoints
        analysis_endpoints = [
            ("get_current_address", "GET"),
            ("get_current_function", "GET"),
            ("decompile_function", "GET"),
            ("disassemble_function", "GET"),
            ("methods", "GET")
        ]
        
        print(f"\n🔬 Analysis Endpoints:")
        analysis_passed = 0
        for endpoint, method in analysis_endpoints:
            success, response, status = self.test_endpoint(endpoint, method)
            if success and status == 200:
                print(f"  ✅ {method} /{endpoint} - SUCCESS")
                analysis_passed += 1
            else:
                print(f"  ❌ {method} /{endpoint} - FAILED ({status})")
        
        # Data type endpoints
        data_endpoints = [
            ("list_data_types", "GET"),
            ("create_struct", "POST", {"name": "TestStruct", "fields": [{"name": "field1", "type": "int", "offset": 0}]}),
            ("create_enum", "POST", {"name": "TestEnum", "values": {"OPTION_A": 0, "OPTION_B": 1}})
        ]
        
        print(f"\n📊 Data Type Endpoints:")
        data_passed = 0
        for endpoint, method, *args in data_endpoints:
            data = args[0] if args else None
            success, response, status = self.test_endpoint(endpoint, method, data)
            if success and status == 200:
                print(f"  ✅ {method} /{endpoint} - SUCCESS")
                data_passed += 1
            else:
                print(f"  ❌ {method} /{endpoint} - FAILED ({status})")
        
        # Modification endpoints (test with dummy data)
        mod_endpoints = [
            ("create_label", "POST", {"address": "0x401000", "name": "test_rest_label"}),
            ("set_disassembly_comment", "POST", {"address": "0x401000", "comment": "Test REST comment"}),
            ("apply_data_type", "POST", {"address": "0x401000", "type_name": "int"})
        ]
        
        print(f"\n✏️ Modification Endpoints:")
        mod_passed = 0
        for endpoint, method, data in mod_endpoints:
            success, response, status = self.test_endpoint(endpoint, method, data)
            if success and status == 200:
                print(f"  ✅ {method} /{endpoint} - SUCCESS")
                mod_passed += 1
            else:
                print(f"  ❌ {method} /{endpoint} - FAILED ({status})")
        
        # Summary
        total_tests = len(nav_endpoints) + len(analysis_endpoints) + len(data_endpoints) + len(mod_endpoints)
        total_passed = nav_passed + analysis_passed + data_passed + mod_passed
        
        print("\n" + "=" * 50)
        print(f"📊 TEST SUMMARY")
        print(f"Navigation: {nav_passed}/{len(nav_endpoints)} passed")
        print(f"Analysis: {analysis_passed}/{len(analysis_endpoints)} passed")
        print(f"Data Types: {data_passed}/{len(data_endpoints)} passed")
        print(f"Modification: {mod_passed}/{len(mod_endpoints)} passed")
        print(f"TOTAL: {total_passed}/{total_tests} passed ({total_passed/total_tests*100:.1f}%)")
        
        if total_passed >= total_tests * 0.7:  # 70% success rate
            print("🎉 REST API is working well!")
            return 0
        else:
            print("⚠️ Some endpoints may need attention")
            return 1

def main():
    server_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8089/"
    
    tester = SimpleRESTTester(server_url)
    return tester.run_tests()

if __name__ == "__main__":
    sys.exit(main())
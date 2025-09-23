#!/usr/bin/env python3
"""
Test script for GhidraMCP struct and enum creation functionality.

This script demonstrates the complete workflow for creating custom data types
in Ghidra using the REST API endpoints.

Fixed Issues:
- "No valid fields provided" error resolved by implementing proper JSON parsing
- create_struct, create_enum, and apply_data_type endpoints now handle JSON correctly
- Error handling and validation work as expected

Usage:
    python test_struct_enum_creation.py
"""

import requests
import json
import sys
from typing import Dict, List, Any, Optional


class GhidraMCPTester:
    def __init__(self, base_url: str = "http://127.0.0.1:8089"):
        self.base_url = base_url
        self.test_results = []
    
    def test_request(self, name: str, endpoint: str, data: Optional[Dict] = None, 
                    method: str = 'GET', expect_success: bool = True) -> bool:
        """Execute a test request and record results."""
        url = f"{self.base_url}/{endpoint}"
        
        try:
            if method == 'POST':
                response = requests.post(url, json=data, 
                                       headers={'Content-Type': 'application/json'}, 
                                       timeout=10)
            else:
                response = requests.get(url, timeout=10)
            
            success = response.status_code == 200
            
            # Check for expected error responses
            if not expect_success:
                success = not success or any(keyword in response.text.lower() 
                                           for keyword in ['error', 'required', 'invalid'])
            
            status_icon = "✅" if success else "❌"
            print(f"{name:40} -> {status_icon} ({response.status_code})")
            
            # Show response details for successful operations
            if success and expect_success and 'successfully' in response.text.lower():
                print(f"    📋 {response.text[:80]}...")
            elif not success:
                print(f"    ⚠️  {response.text[:60]}...")
            
            self.test_results.append((name, success))
            return success
            
        except requests.exceptions.ConnectionError:
            print(f"{name:40} -> ❌ Connection refused (Ghidra not running?)")
            self.test_results.append((name, False))
            return False
        except Exception as e:
            print(f"{name:40} -> ❌ ERROR: {str(e)[:40]}...")
            self.test_results.append((name, False))
            return False

    def run_comprehensive_tests(self) -> None:
        """Run the complete test suite."""
        print("🧪 GHIDRA MCP STRUCT & ENUM CREATION TEST SUITE")
        print("=" * 80)
        
        # Test 1: Basic connectivity
        print("\n📡 Step 1: Testing Basic Connectivity")
        if not self.test_request("Server Health Check", "list_functions"):
            print("❌ Cannot connect to Ghidra MCP server!")
            print("   Please ensure:")
            print("   1. Ghidra is running")
            print("   2. GhidraMCP plugin is enabled")
            print("   3. MCP server is started (Tools > GhidraMCP > Start MCP Server)")
            return
        
        # Test 2: Create various structs
        print("\n📋 Step 2: Creating Custom Structures")
        
        self.test_request(
            "Simple Struct", 
            "create_struct",
            {
                "name": "Point2D",
                "fields": [
                    {"name": "x", "type": "int"},
                    {"name": "y", "type": "int"}
                ]
            },
            "POST"
        )
        
        self.test_request(
            "Complex Struct", 
            "create_struct",
            {
                "name": "NetworkPacket",
                "fields": [
                    {"name": "header", "type": "DWORD"},
                    {"name": "length", "type": "WORD"},
                    {"name": "data", "type": "byte[256]"},
                    {"name": "checksum", "type": "DWORD"}
                ]
            },
            "POST"
        )
        
        # Test 3: Create various enums
        print("\n📝 Step 3: Creating Custom Enumerations")
        
        self.test_request(
            "Status Enum",
            "create_enum",
            {
                "name": "Status",
                "values": {
                    "SUCCESS": 0,
                    "WARNING": 1,
                    "ERROR": 2,
                    "CRITICAL": 3
                },
                "size": 1
            },
            "POST"
        )
        
        self.test_request(
            "File Permissions Enum",
            "create_enum", 
            {
                "name": "FilePermissions",
                "values": {
                    "READ": 4,
                    "WRITE": 2,
                    "EXECUTE": 1,
                    "READ_WRITE": 6,
                    "READ_EXECUTE": 5,
                    "WRITE_EXECUTE": 3,
                    "ALL": 7
                },
                "size": 2
            },
            "POST"
        )
        
        # Test 4: Apply data types
        print("\n🎯 Step 4: Applying Data Types to Memory")
        
        self.test_request(
            "Apply Point2D at 0x401000",
            "apply_data_type",
            {
                "address": "0x401000",
                "type_name": "Point2D",
                "clear_existing": True
            },
            "POST"
        )
        
        self.test_request(
            "Apply NetworkPacket at 0x402000",
            "apply_data_type",
            {
                "address": "0x402000", 
                "type_name": "NetworkPacket",
                "clear_existing": False
            },
            "POST"
        )
        
        # Test 5: Error handling
        print("\n⚠️  Step 5: Testing Error Handling")
        
        self.test_request(
            "Struct without name",
            "create_struct",
            {"fields": [{"name": "x", "type": "int"}]},
            "POST",
            expect_success=False
        )
        
        self.test_request(
            "Enum without values",
            "create_enum",
            {"name": "EmptyEnum", "values": {}},
            "POST", 
            expect_success=False
        )
        
        self.test_request(
            "Apply type without address",
            "apply_data_type",
            {"type_name": "Point2D"},
            "POST",
            expect_success=False
        )
        
        # Test 6: List data types
        print("\n📊 Step 6: Listing Available Data Types")
        self.test_request("List Data Types", "list_data_types")
        
        # Results summary
        self.print_summary()

    def print_summary(self) -> None:
        """Print test results summary."""
        print("\n" + "=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for _, success in self.test_results if success)
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"📊 TEST RESULTS SUMMARY")
        print(f"   Total Tests: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Failed: {total_tests - passed_tests}")
        print(f"   Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 95:
            print("\n🎉 EXCELLENT! Struct & Enum creation is fully functional!")
            print("   All major functionality is working correctly.")
        elif success_rate >= 80:
            print("\n✅ GOOD! Most functionality is working.")
            print("   Some minor issues may remain.")
        elif success_rate >= 60:
            print("\n⚠️  PARTIAL SUCCESS. Some functionality working.")
            print("   Significant issues need to be addressed.")
        else:
            print("\n❌ MAJOR ISSUES! Most tests failed.")
            print("   Functionality needs significant fixes.")
        
        # Show failed tests
        failed_tests = [name for name, success in self.test_results if not success]
        if failed_tests:
            print(f"\n❌ Failed Tests:")
            for test_name in failed_tests:
                print(f"   - {test_name}")
        
        print("\n" + "=" * 80)


def main():
    """Main execution function."""
    print("Starting GhidraMCP Struct & Enum Creation Tests...")
    print("Make sure Ghidra is running with GhidraMCP plugin enabled!\n")
    
    tester = GhidraMCPTester()
    tester.run_comprehensive_tests()
    
    print("\n✨ Test execution completed!")
    print("For more information, see: https://github.com/bethington/ghidra-mcp")


if __name__ == "__main__":
    main()
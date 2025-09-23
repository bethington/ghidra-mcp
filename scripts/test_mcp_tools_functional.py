#!/usr/bin/env python3
"""
MCP Tools Functional Test Suite

This script performs functional tests of MCP tools by testing specific
scenarios and workflows that validate the tools work as expected.

Usage:
    python test_mcp_tools_functional.py [server_url]

Default server URL: http://127.0.0.1:8089/
"""

import requests
import json
import sys
import time
from urllib.parse import urljoin
from typing import Dict, List, Tuple, Any, Optional
import re

class MCPToolsFunctionalTester:
    def __init__(self, server_url: str = "http://127.0.0.1:8089/"):
        self.server_url = server_url.rstrip('/') + '/'
        self.session = requests.Session()
        self.session.timeout = 15
        self.test_artifacts = []  # Track created test artifacts for cleanup
        
    def log(self, message: str, level: str = "INFO"):
        """Log a message with timestamp and color"""
        timestamp = time.strftime("%H:%M:%S")
        colors = {
            "INFO": "\033[36m", "SUCCESS": "\033[32m", "ERROR": "\033[31m", 
            "WARNING": "\033[33m", "TEST": "\033[35m", "RESET": "\033[0m"
        }
        color = colors.get(level, colors["INFO"])
        print(f"{color}[{timestamp}] {level}: {message}{colors['RESET']}")
        
    def safe_request(self, method: str, endpoint: str, params: Optional[Dict] = None) -> Tuple[bool, str, int]:
        """Make a safe HTTP request"""
        url = urljoin(self.server_url, endpoint)
        try:
            if method == "GET":
                response = self.session.get(url, params=params)
            else:
                response = self.session.post(url, data=params)
            return response.ok, response.text.strip(), response.status_code
        except Exception as e:
            return False, f"Request failed: {str(e)}", 0
    
    def test_basic_connectivity(self) -> bool:
        """Test 1: Basic connectivity and plugin status"""
        self.log("Testing basic connectivity...", "TEST")
        
        # Test connection
        success, response, status = self.safe_request("GET", "check_connection")
        if not success:
            self.log(f"❌ Connection test failed: {response}", "ERROR")
            return False
            
        self.log(f"✅ Connection successful: {response}", "SUCCESS")
        
        # Test metadata
        success, response, status = self.safe_request("GET", "get_metadata")
        if success and response:
            self.log(f"✅ Metadata retrieved successfully", "SUCCESS")
            # Try to extract program name
            if "Program:" in response or "Binary:" in response:
                self.log(f"  Program info found in metadata", "INFO")
        else:
            self.log(f"⚠️  Metadata test inconclusive: {response}", "WARNING")
            
        return True
    
    def test_navigation_workflow(self) -> bool:
        """Test 2: Navigation workflow - listing and finding elements"""
        self.log("Testing navigation workflow...", "TEST")
        
        tests_passed = 0
        
        # Test function listing
        success, response, status = self.safe_request("GET", "functions", {"limit": 5})
        if success:
            lines = response.split('\n') if response else []
            if len(lines) > 0 and not lines[0].startswith("Error"):
                self.log(f"✅ Function listing: Found {len(lines)} functions", "SUCCESS")
                tests_passed += 1
            else:
                self.log(f"⚠️  Function listing returned no functions", "WARNING")
        else:
            self.log(f"❌ Function listing failed: {response}", "ERROR")
        
        # Test string listing
        success, response, status = self.safe_request("GET", "strings", {"limit": 10})
        if success:
            lines = response.split('\n') if response else []
            if len(lines) > 0 and not lines[0].startswith("Error"):
                self.log(f"✅ String listing: Found {len(lines)} strings", "SUCCESS")
                tests_passed += 1
        
        # Test imports/exports
        for endpoint, name in [("imports", "Imports"), ("exports", "Exports")]:
            success, response, status = self.safe_request("GET", endpoint, {"limit": 5})
            if success and response and not response.startswith("Error"):
                lines = response.split('\n')
                self.log(f"✅ {name} listing: Found {len(lines)} entries", "SUCCESS")
                tests_passed += 1
        
        # Test current address/function
        success, response, status = self.safe_request("GET", "get_current_address")
        if success:
            if "No current location" not in response:
                self.log(f"✅ Current address: {response}", "SUCCESS")
                tests_passed += 1
            else:
                self.log(f"ℹ️  No current address set (expected in headless mode)", "INFO")
        
        self.log(f"Navigation workflow: {tests_passed}/5 tests passed")
        return tests_passed >= 3
    
    def test_analysis_workflow(self) -> bool:
        """Test 3: Analysis workflow - decompilation and function analysis"""
        self.log("Testing analysis workflow...", "TEST")
        
        tests_passed = 0
        test_function = None
        
        # First, find a function to test with
        success, response, status = self.safe_request("GET", "functions", {"limit": 20})
        if success and response:
            lines = response.split('\n')
            # Look for a likely function name
            for line in lines:
                if line and not line.startswith("Error") and not line.startswith("Total"):
                    # Extract function name (might be in format "address: name" or just "name")
                    if ':' in line:
                        test_function = line.split(':', 1)[1].strip()
                    else:
                        test_function = line.strip()
                    break
        
        if not test_function:
            # Try common function names
            for common_func in ["main", "entry", "start", "WinMain", "_main"]:
                success, response, status = self.safe_request("GET", "function_xrefs", {"name": common_func, "limit": 1})
                if success and response and not response.startswith("Error"):
                    test_function = common_func
                    break
        
        if test_function:
            self.log(f"Using test function: {test_function}", "INFO")
            
            # Test decompilation
            success, response, status = self.safe_request("POST", "decompile", {"name": test_function})
            if success and response and not response.startswith("Error"):
                if len(response) > 50:  # Reasonable decompiled code length
                    self.log(f"✅ Decompilation successful ({len(response)} chars)", "SUCCESS")
                    tests_passed += 1
                else:
                    self.log(f"⚠️  Decompilation returned minimal content", "WARNING")
            
            # Test function callees
            success, response, status = self.safe_request("GET", "function_callees", {"name": test_function, "limit": 5})
            if success:
                if response and not response.startswith("Error"):
                    lines = response.split('\n')
                    self.log(f"✅ Function callees: Found {len(lines)} callees", "SUCCESS")
                    tests_passed += 1
                else:
                    self.log(f"ℹ️  Function has no callees (or error)", "INFO")
            
            # Test function callers
            success, response, status = self.safe_request("GET", "function_callers", {"name": test_function, "limit": 5})
            if success:
                tests_passed += 1  # Count as success even if no callers
                self.log(f"✅ Function callers query successful", "SUCCESS")
            
            # Test call graph
            success, response, status = self.safe_request("GET", "function_call_graph", {"name": test_function, "depth": 2})
            if success:
                tests_passed += 1
                self.log(f"✅ Call graph generation successful", "SUCCESS")
        else:
            self.log(f"⚠️  No suitable test function found", "WARNING")
        
        # Test cross-references with a common address
        success, response, status = self.safe_request("GET", "xrefs_to", {"address": "0x401000", "limit": 5})
        if success:
            tests_passed += 1
            self.log(f"✅ Cross-reference query successful", "SUCCESS")
        
        self.log(f"Analysis workflow: {tests_passed}/5 tests passed")
        return tests_passed >= 2
    
    def test_data_type_workflow(self) -> bool:
        """Test 4: Data type management workflow"""
        self.log("Testing data type workflow...", "TEST")
        
        tests_passed = 0
        
        # Test list data types
        success, response, status = self.safe_request("GET", "list_data_types", {"limit": 10})
        if success and response:
            lines = response.split('\n')
            if len(lines) > 0 and not lines[0].startswith("Error"):
                self.log(f"✅ Data types listing: Found {len(lines)} types", "SUCCESS")
                tests_passed += 1
        
        # Test create structure
        struct_name = f"TestStruct_{int(time.time())}"
        struct_data = {
            "name": struct_name,
            "fields": '[{"name":"id","type":"int"},{"name":"name","type":"char[32]"},{"name":"value","type":"float"}]'
        }
        success, response, status = self.safe_request("POST", "create_struct", struct_data)
        if success and "success" in response.lower():
            self.log(f"✅ Structure creation successful: {struct_name}", "SUCCESS")
            tests_passed += 1
            self.test_artifacts.append(("struct", struct_name))
        else:
            self.log(f"⚠️  Structure creation: {response}", "WARNING")
        
        # Test create enumeration
        enum_name = f"TestEnum_{int(time.time())}"
        enum_data = {
            "name": enum_name,
            "values": '{"OPTION_NONE": 0, "OPTION_ENABLED": 1, "OPTION_DISABLED": 2}',
            "size": "4"
        }
        success, response, status = self.safe_request("POST", "create_enum", enum_data)
        if success and "success" in response.lower():
            self.log(f"✅ Enumeration creation successful: {enum_name}", "SUCCESS")
            tests_passed += 1
            self.test_artifacts.append(("enum", enum_name))
        else:
            self.log(f"⚠️  Enumeration creation: {response}", "WARNING")
        
        # Test type size query
        success, response, status = self.safe_request("GET", "get_type_size", {"type_name": "int"})
        if success and response and not response.startswith("Error"):
            self.log(f"✅ Type size query: {response}", "SUCCESS")
            tests_passed += 1
        
        # Test apply data type
        success, response, status = self.safe_request("POST", "apply_data_type", 
                                                     {"address": "0x401000", "type_name": "int"})
        if success:
            tests_passed += 1
            self.log(f"✅ Apply data type successful", "SUCCESS")
        
        self.log(f"Data type workflow: {tests_passed}/5 tests passed")
        return tests_passed >= 3
    
    def test_search_workflow(self) -> bool:
        """Test 5: Search functionality workflow"""
        self.log("Testing search workflow...", "TEST")
        
        tests_passed = 0
        
        # Test function search
        success, response, status = self.safe_request("GET", "searchFunctions", {"query": "main", "limit": 5})
        if success and response:
            lines = response.split('\n')
            if len(lines) > 0 and not lines[0].startswith("Error"):
                self.log(f"✅ Function search: Found {len(lines)} matches", "SUCCESS")
                tests_passed += 1
        
        # Test data type search
        success, response, status = self.safe_request("GET", "search_data_types", {"pattern": "int", "limit": 5})
        if success and response:
            if not response.startswith("Error"):
                self.log(f"✅ Data type search successful", "SUCCESS")
                tests_passed += 1
        
        # Test function labels (might be empty but should not error)
        success, response, status = self.safe_request("GET", "function_labels", {"name": "main", "limit": 5})
        if success:
            tests_passed += 1
            self.log(f"✅ Function labels query successful", "SUCCESS")
        
        self.log(f"Search workflow: {tests_passed}/3 tests passed")
        return tests_passed >= 2
    
    def test_modification_workflow(self) -> bool:
        """Test 6: Modification operations (with cleanup)"""
        self.log("Testing modification workflow...", "TEST")
        
        tests_passed = 0
        
        # Test comment setting
        test_address = "0x401000"
        comment_text = f"Test comment from MCP test {int(time.time())}"
        
        success, response, status = self.safe_request("POST", "set_disassembly_comment", 
                                                     {"address": test_address, "comment": comment_text})
        if success and not response.startswith("Error"):
            self.log(f"✅ Set disassembly comment successful", "SUCCESS")
            tests_passed += 1
        
        # Test label creation
        label_name = f"test_label_{int(time.time())}"
        success, response, status = self.safe_request("POST", "create_label", 
                                                     {"address": test_address, "name": label_name})
        if success and not response.startswith("Error"):
            self.log(f"✅ Label creation successful: {label_name}", "SUCCESS")
            tests_passed += 1
            self.test_artifacts.append(("label", label_name, test_address))
        
        # Test number conversion (utility function)
        success, response, status = self.safe_request("GET", "convert_number", {"text": "255", "size": 4})
        if success and response:
            if "0xff" in response.lower() or "255" in response:
                self.log(f"✅ Number conversion successful", "SUCCESS")
                tests_passed += 1
        
        self.log(f"Modification workflow: {tests_passed}/3 tests passed")
        return tests_passed >= 2
    
    def test_memory_and_export_workflow(self) -> bool:
        """Test 7: Memory reading and export functionality"""
        self.log("Testing memory and export workflow...", "TEST")
        
        tests_passed = 0
        
        # Test memory reading
        success, response, status = self.safe_request("GET", "readMemory", {"address": "0x401000", "size": 16})
        if success and response:
            if not response.startswith("Error") and len(response) > 10:
                self.log(f"✅ Memory reading successful ({len(response)} chars)", "SUCCESS")
                tests_passed += 1
            else:
                self.log(f"⚠️  Memory reading: {response}", "WARNING")
        
        # Test data type export
        success, response, status = self.safe_request("GET", "export_data_types", {"format": "c", "category": "builtin"})
        if success and response:
            if not response.startswith("Error") and ("int" in response or "char" in response):
                self.log(f"✅ Data type export successful", "SUCCESS")
                tests_passed += 1
        
        self.log(f"Memory and export workflow: {tests_passed}/2 tests passed")
        return tests_passed >= 1
    
    def run_functional_tests(self) -> bool:
        """Run all functional tests"""
        self.log("=" * 60)
        self.log("Starting MCP Tools Functional Testing Suite")
        self.log(f"Target server: {self.server_url}")
        self.log("=" * 60)
        
        test_results = []
        
        # Run test workflows
        workflows = [
            ("Basic Connectivity", self.test_basic_connectivity),
            ("Navigation Workflow", self.test_navigation_workflow),
            ("Analysis Workflow", self.test_analysis_workflow),
            ("Data Type Workflow", self.test_data_type_workflow),
            ("Search Workflow", self.test_search_workflow),
            ("Modification Workflow", self.test_modification_workflow),
            ("Memory & Export Workflow", self.test_memory_and_export_workflow),
        ]
        
        passed_workflows = 0
        for workflow_name, workflow_func in workflows:
            self.log(f"\n{'='*20} {workflow_name} {'='*20}")
            try:
                result = workflow_func()
                test_results.append((workflow_name, result))
                if result:
                    passed_workflows += 1
                    self.log(f"✅ {workflow_name} PASSED", "SUCCESS")
                else:
                    self.log(f"❌ {workflow_name} FAILED", "ERROR")
            except Exception as e:
                self.log(f"❌ {workflow_name} ERROR: {str(e)}", "ERROR")
                test_results.append((workflow_name, False))
        
        # Summary
        self.log("=" * 60)
        self.log(f"FUNCTIONAL TEST SUMMARY")
        self.log(f"Workflows passed: {passed_workflows}/{len(workflows)}")
        success_rate = (passed_workflows / len(workflows)) * 100
        self.log(f"Success rate: {success_rate:.1f}%")
        
        # Show results breakdown
        for workflow_name, result in test_results:
            status = "✅ PASS" if result else "❌ FAIL"
            self.log(f"  {status} {workflow_name}")
        
        # Overall assessment
        if success_rate >= 80:
            self.log("🎉 Overall assessment: MCP Tools are functioning well!", "SUCCESS")
        elif success_rate >= 60:
            self.log("⚠️  Overall assessment: MCP Tools have some issues", "WARNING") 
        else:
            self.log("❌ Overall assessment: MCP Tools have significant problems", "ERROR")
        
        return success_rate >= 70
    
    def cleanup_test_artifacts(self):
        """Clean up any test artifacts created during testing"""
        if not self.test_artifacts:
            return
            
        self.log("Cleaning up test artifacts...", "INFO")
        for artifact in self.test_artifacts:
            # Note: In a real implementation, you'd want to add cleanup endpoints
            # For now, just log what would be cleaned up
            self.log(f"  Would clean up {artifact[0]}: {artifact[1]}", "INFO")


def main():
    """Main function"""
    server_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8089/"
    
    tester = MCPToolsFunctionalTester(server_url)
    
    try:
        success = tester.run_functional_tests()
        sys.exit(0 if success else 1)
    finally:
        tester.cleanup_test_artifacts()


if __name__ == "__main__":
    main()
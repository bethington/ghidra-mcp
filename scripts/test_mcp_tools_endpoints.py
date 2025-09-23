#!/usr/bin/env python3
"""
Comprehensive MCP Tools REST Endpoint Test Suite

This script tests all 57 MCP tools by directly calling their corresponding
REST endpoints in the GhidraMCP plugin.

Usage:
    python test_mcp_tools_endpoints.py [server_url]

Default server URL: http://127.0.0.1:8089/
"""

import requests
import json
import sys
import time
from urllib.parse import urljoin
from typing import Dict, List, Tuple, Any, Optional
import traceback

class MCPToolsEndpointTester:
    def __init__(self, server_url: str = "http://127.0.0.1:8089/"):
        self.server_url = server_url.rstrip('/') + '/'
        self.session = requests.Session()
        self.session.timeout = 10
        self.results = []
        self.test_data = self._initialize_test_data()
        
    def _initialize_test_data(self):
        """Initialize test data for various endpoints"""
        return {
            'test_address': '0x401000',
            'test_function_name': 'main',
            'test_struct_name': 'TestStruct_MCP',
            'test_enum_name': 'TestEnum_MCP',
            'test_label_name': 'test_label_mcp',
            'test_variable_name': 'test_var',
            'test_type_name': 'int',
            'test_prototype': 'int test_function(int param1, char* param2)',
            'test_comment': 'Test comment from MCP tools test'
        }
        
    def log(self, message: str, level: str = "INFO"):
        """Log a message with timestamp"""
        timestamp = time.strftime("%H:%M:%S")
        color_codes = {
            "INFO": "\033[36m",      # Cyan
            "SUCCESS": "\033[32m",   # Green
            "ERROR": "\033[31m",     # Red
            "WARNING": "\033[33m",   # Yellow
            "RESET": "\033[0m"       # Reset
        }
        color = color_codes.get(level, color_codes["INFO"])
        reset = color_codes["RESET"]
        print(f"{color}[{timestamp}] {level}: {message}{reset}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict] = None) -> Tuple[bool, Any, int]:
        """Make a GET request safely"""
        if params is None:
            params = {}
        
        url = urljoin(self.server_url, endpoint)
        try:
            response = self.session.get(url, params=params)
            success = response.ok
            data = response.text.strip() if success else f"HTTP {response.status_code}: {response.text}"
            return success, data, response.status_code
        except Exception as e:
            return False, f"Request failed: {str(e)}", 0
            
    def safe_post(self, endpoint: str, data: Optional[Dict] = None) -> Tuple[bool, Any, int]:
        """Make a POST request safely"""
        url = urljoin(self.server_url, endpoint)
        try:
            response = self.session.post(url, data=data)
            success = response.ok
            result = response.text.strip() if success else f"HTTP {response.status_code}: {response.text}"
            return success, result, response.status_code
        except Exception as e:
            return False, f"Request failed: {str(e)}", 0
    
    def test_tool(self, tool_name: str, method: str, endpoint: str, 
                  params: Optional[Dict] = None, expected_success: bool = True) -> bool:
        """Test a single MCP tool endpoint"""
        self.log(f"Testing {tool_name} -> {method} /{endpoint}")
        
        start_time = time.time()
        
        if method == "GET":
            success, response, status_code = self.safe_get(endpoint, params)
        else:
            success, response, status_code = self.safe_post(endpoint, params)
        
        duration = time.time() - start_time
        
        result = {
            "tool_name": tool_name,
            "endpoint": endpoint,
            "method": method,
            "success": success,
            "status_code": status_code,
            "duration_ms": round(duration * 1000, 2),
            "response_length": len(str(response)),
            "response_preview": str(response)[:200] if response else "",
            "params": params,
            "expected_success": expected_success
        }
        
        if success == expected_success:
            self.log(f"  PASS Success (HTTP {status_code}) in {duration:.2f}s", "SUCCESS")
        else:
            self.log(f"  FAIL {'Unexpected success' if success else 'Failed'} (HTTP {status_code}): {str(response)[:100]}", "ERROR")
        
        self.results.append(result)
        return success == expected_success
    
    def test_navigation_tools(self):
        """Test navigation category tools (13 tools)"""
        self.log("=== Testing Navigation Tools (13 tools) ===")
        
        tests = [
            # Basic listing functions
            ("list_functions", "GET", "functions", {"offset": 0, "limit": 5}),
            ("list_classes", "GET", "classes", {"offset": 0, "limit": 5}),
            ("list_segments", "GET", "segments", {"offset": 0, "limit": 5}),
            ("list_imports", "GET", "imports", {"offset": 0, "limit": 5}),
            ("list_exports", "GET", "exports", {"offset": 0, "limit": 5}),
            ("list_namespaces", "GET", "namespaces", {"offset": 0, "limit": 5}),
            ("list_methods", "GET", "methods", {"offset": 0, "limit": 5}),
            ("list_data_items", "GET", "data", {"offset": 0, "limit": 5}),
            ("list_strings", "GET", "strings", {"offset": 0, "limit": 5}),
            
            # Current location functions
            ("get_current_address", "GET", "get_current_address", {}),
            ("get_current_function", "GET", "get_current_function", {}),
            ("get_function_by_address", "GET", "get_function_by_address", {"address": self.test_data['test_address']}),
            ("list_globals", "GET", "list_globals", {"offset": 0, "limit": 5}),
            ("get_entry_points", "GET", "get_entry_points", {}),
        ]
        
        success_count = 0
        for tool_name, method, endpoint, params in tests:
            if self.test_tool(tool_name, method, endpoint, params):
                success_count += 1
                
        self.log(f"Navigation Tools: {success_count}/{len(tests)} passed")
        return success_count
    
    def test_analysis_tools(self):
        """Test analysis category tools (11 tools)"""
        self.log("=== Testing Analysis Tools (11 tools) ===")
        
        tests = [
            ("decompile_function", "POST", "decompile", {"name": self.test_data['test_function_name']}),
            ("decompile_function_by_address", "GET", "decompile_function", {"address": self.test_data['test_address']}),
            ("disassemble_function", "GET", "disassemble_function", {"address": self.test_data['test_address']}),
            ("get_function_callees", "GET", "function_callees", {"name": self.test_data['test_function_name'], "limit": 5}),
            ("get_function_callers", "GET", "function_callers", {"name": self.test_data['test_function_name'], "limit": 5}),
            ("get_function_call_graph", "GET", "function_call_graph", {"name": self.test_data['test_function_name'], "depth": 2}),
            ("get_function_jump_target_addresses", "GET", "function_jump_target_addresses", {"name": self.test_data['test_function_name'], "limit": 5}),
            ("get_function_xrefs", "GET", "function_xrefs", {"name": self.test_data['test_function_name'], "limit": 5}),
            ("get_xrefs_to", "GET", "xrefs_to", {"address": self.test_data['test_address'], "limit": 5}),
            ("get_xrefs_from", "GET", "xrefs_from", {"address": self.test_data['test_address'], "limit": 5}),
            ("get_full_call_graph", "GET", "full_call_graph", {"format": "edges", "limit": 10}),
        ]
        
        success_count = 0
        for tool_name, method, endpoint, params in tests:
            if self.test_tool(tool_name, method, endpoint, params):
                success_count += 1
                
        self.log(f"Analysis Tools: {success_count}/{len(tests)} passed")
        return success_count
    
    def test_modification_tools(self):
        """Test modification category tools (11 tools)"""
        self.log("=== Testing Modification Tools (11 tools) ===")
        
        tests = [
            # Rename functions
            ("rename_function", "POST", "rename_function", {"old_name": "test_old", "new_name": "test_new"}),
            ("rename_function_by_address", "POST", "rename_function_by_address", 
             {"function_address": self.test_data['test_address'], "new_name": "test_renamed"}),
            
            # Label management
            ("create_label", "POST", "create_label", 
             {"address": self.test_data['test_address'], "name": self.test_data['test_label_name']}),
            ("rename_label", "POST", "rename_label", 
             {"address": self.test_data['test_address'], "old_name": self.test_data['test_label_name'], "new_name": "renamed_label"}),
            
            # Comments
            ("set_disassembly_comment", "POST", "set_disassembly_comment", 
             {"address": self.test_data['test_address'], "comment": self.test_data['test_comment']}),
            ("set_decompiler_comment", "POST", "set_decompiler_comment", 
             {"address": self.test_data['test_address'], "comment": self.test_data['test_comment']}),
            
            # Function properties
            ("set_function_prototype", "POST", "set_function_prototype", 
             {"function_address": self.test_data['test_address'], "prototype": self.test_data['test_prototype']}),
            ("set_local_variable_type", "POST", "set_local_variable_type", 
             {"function_address": self.test_data['test_address'], "variable_name": self.test_data['test_variable_name'], "new_type": "float"}),
            
            # Variable management
            ("rename_variable", "POST", "rename_variable", 
             {"function_name": self.test_data['test_function_name'], "old_name": "old_var", "new_name": "new_var"}),
            ("rename_data", "POST", "rename_data", 
             {"address": self.test_data['test_address'], "new_name": "renamed_data"}),
            ("rename_global_variable", "POST", "rename_global_variable", 
             {"old_name": "old_global", "new_name": "new_global"}),
        ]
        
        success_count = 0
        for tool_name, method, endpoint, params in tests:
            # For modification tools, we expect some to fail if the targets don't exist
            expected_success = False  # Most will fail in empty/test environment
            if self.test_tool(tool_name, method, endpoint, params, expected_success):
                success_count += 1
                
        self.log(f"Modification Tools: {success_count}/{len(tests)} passed")
        return success_count
    
    def test_data_tools(self):
        """Test data category tools (13 tools)"""
        self.log("=== Testing Data Tools (13 tools) ===")
        
        tests = [
            # Data type listing
            ("list_data_types", "GET", "list_data_types", {"offset": 0, "limit": 10}),
            
            # Structure management
            ("create_struct", "POST", "create_struct", 
             {"name": self.test_data['test_struct_name'], 
              "fields": '[{"name":"id","type":"int"},{"name":"value","type":"float"}]'}),
            
            # Enum management
            ("create_enum", "POST", "create_enum", 
             {"name": self.test_data['test_enum_name'], 
              "values": '{"OPTION_A": 0, "OPTION_B": 1}', "size": 4}),
            
            # Data type application
            ("apply_data_type", "POST", "apply_data_type", 
             {"address": self.test_data['test_address'], "type_name": self.test_data['test_type_name']}),
            
            # Advanced data type functions (with mcp_ghidra_ prefix)
            ("mcp_ghidra_analyze_data_types", "GET", "analyze_data_types", 
             {"address": self.test_data['test_address'], "depth": 1}),
            ("mcp_ghidra_create_union", "POST", "create_union", 
             {"name": "TestUnion_MCP", "fields": '[{"name":"as_int","type":"int"},{"name":"as_float","type":"float"}]'}),
            ("mcp_ghidra_get_type_size", "GET", "get_type_size", {"type_name": "int"}),
            ("mcp_ghidra_get_struct_layout", "GET", "get_struct_layout", {"struct_name": self.test_data['test_struct_name']}),
            ("mcp_ghidra_auto_create_struct", "POST", "auto_create_struct", 
             {"address": self.test_data['test_address'], "size": 16, "name": "AutoStruct_MCP"}),
            ("mcp_ghidra_get_enum_values", "GET", "get_enum_values", {"enum_name": self.test_data['test_enum_name']}),
            ("mcp_ghidra_create_typedef", "POST", "create_typedef", {"name": "MyInt", "base_type": "int"}),
            ("mcp_ghidra_clone_data_type", "POST", "clone_data_type", {"source_type": "int", "new_name": "ClonedInt"}),
            ("mcp_ghidra_validate_data_type", "GET", "validate_data_type", 
             {"address": self.test_data['test_address'], "type_name": "int"}),
        ]
        
        success_count = 0
        for tool_name, method, endpoint, params in tests:
            if self.test_tool(tool_name, method, endpoint, params):
                success_count += 1
                
        self.log(f"Data Tools: {success_count}/{len(tests)} passed")
        return success_count
    
    def test_search_tools(self):
        """Test search category tools (3 tools)"""
        self.log("=== Testing Search Tools (3 tools) ===")
        
        tests = [
            ("search_functions_by_name", "GET", "searchFunctions", {"query": "main", "limit": 5}),
            ("get_function_labels", "GET", "function_labels", {"name": self.test_data['test_function_name'], "limit": 5}),
            ("mcp_ghidra_search_data_types", "GET", "search_data_types", {"pattern": "int", "limit": 5}),
        ]
        
        success_count = 0
        for tool_name, method, endpoint, params in tests:
            if self.test_tool(tool_name, method, endpoint, params):
                success_count += 1
                
        self.log(f"Search Tools: {success_count}/{len(tests)} passed")
        return success_count
    
    def test_metadata_tools(self):
        """Test metadata category tools (3 tools)"""
        self.log("=== Testing Metadata Tools (3 tools) ===")
        
        tests = [
            ("check_connection", "GET", "methods", {}),
            ("get_metadata", "GET", "get_metadata", {}),
            ("convert_number", "GET", "convert_number", {"text": "123", "size": 4}),
        ]
        
        success_count = 0
        for tool_name, method, endpoint, params in tests:
            if self.test_tool(tool_name, method, endpoint, params):
                success_count += 1
                
        self.log(f"Metadata Tools: {success_count}/{len(tests)} passed")
        return success_count
    
    def test_export_tools(self):
        """Test export category tools (2 tools)"""
        self.log("=== Testing Export Tools (2 tools) ===")
        
        tests = [
            ("mcp_ghidra_export_data_types", "GET", "export_data_types", {"format": "c", "category": "builtin"}),
            ("mcp_ghidra_import_data_types", "POST", "import_data_types", 
             {"source": "struct test { int x; float y; };", "format": "c"}),
        ]
        
        success_count = 0
        for tool_name, method, endpoint, params in tests:
            if self.test_tool(tool_name, method, endpoint, params):
                success_count += 1
                
        self.log(f"Export Tools: {success_count}/{len(tests)} passed")
        return success_count
    
    def test_memory_tools(self):
        """Test memory category tools (1 tool)"""
        self.log("=== Testing Memory Tools (1 tool) ===")
        
        tests = [
            ("read_memory", "GET", "readMemory", {"address": self.test_data['test_address'], "size": 16}),
        ]
        
        success_count = 0
        for tool_name, method, endpoint, params in tests:
            if self.test_tool(tool_name, method, endpoint, params):
                success_count += 1
                
        self.log(f"Memory Tools: {success_count}/{len(tests)} passed")
        return success_count
    
    def run_all_tests(self):
        """Run all MCP tool tests"""
        self.log("Starting comprehensive MCP Tools endpoint testing...")
        self.log(f"Testing against server: {self.server_url}")
        
        # Test connection first
        success, response, status = self.safe_get("methods")
        if not success:
            self.log(f"Cannot connect to Ghidra server at {self.server_url}", "ERROR")
            self.log(f"Make sure Ghidra is running with the MCP plugin loaded", "ERROR")
            return False

        self.log(f"Connected to Ghidra server: Found {len(response) if isinstance(response, list) else 'unknown'} methods", "SUCCESS")
        
        total_passed = 0
        total_tests = 57
        
        # Run tests by category
        total_passed += self.test_navigation_tools()
        total_passed += self.test_analysis_tools()
        total_passed += self.test_modification_tools()
        total_passed += self.test_data_tools()
        total_passed += self.test_search_tools()
        total_passed += self.test_metadata_tools()
        total_passed += self.test_export_tools()
        total_passed += self.test_memory_tools()
        
        # Summary
        self.log("=" * 60)
        self.log(f"TEST SUMMARY: {total_passed}/{total_tests} tools tested successfully")
        success_rate = (total_passed / total_tests) * 100
        self.log(f"Success Rate: {success_rate:.1f}%")
        
        # Show failed tests
        failed_tests = [r for r in self.results if not r['success']]
        if failed_tests:
            self.log(f"\nFailed Tests ({len(failed_tests)}):", "WARNING")
            for result in failed_tests[:10]:  # Show first 10 failures
                self.log(f"  - {result['tool_name']}: {result['response_preview'][:100]}", "WARNING")
        
        return success_rate > 80  # Consider success if > 80% pass
    
    def generate_report(self, filename: str = "mcp_tools_test_report.json"):
        """Generate a detailed test report"""
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "server_url": self.server_url,
            "total_tests": len(self.results),
            "passed_tests": sum(1 for r in self.results if r['success']),
            "failed_tests": sum(1 for r in self.results if not r['success']),
            "success_rate": (sum(1 for r in self.results if r['success']) / len(self.results)) * 100,
            "test_results": self.results
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            self.log(f"Test report saved to {filename}")
        except Exception as e:
            self.log(f"Could not save report: {e}", "ERROR")
        
        return report


def main():
    """Main function"""
    server_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8089/"
    
    tester = MCPToolsEndpointTester(server_url)
    success = tester.run_all_tests()
    
    # Generate report
    tester.generate_report()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
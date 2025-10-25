#!/usr/bin/env python3
"""
Comprehensive test suite for all MCP tools referenced in ENHANCED_ANALYSIS_PROMPT.md

This script tests all tools mentioned in the prompt to ensure they work as expected.
Requires a running Ghidra instance with GhidraMCP plugin and a loaded binary.
"""

import sys
import json
from typing import Dict, Any, List

# Configure UTF-8 output for Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Test configuration
GHIDRA_URL = "http://127.0.0.1:8089"
TEST_ADDRESS = "0x6fdf0958"  # Known good address

# ANSI color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.errors = []

    def record_pass(self, test_name: str):
        self.passed += 1
        print(f"{GREEN}✓{RESET} {test_name}")

    def record_fail(self, test_name: str, error: str):
        self.failed += 1
        self.errors.append((test_name, error))
        print(f"{RED}✗{RESET} {test_name}: {error}")

    def record_skip(self, test_name: str, reason: str):
        self.skipped += 1
        print(f"{YELLOW}⊘{RESET} {test_name}: {reason}")

    def print_summary(self):
        total = self.passed + self.failed + self.skipped
        print(f"\n{'='*70}")
        print(f"Test Summary:")
        print(f"  Total: {total}")
        print(f"  {GREEN}Passed: {self.passed}{RESET}")
        print(f"  {RED}Failed: {self.failed}{RESET}")
        print(f"  {YELLOW}Skipped: {self.skipped}{RESET}")

        if self.errors:
            print(f"\n{RED}Failed Tests:{RESET}")
            for test_name, error in self.errors:
                print(f"  - {test_name}: {error}")

        print(f"{'='*70}\n")
        return self.failed == 0


def test_connection(results: TestResults):
    """Test basic connection to Ghidra MCP server"""
    print(f"\n{BLUE}Testing Connection{RESET}")

    try:
        import requests
        response = requests.get(f"{GHIDRA_URL}/check_connection", timeout=5)
        if response.status_code == 200 and "running" in response.text.lower():
            results.record_pass("check_connection")
            return True
        else:
            results.record_fail("check_connection", f"Unexpected response: {response.text}")
            return False
    except Exception as e:
        results.record_fail("check_connection", str(e))
        return False


def test_validation_functions(results: TestResults):
    """Test validation functions (v1.6.0+)"""
    print(f"\n{BLUE}Testing Validation Functions{RESET}")

    import requests

    # Test validate_data_type_exists
    try:
        response = requests.get(f"{GHIDRA_URL}/validate_data_type_exists",
                              params={"type_name": "INVALID_TYPE"}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "exists" in data and data["exists"] == False:
                results.record_pass("validate_data_type_exists (invalid type)")
            else:
                results.record_fail("validate_data_type_exists", f"Unexpected response: {data}")
        else:
            results.record_fail("validate_data_type_exists", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("validate_data_type_exists", str(e))

    # Test can_rename_at_address
    try:
        response = requests.get(f"{GHIDRA_URL}/can_rename_at_address",
                              params={"address": TEST_ADDRESS}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "type" in data and "suggested_operation" in data:
                results.record_pass("can_rename_at_address")
            else:
                results.record_fail("can_rename_at_address", f"Missing keys: {data}")
        else:
            results.record_fail("can_rename_at_address", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("can_rename_at_address", str(e))

    # Test get_valid_data_types
    try:
        response = requests.get(f"{GHIDRA_URL}/get_valid_data_types", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "builtin_types" in data and "windows_types" in data:
                if "dword" in data["builtin_types"] and "DWORD" in data["windows_types"]:
                    results.record_pass("get_valid_data_types")
                else:
                    results.record_fail("get_valid_data_types", "Missing expected types")
            else:
                results.record_fail("get_valid_data_types", f"Missing keys: {data}")
        else:
            results.record_fail("get_valid_data_types", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("get_valid_data_types", str(e))


def test_analysis_functions(results: TestResults):
    """Test analysis functions"""
    print(f"\n{BLUE}Testing Analysis Functions{RESET}")

    import requests

    # Test get_current_address
    try:
        response = requests.get(f"{GHIDRA_URL}/get_current_address", timeout=5)
        if response.status_code == 200:
            address = response.text.strip('"')
            if len(address) == 8:  # Hex address without 0x
                results.record_pass("get_current_address")
            else:
                results.record_fail("get_current_address", f"Invalid address format: {address}")
        else:
            results.record_fail("get_current_address", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("get_current_address", str(e))

    # Test analyze_data_region - needs full hex address with 0x prefix
    try:
        # Get current address first to ensure format is correct
        addr_response = requests.get(f"{GHIDRA_URL}/get_current_address", timeout=5)
        if addr_response.status_code == 200:
            addr = addr_response.text.strip('"')
            full_addr = f"0x{addr}"
            response = requests.get(f"{GHIDRA_URL}/analyze_data_region",
                                  params={"address": full_addr}, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if "start_address" in data or "error" not in data:
                    results.record_pass("analyze_data_region")
                else:
                    results.record_fail("analyze_data_region", f"Error: {data.get('error', 'Unknown')}")
            else:
                results.record_fail("analyze_data_region", f"HTTP {response.status_code}")
        else:
            results.record_skip("analyze_data_region", "Could not get current address")
    except Exception as e:
        results.record_fail("analyze_data_region", str(e))

    # Test get_xrefs_to - might be named differently
    try:
        addr_response = requests.get(f"{GHIDRA_URL}/get_current_address", timeout=5)
        if addr_response.status_code == 200:
            addr = f"0x{addr_response.text.strip('\"')}"
            response = requests.get(f"{GHIDRA_URL}/get_xrefs_to",
                                  params={"address": addr, "limit": 10}, timeout=5)
            if response.status_code == 200:
                results.record_pass("get_xrefs_to")
            elif response.status_code == 404:
                results.record_skip("get_xrefs_to", "Endpoint not found (might use different name)")
            else:
                results.record_fail("get_xrefs_to", f"HTTP {response.status_code}")
        else:
            results.record_skip("get_xrefs_to", "Could not get current address")
    except Exception as e:
        results.record_fail("get_xrefs_to", str(e))

    # Test get_bulk_xrefs
    try:
        addresses = f"{TEST_ADDRESS},0x6fdf095c"
        response = requests.post(f"{GHIDRA_URL}/get_bulk_xrefs",
                               json={"addresses": addresses}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict):
                results.record_pass("get_bulk_xrefs")
            else:
                results.record_fail("get_bulk_xrefs", f"Expected dict, got {type(data)}")
        else:
            results.record_fail("get_bulk_xrefs", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("get_bulk_xrefs", str(e))


def test_decompilation_functions(results: TestResults):
    """Test decompilation functions"""
    print(f"\n{BLUE}Testing Decompilation Functions{RESET}")

    import requests

    # First get a function name
    try:
        response = requests.get(f"{GHIDRA_URL}/list_functions",
                              params={"offset": 0, "limit": 1}, timeout=5)
        if response.status_code == 200:
            func_name = response.text.strip()
            results.record_pass("list_functions")

            # Test decompile_function
            try:
                response = requests.get(f"{GHIDRA_URL}/decompile_function",
                                      params={"name": func_name}, timeout=10)
                if response.status_code == 200:
                    code = response.text
                    if len(code) > 0:
                        results.record_pass("decompile_function")
                    else:
                        results.record_fail("decompile_function", "Empty decompiled code")
                else:
                    results.record_fail("decompile_function", f"HTTP {response.status_code}")
            except Exception as e:
                results.record_fail("decompile_function", str(e))
        else:
            results.record_fail("list_functions", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("list_functions", str(e))


def test_function_analysis(results: TestResults):
    """Test function analysis functions"""
    print(f"\n{BLUE}Testing Function Analysis{RESET}")

    import requests

    # Test search_functions_by_name
    try:
        response = requests.get(f"{GHIDRA_URL}/search_functions_by_name",
                              params={"query": "Set", "limit": 5}, timeout=5)
        if response.status_code == 200:
            results.record_pass("search_functions_by_name")
        elif response.status_code == 404:
            results.record_skip("search_functions_by_name", "Endpoint not found")
        else:
            results.record_fail("search_functions_by_name", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("search_functions_by_name", str(e))


def test_data_type_operations(results: TestResults):
    """Test data type operations"""
    print(f"\n{BLUE}Testing Data Type Operations{RESET}")

    import requests

    # Test list_data_types
    try:
        response = requests.get(f"{GHIDRA_URL}/list_data_types",
                              params={"offset": 0, "limit": 10}, timeout=5)
        if response.status_code == 200:
            results.record_pass("list_data_types")
        else:
            results.record_fail("list_data_types", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("list_data_types", str(e))

    # Test search_data_types
    try:
        response = requests.get(f"{GHIDRA_URL}/search_data_types",
                              params={"pattern": "DWORD", "limit": 10}, timeout=5)
        if response.status_code == 200:
            results.record_pass("search_data_types")
        else:
            results.record_fail("search_data_types", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("search_data_types", str(e))


def test_memory_inspection(results: TestResults):
    """Test memory inspection (v1.8.0)"""
    print(f"\n{BLUE}Testing Memory Inspection{RESET}")

    import requests

    # Test inspect_memory_content
    try:
        addr_response = requests.get(f"{GHIDRA_URL}/get_current_address", timeout=5)
        if addr_response.status_code == 200:
            addr = f"0x{addr_response.text.strip('\"')}"
            response = requests.get(f"{GHIDRA_URL}/inspect_memory_content",
                                  params={"address": addr, "length": 64, "detect_strings": True},
                                  timeout=5)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "address" in data and "hex_dump" in data:
                        results.record_pass("inspect_memory_content")
                    else:
                        results.record_fail("inspect_memory_content", f"Missing keys: {list(data.keys())}")
                except json.JSONDecodeError as je:
                    results.record_fail("inspect_memory_content", f"JSON decode error: {str(je)}")
            else:
                results.record_fail("inspect_memory_content", f"HTTP {response.status_code}")
        else:
            results.record_skip("inspect_memory_content", "Could not get current address")
    except Exception as e:
        results.record_fail("inspect_memory_content", str(e))


def test_list_operations(results: TestResults):
    """Test various list operations"""
    print(f"\n{BLUE}Testing List Operations{RESET}")

    import requests

    operations = [
        "list_globals",
        "list_data_items",
        "list_strings",
        "list_imports",
        "list_exports",
        "list_segments",
        "list_namespaces",
    ]

    for op in operations:
        try:
            response = requests.get(f"{GHIDRA_URL}/{op}",
                                  params={"offset": 0, "limit": 10}, timeout=5)
            if response.status_code == 200:
                results.record_pass(op)
            elif response.status_code == 404:
                results.record_skip(op, "Endpoint not found")
            else:
                results.record_fail(op, f"HTTP {response.status_code}")
        except Exception as e:
            results.record_fail(op, str(e))


def test_metadata_operations(results: TestResults):
    """Test metadata query operations (read-only)"""
    print(f"\n{BLUE}Testing Metadata Query Operations{RESET}")

    import requests

    # Test get_version
    try:
        response = requests.get(f"{GHIDRA_URL}/get_version", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "plugin_version" in data and "ghidra_version" in data:
                results.record_pass("get_version")
                print(f"  Plugin version: {data['plugin_version']}")
                print(f"  Ghidra version: {data['ghidra_version']}")
                print(f"  Endpoints: {data['endpoint_count']}")
            else:
                results.record_fail("get_version", f"Missing keys: {data}")
        else:
            results.record_fail("get_version", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("get_version", str(e))

    # Test get_metadata
    try:
        response = requests.get(f"{GHIDRA_URL}/get_metadata", timeout=5)
        if response.status_code == 200:
            results.record_pass("get_metadata")
        else:
            results.record_fail("get_metadata", f"HTTP {response.status_code}")
    except Exception as e:
        results.record_fail("get_metadata", str(e))


def main():
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}Ghidra MCP Tools Test Suite{RESET}")
    print(f"{BLUE}Testing tools referenced in ENHANCED_ANALYSIS_PROMPT.md{RESET}")
    print(f"{BLUE}{'='*70}{RESET}")

    try:
        import requests
    except ImportError:
        print(f"{RED}Error: requests module not found. Install with: pip install requests{RESET}")
        sys.exit(1)

    results = TestResults()

    # Run test suites
    if not test_connection(results):
        print(f"\n{RED}Cannot connect to Ghidra MCP server at {GHIDRA_URL}{RESET}")
        print(f"{YELLOW}Make sure Ghidra is running with GhidraMCP plugin and a binary loaded.{RESET}")
        sys.exit(1)

    test_validation_functions(results)
    test_analysis_functions(results)
    test_decompilation_functions(results)
    test_function_analysis(results)
    test_data_type_operations(results)
    test_memory_inspection(results)
    test_list_operations(results)
    test_metadata_operations(results)

    # Print summary
    success = results.print_summary()

    if success:
        print(f"{GREEN}All tests passed! ✓{RESET}\n")
        sys.exit(0)
    else:
        print(f"{RED}Some tests failed. See details above.{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

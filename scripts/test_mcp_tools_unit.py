#!/usr/bin/env python3
"""
MCP Tools Unit Tests

Pytest-based unit tests for MCP tools REST API endpoints.
These tests can be run with: pytest test_mcp_tools_unit.py -v

Requires: pip install pytest requests
"""

import pytest
import requests
import json
import time
from urllib.parse import urljoin
from typing import Dict, Optional, Any

class TestConfig:
    """Test configuration"""
    SERVER_URL = "http://127.0.0.1:8089/"
    TIMEOUT = 10
    
    # Test data
    TEST_ADDRESS = "0x401000"
    TEST_FUNCTION = "main"
    TEST_STRUCT_NAME = "TestStruct_Unit"
    TEST_ENUM_NAME = "TestEnum_Unit"
    TEST_COMMENT = "Unit test comment"

@pytest.fixture(scope="session")
def api_client():
    """Create API client fixture"""
    return APIClient(TestConfig.SERVER_URL)

@pytest.fixture(scope="session")
def server_check(api_client):
    """Check if server is available"""
    success, response, status = api_client.get("check_connection")
    if not success:
        pytest.skip(f"Ghidra server not available at {TestConfig.SERVER_URL}")
    return response

class APIClient:
    """Simple API client for testing"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/') + '/'
        self.session = requests.Session()
        self.session.timeout = TestConfig.TIMEOUT
    
    def get(self, endpoint: str, params: Optional[Dict] = None):
        """Make GET request"""
        url = urljoin(self.base_url, endpoint)
        try:
            response = self.session.get(url, params=params)
            return response.ok, response.text.strip(), response.status_code
        except Exception as e:
            return False, str(e), 0
    
    def post(self, endpoint: str, data: Optional[Dict] = None):
        """Make POST request"""
        url = urljoin(self.base_url, endpoint)
        try:
            response = self.session.post(url, data=data)
            return response.ok, response.text.strip(), response.status_code
        except Exception as e:
            return False, str(e), 0

class TestNavigationTools:
    """Test navigation category tools"""
    
    def test_list_functions(self, api_client, server_check):
        """Test list_functions endpoint"""
        success, response, status = api_client.get("functions", {"limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
        # Response should be non-empty (unless no functions exist)
        if response and not response.startswith("Error"):
            assert len(response) > 0
    
    def test_list_classes(self, api_client, server_check):
        """Test list_classes endpoint"""
        success, response, status = api_client.get("classes", {"limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_list_segments(self, api_client, server_check):
        """Test list_segments endpoint"""
        success, response, status = api_client.get("segments", {"limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_list_imports(self, api_client, server_check):
        """Test list_imports endpoint"""
        success, response, status = api_client.get("imports", {"limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_list_exports(self, api_client, server_check):
        """Test list_exports endpoint"""
        success, response, status = api_client.get("exports", {"limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_list_namespaces(self, api_client, server_check):
        """Test list_namespaces endpoint"""
        success, response, status = api_client.get("namespaces", {"limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_list_methods(self, api_client, server_check):
        """Test list_methods endpoint"""
        success, response, status = api_client.get("methods", {"limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_list_data_items(self, api_client, server_check):
        """Test list_data_items endpoint"""
        success, response, status = api_client.get("data", {"limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_list_strings(self, api_client, server_check):
        """Test list_strings endpoint"""
        success, response, status = api_client.get("strings", {"limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_current_address(self, api_client, server_check):
        """Test get_current_address endpoint"""
        success, response, status = api_client.get("get_current_address")
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_current_function(self, api_client, server_check):
        """Test get_current_function endpoint"""
        success, response, status = api_client.get("get_current_function")
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_function_by_address(self, api_client, server_check):
        """Test get_function_by_address endpoint"""
        success, response, status = api_client.get("get_function_by_address", 
                                                  {"address": TestConfig.TEST_ADDRESS})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_list_globals(self, api_client, server_check):
        """Test list_globals endpoint"""
        success, response, status = api_client.get("list_globals", {"limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_entry_points(self, api_client, server_check):
        """Test get_entry_points endpoint"""
        success, response, status = api_client.get("get_entry_points")
        assert success, f"Request failed: {response}"
        assert status == 200

class TestAnalysisTools:
    """Test analysis category tools"""
    
    def test_decompile_function(self, api_client, server_check):
        """Test decompile_function endpoint"""
        success, response, status = api_client.post("decompile", {"name": TestConfig.TEST_FUNCTION})
        # May fail if function doesn't exist, but should not error on request
        assert status in [200, 400, 404], f"Unexpected status: {status}"
    
    def test_decompile_function_by_address(self, api_client, server_check):
        """Test decompile_function_by_address endpoint"""
        success, response, status = api_client.get("decompile_function", 
                                                  {"address": TestConfig.TEST_ADDRESS})
        assert status in [200, 400, 404], f"Unexpected status: {status}"
    
    def test_disassemble_function(self, api_client, server_check):
        """Test disassemble_function endpoint"""
        success, response, status = api_client.get("disassemble_function", 
                                                  {"address": TestConfig.TEST_ADDRESS})
        assert status in [200, 400, 404], f"Unexpected status: {status}"
    
    def test_get_function_callees(self, api_client, server_check):
        """Test get_function_callees endpoint"""
        success, response, status = api_client.get("function_callees", 
                                                  {"name": TestConfig.TEST_FUNCTION, "limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_function_callers(self, api_client, server_check):
        """Test get_function_callers endpoint"""
        success, response, status = api_client.get("function_callers", 
                                                  {"name": TestConfig.TEST_FUNCTION, "limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_function_call_graph(self, api_client, server_check):
        """Test get_function_call_graph endpoint"""
        success, response, status = api_client.get("function_call_graph", 
                                                  {"name": TestConfig.TEST_FUNCTION, "depth": 2})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_function_jump_target_addresses(self, api_client, server_check):
        """Test get_function_jump_target_addresses endpoint"""
        success, response, status = api_client.get("function_jump_target_addresses", 
                                                  {"name": TestConfig.TEST_FUNCTION, "limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_function_xrefs(self, api_client, server_check):
        """Test get_function_xrefs endpoint"""
        success, response, status = api_client.get("function_xrefs", 
                                                  {"name": TestConfig.TEST_FUNCTION, "limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_xrefs_to(self, api_client, server_check):
        """Test get_xrefs_to endpoint"""
        success, response, status = api_client.get("xrefs_to", 
                                                  {"address": TestConfig.TEST_ADDRESS, "limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_xrefs_from(self, api_client, server_check):
        """Test get_xrefs_from endpoint"""
        success, response, status = api_client.get("xrefs_from", 
                                                  {"address": TestConfig.TEST_ADDRESS, "limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_full_call_graph(self, api_client, server_check):
        """Test get_full_call_graph endpoint"""
        success, response, status = api_client.get("full_call_graph", 
                                                  {"format": "edges", "limit": 10})
        assert success, f"Request failed: {response}"
        assert status == 200

class TestDataTools:
    """Test data category tools"""
    
    def test_list_data_types(self, api_client, server_check):
        """Test list_data_types endpoint"""
        success, response, status = api_client.get("list_data_types", {"limit": 10})
        assert success, f"Request failed: {response}"
        assert status == 200
        # Should have at least built-in types
        if response and not response.startswith("Error"):
            assert len(response) > 0
    
    def test_create_struct(self, api_client, server_check):
        """Test create_struct endpoint"""
        struct_data = {
            "name": TestConfig.TEST_STRUCT_NAME,
            "fields": '[{"name":"id","type":"int"},{"name":"value","type":"float"}]'
        }
        success, response, status = api_client.post("create_struct", struct_data)
        # May succeed or fail depending on whether struct already exists
        assert status in [200, 400, 409], f"Unexpected status: {status}, response: {response}"
    
    def test_create_enum(self, api_client, server_check):
        """Test create_enum endpoint"""
        enum_data = {
            "name": TestConfig.TEST_ENUM_NAME,
            "values": '{"OPTION_A": 0, "OPTION_B": 1}',
            "size": "4"
        }
        success, response, status = api_client.post("create_enum", enum_data)
        # May succeed or fail depending on whether enum already exists
        assert status in [200, 400, 409], f"Unexpected status: {status}, response: {response}"
    
    def test_apply_data_type(self, api_client, server_check):
        """Test apply_data_type endpoint"""
        apply_data = {
            "address": TestConfig.TEST_ADDRESS,
            "type_name": "int",
            "clear_existing": "true"
        }
        success, response, status = api_client.post("apply_data_type", apply_data)
        # May succeed or fail depending on memory layout
        assert status in [200, 400, 404], f"Unexpected status: {status}, response: {response}"
    
    def test_get_type_size(self, api_client, server_check):
        """Test get_type_size endpoint"""
        success, response, status = api_client.get("get_type_size", {"type_name": "int"})
        assert success, f"Request failed: {response}"
        assert status == 200
        # Should return size information for basic types
        if response and not response.startswith("Error"):
            assert "4" in response or "size" in response.lower()
    
    def test_get_struct_layout(self, api_client, server_check):
        """Test get_struct_layout endpoint"""
        success, response, status = api_client.get("get_struct_layout", 
                                                  {"struct_name": TestConfig.TEST_STRUCT_NAME})
        # May fail if struct doesn't exist
        assert status in [200, 404], f"Unexpected status: {status}, response: {response}"
    
    def test_analyze_data_types(self, api_client, server_check):
        """Test mcp_ghidra_analyze_data_types endpoint"""
        success, response, status = api_client.get("analyze_data_types", 
                                                  {"address": TestConfig.TEST_ADDRESS, "depth": 1})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_create_union(self, api_client, server_check):
        """Test mcp_ghidra_create_union endpoint"""
        union_data = {
            "name": "TestUnion_Unit",
            "fields": '[{"name":"as_int","type":"int"},{"name":"as_float","type":"float"}]'
        }
        success, response, status = api_client.post("create_union", union_data)
        assert status in [200, 400, 409], f"Unexpected status: {status}, response: {response}"
    
    def test_auto_create_struct(self, api_client, server_check):
        """Test mcp_ghidra_auto_create_struct endpoint"""
        struct_data = {
            "address": TestConfig.TEST_ADDRESS,
            "size": "16",
            "name": "AutoStruct_Unit"
        }
        success, response, status = api_client.post("auto_create_struct", struct_data)
        assert status in [200, 400], f"Unexpected status: {status}, response: {response}"
    
    def test_get_enum_values(self, api_client, server_check):
        """Test mcp_ghidra_get_enum_values endpoint"""
        success, response, status = api_client.get("get_enum_values", 
                                                  {"enum_name": TestConfig.TEST_ENUM_NAME})
        assert status in [200, 404], f"Unexpected status: {status}, response: {response}"
    
    def test_create_typedef(self, api_client, server_check):
        """Test mcp_ghidra_create_typedef endpoint"""
        typedef_data = {
            "name": "MyInt_Unit",
            "base_type": "int"
        }
        success, response, status = api_client.post("create_typedef", typedef_data)
        assert status in [200, 400, 409], f"Unexpected status: {status}, response: {response}"
    
    def test_clone_data_type(self, api_client, server_check):
        """Test mcp_ghidra_clone_data_type endpoint"""
        clone_data = {
            "source_type": "int",
            "new_name": "ClonedInt_Unit"
        }
        success, response, status = api_client.post("clone_data_type", clone_data)
        assert status in [200, 400, 409], f"Unexpected status: {status}, response: {response}"
    
    def test_validate_data_type(self, api_client, server_check):
        """Test mcp_ghidra_validate_data_type endpoint"""
        success, response, status = api_client.get("validate_data_type", 
                                                  {"address": TestConfig.TEST_ADDRESS, "type_name": "int"})
        assert success, f"Request failed: {response}"
        assert status == 200

class TestSearchTools:
    """Test search category tools"""
    
    def test_search_functions_by_name(self, api_client, server_check):
        """Test search_functions_by_name endpoint"""
        success, response, status = api_client.get("searchFunctions", 
                                                  {"query": "main", "limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_get_function_labels(self, api_client, server_check):
        """Test get_function_labels endpoint"""
        success, response, status = api_client.get("function_labels", 
                                                  {"name": TestConfig.TEST_FUNCTION, "limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_search_data_types(self, api_client, server_check):
        """Test mcp_ghidra_search_data_types endpoint"""
        success, response, status = api_client.get("search_data_types", 
                                                  {"pattern": "int", "limit": 5})
        assert success, f"Request failed: {response}"
        assert status == 200

class TestMetadataTools:
    """Test metadata category tools"""
    
    def test_check_connection(self, api_client):
        """Test check_connection endpoint"""
        success, response, status = api_client.get("check_connection")
        assert success, f"Request failed: {response}"
        assert status == 200
        assert response  # Should have some response content
    
    def test_get_metadata(self, api_client, server_check):
        """Test get_metadata endpoint"""
        success, response, status = api_client.get("get_metadata")
        assert success, f"Request failed: {response}"
        assert status == 200
    
    def test_convert_number(self, api_client, server_check):
        """Test convert_number endpoint"""
        success, response, status = api_client.get("convert_number", 
                                                  {"text": "255", "size": "4"})
        assert success, f"Request failed: {response}"
        assert status == 200
        # Should contain hex representation
        if response and not response.startswith("Error"):
            assert "0xff" in response.lower() or "255" in response

class TestModificationTools:
    """Test modification category tools (these may fail in read-only scenarios)"""
    
    def test_create_label(self, api_client, server_check):
        """Test create_label endpoint"""
        label_data = {
            "address": TestConfig.TEST_ADDRESS,
            "name": f"test_label_{int(time.time())}"
        }
        success, response, status = api_client.post("create_label", label_data)
        # May fail due to permissions or invalid address
        assert status in [200, 400, 403, 404], f"Unexpected status: {status}, response: {response}"
    
    def test_set_disassembly_comment(self, api_client, server_check):
        """Test set_disassembly_comment endpoint"""
        comment_data = {
            "address": TestConfig.TEST_ADDRESS,
            "comment": TestConfig.TEST_COMMENT
        }
        success, response, status = api_client.post("set_disassembly_comment", comment_data)
        assert status in [200, 400, 403, 404], f"Unexpected status: {status}, response: {response}"
    
    def test_set_decompiler_comment(self, api_client, server_check):
        """Test set_decompiler_comment endpoint"""
        comment_data = {
            "address": TestConfig.TEST_ADDRESS,
            "comment": TestConfig.TEST_COMMENT
        }
        success, response, status = api_client.post("set_decompiler_comment", comment_data)
        assert status in [200, 400, 403, 404], f"Unexpected status: {status}, response: {response}"
    
    def test_rename_function(self, api_client, server_check):
        """Test rename_function endpoint"""
        rename_data = {
            "old_name": "nonexistent_function",
            "new_name": "renamed_function"
        }
        success, response, status = api_client.post("rename_function", rename_data)
        # Expected to fail for nonexistent function
        assert status in [200, 400, 404], f"Unexpected status: {status}, response: {response}"

class TestExportTools:
    """Test export category tools"""
    
    def test_export_data_types(self, api_client, server_check):
        """Test mcp_ghidra_export_data_types endpoint"""
        success, response, status = api_client.get("export_data_types", 
                                                  {"format": "c", "category": "builtin"})
        assert success, f"Request failed: {response}"
        assert status == 200
        # Should contain C-style type definitions
        if response and not response.startswith("Error"):
            assert len(response) > 0
    
    def test_import_data_types(self, api_client, server_check):
        """Test mcp_ghidra_import_data_types endpoint"""
        import_data = {
            "source": "struct test_import { int x; float y; };",
            "format": "c"
        }
        success, response, status = api_client.post("import_data_types", import_data)
        # May succeed or fail depending on implementation
        assert status in [200, 400, 501], f"Unexpected status: {status}, response: {response}"

class TestMemoryTools:
    """Test memory category tools"""
    
    def test_read_memory(self, api_client, server_check):
        """Test read_memory endpoint"""
        success, response, status = api_client.get("readMemory", 
                                                  {"address": TestConfig.TEST_ADDRESS, "size": "16"})
        # May succeed or fail depending on address validity
        assert status in [200, 400, 404], f"Unexpected status: {status}, response: {response}"


# Pytest configuration and custom markers
pytestmark = pytest.mark.integration

def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring running Ghidra server"
    )

if __name__ == "__main__":
    # Run tests if executed directly
    pytest.main([__file__, "-v", "--tb=short"])
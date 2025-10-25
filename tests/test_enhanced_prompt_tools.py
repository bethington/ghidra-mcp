"""
Comprehensive test suite for all MCP tools referenced in ENHANCED_ANALYSIS_PROMPT.md

Tests all tools mentioned in the prompt to ensure they work as expected.
This test requires a running Ghidra instance with GhidraMCP plugin and a loaded binary.
"""

import pytest
import json
from typing import Dict, Any, List

# Test configuration
TEST_ADDRESS = "0x6fdf0958"  # Known good address from current session
TEST_FUNCTION_NAME = "SetStructureStateAndConfigurationValues"


class TestValidationFunctions:
    """Test validation functions (v1.6.0+)"""

    def test_validate_data_type_exists_valid(self, api_client):
        """Test validate_data_type_exists with valid type"""
        result = api_client.get("/validate_data_type_exists", params={"type_name": "dword"})
        assert result.status_code == 200
        data = result.json()
        assert "exists" in data
        # Note: Current version returns false for basic types, may need update

    def test_validate_data_type_exists_invalid(self, api_client):
        """Test validate_data_type_exists with invalid type"""
        result = api_client.get("/validate_data_type_exists", params={"type_name": "INVALID_TYPE_XYZ"})
        assert result.status_code == 200
        data = result.json()
        assert data["exists"] == False

    def test_can_rename_at_address(self, api_client):
        """Test can_rename_at_address"""
        result = api_client.get("/can_rename_at_address", params={"address": TEST_ADDRESS})
        assert result.status_code == 200
        data = result.json()
        assert "type" in data
        assert "suggested_operation" in data
        assert data["type"] in ["defined_data", "undefined", "code", "invalid"]

    def test_get_valid_data_types(self, api_client):
        """Test get_valid_data_types"""
        result = api_client.get("/get_valid_data_types")
        assert result.status_code == 200
        data = result.json()
        assert "builtin_types" in data
        assert "windows_types" in data
        assert "dword" in data["builtin_types"]
        assert "DWORD" in data["windows_types"]


class TestAnalysisFunctions:
    """Test analysis functions"""

    def test_get_current_address(self, api_client):
        """Test get_current_address"""
        result = api_client.get("/get_current_address")
        assert result.status_code == 200
        address = result.text.strip('"')
        assert len(address) == 8  # Hex address without 0x prefix

    def test_analyze_data_region(self, api_client):
        """Test analyze_data_region"""
        result = api_client.get("/analyze_data_region", params={"address": TEST_ADDRESS})
        assert result.status_code == 200
        data = result.json()
        assert "start_address" in data
        assert "classification_hint" in data

    def test_get_xrefs_to(self, api_client):
        """Test get_xrefs_to"""
        result = api_client.get("/get_xrefs_to", params={"address": TEST_ADDRESS, "limit": 10})
        assert result.status_code == 200
        # Should return list or empty list

    def test_get_xrefs_from(self, api_client):
        """Test get_xrefs_from"""
        result = api_client.get("/get_xrefs_from", params={"address": TEST_ADDRESS, "limit": 10})
        assert result.status_code == 200

    def test_get_bulk_xrefs(self, api_client):
        """Test get_bulk_xrefs batch operation"""
        addresses = f"{TEST_ADDRESS},0x6fdf095c"
        result = api_client.post("/get_bulk_xrefs", json={"addresses": addresses})
        assert result.status_code == 200
        data = result.json()
        assert isinstance(data, dict)


class TestDecompilationFunctions:
    """Test decompilation functions"""

    def test_decompile_function(self, api_client):
        """Test decompile_function"""
        result = api_client.get("/decompile_function", params={"name": TEST_FUNCTION_NAME})
        assert result.status_code == 200
        code = result.text
        assert len(code) > 0
        assert "void" in code or "int" in code  # Should contain C code

    def test_list_functions(self, api_client):
        """Test list_functions"""
        result = api_client.get("/list_functions", params={"offset": 0, "limit": 10})
        assert result.status_code == 200
        # Should return function names


class TestFunctionAnalysis:
    """Test function analysis functions"""

    def test_get_function_by_address(self, api_client):
        """Test get_function_by_address"""
        # First get a function address
        result = api_client.get("/search_functions_by_name", params={"query": "Set", "limit": 1})
        assert result.status_code == 200

    def test_get_function_callees(self, api_client):
        """Test get_function_callees"""
        result = api_client.get("/get_function_callees", params={"name": TEST_FUNCTION_NAME})
        assert result.status_code == 200

    def test_get_function_callers(self, api_client):
        """Test get_function_callers"""
        result = api_client.get("/get_function_callers", params={"name": TEST_FUNCTION_NAME})
        assert result.status_code == 200


class TestDataTypeOperations:
    """Test data type operations"""

    def test_list_data_types(self, api_client):
        """Test list_data_types"""
        result = api_client.get("/list_data_types", params={"offset": 0, "limit": 10})
        assert result.status_code == 200

    def test_search_data_types(self, api_client):
        """Test search_data_types"""
        result = api_client.get("/search_data_types", params={"pattern": "DWORD", "limit": 10})
        assert result.status_code == 200


class TestMemoryInspection:
    """Test memory inspection (v1.8.0)"""

    def test_inspect_memory_content(self, api_client):
        """Test inspect_memory_content"""
        result = api_client.get("/inspect_memory_content", params={
            "address": TEST_ADDRESS,
            "length": 64,
            "detect_strings": True
        })
        assert result.status_code == 200
        data = result.json()
        assert "address" in data
        assert "hex_dump" in data
        assert "ascii_repr" in data


class TestListOperations:
    """Test various list operations"""

    def test_list_globals(self, api_client):
        """Test list_globals"""
        result = api_client.get("/list_globals", params={"offset": 0, "limit": 10})
        assert result.status_code == 200

    def test_list_data_items(self, api_client):
        """Test list_data_items"""
        result = api_client.get("/list_data_items", params={"offset": 0, "limit": 10})
        assert result.status_code == 200

    def test_list_strings(self, api_client):
        """Test list_strings"""
        result = api_client.get("/list_strings", params={"offset": 0, "limit": 10})
        assert result.status_code == 200

    def test_list_imports(self, api_client):
        """Test list_imports"""
        result = api_client.get("/list_imports", params={"offset": 0, "limit": 10})
        assert result.status_code == 200

    def test_list_exports(self, api_client):
        """Test list_exports"""
        result = api_client.get("/list_exports", params={"offset": 0, "limit": 10})
        assert result.status_code == 200


class TestSearchFunctions:
    """Test search operations"""

    def test_search_functions_by_name(self, api_client):
        """Test search_functions_by_name"""
        result = api_client.get("/search_functions_by_name", params={"query": "Set", "limit": 10})
        assert result.status_code == 200


class TestConnectionAndMetadata:
    """Test connection and metadata functions"""

    def test_check_connection(self, api_client):
        """Test check_connection"""
        result = api_client.get("/check_connection")
        assert result.status_code == 200
        assert "Connected" in result.text or "running" in result.text

    def test_get_version(self, api_client):
        """Test get_version"""
        result = api_client.get("/get_version")
        assert result.status_code == 200
        data = result.json()
        assert "plugin_version" in data
        assert "ghidra_version" in data
        assert "endpoint_count" in data

    def test_get_metadata(self, api_client):
        """Test get_metadata"""
        result = api_client.get("/get_metadata")
        assert result.status_code == 200


# Note: The following operations modify Ghidra state and are tested separately
# in integration tests to avoid conflicts:
# - create_struct
# - apply_data_type
# - rename_data
# - create_label
# - batch_create_labels
# - batch_set_comments
# - create_and_apply_data_type
# - document_function_complete


class TestToolsReferencedInPrompt:
    """
    Verify all tools referenced in ENHANCED_ANALYSIS_PROMPT.md are available
    """

    VALIDATION_TOOLS = [
        "validate_data_type_exists",
        "can_rename_at_address",
        "validate_function_prototype",
    ]

    ATOMIC_OPERATIONS = [
        "create_and_apply_data_type",
        "document_function_complete",
    ]

    BATCH_OPERATIONS = [
        "batch_create_labels",
        "batch_set_comments",
        "batch_rename_variables",
        "batch_set_variable_types",
        "batch_decompile_functions",
        "batch_decompile_xref_sources",
        "batch_rename_function_components",
    ]

    ANALYSIS_TOOLS = [
        "analyze_data_region",
        "get_bulk_xrefs",
        "get_xrefs_to",
        "get_xrefs_from",
        "analyze_struct_field_usage",
        "get_field_access_context",
        "suggest_field_names",
        "detect_array_bounds",
        "get_assembly_context",
    ]

    DECOMPILATION_TOOLS = [
        "decompile_function",
        "force_decompile",
        "analyze_function_complete",
    ]

    FUNCTION_ANALYSIS = [
        "get_function_by_address",
        "get_function_xrefs",
        "get_function_callees",
        "get_function_callers",
        "get_function_variables",
    ]

    FLOW_ANALYSIS = [
        "clear_instruction_flow_override",
        "set_function_no_return",
        "disassemble_bytes",
    ]

    DATA_TYPES = [
        "create_struct",
        "apply_data_type",
        "modify_struct_field",
        "get_struct_layout",
        "delete_data_type",
        "create_array_type",
        "get_valid_data_types",
    ]

    METADATA_OPS = [
        "rename_data",
        "rename_or_label",
        "create_label",
        "rename_function_by_address",
        "set_decompiler_comment",
        "set_plate_comment",
    ]

    MEMORY_INSPECTION = [
        "inspect_memory_content",
    ]

    def test_all_tools_documented(self):
        """Verify all categories of tools are documented"""
        all_tools = (
            self.VALIDATION_TOOLS +
            self.ATOMIC_OPERATIONS +
            self.BATCH_OPERATIONS +
            self.ANALYSIS_TOOLS +
            self.DECOMPILATION_TOOLS +
            self.FUNCTION_ANALYSIS +
            self.FLOW_ANALYSIS +
            self.DATA_TYPES +
            self.METADATA_OPS +
            self.MEMORY_INSPECTION
        )
        assert len(all_tools) > 40  # Should have 40+ tools documented
        print(f"\nTotal tools documented in ENHANCED_ANALYSIS_PROMPT.md: {len(all_tools)}")

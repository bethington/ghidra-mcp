"""
Unit tests for MCP tool functions in bridge_mcp_ghidra.py.

Tests every @mcp.tool() function by mocking the HTTP helpers (safe_get, safe_post, etc.)
to verify correct endpoint names, parameter construction, and input validation.

These tests run WITHOUT requiring a Ghidra server.
"""

import json
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# =============================================================================
# Listing Tools - Pattern: safe_get("endpoint", {offset, limit, program?})
# =============================================================================

class TestListingTools:
    """Tests for listing tool endpoint and parameter mapping."""

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_functions_default(self, mock_get):
        mock_get.return_value = ["func1 @ 0x401000"]
        from bridge_mcp_ghidra import list_functions
        list_functions()
        mock_get.assert_called_once_with("list_functions", {"offset": 0, "limit": 100})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_functions_with_program(self, mock_get):
        mock_get.return_value = ["func1"]
        from bridge_mcp_ghidra import list_functions
        list_functions(offset=10, limit=50, program="test.dll")
        mock_get.assert_called_once_with("list_functions", {"offset": 10, "limit": 50, "program": "test.dll"})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_functions_no_program_omitted(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_functions
        list_functions(program=None)
        args = mock_get.call_args[0]
        assert "program" not in args[1]

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_classes(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_classes
        list_classes(offset=5, limit=25, program="prog.exe")
        mock_get.assert_called_once_with("list_classes", {"offset": 5, "limit": 25, "program": "prog.exe"})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_segments(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_segments
        list_segments()
        mock_get.assert_called_once_with("list_segments", {"offset": 0, "limit": 100})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_imports(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_imports
        list_imports()
        mock_get.assert_called_once_with("list_imports", {"offset": 0, "limit": 100})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_exports(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_exports
        list_exports()
        mock_get.assert_called_once_with("list_exports", {"offset": 0, "limit": 100})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_external_locations(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_external_locations
        list_external_locations(offset=0, limit=50, program="test.dll")
        mock_get.assert_called_once_with("list_external_locations", {"offset": 0, "limit": 50, "program": "test.dll"})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_namespaces(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_namespaces
        list_namespaces()
        mock_get.assert_called_once_with("list_namespaces", {"offset": 0, "limit": 100})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_data_items(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_data_items
        list_data_items()
        mock_get.assert_called_once_with("list_data_items", {"offset": 0, "limit": 100})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_strings(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_strings
        list_strings(filter="hello")
        args = mock_get.call_args[0]
        assert args[0] == "list_strings"
        assert args[1]["filter"] == "hello"

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_globals(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_globals
        list_globals(filter="test", program="prog.exe")
        args = mock_get.call_args[0]
        assert args[0] == "list_globals"
        assert args[1]["filter"] == "test"
        assert args[1]["program"] == "prog.exe"

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_data_types(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import list_data_types
        list_data_types(category="struct")
        args = mock_get.call_args[0]
        assert args[0] == "list_data_types"
        assert args[1]["category"] == "struct"


# =============================================================================
# Getter Tools - Various GET patterns
# =============================================================================

class TestGetterTools:
    """Tests for getter tool endpoint and parameter mapping."""

    @patch("bridge_mcp_ghidra.safe_get_json")
    def test_validate_data_type_exists(self, mock_get):
        mock_get.return_value = '{"exists": true}'
        from bridge_mcp_ghidra import validate_data_type_exists
        validate_data_type_exists("int")
        mock_get.assert_called_once_with("validate_data_type_exists", {"type_name": "int"})

    @patch("bridge_mcp_ghidra.safe_get_json")
    def test_get_data_type_size(self, mock_get):
        mock_get.return_value = '{"size": 4}'
        from bridge_mcp_ghidra import get_data_type_size
        get_data_type_size("int")
        mock_get.assert_called_once_with("get_data_type_size", {"type_name": "int"})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_labels(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_function_labels
        get_function_labels("main", offset=5, limit=10)
        mock_get.assert_called_once_with("get_function_labels", {"name": "main", "offset": 5, "limit": 10})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_callees(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_function_callees
        get_function_callees("main", program="test.dll")
        args = mock_get.call_args[0]
        assert args[0] == "get_function_callees"
        assert args[1]["name"] == "main"
        assert args[1]["program"] == "test.dll"

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_callers(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_function_callers
        get_function_callers("main")
        args = mock_get.call_args[0]
        assert args[0] == "get_function_callers"
        assert args[1]["name"] == "main"

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_call_graph(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_function_call_graph
        get_function_call_graph("main", depth=3, direction="callers")
        args = mock_get.call_args[0]
        assert args[0] == "get_function_call_graph"
        assert args[1]["depth"] == 3
        assert args[1]["direction"] == "callers"

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_full_call_graph(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_full_call_graph
        get_full_call_graph(format="nodes", limit=200)
        args = mock_get.call_args[0]
        assert args[0] == "get_full_call_graph"
        assert args[1]["format"] == "nodes"
        assert args[1]["limit"] == 200

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_entry_points(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_entry_points
        get_entry_points()
        mock_get.assert_called_once_with("get_entry_points")

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_enum_values(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_enum_values
        get_enum_values("MyEnum")
        mock_get.assert_called_once_with("get_enum_values", {"enum_name": "MyEnum"})

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_jump_targets(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_function_jump_targets
        get_function_jump_targets("main")
        args = mock_get.call_args[0]
        assert args[0] == "get_function_jump_targets"
        assert args[1]["name"] == "main"

    @patch("bridge_mcp_ghidra.safe_get_json")
    def test_get_function_variables(self, mock_get):
        mock_get.return_value = '{"variables": []}'
        from bridge_mcp_ghidra import get_function_variables
        get_function_variables("main", program="test.dll")
        args = mock_get.call_args[0]
        assert args[0] == "get_function_variables"
        assert args[1]["function_name"] == "main"
        assert args[1]["program"] == "test.dll"


# =============================================================================
# Utility / Status Tools
# =============================================================================

class TestUtilityTools:
    """Tests for utility/status tool endpoint mapping."""

    @patch("bridge_mcp_ghidra.session")
    def test_check_connection(self, mock_session):
        """check_connection uses session.get() directly, not safe_get_json."""
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.text = "Connected"
        mock_session.get.return_value = mock_response
        from bridge_mcp_ghidra import check_connection
        result = check_connection()
        assert mock_session.get.called
        assert result == "Connected"

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_version(self, mock_get):
        """get_version uses safe_get (returns list) and joins with newline."""
        mock_get.return_value = ["GhidraMCP 2.0.0"]
        from bridge_mcp_ghidra import get_version
        result = get_version()
        mock_get.assert_called_once_with("get_version")
        assert "2.0.0" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_metadata(self, mock_get):
        """get_metadata uses safe_get (returns list) and joins with newline."""
        mock_get.return_value = ['{"name": "test.exe"}']
        from bridge_mcp_ghidra import get_metadata
        result = get_metadata()
        mock_get.assert_called_once_with("get_metadata")
        assert "test.exe" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_calling_conventions(self, mock_get):
        """list_calling_conventions uses safe_get with no params."""
        mock_get.return_value = ["__cdecl", "__stdcall"]
        from bridge_mcp_ghidra import list_calling_conventions
        list_calling_conventions()
        mock_get.assert_called_once_with("list_calling_conventions")


# =============================================================================
# Rename / Write Tools - Pattern: safe_post("endpoint", {...})
# =============================================================================

class TestRenameTools:
    """Tests for rename tool endpoint and parameter mapping."""

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_function(self, mock_post):
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import rename_function
        rename_function("old_func", "new_func")
        mock_post.assert_called_once_with("rename_function", {"oldName": "old_func", "newName": "new_func"})

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_label(self, mock_post):
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import rename_label
        rename_label("0x401000", "old_label", "new_label")
        mock_post.assert_called_once_with(
            "rename_label",
            {"address": "0x401000", "old_name": "old_label", "new_name": "new_label"},
        )

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_global_variable(self, mock_post):
        """rename_global_variable uses snake_case params: old_name, new_name."""
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import rename_global_variable
        rename_global_variable("gOldName", "gNewName")
        mock_post.assert_called_once_with(
            "rename_global_variable", {"old_name": "gOldName", "new_name": "gNewName"}
        )

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_external_location(self, mock_post):
        """rename_external_location sanitizes address and passes string."""
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import rename_external_location
        rename_external_location("0x401000", "NewName")
        mock_post.assert_called_once_with(
            "rename_external_location", {"address": "0x401000", "new_name": "NewName"}
        )

    def test_rename_external_location_invalid_address(self):
        """rename_external_location should reject invalid addresses."""
        from bridge_mcp_ghidra import rename_external_location, GhidraValidationError
        with pytest.raises(GhidraValidationError):
            rename_external_location("not_hex", "NewName")

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_or_label(self, mock_post):
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import rename_or_label
        rename_or_label("0x401000", "myLabel")
        mock_post.assert_called_once_with(
            "rename_or_label", {"address": "0x401000", "name": "myLabel"}
        )


# =============================================================================
# Rename with Validation
# =============================================================================

class TestRenameWithValidation:
    """Tests for rename tools that perform address validation."""

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_data_valid_address(self, mock_post):
        mock_post.return_value = "Successfully renamed"
        from bridge_mcp_ghidra import rename_data
        rename_data("0x401000", "myData")
        assert mock_post.called
        args = mock_post.call_args[0]
        assert args[0] == "rename_data"
        assert args[1]["address"] == "0x401000"
        assert args[1]["newName"] == "myData"

    def test_rename_data_invalid_address(self):
        from bridge_mcp_ghidra import rename_data, GhidraValidationError
        with pytest.raises(GhidraValidationError):
            rename_data("not_hex", "myData")

    def test_rename_data_empty_name(self):
        from bridge_mcp_ghidra import rename_data, GhidraValidationError
        with pytest.raises(GhidraValidationError):
            rename_data("0x401000", "")

    def test_rename_data_invalid_name_chars(self):
        from bridge_mcp_ghidra import rename_data, GhidraValidationError
        with pytest.raises(GhidraValidationError):
            rename_data("0x401000", "invalid name!")

    @patch("bridge_mcp_ghidra.safe_post")
    @patch("bridge_mcp_ghidra.safe_get")
    def test_rename_function_by_address(self, mock_get, mock_post):
        """rename_function_by_address verifies function exists via safe_get before posting."""
        mock_get.return_value = ["main @ 0x401000"]  # function existence check
        mock_post.return_value = "Successfully renamed"
        from bridge_mcp_ghidra import rename_function_by_address
        rename_function_by_address("0x401000", "newFunc")
        assert mock_post.called
        args = mock_post.call_args[0]
        assert args[0] == "rename_function_by_address"

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_by_address_valid(self, mock_get):
        """get_function_by_address uses safe_get (returns list), joined with newline."""
        mock_get.return_value = ['{"name": "main"}']
        from bridge_mcp_ghidra import get_function_by_address
        get_function_by_address("0x401000")
        args = mock_get.call_args[0]
        assert args[0] == "get_function_by_address"
        assert args[1]["address"] == "0x401000"

    def test_get_function_by_address_invalid(self):
        from bridge_mcp_ghidra import get_function_by_address, GhidraValidationError
        with pytest.raises(GhidraValidationError):
            get_function_by_address("not_hex")


# =============================================================================
# Comment Tools
# =============================================================================

class TestCommentTools:
    """Tests for comment tool endpoint and parameter mapping."""

    @patch("bridge_mcp_ghidra.safe_post")
    def test_set_decompiler_comment(self, mock_post):
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import set_decompiler_comment
        set_decompiler_comment("0x401000", "This is a comment")
        mock_post.assert_called_once_with(
            "set_decompiler_comment", {"address": "0x401000", "comment": "This is a comment"}
        )

    @patch("bridge_mcp_ghidra.safe_post")
    def test_set_disassembly_comment(self, mock_post):
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import set_disassembly_comment
        set_disassembly_comment("0x401000", "EOL comment")
        mock_post.assert_called_once_with(
            "set_disassembly_comment", {"address": "0x401000", "comment": "EOL comment"}
        )

    @patch("bridge_mcp_ghidra.safe_get_json")
    def test_get_plate_comment(self, mock_get):
        mock_get.return_value = '{"comment": "plate"}'
        from bridge_mcp_ghidra import get_plate_comment
        get_plate_comment("0x401000")
        mock_get.assert_called_once_with("get_plate_comment", {"address": "0x401000"})


# =============================================================================
# Search Tools
# =============================================================================

class TestSearchTools:
    """Tests for search tool endpoint and parameter mapping."""

    @patch("bridge_mcp_ghidra.safe_get")
    def test_search_data_types(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import search_data_types
        search_data_types("struct_", offset=0, limit=20)
        mock_get.assert_called_once_with(
            "search_data_types", {"pattern": "struct_", "offset": 0, "limit": 20}
        )

    @patch("bridge_mcp_ghidra.safe_get")
    def test_search_byte_patterns(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import search_byte_patterns
        search_byte_patterns("E8 ?? ?? ?? ??", mask="FF 00 00 00 00")
        args = mock_get.call_args[0]
        assert args[0] == "search_byte_patterns"
        assert args[1]["pattern"] == "E8 ?? ?? ?? ??"
        assert args[1]["mask"] == "FF 00 00 00 00"


# =============================================================================
# Cross-Reference Tools
# =============================================================================

class TestXrefTools:
    """Tests for xref tool endpoint and parameter mapping."""

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_xrefs_to(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_xrefs_to
        get_xrefs_to("0x401000", offset=0, limit=50, program="test.dll")
        mock_get.assert_called_once_with(
            "get_xrefs_to", {"address": "0x401000", "offset": 0, "limit": 50, "program": "test.dll"}
        )

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_xrefs_from(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_xrefs_from
        get_xrefs_from("0x401000")
        args = mock_get.call_args[0]
        assert args[0] == "get_xrefs_from"
        assert args[1]["address"] == "0x401000"

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_xrefs(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_function_xrefs
        get_function_xrefs("main", program="test.dll")
        args = mock_get.call_args[0]
        assert args[0] == "get_function_xrefs"
        assert args[1]["name"] == "main"
        assert args[1]["program"] == "test.dll"


# =============================================================================
# Data Type Tools
# =============================================================================

class TestDataTypeTools:
    """Tests for data type tool endpoint and parameter mapping."""

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_create_struct(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import create_struct
        fields = [{"name": "field1", "type": "int", "offset": 0}]
        create_struct("MyStruct", fields)
        args = mock_post.call_args[0]
        assert args[0] == "create_struct"
        assert args[1]["name"] == "MyStruct"
        assert args[1]["fields"] == fields

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_create_enum(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import create_enum
        values = {"VALUE_A": 0, "VALUE_B": 1}
        create_enum("MyEnum", values, size=4)
        args = mock_post.call_args[0]
        assert args[0] == "create_enum"
        assert args[1]["name"] == "MyEnum"
        assert args[1]["values"] == values
        assert args[1]["size"] == 4

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_apply_data_type(self, mock_post):
        """apply_data_type uses safe_post_json and includes clear_existing."""
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import apply_data_type
        apply_data_type("0x401000", "dword", clear_existing=False)
        args = mock_post.call_args[0]
        assert args[0] == "apply_data_type"
        assert args[1]["address"] == "0x401000"
        assert args[1]["type_name"] == "dword"
        assert args[1]["clear_existing"] is False

    @patch("bridge_mcp_ghidra.safe_post_json")
    @patch("bridge_mcp_ghidra.safe_get")
    def test_set_function_prototype(self, mock_get, mock_post):
        """set_function_prototype verifies function exists then uses safe_post_json."""
        mock_get.return_value = ["main @ 0x401000"]  # function existence check
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import set_function_prototype
        set_function_prototype("0x401000", "int main(int argc, char** argv)")
        assert mock_post.called

    @patch("bridge_mcp_ghidra.safe_post")
    def test_set_local_variable_type(self, mock_post):
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import set_local_variable_type
        set_local_variable_type("0x401000", "local_c", "int")
        args = mock_post.call_args[0]
        assert args[0] == "set_local_variable_type"

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_delete_data_type(self, mock_post):
        """delete_data_type uses safe_post_json."""
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import delete_data_type
        delete_data_type("MyOldStruct")
        mock_post.assert_called_once_with("delete_data_type", {"type_name": "MyOldStruct"})

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_modify_struct_field(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import modify_struct_field
        modify_struct_field("MyStruct", "field1", new_type="long", new_name="newField1")
        args = mock_post.call_args[0]
        assert args[0] == "modify_struct_field"
        assert args[1]["struct_name"] == "MyStruct"

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_add_struct_field(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import add_struct_field
        add_struct_field("MyStruct", "newField", "int", offset=8)
        args = mock_post.call_args[0]
        assert args[0] == "add_struct_field"

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_remove_struct_field(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import remove_struct_field
        remove_struct_field("MyStruct", "oldField")
        args = mock_post.call_args[0]
        assert args[0] == "remove_struct_field"

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_create_array_type(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import create_array_type
        create_array_type("byte", 16, name="ByteArray16")
        args = mock_post.call_args[0]
        assert args[0] == "create_array_type"
        assert args[1]["base_type"] == "byte"
        assert args[1]["length"] == 16

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_batch_set_variable_types(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import batch_set_variable_types
        types = {"local_c": "int", "local_10": "char *"}
        batch_set_variable_types("0x401000", types)
        args = mock_post.call_args[0]
        assert args[0] == "batch_set_variable_types"
        assert args[1]["function_address"] == "0x401000"

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_set_parameter_type(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import set_parameter_type
        set_parameter_type("0x401000", "param_1", "MyStruct *")
        args = mock_post.call_args[0]
        assert args[0] == "set_parameter_type"
        assert args[1]["parameter_name"] == "param_1"
        assert args[1]["new_type"] == "MyStruct *"


# =============================================================================
# Label Tools
# =============================================================================

class TestLabelTools:
    """Tests for label tool endpoint and parameter mapping."""

    @patch("bridge_mcp_ghidra.safe_post")
    def test_create_label(self, mock_post):
        mock_post.return_value = "Created"
        from bridge_mcp_ghidra import create_label
        create_label("0x401000", "myLabel")
        assert mock_post.called
        args = mock_post.call_args[0]
        assert args[0] == "create_label"

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_batch_create_labels(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import batch_create_labels
        labels = [{"address": "0x401000", "name": "label1"}]
        batch_create_labels(labels)
        args = mock_post.call_args[0]
        assert args[0] == "batch_create_labels"

    @patch("bridge_mcp_ghidra.safe_post")
    def test_delete_label(self, mock_post):
        mock_post.return_value = "Deleted"
        from bridge_mcp_ghidra import delete_label
        delete_label("0x401000", "myLabel")
        assert mock_post.called
        args = mock_post.call_args[0]
        assert args[0] == "delete_label"

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_batch_delete_labels(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import batch_delete_labels
        labels = [{"address": "0x401000", "name": "label1"}]
        batch_delete_labels(labels)
        args = mock_post.call_args[0]
        assert args[0] == "batch_delete_labels"


# =============================================================================
# Analysis Tools
# =============================================================================

class TestAnalysisTools:
    """Tests for analysis tool endpoint and parameter mapping."""

    @patch("bridge_mcp_ghidra.safe_get_json")
    def test_analyze_function_completeness(self, mock_get):
        mock_get.return_value = '{"score": 85}'
        from bridge_mcp_ghidra import analyze_function_completeness
        analyze_function_completeness("0x401000")
        args = mock_get.call_args[0]
        assert args[0] == "analyze_function_completeness"
        assert args[1]["function_address"] == "0x401000"

    @patch("bridge_mcp_ghidra.make_request")
    def test_analyze_control_flow(self, mock_request):
        """analyze_control_flow uses make_request with GET."""
        mock_request.return_value = '{"blocks": []}'
        from bridge_mcp_ghidra import analyze_control_flow
        analyze_control_flow("main")
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "analyze_control_flow" in args[0]
        assert kwargs.get("method", args[1] if len(args) > 1 else "GET") == "GET"

    @patch("bridge_mcp_ghidra.make_request")
    def test_find_dead_code(self, mock_request):
        """find_dead_code uses make_request with GET."""
        mock_request.return_value = '{"dead_blocks": []}'
        from bridge_mcp_ghidra import find_dead_code
        find_dead_code("main")
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "find_dead_code" in args[0]

    @patch("bridge_mcp_ghidra.make_request")
    def test_find_anti_analysis_techniques(self, mock_request):
        """find_anti_analysis_techniques uses make_request with GET."""
        mock_request.return_value = '{"techniques": []}'
        from bridge_mcp_ghidra import find_anti_analysis_techniques
        find_anti_analysis_techniques()
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "find_anti_analysis_techniques" in args[0]

    @patch("bridge_mcp_ghidra.safe_get")
    def test_inspect_memory_content(self, mock_get):
        """inspect_memory_content uses safe_get and parses JSON result."""
        mock_get.return_value = ['{"bytes": "00 01 02"}']
        from bridge_mcp_ghidra import inspect_memory_content
        inspect_memory_content("0x401000", length=32, detect_strings=False)
        args = mock_get.call_args[0]
        assert args[0] == "inspect_memory_content"
        assert args[1]["address"] == "0x401000"
        assert args[1]["length"] == 32

    @patch("bridge_mcp_ghidra.make_request")
    def test_read_memory(self, mock_request):
        """read_memory uses make_request with GET."""
        mock_request.return_value = '{"data": "AABB"}'
        from bridge_mcp_ghidra import read_memory
        read_memory("0x401000", length=128)
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "read_memory" in args[0]
        assert kwargs["params"]["address"] == "0x401000"
        assert kwargs["params"]["length"] == 128


# =============================================================================
# Program Management Tools
# =============================================================================

class TestProgramManagementTools:
    """Tests for program management tool endpoint mapping."""

    @patch("bridge_mcp_ghidra.make_request")
    def test_list_open_programs(self, mock_request):
        """list_open_programs uses make_request with GET."""
        mock_request.return_value = '{"programs": []}'
        from bridge_mcp_ghidra import list_open_programs
        list_open_programs()
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "list_open_programs" in args[0]

    @patch("bridge_mcp_ghidra.make_request")
    def test_get_current_program_info(self, mock_request):
        """get_current_program_info uses make_request with GET."""
        mock_request.return_value = '{"name": "test.exe"}'
        from bridge_mcp_ghidra import get_current_program_info
        get_current_program_info()
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "get_current_program_info" in args[0]

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_save_program(self, mock_post):
        """save_program uses safe_post_json."""
        mock_post.return_value = '{"status": "saved"}'
        from bridge_mcp_ghidra import save_program
        save_program()
        mock_post.assert_called_once_with("save_program", {})

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_exit_ghidra(self, mock_post):
        """exit_ghidra uses safe_post_json."""
        mock_post.return_value = '{"status": "exiting"}'
        from bridge_mcp_ghidra import exit_ghidra
        exit_ghidra()
        mock_post.assert_called_once_with("exit_ghidra", {})


# =============================================================================
# Bookmark Tools
# =============================================================================

class TestBookmarkTools:
    """Tests for bookmark tool endpoint and parameter mapping."""

    @patch("bridge_mcp_ghidra.make_request")
    def test_set_bookmark(self, mock_request):
        """set_bookmark uses make_request with POST and JSON data."""
        mock_request.return_value = '{"success": true}'
        from bridge_mcp_ghidra import set_bookmark
        set_bookmark("0x401000", category="Analysis", comment="Important")
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "set_bookmark" in args[0]
        assert kwargs["method"] == "POST"
        data = json.loads(kwargs["data"])
        assert data["address"] == "0x401000"
        assert data["category"] == "Analysis"
        assert data["comment"] == "Important"

    @patch("bridge_mcp_ghidra.make_request")
    def test_delete_bookmark(self, mock_request):
        """delete_bookmark uses make_request with POST and JSON data."""
        mock_request.return_value = '{"success": true}'
        from bridge_mcp_ghidra import delete_bookmark
        delete_bookmark("0x401000", category="Analysis")
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "delete_bookmark" in args[0]
        assert kwargs["method"] == "POST"
        data = json.loads(kwargs["data"])
        assert data["address"] == "0x401000"
        assert data["category"] == "Analysis"

    def test_set_bookmark_requires_address(self):
        """set_bookmark should reject empty address."""
        from bridge_mcp_ghidra import set_bookmark, GhidraValidationError
        with pytest.raises(GhidraValidationError):
            set_bookmark("")

    def test_delete_bookmark_requires_address(self):
        """delete_bookmark should reject empty address."""
        from bridge_mcp_ghidra import delete_bookmark, GhidraValidationError
        with pytest.raises(GhidraValidationError):
            delete_bookmark("")


# =============================================================================
# Script Tools (HTTP-based only)
# =============================================================================

class TestScriptTools:
    """Tests for script execution tool endpoint mapping."""

    @patch("bridge_mcp_ghidra.safe_post")
    def test_run_script(self, mock_post):
        mock_post.return_value = "Script output"
        from bridge_mcp_ghidra import run_script
        run_script("/path/to/script.java", args="arg1 arg2")
        args = mock_post.call_args[0]
        assert args[0] == "run_script"
        assert args[1]["script_path"] == "/path/to/script.java"
        assert args[1]["args"] == "arg1 arg2"

    @patch("bridge_mcp_ghidra.safe_get_json")
    def test_list_scripts(self, mock_get):
        mock_get.return_value = '[]'
        from bridge_mcp_ghidra import list_scripts
        list_scripts(filter="FunctionExporter")
        args = mock_get.call_args[0]
        assert args[0] == "list_scripts"
        assert args[1]["filter"] == "FunctionExporter"


# =============================================================================
# Decompile / Disassemble Tools
# =============================================================================

class TestDecompileTools:
    """Tests for decompilation/disassembly tool logic."""

    def test_decompile_function_requires_name_or_address(self):
        """Should raise if neither name nor address provided."""
        from bridge_mcp_ghidra import decompile_function, GhidraValidationError
        with pytest.raises(GhidraValidationError, match="Either 'name' or 'address'"):
            decompile_function()

    @patch("bridge_mcp_ghidra.safe_get")
    def test_decompile_function_by_address(self, mock_get):
        """Should call decompile_function endpoint with address."""
        mock_get.return_value = ["int main() {", "  return 0;", "}"]
        from bridge_mcp_ghidra import decompile_function
        result = decompile_function(address="0x401000")
        # Should have called safe_get with decompile_function endpoint
        assert mock_get.called
        assert "main" in result or "return" in result

    @patch("bridge_mcp_ghidra.safe_post")
    @patch("bridge_mcp_ghidra.safe_get")
    def test_decompile_function_force_by_address(self, mock_get, mock_post):
        """Force decompile should use POST to force_decompile."""
        mock_post.return_value = "int main() { return 0; }"
        from bridge_mcp_ghidra import decompile_function
        decompile_function(address="0x401000", force=True)
        mock_post.assert_called_once_with("force_decompile", {"function_address": "0x401000"})

    def test_decompile_function_invalid_address(self):
        """Should raise on invalid hex address."""
        from bridge_mcp_ghidra import decompile_function, GhidraValidationError
        with pytest.raises(GhidraValidationError):
            decompile_function(address="not_hex_at_all!")

    @patch("bridge_mcp_ghidra.safe_get")
    def test_disassemble_function(self, mock_get):
        mock_get.return_value = ["0x401000: PUSH EBP"]
        from bridge_mcp_ghidra import disassemble_function
        disassemble_function("0x401000")
        args = mock_get.call_args[0]
        assert args[0] == "disassemble_function"
        assert args[1]["address"] == "0x401000"


# =============================================================================
# Cross-Binary Tools
# =============================================================================

class TestCrossBinaryTools:
    """Tests for cross-binary analysis tools (use make_request, not safe_get)."""

    @patch("bridge_mcp_ghidra.make_request")
    def test_get_function_hash(self, mock_request):
        """get_function_hash uses make_request with GET."""
        mock_request.return_value = '{"hash": "abc123"}'
        from bridge_mcp_ghidra import get_function_hash
        get_function_hash("0x401000", program="test.dll")
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "get_function_hash" in args[0]
        assert kwargs["params"]["address"] == "0x401000"
        assert kwargs["params"]["program"] == "test.dll"

    @patch("bridge_mcp_ghidra.make_request")
    def test_get_bulk_function_hashes(self, mock_request):
        """get_bulk_function_hashes uses make_request with GET."""
        mock_request.return_value = '{"hashes": []}'
        from bridge_mcp_ghidra import get_bulk_function_hashes
        get_bulk_function_hashes(offset=0, limit=50, filter="documented")
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "get_bulk_function_hashes" in args[0]

    @patch("bridge_mcp_ghidra.make_request")
    def test_get_function_documentation(self, mock_request):
        """get_function_documentation uses make_request with GET."""
        mock_request.return_value = '{"name": "main"}'
        from bridge_mcp_ghidra import get_function_documentation
        get_function_documentation("0x401000")
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "get_function_documentation" in args[0]
        assert kwargs["params"]["address"] == "0x401000"

    @patch("bridge_mcp_ghidra.make_request")
    def test_compare_programs_documentation(self, mock_request):
        """compare_programs_documentation uses make_request with GET."""
        mock_request.return_value = '{"programs": []}'
        from bridge_mcp_ghidra import compare_programs_documentation
        compare_programs_documentation()
        assert mock_request.called
        args, kwargs = mock_request.call_args
        assert "compare_programs_documentation" in args[0]


# =============================================================================
# Batch Comment Tools
# =============================================================================

class TestBatchCommentTools:
    """Tests for batch comment tool parameter construction."""

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_batch_set_comments(self, mock_post):
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import batch_set_comments
        batch_set_comments(
            function_address="0x401000",
            decompiler_comments=[{"address": "0x401010", "comment": "test"}],
            plate_comment="Function header",
        )
        args = mock_post.call_args[0]
        assert args[0] == "batch_set_comments"
        assert args[1]["function_address"] == "0x401000"
        assert args[1]["plate_comment"] == "Function header"


# =============================================================================
# Input Validation Edge Cases
# =============================================================================

class TestInputValidationEdgeCases:
    """Tests for input validation in tools with address parameters."""

    def test_rename_data_normalizes_address(self):
        """Address should be normalized before validation."""
        from bridge_mcp_ghidra import rename_data, GhidraValidationError
        # Address without 0x prefix should be normalized, not rejected
        # But "not_hex" should still fail
        with pytest.raises(GhidraValidationError):
            rename_data("zzz_invalid", "myData")

    @patch("bridge_mcp_ghidra.safe_get")
    @patch("bridge_mcp_ghidra.safe_post")
    def test_decompile_function_by_name_calls_search_first(self, mock_post, mock_get):
        """Decompile by name should search for function first."""
        # Search returns the function
        mock_get.return_value = ["main @ 0x401000"]
        from bridge_mcp_ghidra import decompile_function
        decompile_function(name="main")
        # First call should be to search_functions
        first_call = mock_get.call_args_list[0]
        assert first_call[0][0] == "search_functions"

    @patch("bridge_mcp_ghidra.safe_get")
    def test_decompile_function_name_not_found(self, mock_get):
        """Should return error when function name not found."""
        mock_get.return_value = ["other_func @ 0x402000"]
        from bridge_mcp_ghidra import decompile_function
        result = decompile_function(name="nonexistent_function")
        assert "not found" in result.lower() or "error" in result.lower()

    def test_set_function_no_return_validates_address(self):
        """set_function_no_return should validate address."""
        from bridge_mcp_ghidra import set_function_no_return, GhidraValidationError
        with pytest.raises(GhidraValidationError):
            set_function_no_return("not_an_address", True)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

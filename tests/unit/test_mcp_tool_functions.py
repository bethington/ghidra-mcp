"""
Unit tests for MCP tool infrastructure in bridge_mcp_ghidra.py.

Tests the dynamic tool registration system (_make_tool_handler, _register_schema_tools),
schema parsing, parameter routing, and static tool availability.

These tests run WITHOUT requiring a Ghidra server.
"""

import inspect
import json
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import bridge_mcp_ghidra


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
        mock_get.assert_called_once_with(
            "list_functions", {"offset": 10, "limit": 50, "program": "test.dll"}
        )

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
        mock_get.assert_called_once_with(
            "list_classes", {"offset": 5, "limit": 25, "program": "prog.exe"}
        )

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
        mock_get.assert_called_once_with(
            "list_external_locations", {"offset": 0, "limit": 50, "program": "test.dll"}
        )

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
        mock_get.assert_called_once_with(
            "validate_data_type_exists", {"type_name": "int"}, program=None
        )

    @patch("bridge_mcp_ghidra.safe_get_json")
    def test_get_data_type_size(self, mock_get):
        mock_get.return_value = '{"size": 4}'
        from bridge_mcp_ghidra import get_data_type_size

        get_data_type_size("int")
        mock_get.assert_called_once_with(
            "get_data_type_size", {"type_name": "int"}, program=None
        )

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_function_labels(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_function_labels

        get_function_labels("main", offset=5, limit=10)
        mock_get.assert_called_once_with(
            "get_function_labels",
            {"name": "main", "offset": 5, "limit": 10},
            program=None,
        )

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
        mock_get.assert_called_once_with("get_entry_points", program=None)

    @patch("bridge_mcp_ghidra.safe_get")
    def test_get_enum_values(self, mock_get):
        mock_get.return_value = []
        from bridge_mcp_ghidra import get_enum_values

        get_enum_values("MyEnum")
        mock_get.assert_called_once_with(
            "get_enum_values", {"enum_name": "MyEnum"}, program=None
        )

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
        mock_get.assert_called_once_with("get_metadata", program=None)
        assert "test.exe" in result

    @patch("bridge_mcp_ghidra.safe_get")
    def test_list_calling_conventions(self, mock_get):
        """list_calling_conventions uses safe_get with no params."""
        mock_get.return_value = ["__cdecl", "__stdcall"]
        from bridge_mcp_ghidra import list_calling_conventions

        list_calling_conventions()
        mock_get.assert_called_once_with("list_calling_conventions", program=None)


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
        mock_post.assert_called_once_with(
            "rename_function",
            {"oldName": "old_func", "newName": "new_func"},
            program=None,
        )

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_label(self, mock_post):
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import rename_label

        rename_label("0x401000", "old_label", "new_label")
        mock_post.assert_called_once_with(
            "rename_label",
            {"address": "0x401000", "old_name": "old_label", "new_name": "new_label"},
            program=None,
        )

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_global_variable(self, mock_post):
        """rename_global_variable uses snake_case params: old_name, new_name."""
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import rename_global_variable

        rename_global_variable("gOldName", "gNewName")
        mock_post.assert_called_once_with(
            "rename_global_variable",
            {"old_name": "gOldName", "new_name": "gNewName"},
            program=None,
        )

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_external_location(self, mock_post):
        """rename_external_location sanitizes address and passes string."""
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import rename_external_location

        rename_external_location("0x401000", "NewName")
        mock_post.assert_called_once_with(
            "rename_external_location",
            {"address": "0x401000", "new_name": "NewName"},
            program=None,
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
            "rename_or_label", {"address": "0x401000", "name": "myLabel"}, program=None
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
            "set_decompiler_comment",
            {"address": "0x401000", "comment": "This is a comment"},
            program=None,
        )

    @patch("bridge_mcp_ghidra.safe_post")
    def test_set_disassembly_comment(self, mock_post):
        mock_post.return_value = "Success"
        from bridge_mcp_ghidra import set_disassembly_comment

        set_disassembly_comment("0x401000", "EOL comment")
        mock_post.assert_called_once_with(
            "set_disassembly_comment",
            {"address": "0x401000", "comment": "EOL comment"},
            program=None,
        )

    @patch("bridge_mcp_ghidra.safe_get_json")
    def test_get_plate_comment(self, mock_get):
        mock_get.return_value = '{"comment": "plate"}'
        from bridge_mcp_ghidra import get_plate_comment

        get_plate_comment("0x401000")
        mock_get.assert_called_once_with(
            "get_plate_comment", {"address": "0x401000"}, program=None
        )


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
            "search_data_types",
            {"pattern": "struct_", "offset": 0, "limit": 20},
            program=None,
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
            "get_xrefs_to",
            {"address": "0x401000", "offset": 0, "limit": 50, "program": "test.dll"},
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
        mock_post.assert_called_once_with(
            "delete_data_type", {"type_name": "MyOldStruct"}, program=None
        )

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
        mock_post.assert_called_once_with("save_program", {}, program=None)

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_exit_ghidra(self, mock_post):
        """exit_ghidra uses safe_post_json."""
        mock_post.return_value = '{"status": "exiting"}'
        from bridge_mcp_ghidra import exit_ghidra

        exit_ghidra()
        mock_post.assert_called_once_with("exit_ghidra", {})

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_load_program(self, mock_post):
        """load_program uses safe_post_json."""
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import load_program

        load_program("/data/test.bin")
        mock_post.assert_called_once_with("load_program", {"file": "/data/test.bin"})

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_close_program(self, mock_post):
        """close_program uses safe_post_json."""
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import close_program

        close_program("test.bin")
        mock_post.assert_called_once_with("close_program", {"name": "test.bin"})

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_load_program_from_project(self, mock_post):
        """load_program_from_project uses safe_post_json."""
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import load_program_from_project

        load_program_from_project("/Test")
        mock_post.assert_called_once_with(
            "load_program_from_project", {"path": "/Test"}
        )

    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_open_project(self, mock_post):
        """open_project uses safe_post_json for headless compatibility."""
        mock_post.return_value = '{"success": true}'
        from bridge_mcp_ghidra import open_project

        open_project("/projects/Test.gpr")
        mock_post.assert_called_once_with(
            "open_project", {"path": "/projects/Test.gpr"}
        )

    @patch("bridge_mcp_ghidra.safe_get_json")
    def test_project_info_falls_back_to_headless_endpoint(self, mock_get_json):
        """project_info falls back to get_project_info when project/info is unavailable."""
        mock_get_json.side_effect = [
            '{"error": "Endpoint not found: project/info"}',
            '{"has_project": false}',
        ]
        from bridge_mcp_ghidra import project_info

        result = project_info()
        assert result == '{"has_project": false}'
        assert mock_get_json.call_args_list[0].args == ("project/info", {})
        assert mock_get_json.call_args_list[1].args == ("get_project_info", {})

    @patch("bridge_mcp_ghidra.safe_post_json")
    @patch("bridge_mcp_ghidra.make_request")
    def test_open_program_falls_back_to_headless_project_load(
        self, mock_request, mock_post
    ):
        """open_program falls back to load_program_from_project in headless mode."""
        mock_request.return_value = (
            '{"error":"Opening programs requires GUI mode (PluginTool not available)"}'
        )
        mock_post.return_value = '{"success": true, "program": "Test"}'
        from bridge_mcp_ghidra import open_program

        result = open_program("/Test")
        assert result == '{"success": true, "program": "Test"}'
        mock_post.assert_called_once_with(
            "load_program_from_project", {"path": "/Test"}
        )

    @patch("bridge_mcp_ghidra.run_analysis")
    @patch("bridge_mcp_ghidra.switch_program")
    @patch("bridge_mcp_ghidra.load_program")
    @patch("bridge_mcp_ghidra.safe_post_json")
    def test_upload_binary_uploads_and_loads(
        self, mock_post, mock_load, mock_switch, mock_analyze, tmp_path
    ):
        """upload_binary uploads local bytes then loads and switches to the new program."""
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"\x7fELFtest")

        mock_post.return_value = (
            '{"success": true, "path": "/data/uploads/sample.bin", '
            '"filename": "sample.bin", "size": 8}'
        )
        mock_load.return_value = '{"success": true, "program": "sample.bin"}'
        mock_switch.return_value = '{"success": true, "switched_to": "sample.bin"}'
        mock_analyze.return_value = '{"success": true, "program": "sample.bin"}'

        from bridge_mcp_ghidra import upload_binary

        result = json.loads(upload_binary(str(sample), analyze=True))

        assert result["uploaded"]["path"] == "/data/uploads/sample.bin"
        assert result["load"]["program"] == "sample.bin"
        assert result["switch"]["switched_to"] == "sample.bin"
        assert result["analysis"]["program"] == "sample.bin"

        call_endpoint, payload = mock_post.call_args.args
        assert call_endpoint == "upload_file"
        assert payload["filename"] == "sample.bin"
        assert payload["directory"] == "/data/uploads"
        assert payload["content_base64"] == "f0VMRnRlc3Q="
        mock_load.assert_called_once_with("/data/uploads/sample.bin")
        mock_switch.assert_called_once_with("sample.bin")
        mock_analyze.assert_called_once_with(program="sample.bin")


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
        mock_get.return_value = "[]"
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
        mock_post.assert_called_once_with(
            "force_decompile", {"function_address": "0x401000"}
        )

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


# =============================================================================
# Schema Type Mapping
# =============================================================================


class TestSchemaTypeMap:
    """Verify _SCHEMA_TYPE_MAP covers expected types."""

    def test_string_maps_to_str(self):
        assert bridge_mcp_ghidra._SCHEMA_TYPE_MAP["string"] is str

    def test_json_maps_to_str(self):
        assert bridge_mcp_ghidra._SCHEMA_TYPE_MAP["json"] is str

    def test_integer_maps_to_int(self):
        assert bridge_mcp_ghidra._SCHEMA_TYPE_MAP["integer"] is int

    def test_boolean_maps_to_bool(self):
        assert bridge_mcp_ghidra._SCHEMA_TYPE_MAP["boolean"] is bool

    def test_number_maps_to_float(self):
        assert bridge_mcp_ghidra._SCHEMA_TYPE_MAP["number"] is float

    def test_object_maps_to_dict(self):
        assert bridge_mcp_ghidra._SCHEMA_TYPE_MAP["object"] is dict

    def test_array_maps_to_list(self):
        assert bridge_mcp_ghidra._SCHEMA_TYPE_MAP["array"] is list

    def test_any_maps_to_str(self):
        assert bridge_mcp_ghidra._SCHEMA_TYPE_MAP["any"] is str

    def test_unknown_type_defaults_to_str(self):
        assert bridge_mcp_ghidra._SCHEMA_TYPE_MAP.get("unknown", str) is str


# =============================================================================
# Python Default Conversion
# =============================================================================


class TestPythonDefault:
    """Test _python_default converts schema defaults to Python values."""

    def test_none_default_returns_empty(self):
        result = bridge_mcp_ghidra._python_default("string", None)
        assert result is inspect.Parameter.empty

    def test_integer_default(self):
        assert bridge_mcp_ghidra._python_default("integer", "42") == 42

    def test_integer_default_invalid(self):
        assert bridge_mcp_ghidra._python_default("integer", "abc") == 0

    def test_boolean_default_true(self):
        assert bridge_mcp_ghidra._python_default("boolean", "true") is True

    def test_boolean_default_false(self):
        assert bridge_mcp_ghidra._python_default("boolean", "false") is False

    def test_number_default(self):
        assert bridge_mcp_ghidra._python_default("number", "3.14") == pytest.approx(
            3.14
        )

    def test_number_default_invalid(self):
        assert bridge_mcp_ghidra._python_default("number", "abc") == 0.0

    def test_string_default(self):
        assert bridge_mcp_ghidra._python_default("string", "hello") == "hello"

    def test_string_default_empty(self):
        assert bridge_mcp_ghidra._python_default("string", "") is None

    def test_json_default(self):
        assert bridge_mcp_ghidra._python_default("json", "{}") == "{}"


# =============================================================================
# Handler Creation (_make_tool_handler)
# =============================================================================


class TestMakeToolHandler:
    """Test _make_tool_handler creates proper handlers with correct signatures."""

    def _make_get_tool(self, params=None):
        """Helper: create a GET tool definition."""
        return {
            "path": "/test_endpoint",
            "method": "GET",
            "description": "Test endpoint",
            "params": params or [],
        }

    def _make_post_tool(self, params=None):
        """Helper: create a POST tool definition."""
        return {
            "path": "/test_endpoint",
            "method": "POST",
            "description": "Test endpoint",
            "params": params or [],
        }

    def test_get_handler_has_signature(self):
        handler = bridge_mcp_ghidra._make_tool_handler(self._make_get_tool())
        sig = inspect.signature(handler)
        # Should at least have 'program' param (auto-added)
        assert "program" in sig.parameters

    def test_get_handler_with_query_params(self):
        tool_def = self._make_get_tool(
            [
                {
                    "name": "offset",
                    "type": "integer",
                    "source": "query",
                    "required": False,
                    "default": "0",
                },
                {
                    "name": "limit",
                    "type": "integer",
                    "source": "query",
                    "required": False,
                    "default": "100",
                },
            ]
        )
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        assert "offset" in sig.parameters
        assert "limit" in sig.parameters
        assert "program" in sig.parameters
        assert sig.parameters["offset"].default == 0
        assert sig.parameters["limit"].default == 100

    def test_get_handler_with_required_params(self):
        tool_def = self._make_get_tool(
            [
                {
                    "name": "address",
                    "type": "string",
                    "source": "query",
                    "required": True,
                },
            ]
        )
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        assert sig.parameters["address"].default is inspect.Parameter.empty

    def test_post_handler_with_body_params(self):
        tool_def = self._make_post_tool(
            [
                {"name": "name", "type": "string", "source": "body", "required": True},
                {
                    "name": "value",
                    "type": "string",
                    "source": "body",
                    "required": False,
                    "default": "",
                },
            ]
        )
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        assert "name" in sig.parameters
        assert "value" in sig.parameters

    def test_get_handler_calls_safe_get_json(self):
        tool_def = self._make_get_tool(
            [
                {
                    "name": "offset",
                    "type": "integer",
                    "source": "query",
                    "required": False,
                    "default": "0",
                },
            ]
        )
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_get_json") as mock_get:
            mock_get.return_value = {"result": "ok"}
            handler(offset=10)
            mock_get.assert_called_once_with(
                "test_endpoint", {"offset": 10}, program=None
            )

    def test_get_handler_omits_none_params(self):
        tool_def = self._make_get_tool(
            [
                {
                    "name": "offset",
                    "type": "integer",
                    "source": "query",
                    "required": False,
                    "default": "0",
                },
                {
                    "name": "filter",
                    "type": "string",
                    "source": "query",
                    "required": False,
                },
            ]
        )
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_get_json") as mock_get:
            mock_get.return_value = {}
            handler(offset=5, filter=None)
            mock_get.assert_called_once_with(
                "test_endpoint", {"offset": 5}, program=None
            )

    def test_post_handler_calls_safe_post_json(self):
        tool_def = self._make_post_tool(
            [
                {"name": "name", "type": "string", "source": "body", "required": True},
            ]
        )
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_post_json") as mock_post:
            mock_post.return_value = {"status": "ok"}
            handler(name="test_func")
            mock_post.assert_called_once_with(
                "test_endpoint", {"name": "test_func"}, program=None
            )

    def test_post_handler_separates_query_and_body_params(self):
        tool_def = self._make_post_tool(
            [
                {
                    "name": "address",
                    "type": "string",
                    "source": "query",
                    "required": True,
                },
                {
                    "name": "comment",
                    "type": "string",
                    "source": "body",
                    "required": True,
                },
            ]
        )
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_post_json") as mock_post:
            mock_post.return_value = {}
            handler(address="0x401000", comment="test comment")
            # Query params should be appended to URL
            call_args = mock_post.call_args
            assert "address=0x401000" in call_args[0][0]
            assert call_args[0][1] == {"comment": "test comment"}

    def test_program_param_forwarded(self):
        tool_def = self._make_get_tool()
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_get_json") as mock_get:
            mock_get.return_value = {}
            handler(program="test.dll")
            mock_get.assert_called_once_with("test_endpoint", {}, program="test.dll")

    def test_program_param_not_duplicated(self):
        """If 'program' is already in the schema params, don't add it again."""
        tool_def = self._make_get_tool(
            [
                {
                    "name": "program",
                    "type": "string",
                    "source": "query",
                    "required": False,
                },
            ]
        )
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        # Should only have one 'program' param
        program_params = [k for k in sig.parameters if k == "program"]
        assert len(program_params) == 1

    def test_boolean_param_annotation(self):
        tool_def = self._make_get_tool(
            [
                {
                    "name": "recursive",
                    "type": "boolean",
                    "source": "query",
                    "required": False,
                    "default": "false",
                },
            ]
        )
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        assert sig.parameters["recursive"].default is False
        assert sig.parameters["recursive"].annotation is bool

    def test_array_param_annotation(self):
        tool_def = self._make_post_tool(
            [
                {"name": "items", "type": "array", "source": "body", "required": True},
            ]
        )
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        assert sig.parameters["items"].annotation is list


# =============================================================================
# Dynamic Registration (_register_schema_tools)
# =============================================================================


class TestRegisterSchemaTools:
    """Test _register_schema_tools processes schema correctly."""

    SAMPLE_SCHEMA = {
        "tools": [
            {
                "path": "/list_functions",
                "method": "GET",
                "description": "List functions",
                "category": "listing",
                "params": [
                    {
                        "name": "offset",
                        "type": "integer",
                        "source": "query",
                        "required": False,
                        "default": "0",
                    },
                    {
                        "name": "limit",
                        "type": "integer",
                        "source": "query",
                        "required": False,
                        "default": "100",
                    },
                ],
            },
            {
                "path": "/rename_function",
                "method": "POST",
                "description": "Rename function",
                "category": "rename",
                "params": [
                    {
                        "name": "old_name",
                        "type": "string",
                        "source": "body",
                        "required": True,
                    },
                    {
                        "name": "new_name",
                        "type": "string",
                        "source": "body",
                        "required": True,
                    },
                ],
            },
            # This one should be skipped (in STATIC_TOOL_NAMES)
            {
                "path": "/check_connection",
                "method": "GET",
                "description": "Check connection",
                "params": [],
            },
        ],
        "count": 3,
    }

    @patch.object(bridge_mcp_ghidra, "mcp")
    @patch.object(bridge_mcp_ghidra, "session")
    def test_registers_non_static_tools(self, mock_session, mock_mcp):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = self.SAMPLE_SCHEMA
        mock_session.get.return_value = mock_response

        mock_tool_decorator = MagicMock(return_value=lambda f: f)
        mock_mcp.tool.return_value = mock_tool_decorator

        count = bridge_mcp_ghidra._register_schema_tools()

        # list_functions + rename_function registered, check_connection skipped
        assert count == 2

    @patch.object(bridge_mcp_ghidra, "mcp")
    @patch.object(bridge_mcp_ghidra, "session")
    def test_skips_static_tools(self, mock_session, mock_mcp):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = self.SAMPLE_SCHEMA
        mock_session.get.return_value = mock_response

        mock_tool_decorator = MagicMock(return_value=lambda f: f)
        mock_mcp.tool.return_value = mock_tool_decorator

        bridge_mcp_ghidra._register_schema_tools()

        # Verify check_connection was NOT registered
        registered_names = [
            call.kwargs.get("name", call.args[0] if call.args else None)
            for call in mock_mcp.tool.call_args_list
        ]
        assert "check_connection" not in registered_names

    @patch.object(bridge_mcp_ghidra, "mcp")
    @patch.object(bridge_mcp_ghidra, "session")
    def test_connection_error_returns_zero(self, mock_session, mock_mcp):
        import requests

        mock_session.get.side_effect = requests.exceptions.ConnectionError()
        count = bridge_mcp_ghidra._register_schema_tools()
        assert count == 0

    @patch.object(bridge_mcp_ghidra, "mcp")
    @patch.object(bridge_mcp_ghidra, "session")
    def test_http_error_returns_zero(self, mock_session, mock_mcp):
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 500
        mock_session.get.return_value = mock_response
        count = bridge_mcp_ghidra._register_schema_tools()
        assert count == 0


# =============================================================================
# Static Tool Names Sanity Checks
# =============================================================================


class TestStaticToolNames:
    """Verify STATIC_TOOL_NAMES set is correct."""

    def test_check_connection_is_static(self):
        assert "check_connection" in bridge_mcp_ghidra.STATIC_TOOL_NAMES

    def test_get_version_is_static(self):
        assert "get_version" in bridge_mcp_ghidra.STATIC_TOOL_NAMES

    def test_decompile_function_is_static(self):
        assert "decompile_function" in bridge_mcp_ghidra.STATIC_TOOL_NAMES

    def test_knowledge_db_tools_are_static(self):
        kb_tools = {
            "store_function_knowledge",
            "query_knowledge_context",
            "store_ordinal_mapping",
            "get_ordinal_mapping",
            "export_system_knowledge",
        }
        assert kb_tools.issubset(bridge_mcp_ghidra.STATIC_TOOL_NAMES)

    def test_script_lifecycle_tools_are_static(self):
        script_tools = {
            "save_ghidra_script",
            "list_ghidra_scripts",
            "get_ghidra_script",
            "update_ghidra_script",
            "delete_ghidra_script",
        }
        assert script_tools.issubset(bridge_mcp_ghidra.STATIC_TOOL_NAMES)

    def test_static_count_reasonable(self):
        count = len(bridge_mcp_ghidra.STATIC_TOOL_NAMES)
        assert 15 <= count <= 30, (
            f"STATIC_TOOL_NAMES has {count} entries, expected 15-30"
        )


# =============================================================================
# Static Tool Existence Tests
# =============================================================================


class TestStaticToolsExist:
    """Verify that static tools are actually defined as functions in the bridge."""

    def test_check_connection_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "check_connection", None))

    def test_get_version_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "get_version", None))

    def test_decompile_function_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "decompile_function", None))

    def test_disassemble_function_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "disassemble_function", None))

    def test_rename_variables_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "rename_variables", None))

    def test_rename_function_by_address_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "rename_function_by_address", None))

    def test_set_function_prototype_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "set_function_prototype", None))

    def test_get_current_selection_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "get_current_selection", None))

    def test_get_function_metrics_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "get_function_metrics", None))

    def test_save_ghidra_script_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "save_ghidra_script", None))

    def test_build_function_hash_index_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "build_function_hash_index", None))

    def test_propagate_documentation_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "propagate_documentation", None))


# =============================================================================
# Static Tool Function Tests (complex bridge-side logic)
# =============================================================================


class TestCheckConnection:
    """Test check_connection static tool."""

    @patch.object(bridge_mcp_ghidra, "session")
    def test_successful_connection(self, mock_session):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Ghidra MCP ready"
        mock_session.get.return_value = mock_response
        result = bridge_mcp_ghidra.check_connection()
        assert (
            "ready" in result.lower()
            or "connected" in result.lower()
            or "200" in result
        )

    @patch.object(bridge_mcp_ghidra, "session")
    def test_connection_failure(self, mock_session):
        import requests

        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        result = bridge_mcp_ghidra.check_connection()
        assert (
            "error" in result.lower()
            or "fail" in result.lower()
            or "not" in result.lower()
        )


class TestDecompileFunction:
    """Test decompile_function static tool."""

    @patch.object(bridge_mcp_ghidra, "safe_get")
    def test_by_name(self, mock_get):
        mock_get.return_value = ["int main() { return 0; }"]
        result = bridge_mcp_ghidra.decompile_function(name="main")
        mock_get.assert_called_once()

    @patch.object(bridge_mcp_ghidra, "safe_get")
    def test_by_address(self, mock_get):
        mock_get.return_value = ["void func() {}"]
        result = bridge_mcp_ghidra.decompile_function(address="0x401000")
        mock_get.assert_called_once()

    def test_requires_name_or_address(self):
        with pytest.raises(Exception):
            bridge_mcp_ghidra.decompile_function()


class TestDisassembleFunction:
    """Test disassemble_function static tool."""

    @patch.object(bridge_mcp_ghidra, "safe_get")
    def test_by_address(self, mock_get):
        mock_get.return_value = ["0x401000: push ebp"]
        result = bridge_mcp_ghidra.disassemble_function(address="0x401000")
        mock_get.assert_called_once()


class TestRenameVariables:
    """Test rename_variables static tool."""

    @patch.object(bridge_mcp_ghidra, "safe_post_json")
    def test_rename(self, mock_post):
        mock_post.return_value = {"status": "ok"}
        result = bridge_mcp_ghidra.rename_variables(
            function_address="0x401000",
            variable_renames={"var1": "counter", "var2": "buffer"},
        )
        mock_post.assert_called_once()


class TestSetFunctionPrototype:
    """Test set_function_prototype static tool."""

    @patch.object(bridge_mcp_ghidra, "safe_get")
    @patch.object(bridge_mcp_ghidra, "safe_post_json")
    def test_set_prototype(self, mock_post, mock_get):
        mock_get.return_value = "Function: main @ 0x401000"
        mock_post.return_value = "success: prototype set"
        result = bridge_mcp_ghidra.set_function_prototype(
            function_address="0x401000",
            prototype="int main(int argc, char **argv)",
        )
        mock_post.assert_called_once()


# =============================================================================
# Handler Routing Edge Cases
# =============================================================================


class TestHandlerRouting:
    """Test edge cases in dynamic handler parameter routing."""

    def test_get_strips_leading_slash(self):
        """GET handler should strip leading slash from path."""
        tool_def = {
            "path": "/list_functions",
            "method": "GET",
            "params": [],
        }
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_get_json") as mock_get:
            mock_get.return_value = {}
            handler()
            assert mock_get.call_args[0][0] == "list_functions"

    def test_post_strips_leading_slash(self):
        """POST handler should strip leading slash from path."""
        tool_def = {
            "path": "/rename_function",
            "method": "POST",
            "params": [
                {"name": "name", "type": "string", "source": "body", "required": True},
            ],
        }
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_post_json") as mock_post:
            mock_post.return_value = {}
            handler(name="test")
            assert mock_post.call_args[0][0] == "rename_function"

    def test_post_unknown_source_goes_to_body(self):
        """POST params with unknown source should go to body."""
        tool_def = {
            "path": "/test",
            "method": "POST",
            "params": [
                {"name": "data", "type": "string", "required": True},
                # No 'source' field
            ],
        }
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_post_json") as mock_post:
            mock_post.return_value = {}
            handler(data="value")
            assert mock_post.call_args[0][1] == {"data": "value"}

    def test_handler_return_annotation_is_str(self):
        """Handler signature should have str return annotation."""
        tool_def = {
            "path": "/test",
            "method": "GET",
            "params": [],
        }
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        assert sig.return_annotation is str


# =============================================================================
# Bridge Import Sanity
# =============================================================================


class TestBridgeImport:
    """Basic sanity checks on bridge module."""

    def test_mcp_object_exists(self):
        assert hasattr(bridge_mcp_ghidra, "mcp")

    def test_session_object_exists(self):
        assert hasattr(bridge_mcp_ghidra, "session")

    def test_safe_get_json_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "safe_get_json", None))

    def test_safe_post_json_exists(self):
        assert callable(getattr(bridge_mcp_ghidra, "safe_post_json", None))

    def test_ghidra_server_url_set(self):
        assert hasattr(bridge_mcp_ghidra, "ghidra_server_url")
        assert "127.0.0.1" in bridge_mcp_ghidra.ghidra_server_url

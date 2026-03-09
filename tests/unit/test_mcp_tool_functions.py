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
        assert bridge_mcp_ghidra._python_default("number", "3.14") == pytest.approx(3.14)

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
        tool_def = self._make_get_tool([
            {"name": "offset", "type": "integer", "source": "query", "required": False, "default": "0"},
            {"name": "limit", "type": "integer", "source": "query", "required": False, "default": "100"},
        ])
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        assert "offset" in sig.parameters
        assert "limit" in sig.parameters
        assert "program" in sig.parameters
        assert sig.parameters["offset"].default == 0
        assert sig.parameters["limit"].default == 100

    def test_get_handler_with_required_params(self):
        tool_def = self._make_get_tool([
            {"name": "address", "type": "string", "source": "query", "required": True},
        ])
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        assert sig.parameters["address"].default is inspect.Parameter.empty

    def test_post_handler_with_body_params(self):
        tool_def = self._make_post_tool([
            {"name": "name", "type": "string", "source": "body", "required": True},
            {"name": "value", "type": "string", "source": "body", "required": False, "default": ""},
        ])
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        assert "name" in sig.parameters
        assert "value" in sig.parameters

    def test_get_handler_calls_safe_get_json(self):
        tool_def = self._make_get_tool([
            {"name": "offset", "type": "integer", "source": "query", "required": False, "default": "0"},
        ])
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_get_json") as mock_get:
            mock_get.return_value = {"result": "ok"}
            handler(offset=10)
            mock_get.assert_called_once_with("test_endpoint", {"offset": 10}, program=None)

    def test_get_handler_omits_none_params(self):
        tool_def = self._make_get_tool([
            {"name": "offset", "type": "integer", "source": "query", "required": False, "default": "0"},
            {"name": "filter", "type": "string", "source": "query", "required": False},
        ])
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_get_json") as mock_get:
            mock_get.return_value = {}
            handler(offset=5, filter=None)
            mock_get.assert_called_once_with("test_endpoint", {"offset": 5}, program=None)

    def test_post_handler_calls_safe_post_json(self):
        tool_def = self._make_post_tool([
            {"name": "name", "type": "string", "source": "body", "required": True},
        ])
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        with patch.object(bridge_mcp_ghidra, "safe_post_json") as mock_post:
            mock_post.return_value = {"status": "ok"}
            handler(name="test_func")
            mock_post.assert_called_once_with("test_endpoint", {"name": "test_func"}, program=None)

    def test_post_handler_separates_query_and_body_params(self):
        tool_def = self._make_post_tool([
            {"name": "address", "type": "string", "source": "query", "required": True},
            {"name": "comment", "type": "string", "source": "body", "required": True},
        ])
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
        tool_def = self._make_get_tool([
            {"name": "program", "type": "string", "source": "query", "required": False},
        ])
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        # Should only have one 'program' param
        program_params = [k for k in sig.parameters if k == "program"]
        assert len(program_params) == 1

    def test_boolean_param_annotation(self):
        tool_def = self._make_get_tool([
            {"name": "recursive", "type": "boolean", "source": "query", "required": False, "default": "false"},
        ])
        handler = bridge_mcp_ghidra._make_tool_handler(tool_def)
        sig = inspect.signature(handler)
        assert sig.parameters["recursive"].default is False
        assert sig.parameters["recursive"].annotation is bool

    def test_array_param_annotation(self):
        tool_def = self._make_post_tool([
            {"name": "items", "type": "array", "source": "body", "required": True},
        ])
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
                    {"name": "offset", "type": "integer", "source": "query", "required": False, "default": "0"},
                    {"name": "limit", "type": "integer", "source": "query", "required": False, "default": "100"},
                ],
            },
            {
                "path": "/rename_function",
                "method": "POST",
                "description": "Rename function",
                "category": "rename",
                "params": [
                    {"name": "old_name", "type": "string", "source": "body", "required": True},
                    {"name": "new_name", "type": "string", "source": "body", "required": True},
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
        assert 15 <= count <= 30, f"STATIC_TOOL_NAMES has {count} entries, expected 15-30"


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
        assert "ready" in result.lower() or "connected" in result.lower() or "200" in result

    @patch.object(bridge_mcp_ghidra, "session")
    def test_connection_failure(self, mock_session):
        import requests
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        result = bridge_mcp_ghidra.check_connection()
        assert "error" in result.lower() or "fail" in result.lower() or "not" in result.lower()


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

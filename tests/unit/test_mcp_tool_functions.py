"""
Unit tests for MCP dynamic tool function generation.

Tests _build_tool_function behavior for various schema patterns,
verifying that dynamically generated functions correctly dispatch
GET/POST requests with proper parameter handling.
"""

import json
import inspect
import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class TestGetToolDispatch(unittest.TestCase):
    """Test that GET tool functions dispatch correctly."""

    @patch("bridge_mcp_ghidra.dispatch_get")
    def test_get_with_required_param(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        mock_get.return_value = '{"result": "ok"}'

        schema = {
            "properties": {"address": {"type": "string"}},
            "required": ["address"],
        }
        fn = _build_tool_function("/decompile_function", "GET", schema)
        result = fn(address="0x401000")

        mock_get.assert_called_once_with(
            "/decompile_function", params={"address": "0x401000"}
        )
        self.assertEqual(result, '{"result": "ok"}')

    @patch("bridge_mcp_ghidra.dispatch_get")
    def test_get_with_optional_param_none(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        mock_get.return_value = '{"data": []}'

        schema = {
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
            },
            "required": [],
        }
        fn = _build_tool_function("/list_functions", "GET", schema)
        result = fn(offset=None, limit=None)

        # None values should be filtered out
        mock_get.assert_called_once_with("/list_functions", params=None)

    @patch("bridge_mcp_ghidra.dispatch_get")
    def test_get_with_no_params(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        mock_get.return_value = '{"version": "4.2.0"}'

        schema = {"properties": {}, "required": []}
        fn = _build_tool_function("/get_version", "GET", schema)
        result = fn()

        mock_get.assert_called_once_with("/get_version", params=None)


class TestPostToolDispatch(unittest.TestCase):
    """Test that POST tool functions dispatch correctly."""

    @patch("bridge_mcp_ghidra.dispatch_post")
    def test_post_with_json_body(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function
        mock_post.return_value = '{"success": true}'

        schema = {
            "properties": {
                "address": {"type": "string"},
                "name": {"type": "string"},
            },
            "required": ["address", "name"],
        }
        fn = _build_tool_function("/rename_function", "POST", schema)
        result = fn(address="0x401000", name="main")

        mock_post.assert_called_once_with(
            "/rename_function", data={"address": "0x401000", "name": "main"}, query_params=None
        )

    @patch("bridge_mcp_ghidra.dispatch_post")
    def test_post_filters_none_values(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function
        mock_post.return_value = '{"success": true}'

        schema = {
            "properties": {
                "address": {"type": "string"},
                "program": {"type": "string"},
            },
            "required": ["address"],
        }
        fn = _build_tool_function("/rename_function", "POST", schema)
        fn(address="0x401000", program=None)

        mock_post.assert_called_once_with(
            "/rename_function", data={"address": "0x401000"}, query_params=None
        )

    @patch("bridge_mcp_ghidra.dispatch_post")
    def test_post_integer_params(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function
        mock_post.return_value = '{"data": []}'

        schema = {
            "properties": {
                "offset": {"type": "integer"},
                "limit": {"type": "integer"},
            },
            "required": ["offset", "limit"],
        }
        fn = _build_tool_function("/search", "POST", schema)
        fn(offset=0, limit=50)

        # POST sends native types, not strings
        mock_post.assert_called_once_with("/search", data={"offset": 0, "limit": 50}, query_params=None)


class TestSchemaEdgeCases(unittest.TestCase):
    """Test edge cases in schema parsing."""

    def test_unknown_type_defaults_to_string(self):
        from bridge_mcp_ghidra import _build_tool_function
        schema = {
            "properties": {"data": {"type": "unknown_type"}},
            "required": ["data"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        self.assertEqual(fn.__annotations__["data"], str)

    def test_missing_type_defaults_to_string(self):
        from bridge_mcp_ghidra import _build_tool_function
        schema = {
            "properties": {"data": {}},
            "required": ["data"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        self.assertEqual(fn.__annotations__["data"], str)

    def test_missing_required_field(self):
        """Schema without 'required' field should treat all as optional."""
        from bridge_mcp_ghidra import _build_tool_function
        schema = {
            "properties": {"data": {"type": "string"}},
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIsNone(sig.parameters["data"].default)

    def test_many_parameters(self):
        """Schema with many parameters should work."""
        from bridge_mcp_ghidra import _build_tool_function
        props = {f"param_{i}": {"type": "string"} for i in range(20)}
        schema = {"properties": props, "required": ["param_0"]}
        fn = _build_tool_function("/test", "POST", schema)
        sig = inspect.signature(fn)
        self.assertEqual(len(sig.parameters), 21)
        self.assertIn("dry_run", sig.parameters)


class TestToolRegistrationRoundTrip(unittest.TestCase):
    """Test full schema → registration → dispatch round trip."""

    @patch("bridge_mcp_ghidra.dispatch_get")
    def test_full_roundtrip(self, mock_get):
        from bridge_mcp_ghidra import register_tools_from_schema, mcp
        mock_get.return_value = '{"functions": []}'

        schema = [
            {
                "name": "roundtrip_test_tool",
                "description": "Test decompilation",
                "endpoint": "/roundtrip_test",
                "http_method": "GET",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Function address"},
                    },
                    "required": ["address"],
                },
            },
        ]
        count = register_tools_from_schema(schema)
        self.assertEqual(count, 1)

        # The tool should be registered in the MCP server
        tools = mcp._tool_manager._tools
        self.assertIn("roundtrip_test_tool", tools)


if __name__ == "__main__":
    unittest.main()

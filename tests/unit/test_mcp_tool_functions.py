"""
Unit tests for MCP dynamic tool function generation.

Tests schema.build_tool_function behavior for various schema patterns,
verifying that dynamically generated functions correctly dispatch GET/POST
requests with proper parameter handling.
"""

import inspect
import unittest
from unittest.mock import patch

from ghidra_mcp_bridge import registry
from ghidra_mcp_bridge.schema import build_tool_function


class TestGetToolDispatch(unittest.TestCase):
    """Test that GET tool functions dispatch correctly."""

    @patch("ghidra_mcp_bridge.connection.dispatch_get")
    def test_get_with_required_param(self, mock_get):
        mock_get.return_value = '{"result": "ok"}'

        schema = {
            "properties": {"address": {"type": "string"}},
            "required": ["address"],
        }
        fn = build_tool_function("/decompile_function", "GET", schema)
        result = fn(address="0x401000")

        mock_get.assert_called_once_with(
            "/decompile_function", params={"address": "0x401000"}
        )
        self.assertEqual(result, '{"result": "ok"}')

    @patch("ghidra_mcp_bridge.connection.dispatch_get")
    def test_get_with_optional_param_none(self, mock_get):
        mock_get.return_value = '{"data": []}'

        schema = {
            "properties": {
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 100},
            },
            "required": [],
        }
        fn = build_tool_function("/list_functions", "GET", schema)
        fn(offset=None, limit=None)

        # None values should be filtered out
        mock_get.assert_called_once_with("/list_functions", params=None)

    @patch("ghidra_mcp_bridge.connection.dispatch_get")
    def test_get_with_no_params(self, mock_get):
        mock_get.return_value = '{"version": "4.2.0"}'

        schema = {"properties": {}, "required": []}
        fn = build_tool_function("/get_version", "GET", schema)
        fn()

        mock_get.assert_called_once_with("/get_version", params=None)


class TestPostToolDispatch(unittest.TestCase):
    """Test that POST tool functions dispatch correctly."""

    @patch("ghidra_mcp_bridge.connection.dispatch_post")
    def test_post_with_json_body(self, mock_post):
        mock_post.return_value = '{"success": true}'

        schema = {
            "properties": {
                "address": {"type": "string"},
                "name": {"type": "string"},
            },
            "required": ["address", "name"],
        }
        fn = build_tool_function("/rename_function", "POST", schema)
        fn(address="0x401000", name="main")

        mock_post.assert_called_once_with(
            "/rename_function", data={"address": "0x401000", "name": "main"}, query_params=None
        )

    @patch("ghidra_mcp_bridge.connection.dispatch_post")
    def test_post_filters_none_values(self, mock_post):
        mock_post.return_value = '{"success": true}'

        schema = {
            "properties": {
                "address": {"type": "string"},
                "program": {"type": "string"},
            },
            "required": ["address"],
        }
        fn = build_tool_function("/rename_function", "POST", schema)
        fn(address="0x401000", program=None)

        mock_post.assert_called_once_with(
            "/rename_function", data={"address": "0x401000"}, query_params=None
        )

    @patch("ghidra_mcp_bridge.connection.dispatch_post")
    def test_post_integer_params(self, mock_post):
        mock_post.return_value = '{"data": []}'

        schema = {
            "properties": {
                "offset": {"type": "integer"},
                "limit": {"type": "integer"},
            },
            "required": ["offset", "limit"],
        }
        fn = build_tool_function("/search", "POST", schema)
        fn(offset=0, limit=50)

        # POST sends native types, not strings
        mock_post.assert_called_once_with("/search", data={"offset": 0, "limit": 50}, query_params=None)

    @patch("ghidra_mcp_bridge.connection.dispatch_post")
    def test_post_synthetic_dry_run_only_for_true_values(self, mock_post):
        mock_post.return_value = '{"success": true}'

        schema = {
            "properties": {
                "address": {"type": "string"},
                "name": {"type": "string"},
            },
            "required": ["address", "name"],
        }
        fn = build_tool_function("/rename_function", "POST", schema)

        fn(address="0x401000", name="main", dry_run="false")
        mock_post.assert_called_once_with(
            "/rename_function",
            data={"address": "0x401000", "name": "main"},
            query_params=None,
        )

        mock_post.reset_mock()
        fn(address="0x401000", name="main", dry_run=True)
        mock_post.assert_called_once_with(
            "/rename_function",
            data={"address": "0x401000", "name": "main"},
            query_params={"dry_run": "true"},
        )

    @patch("ghidra_mcp_bridge.connection.dispatch_post")
    def test_schema_declared_query_dry_run_does_not_duplicate_signature(self, mock_post):
        mock_post.return_value = '{"dry_run": true}'

        schema = {
            "properties": {
                "program": {"type": "string", "source": "query", "default": ""},
                "dry_run": {
                    "type": "boolean",
                    "source": "query",
                    "default": "false",
                },
            },
            "required": [],
        }
        fn = build_tool_function("/archive_ingest_program", "POST", schema)
        sig = inspect.signature(fn)

        self.assertEqual(list(sig.parameters).count("dry_run"), 1)

        fn(program="pwahelper.exe", dry_run="false")
        mock_post.assert_called_once_with(
            "/archive_ingest_program",
            data={},
            query_params={"program": "pwahelper.exe", "dry_run": "false"},
        )

    @patch("ghidra_mcp_bridge.connection.dispatch_post")
    def test_schema_declared_body_dry_run_uses_body_source(self, mock_post):
        mock_post.return_value = '{"dry_run": true}'

        schema = {
            "properties": {
                "source": {"type": "string", "source": "body"},
                "target": {"type": "string", "source": "body"},
                "dry_run": {
                    "type": "boolean",
                    "source": "body",
                    "default": "false",
                },
            },
            "required": ["source", "target"],
        }
        fn = build_tool_function("/merge_program_documentation", "POST", schema)
        sig = inspect.signature(fn)

        self.assertEqual(list(sig.parameters).count("dry_run"), 1)

        fn(source="recovered", target="original", dry_run=True)
        mock_post.assert_called_once_with(
            "/merge_program_documentation",
            data={"source": "recovered", "target": "original", "dry_run": True},
            query_params=None,
        )


class TestSchemaEdgeCases(unittest.TestCase):
    """Test edge cases in schema parsing."""

    def test_unknown_type_defaults_to_string(self):
        schema = {
            "properties": {"data": {"type": "unknown_type"}},
            "required": ["data"],
        }
        fn = build_tool_function("/test", "GET", schema)
        self.assertEqual(fn.__annotations__["data"], str)

    def test_missing_type_defaults_to_string(self):
        schema = {
            "properties": {"data": {}},
            "required": ["data"],
        }
        fn = build_tool_function("/test", "GET", schema)
        self.assertEqual(fn.__annotations__["data"], str)

    def test_missing_required_field(self):
        """Schema without 'required' field should treat all as optional."""
        schema = {
            "properties": {"data": {"type": "string"}},
        }
        fn = build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIsNone(sig.parameters["data"].default)

    def test_many_parameters(self):
        """Schema with many parameters should work."""
        props = {f"param_{i}": {"type": "string"} for i in range(20)}
        schema = {"properties": props, "required": ["param_0"]}
        fn = build_tool_function("/test", "POST", schema)
        sig = inspect.signature(fn)
        self.assertEqual(len(sig.parameters), 21)
        self.assertIn("dry_run", sig.parameters)


class TestToolRegistrationRoundTrip(unittest.TestCase):
    """Test full schema → registration → dispatch round trip."""

    def test_full_roundtrip(self):
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
        count = registry.register_tools_from_schema(schema)
        self.assertEqual(count, 1)

        # The tool should be tracked as a registered dynamic tool.
        self.assertIn("roundtrip_test_tool", registry.dynamic_tool_names())


if __name__ == "__main__":
    unittest.main()

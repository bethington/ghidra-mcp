"""
Unit tests for the MCP bridge dynamic tool system.

Tests the thin multiplexer's core functionality: schema parsing, tool
registration, transport mode management, and static tool contracts against the
``ghidra_mcp_bridge`` package.
"""

import inspect
import json
import re
import unittest

from ghidra_mcp_bridge import connection, tools
from ghidra_mcp_bridge.config import ENDPOINT_TIMEOUTS, STATIC_TOOL_NAMES
from ghidra_mcp_bridge.schema import build_tool_function, parse_schema


class TestTransportModes(unittest.TestCase):
    """Test transport mode state management."""

    def test_initial_state(self):
        """Transport mode is always one of the three known values."""
        self.assertIn(connection.transport_mode(), ("none", "uds", "tcp"))

    def test_do_request_raises_when_disconnected(self):
        """do_request should raise ConnectionError when no transport active."""
        connection.reset()
        with self.assertRaises(ConnectionError):
            connection.do_request("GET", "/test")


class TestStaticTools(unittest.TestCase):
    """Test that static MCP tools are always available."""

    def test_list_instances_is_static(self):
        self.assertIn("list_instances", STATIC_TOOL_NAMES)

    def test_connect_instance_is_static(self):
        self.assertIn("connect_instance", STATIC_TOOL_NAMES)

    def test_list_instances_returns_json(self):
        """list_instances should return valid JSON with an instances list."""
        result = tools.list_instances()
        data = json.loads(result)
        self.assertIn("instances", data)
        self.assertIsInstance(data["instances"], list)


class TestEndpointTimeouts(unittest.TestCase):
    """Test endpoint timeout configuration."""

    def test_all_timeouts_positive(self):
        for name, timeout in ENDPOINT_TIMEOUTS.items():
            self.assertGreater(timeout, 0, f"Timeout for {name} should be positive")

    def test_script_timeouts_high(self):
        self.assertGreaterEqual(ENDPOINT_TIMEOUTS.get("run_ghidra_script", 0), 600)
        self.assertGreaterEqual(ENDPOINT_TIMEOUTS.get("run_script_inline", 0), 600)

    def test_default_exists(self):
        self.assertIn("default", ENDPOINT_TIMEOUTS)


class TestSchemaFormat(unittest.TestCase):
    """Test that tool schema format matches expectations."""

    def test_register_with_all_json_types(self):
        """Schema with all JSON types should produce correct Python signatures."""
        schema = {
            "properties": {
                "str_param": {"type": "string"},
                "int_param": {"type": "integer"},
                "bool_param": {"type": "boolean"},
                "num_param": {"type": "number"},
            },
            "required": ["str_param"],
        }
        fn = build_tool_function("/test", "POST", schema)
        sig = inspect.signature(fn)
        self.assertEqual(len(sig.parameters), 5)
        self.assertIn("dry_run", sig.parameters)

    def test_schema_with_descriptions(self):
        """Schema properties with descriptions should not affect function building."""
        schema = {
            "properties": {
                "address": {
                    "type": "string",
                    "description": "The function address or name",
                },
            },
            "required": ["address"],
        }
        fn = build_tool_function("/decompile_function", "GET", schema)
        self.assertTrue(callable(fn))

    def test_parsed_schema_tool_names_match_capi_regex(self):
        """Every parsed MCP-visible tool name should be safe for Copilot/CAPI."""
        raw = {
            "tools": [
                {"path": "/regular_tool", "method": "GET", "params": []},
                {"path": "/debugger/status", "method": "GET", "params": []},
                {"path": "/server/status", "method": "GET", "params": []},
            ]
        }
        pattern = re.compile(r"^[a-zA-Z0-9_-]+$")
        for tool in parse_schema(raw):
            self.assertRegex(tool["name"], pattern)


if __name__ == "__main__":
    unittest.main()

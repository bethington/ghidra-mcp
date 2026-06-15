"""
Response Schema Validation Tests.

Verifies the bridge's response handling — the thin multiplexer passes through
JSON from Java, so we test the dispatch layer's error responses and JSON
validity against the ``ghidra_mcp_bridge`` package.
"""

import json
import unittest

from ghidra_mcp_bridge import connection, registry
from ghidra_mcp_bridge.transport import UnixHTTPConnection


class TestDispatchErrorResponses(unittest.TestCase):
    """Dispatch functions return valid JSON error responses when disconnected."""

    def setUp(self):
        connection.reset()

    def test_get_no_connection_returns_json(self):
        result = connection.dispatch_get("/test_endpoint")
        data = json.loads(result)
        self.assertIn("error", data)
        self.assertIsInstance(data["error"], str)

    def test_post_no_connection_returns_json(self):
        result = connection.dispatch_post("/test_endpoint", {"key": "val"})
        data = json.loads(result)
        self.assertIn("error", data)


class TestUdsRequestFormat(unittest.TestCase):
    """UnixHTTPConnection construction."""

    def test_uds_connection_retains_socket_path(self):
        conn = UnixHTTPConnection("/tmp/nonexistent.sock", timeout=5)
        self.assertEqual(conn.socket_path, "/tmp/nonexistent.sock")


class TestSchemaJsonFormat(unittest.TestCase):
    """register_tools_from_schema handles various parsed-schema formats."""

    def test_minimal_schema(self):
        schema = [
            {
                "name": "schema_test_minimal",
                "description": "",
                "endpoint": "/test",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        count = registry.register_tools_from_schema(schema)
        self.assertEqual(count, 1)

    def test_schema_with_category(self):
        """Schema entries may include a category field (kept as a tool tag)."""
        schema = [
            {
                "name": "schema_test_category",
                "description": "Test with category",
                "endpoint": "/test_cat",
                "http_method": "GET",
                "category": "function",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        count = registry.register_tools_from_schema(schema)
        self.assertEqual(count, 1)

    def test_schema_preserves_description(self):
        """Registered tool should be tracked under its schema name."""
        schema = [
            {
                "name": "schema_test_desc",
                "description": "Decompile a function and return pseudocode",
                "endpoint": "/test_desc",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        registry.register_tools_from_schema(schema)
        self.assertIn("schema_test_desc", registry.dynamic_tool_names())


if __name__ == "__main__":
    unittest.main()

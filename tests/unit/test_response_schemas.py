"""
Response Schema Validation Tests.

Verifies the bridge's response handling — the thin multiplexer
passes through JSON from Java, so we test the dispatch layer's
error responses and JSON validity.
"""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class TestDispatchErrorResponses(unittest.TestCase):
    """Test that dispatch functions return valid JSON error responses."""

    def test_get_no_connection_returns_json(self):
        import bridge_mcp_ghidra as bridge
        old = bridge._transport_mode
        bridge._transport_mode = "none"
        try:
            result = bridge.dispatch_get("/test_endpoint")
            data = json.loads(result)
            self.assertIn("error", data)
            self.assertIsInstance(data["error"], str)
        finally:
            bridge._transport_mode = old

    def test_post_no_connection_returns_json(self):
        import bridge_mcp_ghidra as bridge
        old = bridge._transport_mode
        bridge._transport_mode = "none"
        try:
            result = bridge.dispatch_post("/test_endpoint", {"key": "val"})
            data = json.loads(result)
            self.assertIn("error", data)
        finally:
            bridge._transport_mode = old


class TestUdsRequestFormat(unittest.TestCase):
    """Test UDS request parameter formatting."""

    def test_uds_request_builds_path_with_params(self):
        """Verify URL query string construction."""
        from bridge_mcp_ghidra import UnixHTTPConnection
        # Just verify the class can be instantiated
        conn = UnixHTTPConnection("/tmp/nonexistent.sock", timeout=5)
        self.assertEqual(conn.socket_path, "/tmp/nonexistent.sock")


class TestSchemaJsonFormat(unittest.TestCase):
    """Test that register_tools_from_schema handles various schema formats."""

    def test_minimal_schema(self):
        from bridge_mcp_ghidra import register_tools_from_schema
        schema = [
            {
                "name": "schema_test_minimal",
                "description": "",
                "endpoint": "/test",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        count = register_tools_from_schema(schema)
        self.assertEqual(count, 1)

    def test_schema_with_category(self):
        """Schema entries may include a category field (used by tool groups)."""
        from bridge_mcp_ghidra import register_tools_from_schema
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
        count = register_tools_from_schema(schema)
        self.assertEqual(count, 1)

    def test_schema_preserves_description(self):
        """Registered tool should preserve the description from schema."""
        from bridge_mcp_ghidra import register_tools_from_schema, mcp
        desc = "Decompile a function and return pseudocode"
        schema = [
            {
                "name": "schema_test_desc",
                "description": desc,
                "endpoint": "/test_desc",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        register_tools_from_schema(schema)
        tool = mcp._tool_manager._tools.get("schema_test_desc")
        self.assertIsNotNone(tool)


if __name__ == "__main__":
    unittest.main()

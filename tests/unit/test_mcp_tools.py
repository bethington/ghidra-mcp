"""
Unit tests for the MCP bridge dynamic tool system.

Tests the thin multiplexer's core functionality: schema parsing, tool
registration, transport mode management, and static tool contracts against the
``ghidra_mcp_bridge`` package.
"""

import asyncio
import inspect
import json
import re
import unittest
from unittest import mock

from ghidra_mcp_bridge import connection, discovery, registry, tools
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


class TestConnectInstanceRollback(unittest.TestCase):
    """A failed connect must not leave a mismatched transport/tool state.

    On schema-fetch failure the bridge drops the just-activated transport and
    tears down stale dynamic tools, so nothing dispatches against the new
    (broken) instance. reset() preserves _connected_project (now the just-tried
    project) so lazy reconnect targets the right instance.
    """

    def setUp(self):
        # Fully snapshot/restore connection globals -- reset() deliberately
        # preserves _connected_project, which would otherwise leak into other
        # tests (see TestConnectInstanceTcpProject).
        saved = (
            connection._active_socket,
            connection._active_tcp,
            connection._transport_mode,
            connection._connected_project,
        )

        def _restore_conn():
            (
                connection._active_socket,
                connection._active_tcp,
                connection._transport_mode,
                connection._connected_project,
            ) = saved

        self.addCleanup(_restore_conn)
        self.addCleanup(registry.register_tools_from_schema, [])

        # Register a dynamic tool to stand in for a prior session's schema, so
        # we can assert it's cleared on rollback.
        registry.register_tools_from_schema(
            [
                {
                    "name": "stale_probe_tool",
                    "endpoint": "/stale_probe",
                    "http_method": "GET",
                    "input_schema": {"type": "object", "properties": {}},
                }
            ]
        )

    def test_uds_schema_failure_resets_and_clears_tools(self):
        connection.activate_uds("/tmp/sock-old", "OldProject")
        self.assertTrue(registry.dynamic_tool_names())  # precondition

        instances = [{"project": "NewProject", "socket": "/tmp/sock-new", "pid": 42}]
        with mock.patch.object(discovery, "discover_instances", return_value=instances), \
             mock.patch.object(
                 registry,
                 "fetch_and_register_schema",
                 side_effect=RuntimeError("Failed to fetch schema: HTTP 500"),
             ):
            result = json.loads(asyncio.run(tools.connect_instance("NewProject")))

        self.assertIn("error", result)
        # Transport dropped — not stranded half-connected on the new socket.
        self.assertEqual(connection.transport_mode(), "none")
        self.assertIsNone(connection.active_socket())
        # Reconnect targets the project we just tried, not the stale one.
        self.assertEqual(connection.connected_project(), "NewProject")
        # Stale dynamic tools are gone.
        self.assertEqual(registry.dynamic_tool_names(), [])

    def test_tcp_schema_failure_resets_and_clears_tools(self):
        connection.activate_uds("/tmp/sock-old", "OldProject")
        self.assertTrue(registry.dynamic_tool_names())  # precondition

        # No UDS instances -> TCP fallback path; force the env override so we
        # take the deterministic tcp_url branch.
        with mock.patch.object(discovery, "discover_instances", return_value=[]), \
             mock.patch.dict("os.environ", {"GHIDRA_MCP_URL": "http://127.0.0.1:8089"}), \
             mock.patch.object(
                 discovery, "_resolve_tcp_project", return_value="NewProject"
             ), \
             mock.patch.object(
                 registry,
                 "fetch_and_register_schema",
                 side_effect=RuntimeError("boom"),
             ):
            result = json.loads(asyncio.run(tools.connect_instance("NewProject")))

        self.assertIn("error", result)
        self.assertEqual(connection.transport_mode(), "none")
        self.assertIsNone(connection.active_tcp())
        self.assertEqual(connection.connected_project(), "NewProject")
        self.assertEqual(registry.dynamic_tool_names(), [])


class TestRegisterToolsTransactional(unittest.TestCase):
    """register_tools_from_schema must not tear down old tools if it fails early."""

    def tearDown(self):
        registry.register_tools_from_schema([])

    def test_normalize_failure_preserves_existing_tools(self):
        schema = [
            {
                "name": "rollback_probe_tool",
                "endpoint": "/rollback_probe",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        count = registry.register_tools_from_schema(schema)
        self.assertEqual(count, 1)
        before = list(registry.dynamic_tool_names())
        self.assertIn("rollback_probe_tool", before)

        # A normalization failure happens before any teardown, so the previously
        # registered tools must still be live afterward.
        with mock.patch.object(
            registry,
            "_normalize_tool_def_names",
            side_effect=RuntimeError("bad schema"),
        ):
            with self.assertRaises(RuntimeError):
                registry.register_tools_from_schema([{"endpoint": "/whatever"}])

        self.assertEqual(registry.dynamic_tool_names(), before)


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

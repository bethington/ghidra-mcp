"""
Unit tests for MCP bridge dynamic tool system.

Tests the thin multiplexer's core functionality: schema parsing,
tool registration, transport mode management, and static tool contracts.
"""

import asyncio
import json
import os
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class TestTransportModes(unittest.TestCase):
    """Test transport mode state management."""

    def test_initial_state(self):
        """Transport mode should be set after module init (may auto-connect)."""
        import bridge_mcp_ghidra as bridge

        self.assertIn(bridge._transport_mode, ("none", "uds", "tcp"))

    def test_do_request_raises_when_disconnected(self):
        """do_request should raise ConnectionError when no transport active."""
        import bridge_mcp_ghidra as bridge

        old_mode = bridge._transport_mode
        bridge._transport_mode = "none"
        try:
            with self.assertRaises(ConnectionError):
                bridge.do_request("GET", "/test")
        finally:
            bridge._transport_mode = old_mode


class TestStaticTools(unittest.TestCase):
    """Test that static MCP tools are always registered."""

    def test_list_instances_registered(self):
        """list_instances should be available as a static tool."""
        import bridge_mcp_ghidra as bridge

        tools = bridge.mcp._tool_manager._tools
        self.assertIn("list_instances", tools)

    def test_connect_instance_registered(self):
        """connect_instance should be available as a static tool."""
        import bridge_mcp_ghidra as bridge

        tools = bridge.mcp._tool_manager._tools
        self.assertIn("connect_instance", tools)

    def test_list_instances_returns_json(self):
        """list_instances should return valid JSON."""
        from bridge_mcp_ghidra import list_instances

        result = list_instances()
        data = json.loads(result)
        self.assertIn("instances", data)
        self.assertIsInstance(data["instances"], list)


class TestToolGroupManagement(unittest.TestCase):
    """Test tool group management tools."""

    def test_lazy_loading_disabled_by_default(self):
        import bridge_mcp_ghidra as bridge

        self.assertFalse(bridge._lazy_mode)

    def test_list_tool_groups_registered(self):
        import bridge_mcp_ghidra as bridge

        tools = bridge.mcp._tool_manager._tools
        self.assertIn("list_tool_groups", tools)

    def test_load_tool_group_registered(self):
        import bridge_mcp_ghidra as bridge

        tools = bridge.mcp._tool_manager._tools
        self.assertIn("load_tool_group", tools)

    def test_unload_tool_group_registered(self):
        import bridge_mcp_ghidra as bridge

        tools = bridge.mcp._tool_manager._tools
        self.assertIn("unload_tool_group", tools)

    def test_list_tool_groups_returns_json(self):
        from bridge_mcp_ghidra import list_tool_groups

        result = json.loads(list_tool_groups())
        # Either an error (no schema) or a groups list
        self.assertTrue("error" in result or "groups" in result)

    def test_core_groups_defined(self):
        from bridge_mcp_ghidra import CORE_GROUPS

        self.assertIn("listing", CORE_GROUPS)
        self.assertIn("function", CORE_GROUPS)

    def test_unload_core_group_blocked(self):
        import asyncio
        from bridge_mcp_ghidra import unload_tool_group

        result = json.loads(asyncio.run(unload_tool_group("function")))
        self.assertIn("error", result)
        self.assertIn("default", result["error"].lower())

    def test_load_group_with_schema(self):
        """Loading a group after register_tools_from_schema should work."""
        from bridge_mcp_ghidra import (
            register_tools_from_schema,
            _load_group,
            _loaded_groups,
        )

        schema = [
            {
                "name": "grp_test_a",
                "description": "",
                "endpoint": "/a",
                "http_method": "GET",
                "category": "grp_alpha",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "grp_test_b",
                "description": "",
                "endpoint": "/b",
                "http_method": "GET",
                "category": "grp_beta",
                "input_schema": {"type": "object", "properties": {}},
            },
        ]
        register_tools_from_schema(schema, groups={"grp_alpha"})
        self.assertIn("grp_alpha", _loaded_groups)
        self.assertNotIn("grp_beta", _loaded_groups)

        loaded = _load_group("grp_beta")
        self.assertEqual(loaded, ["grp_test_b"])
        self.assertIn("grp_beta", _loaded_groups)


class TestConnectInstance(unittest.TestCase):
    """Test connect_instance eager-loading behavior."""

    def test_connect_instance_eager_loads_all_tools_and_notifies(self):
        import bridge_mcp_ghidra as bridge

        schema = {
            "tools": [
                {
                    "path": "/listing_tool",
                    "method": "GET",
                    "category": "listing",
                    "params": [],
                },
                {
                    "path": "/datatype_tool",
                    "method": "GET",
                    "category": "datatype",
                    "params": [],
                },
            ]
        }

        session = SimpleNamespace(send_tool_list_changed=mock.AsyncMock())
        ctx = SimpleNamespace(
            _request_context=object(),
            request_context=SimpleNamespace(session=session),
        )

        old_lazy_mode = bridge._lazy_mode
        old_active_socket = bridge._active_socket
        old_active_tcp = bridge._active_tcp
        old_transport_mode = bridge._transport_mode
        old_connected_project = bridge._connected_project
        old_dynamic_names = list(bridge._dynamic_tool_names)
        old_full_schema = list(bridge._full_schema)
        old_loaded_groups = set(bridge._loaded_groups)

        try:
            bridge._lazy_mode = False
            with mock.patch.object(
                bridge,
                "discover_instances",
                return_value=[
                    {"project": "TestProject", "socket": "/tmp/test.sock", "pid": 42}
                ],
            ), mock.patch.object(
                bridge,
                "do_request",
                return_value=(json.dumps(schema), 200),
            ):
                result = json.loads(
                    asyncio.run(bridge.connect_instance("TestProject", ctx=ctx))
                )

            self.assertTrue(result["connected"])
            self.assertEqual(result["tools_registered"], 2)
            self.assertEqual(result["tools_total"], 2)
            self.assertEqual(set(result["loaded_groups"]), {"listing", "datatype"})
            self.assertEqual(result["note"], "Loaded all 2 tools on connect.")
            session.send_tool_list_changed.assert_awaited_once()
        finally:
            for name in list(bridge._dynamic_tool_names):
                bridge.mcp._tool_manager._tools.pop(name, None)
            bridge._dynamic_tool_names[:] = old_dynamic_names
            bridge._full_schema[:] = old_full_schema
            bridge._loaded_groups.clear()
            bridge._loaded_groups.update(old_loaded_groups)
            bridge._lazy_mode = old_lazy_mode
            bridge._active_socket = old_active_socket
            bridge._active_tcp = old_active_tcp
            bridge._transport_mode = old_transport_mode
            bridge._connected_project = old_connected_project


class TestEndpointTimeouts(unittest.TestCase):
    """Test endpoint timeout configuration."""

    def test_all_timeouts_positive(self):
        from bridge_mcp_ghidra import ENDPOINT_TIMEOUTS

        for name, timeout in ENDPOINT_TIMEOUTS.items():
            self.assertGreater(timeout, 0, f"Timeout for {name} should be positive")

    def test_script_timeouts_high(self):
        from bridge_mcp_ghidra import ENDPOINT_TIMEOUTS

        self.assertGreaterEqual(ENDPOINT_TIMEOUTS.get("run_ghidra_script", 0), 600)
        self.assertGreaterEqual(ENDPOINT_TIMEOUTS.get("run_script_inline", 0), 600)

    def test_default_exists(self):
        from bridge_mcp_ghidra import ENDPOINT_TIMEOUTS

        self.assertIn("default", ENDPOINT_TIMEOUTS)


class TestSchemaFormat(unittest.TestCase):
    """Test that tool schema format matches expectations."""

    def test_register_with_all_json_types(self):
        """Schema with all JSON types should produce correct Python signatures."""
        from bridge_mcp_ghidra import _build_tool_function
        import inspect

        schema = {
            "properties": {
                "str_param": {"type": "string"},
                "int_param": {"type": "integer"},
                "bool_param": {"type": "boolean"},
                "num_param": {"type": "number"},
            },
            "required": ["str_param"],
        }
        fn = _build_tool_function("/test", "POST", schema)
        sig = inspect.signature(fn)
        self.assertEqual(len(sig.parameters), 5)
        self.assertIn("dry_run", sig.parameters)

    def test_schema_with_descriptions(self):
        """Schema properties with descriptions should not affect function building."""
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {
                "address": {
                    "type": "string",
                    "description": "The function address or name",
                },
            },
            "required": ["address"],
        }
        fn = _build_tool_function("/decompile_function", "GET", schema)
        self.assertTrue(callable(fn))

    def test_parsed_schema_tool_names_match_capi_regex(self):
        """Every parsed MCP-visible tool name should be safe for Copilot/CAPI."""
        from bridge_mcp_ghidra import _parse_schema

        raw = {
            "tools": [
                {"path": "/regular_tool", "method": "GET", "params": []},
                {"path": "/debugger/status", "method": "GET", "params": []},
                {"path": "/server/status", "method": "GET", "params": []},
            ]
        }
        pattern = re.compile(r"^[a-zA-Z0-9_-]+$")
        for tool in _parse_schema(raw):
            self.assertRegex(tool["name"], pattern)


if __name__ == "__main__":
    unittest.main()

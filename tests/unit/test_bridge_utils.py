"""
Unit tests for GhidraMCP bridge utility functions.

These tests run WITHOUT requiring a Ghidra server connection.
They test transport utilities, timeout logic, and discovery functions.
"""

import json
import os
import inspect
import re
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class TestGetSocketDir(unittest.TestCase):
    """Test socket directory resolution."""

    @patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}, clear=False)
    def test_xdg_runtime_dir(self):
        from bridge_mcp_ghidra import get_socket_dir

        result = get_socket_dir()
        self.assertEqual(result, Path("/run/user/1000/ghidra-mcp"))

    def test_tmpdir_fallback(self):
        # Force TMPDIR fallback by:
        #   (a) clearing XDG_RUNTIME_DIR so the function skips the first branch
        #   (b) shadowing os.getuid to return a UID whose /run/user/<uid> won't
        #       exist (CI's ubuntu-latest runner has /run/user/1001 populated,
        #       which would otherwise win before the TMPDIR branch)
        env = {k: v for k, v in os.environ.items() if k != "XDG_RUNTIME_DIR"}
        env["TMPDIR"] = "/custom/tmp"
        env["USER"] = "testuser"
        with patch.dict(os.environ, env, clear=True), patch(
            "os.getuid", return_value=9_999_999, create=True
        ):
            from bridge_mcp_ghidra import get_socket_dir

            result = get_socket_dir()
            self.assertEqual(result, Path("/custom/tmp/ghidra-mcp-testuser"))


class TestIsPidAlive(unittest.TestCase):
    """Test PID liveness check."""

    def test_current_pid_alive(self):
        from bridge_mcp_ghidra import is_pid_alive

        self.assertTrue(is_pid_alive(os.getpid()))

    def test_nonexistent_pid(self):
        from bridge_mcp_ghidra import is_pid_alive

        self.assertFalse(is_pid_alive(4000000))


class TestGetTimeout(unittest.TestCase):
    """Test per-endpoint timeout calculation."""

    def test_default_timeout(self):
        from bridge_mcp_ghidra import get_timeout

        self.assertEqual(get_timeout("/some_unknown_endpoint"), 30)

    def test_decompile_timeout(self):
        from bridge_mcp_ghidra import get_timeout

        self.assertEqual(get_timeout("/decompile_function"), 45)

    def test_script_timeout(self):
        from bridge_mcp_ghidra import get_timeout

        self.assertEqual(get_timeout("/run_ghidra_script"), 1800)

    def test_batch_rename_scaling(self):
        from bridge_mcp_ghidra import get_timeout

        payload = {"variable_renames": {f"var_{i}": f"new_{i}" for i in range(10)}}
        timeout = get_timeout("/rename_variables", payload)
        self.assertGreater(timeout, 120)

    def test_batch_comments_scaling(self):
        from bridge_mcp_ghidra import get_timeout

        payload = {
            "decompiler_comments": [{"addr": "0x1000", "comment": "test"}] * 5,
            "disassembly_comments": [],
        }
        timeout = get_timeout("/batch_set_comments", payload)
        self.assertGreater(timeout, 120)


class TestBuildToolFunction(unittest.TestCase):
    """Test dynamic tool function builder."""

    def test_builds_callable(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {
                "address": {"type": "string"},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["address"],
        }
        fn = _build_tool_function("/decompile_function", "GET", schema)
        self.assertTrue(callable(fn))

    def test_signature_has_correct_params(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {
                "address": {"type": "string"},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["address"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIn("address", sig.parameters)
        self.assertIn("limit", sig.parameters)
        self.assertEqual(sig.parameters["limit"].default, 100)

    def test_required_params_no_default(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertEqual(sig.parameters["name"].default, inspect.Parameter.empty)

    def test_optional_params_default_none(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIsNone(sig.parameters["name"].default)

    def test_type_annotations(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "enabled": {"type": "boolean"},
                "ratio": {"type": "number"},
            },
            "required": ["name", "count", "enabled", "ratio"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        annotations = fn.__annotations__
        self.assertEqual(annotations["name"], str)
        self.assertEqual(annotations["count"], int)
        self.assertEqual(annotations["enabled"], bool)
        self.assertEqual(annotations["ratio"], float)

    def test_empty_schema(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {"type": "object", "properties": {}}
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertEqual(len(sig.parameters), 0)

    def test_post_query_params_are_not_sent_in_body(self):
        from bridge_mcp_ghidra import _build_tool_function

        schema = {
            "properties": {
                "function_address": {
                    "type": "string",
                    "source": "body",
                    "param_type": "address",
                },
                "prototype": {"type": "string", "source": "body"},
                "program": {"type": "string", "source": "query", "default": ""},
            },
            "required": ["function_address", "prototype"],
        }
        fn = _build_tool_function("/set_function_prototype", "POST", schema)

        with patch("bridge_mcp_ghidra.dispatch_post") as mock_dispatch_post:
            mock_dispatch_post.return_value = "ok"
            result = fn(
                function_address="6FA26FD0",
                prototype="undefined4 __fastcall FUN_6fa26fd0(int param_1, uint param_2)",
                program="/Vanilla/1.13d/D2MCPClient.dll",
            )

        self.assertEqual(result, "ok")
        mock_dispatch_post.assert_called_once_with(
            "/set_function_prototype",
            data={
                "function_address": "0x6fa26fd0",
                "prototype": "undefined4 __fastcall FUN_6fa26fd0(int param_1, uint param_2)",
            },
            query_params={"program": "/Vanilla/1.13d/D2MCPClient.dll"},
        )


class TestToolNameSanitization(unittest.TestCase):
    """Test MCP tool name normalization for strict clients."""

    def test_sanitize_tool_name_replaces_invalid_separators(self):
        from bridge_mcp_ghidra import sanitize_tool_name

        self.assertEqual(sanitize_tool_name("/Debugger.Status "), "debugger_status")
        self.assertEqual(sanitize_tool_name("server/status"), "server_status")
        self.assertEqual(sanitize_tool_name("A::B...C"), "a_b_c")

    def test_sanitize_tool_name_truncates_to_claude_limit(self):
        from bridge_mcp_ghidra import MAX_TOOL_NAME_LENGTH, sanitize_tool_name

        raw = "/" + ("VeryLongToolNameSegment_" * 6)
        sanitized = sanitize_tool_name(raw)

        self.assertLessEqual(len(sanitized), MAX_TOOL_NAME_LENGTH)
        self.assertRegex(sanitized, r"^[a-zA-Z0-9_-]{1,64}$")

    def test_sanitize_tool_name_rejects_empty_names(self):
        from bridge_mcp_ghidra import sanitize_tool_name

        with self.assertRaises(ValueError):
            sanitize_tool_name("///")

    def test_parse_schema_normalizes_nested_endpoint_paths(self):
        from bridge_mcp_ghidra import _parse_schema

        schema = _parse_schema(
            {
                "tools": [
                    {
                        "path": "/server/status",
                        "method": "GET",
                        "params": [],
                    }
                ]
            }
        )
        self.assertEqual(schema[0]["name"], "server_status")
        self.assertEqual(schema[0]["endpoint"], "/server/status")

    def test_parse_schema_suffixes_static_name_collisions(self):
        from bridge_mcp_ghidra import _parse_schema

        schema = _parse_schema(
            {
                "tools": [
                    {
                        "path": "/debugger/status",
                        "method": "GET",
                        "params": [],
                    }
                ]
            }
        )
        self.assertEqual(schema[0]["name"], "debugger_status_2")
        self.assertEqual(schema[0]["sanitized_name"], "debugger_status")
        self.assertTrue(schema[0]["name_collided"])

    def test_parse_schema_suffixes_dynamic_name_collisions(self):
        from bridge_mcp_ghidra import _parse_schema

        schema = _parse_schema(
            {
                "tools": [
                    {"path": "/foo.bar", "method": "GET", "params": []},
                    {"path": "/foo/bar", "method": "GET", "params": []},
                ]
            }
        )
        self.assertEqual([tool["name"] for tool in schema], ["foo_bar", "foo_bar_2"])

    def test_parse_schema_suffixes_truncated_name_collisions_within_limit(self):
        from bridge_mcp_ghidra import MAX_TOOL_NAME_LENGTH, _parse_schema

        raw = "/" + ("LongEndpointSegment_" * 5)
        schema = _parse_schema(
            {
                "tools": [
                    {"path": raw, "method": "GET", "params": []},
                    {"path": raw + "/v2", "method": "GET", "params": []},
                ]
            }
        )

        self.assertLessEqual(len(schema[0]["name"]), MAX_TOOL_NAME_LENGTH)
        self.assertLessEqual(len(schema[1]["name"]), MAX_TOOL_NAME_LENGTH)
        self.assertNotEqual(schema[0]["name"], schema[1]["name"])
        self.assertRegex(schema[0]["name"], r"^[a-zA-Z0-9_-]{1,64}$")
        self.assertRegex(schema[1]["name"], r"^[a-zA-Z0-9_-]{1,64}$")

    def test_active_registry_tool_names_are_valid(self):
        import bridge_mcp_ghidra as bridge

        pattern = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
        invalid = [
            name
            for name in bridge.mcp._tool_manager._tools
            if not pattern.fullmatch(name)
        ]
        self.assertEqual(invalid, [])

    def test_registered_dynamic_tool_names_are_valid(self):
        import bridge_mcp_ghidra as bridge

        schema = bridge._parse_schema(
            {
                "tools": [
                    {"path": "/server/status", "method": "GET", "params": []},
                    {"path": "/debugger/status", "method": "GET", "params": []},
                    {"path": "/foo.bar", "method": "GET", "params": []},
                    {"path": "/foo/bar", "method": "GET", "params": []},
                ]
            }
        )

        bridge.register_tools_from_schema(schema, groups=None)
        pattern = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
        try:
            invalid = [
                name
                for name in bridge.mcp._tool_manager._tools
                if not pattern.fullmatch(name)
            ]
            self.assertEqual(invalid, [])
            self.assertIn("server_status", bridge.mcp._tool_manager._tools)
            self.assertIn("debugger_status_2", bridge.mcp._tool_manager._tools)
            self.assertIn("foo_bar", bridge.mcp._tool_manager._tools)
            self.assertIn("foo_bar_2", bridge.mcp._tool_manager._tools)
        finally:
            bridge.register_tools_from_schema([], groups=None)


class TestRegisterToolsFromSchema(unittest.TestCase):
    """Test dynamic tool registration from schema."""

    def test_registers_tools(self):
        from bridge_mcp_ghidra import register_tools_from_schema, _dynamic_tool_names

        schema = [
            {
                "name": "test_tool_reg_1",
                "description": "A test tool",
                "endpoint": "/test1",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "test_tool_reg_2",
                "description": "Another test tool",
                "endpoint": "/test2",
                "http_method": "POST",
                "input_schema": {
                    "type": "object",
                    "properties": {"data": {"type": "string"}},
                    "required": ["data"],
                },
            },
        ]
        count = register_tools_from_schema(schema)
        self.assertEqual(count, 2)
        self.assertIn("test_tool_reg_1", _dynamic_tool_names)
        self.assertIn("test_tool_reg_2", _dynamic_tool_names)

    def test_clears_previous_tools(self):
        from bridge_mcp_ghidra import register_tools_from_schema, _dynamic_tool_names

        schema1 = [
            {
                "name": "old_tool_clear",
                "description": "",
                "endpoint": "/old",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        schema2 = [
            {
                "name": "new_tool_clear",
                "description": "",
                "endpoint": "/new",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
        register_tools_from_schema(schema1)
        self.assertIn("old_tool_clear", _dynamic_tool_names)
        register_tools_from_schema(schema2)
        self.assertNotIn("old_tool_clear", _dynamic_tool_names)
        self.assertIn("new_tool_clear", _dynamic_tool_names)


class TestDispatchErrors(unittest.TestCase):
    """Test dispatch functions when no instance connected."""

    def test_dispatch_get_no_connection(self):
        import bridge_mcp_ghidra as bridge

        old = bridge._transport_mode
        bridge._transport_mode = "none"
        try:
            result = bridge.dispatch_get("/test")
            data = json.loads(result)
            self.assertIn("error", data)
            self.assertIn("connect_instance", data["error"])
        finally:
            bridge._transport_mode = old

    def test_dispatch_post_no_connection(self):
        import bridge_mcp_ghidra as bridge

        old = bridge._transport_mode
        bridge._transport_mode = "none"
        try:
            result = bridge.dispatch_post("/test", {"key": "value"})
            data = json.loads(result)
            self.assertIn("error", data)
        finally:
            bridge._transport_mode = old


class TestUnixHTTPConnection(unittest.TestCase):
    """Test UnixHTTPConnection class."""

    def test_sets_socket_path(self):
        from bridge_mcp_ghidra import UnixHTTPConnection

        conn = UnixHTTPConnection("/tmp/test.sock", timeout=10)
        self.assertEqual(conn.socket_path, "/tmp/test.sock")
        self.assertEqual(conn.timeout, 10)


if __name__ == "__main__":
    unittest.main()

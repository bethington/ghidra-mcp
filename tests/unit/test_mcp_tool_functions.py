"""
Unit tests for MCP dynamic tool function generation.

Tests _build_tool_function behavior for various schema patterns,
verifying that dynamically generated functions correctly dispatch
GET/POST requests with proper parameter handling.
"""

import json
import inspect
import os
import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


def setUpModule():
    """Force strict mode off for tests that don't manage it explicitly.

    The bridge reads GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS at import (via
    bridge_mcp_ghidra.state._init_require_selectors()). If the variable happens
    to be set in the surrounding shell or CI, that import would flip
    state._require_selectors=True and leak into tests that assume the default
    off state (i.e. every test outside TestProgramRequired). Clamp the module
    state here so the suite is deterministic regardless of the environment;
    TestProgramRequired manages its own state via setUp/tearDown.
    """
    import bridge_mcp_ghidra
    bridge_mcp_ghidra.state._require_selectors = False


class TestGetToolDispatch(unittest.TestCase):
    """Test that GET tool functions dispatch correctly."""

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
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

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
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

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_get_with_no_params(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        mock_get.return_value = '{"version": "4.2.0"}'

        schema = {"properties": {}, "required": []}
        fn = _build_tool_function("/get_version", "GET", schema)
        result = fn()

        mock_get.assert_called_once_with("/get_version", params=None)


class TestPostToolDispatch(unittest.TestCase):
    """Test that POST tool functions dispatch correctly."""

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
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

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
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

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
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

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_post_synthetic_dry_run_only_for_true_values(self, mock_post):
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

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_schema_declared_query_dry_run_does_not_duplicate_signature(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function
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
        fn = _build_tool_function("/archive_ingest_program", "POST", schema)
        sig = inspect.signature(fn)

        self.assertEqual(list(sig.parameters).count("dry_run"), 1)

        fn(program="pwahelper.exe", dry_run="false")
        mock_post.assert_called_once_with(
            "/archive_ingest_program",
            data={},
            query_params={"program": "pwahelper.exe", "dry_run": "false"},
        )

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_schema_declared_body_dry_run_uses_body_source(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function
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
        fn = _build_tool_function("/merge_program_documentation", "POST", schema)
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

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
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


class TestProgramRequired(unittest.TestCase):
    """GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS: refuse calls missing a program selector."""

    def setUp(self):
        import bridge_mcp_ghidra as bridge
        self.bridge = bridge
        self._saved = bridge.state._require_selectors

    def tearDown(self):
        self.bridge.state._require_selectors = self._saved

    _OPTIONAL_PROGRAM_TOOL = {
        "properties": {
            "address": {"type": "string"},
            "program": {"type": "string", "source": "query"},
        },
        "required": ["address"],
    }

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_get_refuses_when_program_omitted(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/decompile_function", "GET", self._OPTIONAL_PROGRAM_TOOL)
        result = fn(address="0x401000")

        mock_get.assert_not_called()
        data = json.loads(result)
        self.assertIn("error", data)
        self.assertIn("program=", data["error"])
        self.assertIn("GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS", data["error"])

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_get_allows_explicit_program(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        mock_get.return_value = "{}"
        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/decompile_function", "GET", self._OPTIONAL_PROGRAM_TOOL)
        fn(address="0x401000", program="game.exe")

        mock_get.assert_called_once_with(
            "/decompile_function",
            params={"address": "0x401000", "program": "game.exe"},
        )

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_pass_through_when_strict_mode_disabled(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        mock_get.return_value = "{}"
        self.bridge.state._require_selectors = False

        fn = _build_tool_function("/decompile_function", "GET", self._OPTIONAL_PROGRAM_TOOL)
        fn(address="0x401000")

        mock_get.assert_called_once_with(
            "/decompile_function", params={"address": "0x401000"}
        )

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_no_refusal_for_tools_without_program_param(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        mock_get.return_value = "{}"
        self.bridge.state._require_selectors = True

        # Some tools have no program= selector at all.
        schema = {"properties": {"address": {"type": "string"}}, "required": ["address"]}
        fn = _build_tool_function("/some_tool", "GET", schema)
        fn(address="0x401000")

        mock_get.assert_called_once_with("/some_tool", params={"address": "0x401000"})

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_empty_program_counts_as_omitted(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        self.bridge.state._require_selectors = True

        # An empty string is filtered upstream of the strict check, so the
        # check should treat it as a missing program=.
        fn = _build_tool_function("/decompile_function", "GET", self._OPTIONAL_PROGRAM_TOOL)
        result = fn(address="0x401000", program="")

        mock_get.assert_not_called()
        self.assertIn("error", json.loads(result))

    # Cross-program tools (diff_functions, bulk_fuzzy_match,
    # find_similar_functions_fuzzy) take source_program/target_program or
    # program_a/program_b. These are schema-required, yet the server falls back
    # to the current program when one arrives empty (getProgramOrError), so
    # strict mode enforces them regardless of the required flag. The tests pass
    # empty strings to mirror that path: the bridge filter drops "" so the
    # selector is absent in `filtered` and the call is refused.

    _FUZZY_SCHEMA = {
        "properties": {
            "address": {"type": "string"},
            "source_program": {"type": "string", "source": "query"},
            "target_program": {"type": "string", "source": "query"},
        },
        "required": ["address", "source_program", "target_program"],
    }
    _DIFF_SCHEMA = {
        "properties": {
            "address_a": {"type": "string"},
            "address_b": {"type": "string"},
            "program_a": {"type": "string", "source": "query"},
            "program_b": {"type": "string", "source": "query"},
        },
        "required": ["address_a", "address_b", "program_a", "program_b"],
    }

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_multi_program_refuses_when_both_selectors_empty(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/bulk_fuzzy_match", "GET", self._FUZZY_SCHEMA)
        result = fn(address="0x401000", source_program="", target_program="")

        mock_get.assert_not_called()
        data = json.loads(result)
        self.assertIn("source_program=", data["error"])
        self.assertIn("target_program=", data["error"])

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_multi_program_refuses_when_one_selector_empty(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/bulk_fuzzy_match", "GET", self._FUZZY_SCHEMA)
        result = fn(address="0x401000", source_program="game.exe", target_program="")

        mock_get.assert_not_called()
        data = json.loads(result)
        # Only the missing one is named.
        self.assertIn("target_program=", data["error"])
        self.assertNotIn("source_program=", data["error"])

    @patch("bridge_mcp_ghidra.dispatch.dispatch_get")
    def test_multi_program_allows_when_all_present(self, mock_get):
        from bridge_mcp_ghidra import _build_tool_function
        mock_get.return_value = "{}"
        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/bulk_fuzzy_match", "GET", self._FUZZY_SCHEMA)
        fn(address="0x401000", source_program="game.exe", target_program="test.dll")

        mock_get.assert_called_once_with(
            "/bulk_fuzzy_match",
            params={
                "address": "0x401000",
                "source_program": "game.exe",
                "target_program": "test.dll",
            },
        )

    @patch("bridge_mcp_ghidra.dispatch.dispatch_post")
    def test_program_a_b_pattern_enforced(self, mock_post):
        from bridge_mcp_ghidra import _build_tool_function
        self.bridge.state._require_selectors = True

        fn = _build_tool_function("/diff_functions", "POST", self._DIFF_SCHEMA)
        result = fn(address_a="0x401000", address_b="0x402000", program_a="", program_b="")

        mock_post.assert_not_called()
        data = json.loads(result)
        self.assertIn("program_a=", data["error"])
        self.assertIn("program_b=", data["error"])

    def test_init_value_1_enables_strict_mode(self):
        for val in ("1", " 1 "):  # only "1" (surrounding whitespace tolerated)
            self.bridge.state._require_selectors = False
            with patch.dict("os.environ", {"GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS": val}):
                # assertLogs captures the enable-time INFO line (keeping it out
                # of test output) and doubles as an assertion that it fires.
                with self.assertLogs("bridge_mcp_ghidra", level="INFO"):
                    self.bridge.state._init_require_selectors()
            self.assertTrue(
                self.bridge.state._require_selectors, f"{val!r} should enable strict mode"
            )

    def test_init_non_1_values_leave_strict_mode_off(self):
        # Only "1" enables; other spellings (true/yes/on) and falsy values don't.
        for val in ("true", "yes", "on", "TRUE", "0", "2", "", "anything"):
            self.bridge.state._require_selectors = True
            with patch.dict("os.environ", {"GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS": val}):
                self.bridge.state._init_require_selectors()
            self.assertFalse(
                self.bridge.state._require_selectors, f"{val!r} should not enable strict mode"
            )

    def test_init_unset_env_leaves_strict_mode_off(self):
        self.bridge.state._require_selectors = True
        env = {k: v for k, v in os.environ.items() if k != "GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS"}
        with patch.dict("os.environ", env, clear=True):
            self.bridge.state._init_require_selectors()
        self.assertFalse(self.bridge.state._require_selectors)


if __name__ == "__main__":
    unittest.main()

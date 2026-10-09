"""
Unit tests for MCP bridge dynamic tool system.

Tests the thin multiplexer's core functionality: schema parsing,
tool registration, transport mode management, and static tool contracts.
"""

import asyncio
import json
import os
import re
import time
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

        self.assertIn(bridge.state._transport_mode, ("none", "uds", "tcp"))

    def test_do_request_raises_when_disconnected(self):
        """do_request should raise ConnectionError when no transport active."""
        import bridge_mcp_ghidra as bridge

        old_mode = bridge.state._transport_mode
        bridge.state._transport_mode = "none"
        try:
            with self.assertRaises(ConnectionError):
                bridge.do_request("GET", "/test")
        finally:
            bridge.state._transport_mode = old_mode


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

    def test_lazy_loading_enabled_by_default(self):
        # See state._lazy_mode (#440). Eager loading put every endpoint in a
        # single tools/list, over Gemini's function-declaration limit.
        import bridge_mcp_ghidra as bridge

        self.assertTrue(bridge.state._lazy_mode)

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

    def test_load_group_skips_bad_tool_and_continues(self):
        """Lazy group loading should not abort on one malformed tool."""
        import bridge_mcp_ghidra as bridge

        schema = [
            {
                "name": "issue_212_already_loaded",
                "description": "",
                "endpoint": "/issue_212_already_loaded",
                "http_method": "GET",
                "category": "grp_alpha",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "issue_212_lazy_bad_signature",
                "description": "",
                "endpoint": "/issue_212_lazy_bad_signature",
                "http_method": "GET",
                "category": "grp_beta",
                "input_schema": {
                    "type": "object",
                    "properties": {"bad-param": {"type": "string"}},
                },
            },
            {
                "name": "issue_212_lazy_valid_after",
                "description": "",
                "endpoint": "/issue_212_lazy_valid_after",
                "http_method": "GET",
                "category": "grp_beta",
                "input_schema": {"type": "object", "properties": {}},
            },
        ]

        try:
            bridge.register_tools_from_schema(schema, groups={"grp_alpha"})
            with mock.patch("sys.stderr") as mock_stderr:
                loaded = bridge._load_group("grp_beta")

            self.assertEqual(loaded, ["issue_212_lazy_valid_after"])
            self.assertIn("grp_beta", bridge.state._loaded_groups)
            self.assertIn("issue_212_lazy_valid_after", bridge.state._dynamic_tool_names)
            self.assertNotIn("issue_212_lazy_bad_signature", bridge.state._dynamic_tool_names)
            message = mock_stderr.write.call_args.args[0]
            self.assertIn("1 tool(s) failed to register", message)
            self.assertIn("issue_212_lazy_bad_signature", message)
            self.assertIn("bad-param", message)
        finally:
            bridge.register_tools_from_schema([])


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

        old_lazy_mode = bridge.state._lazy_mode
        old_active_socket = bridge.state._active_socket
        old_active_tcp = bridge.state._active_tcp
        old_transport_mode = bridge.state._transport_mode
        old_connected_project = bridge.state._connected_project
        old_dynamic_names = list(bridge.state._dynamic_tool_names)
        old_full_schema = list(bridge.state._full_schema)
        old_loaded_groups = set(bridge.state._loaded_groups)

        try:
            bridge.state._lazy_mode = False
            with (
                mock.patch.object(
                    bridge.discovery,
                    "discover_instances",
                    return_value=[{"project": "TestProject", "socket": "/tmp/test.sock", "pid": 42}],
                ),
                mock.patch.object(
                    bridge.transport,
                    "do_request",
                    return_value=(json.dumps(schema), 200),
                ),
            ):
                result = json.loads(asyncio.run(bridge.connect_instance("TestProject", ctx=ctx)))

            self.assertTrue(result["connected"])
            self.assertEqual(result["tools_registered"], 2)
            self.assertEqual(result["tools_total"], 2)
            self.assertEqual(set(result["loaded_groups"]), {"listing", "datatype"})
            self.assertEqual(result["note"], "Loaded all 2 tools on connect.")
            session.send_tool_list_changed.assert_awaited_once()
        finally:
            for name in list(bridge.state._dynamic_tool_names):
                bridge.mcp._tool_manager._tools.pop(name, None)
            bridge.state._dynamic_tool_names[:] = old_dynamic_names
            bridge.state._full_schema[:] = old_full_schema
            bridge.state._loaded_groups.clear()
            bridge.state._loaded_groups.update(old_loaded_groups)
            bridge.state._lazy_mode = old_lazy_mode
            bridge.state._active_socket = old_active_socket
            bridge.state._active_tcp = old_active_tcp
            bridge.state._transport_mode = old_transport_mode
            bridge.state._connected_project = old_connected_project


class TestToolsChangedFanout(unittest.TestCase):
    def test_worker_notification_fans_out_to_all_sessions(self):
        import bridge_mcp_ghidra as bridge

        session1 = SimpleNamespace(send_tool_list_changed=mock.AsyncMock())
        session2 = SimpleNamespace(send_tool_list_changed=mock.AsyncMock())

        async def scenario():
            ctx1 = SimpleNamespace(
                _request_context=object(),
                request_context=SimpleNamespace(session=session1),
            )
            ctx2 = SimpleNamespace(
                _request_context=object(),
                request_context=SimpleNamespace(session=session2),
            )
            bridge.state.remember_tools_changed_context(ctx1)
            bridge.state.remember_tools_changed_context(ctx2)
            bridge.state.notify_tools_changed_from_worker()
            await asyncio.sleep(0)

        old_targets = list(bridge.state._tools_changed_targets)
        try:
            bridge.state._tools_changed_targets.clear()
            asyncio.run(scenario())
        finally:
            bridge.state._tools_changed_targets[:] = old_targets

        session1.send_tool_list_changed.assert_awaited_once()
        session2.send_tool_list_changed.assert_awaited_once()


class TestToolsListCapturesSession(unittest.TestCase):
    """tools/list must register the notification target.

    Registration used to happen only inside connect_instance/load_tool_group/
    unload_tool_group/import_file. That made the background auto-connect retry
    (which exists for a bridge started BEFORE Ghidra) notify an EMPTY target
    list: the client is never told the other ~238 tools arrived, so the whole
    session shows 35 of 273 tools while Ghidra is healthy. Every MCP client
    lists tools right after initialize, so capturing there is what guarantees a
    target exists before the retry can win.
    """

    @staticmethod
    def _run_list_tools(session):
        import bridge_mcp_ghidra as bridge
        from mcp.server.lowlevel import server as lowlevel

        async def scenario():
            token = lowlevel.request_ctx.set(SimpleNamespace(session=session))
            try:
                return await bridge.mcp.list_tools()
            finally:
                lowlevel.request_ctx.reset(token)

        return asyncio.run(scenario())

    def test_tools_list_registers_notification_target(self):
        import bridge_mcp_ghidra as bridge

        session = SimpleNamespace(send_tool_list_changed=mock.AsyncMock())
        old_targets = list(bridge.state._tools_changed_targets)
        try:
            bridge.state._tools_changed_targets.clear()
            tools = self._run_list_tools(session)
            self.assertTrue(tools, "tools/list must still return the tool list")
            self.assertEqual(len(bridge.state._tools_changed_targets), 1)
            self.assertIs(bridge.state._tools_changed_targets[0][1], session)
        finally:
            bridge.state._tools_changed_targets[:] = old_targets

    def test_late_registration_notifies_a_client_that_only_listed_tools(self):
        """The end-to-end shape of the bug: list tools, then register late."""
        import bridge_mcp_ghidra as bridge
        from mcp.server.lowlevel import server as lowlevel

        session = SimpleNamespace(send_tool_list_changed=mock.AsyncMock())

        async def scenario():
            token = lowlevel.request_ctx.set(SimpleNamespace(session=session))
            try:
                await bridge.mcp.list_tools()
            finally:
                lowlevel.request_ctx.reset(token)
            # Ghidra arrives later; the retry thread notifies from a worker.
            await asyncio.get_running_loop().run_in_executor(
                None, bridge.state.notify_tools_changed_from_worker
            )
            await asyncio.sleep(0)

        old_targets = list(bridge.state._tools_changed_targets)
        try:
            bridge.state._tools_changed_targets.clear()
            asyncio.run(scenario())
        finally:
            bridge.state._tools_changed_targets[:] = old_targets

        session.send_tool_list_changed.assert_awaited_once()

    def test_tools_list_without_request_context_still_works(self):
        """A direct call (no active request) must not raise."""
        import bridge_mcp_ghidra as bridge

        old_targets = list(bridge.state._tools_changed_targets)
        try:
            bridge.state._tools_changed_targets.clear()
            tools = asyncio.run(bridge.mcp.list_tools())
            self.assertTrue(tools)
            self.assertEqual(bridge.state._tools_changed_targets, [])
        finally:
            bridge.state._tools_changed_targets[:] = old_targets

    def test_lowlevel_handler_uses_the_capturing_wrapper(self):
        """Patching only FastMCP.list_tools would miss the real request path."""
        import bridge_mcp_ghidra as bridge
        import mcp.types as types
        from mcp.server.lowlevel import server as lowlevel

        session = SimpleNamespace(send_tool_list_changed=mock.AsyncMock())
        handler = bridge.mcp._mcp_server.request_handlers[types.ListToolsRequest]

        async def scenario():
            token = lowlevel.request_ctx.set(SimpleNamespace(session=session))
            try:
                return await handler(types.ListToolsRequest(method="tools/list"))
            finally:
                lowlevel.request_ctx.reset(token)

        old_targets = list(bridge.state._tools_changed_targets)
        try:
            bridge.state._tools_changed_targets.clear()
            result = asyncio.run(scenario())
            self.assertTrue(result.root.tools)
            self.assertEqual(len(bridge.state._tools_changed_targets), 1)
        finally:
            bridge.state._tools_changed_targets[:] = old_targets


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
                # `program` also makes the endpoint eligible for the synthetic
                # dry_run -- the server can only roll back a scoped write.
                "program": {"type": "string", "source": "query"},
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
        fn = _build_tool_function("/get_functions", "GET", schema)
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


class TestToolAccessAnnotations(unittest.TestCase):
    """readOnlyHint/destructiveHint carried from the server's `access` value.

    These are not decoration. Claude Code derives a tool's read-only-ness
    solely from readOnlyHint (absent ⇒ false) and, in plan mode, forces a
    permission prompt for every MCP tool that is not read-only — one an
    allow-rule cannot suppress. The same flag gates parallel execution.
    """

    def _parsed(self, tool):
        from bridge_mcp_ghidra import _parse_schema

        return _parse_schema({"tools": [tool]})[0]

    def test_read_only_flags_survive_parsing(self):
        parsed = self._parsed(
            {"path": "/find_functions", "method": "GET", "params": [],
             "read_only": True, "destructive": False}
        )
        self.assertTrue(parsed["read_only"])
        self.assertFalse(parsed["destructive"])

    def test_unclassified_tool_carries_no_flags(self):
        parsed = self._parsed({"path": "/mystery", "method": "GET", "params": []})
        self.assertNotIn("read_only", parsed)
        self.assertNotIn("destructive", parsed)

    def test_annotations_map_from_flags(self):
        from bridge_mcp_ghidra.registry import _tool_annotations

        ro = _tool_annotations({"read_only": True, "destructive": False})
        self.assertTrue(ro.readOnlyHint)
        self.assertFalse(ro.destructiveHint)

        write = _tool_annotations({"read_only": False, "destructive": False})
        self.assertFalse(write.readOnlyHint)
        self.assertFalse(write.destructiveHint)

        destructive = _tool_annotations({"read_only": False, "destructive": True})
        self.assertFalse(destructive.readOnlyHint)
        self.assertTrue(destructive.destructiveHint)

    def test_unclassified_tool_gets_no_annotations(self):
        """Guessing read-only from the HTTP method is what this avoids: several
        GET endpoints mutate (/switch_program, /save_program, /open_program,
        /save_all_programs), and one of those running unprompted mid-plan is the
        failure mode. No classification ⇒ no hint ⇒ client's own default."""
        from bridge_mcp_ghidra.registry import _tool_annotations

        self.assertIsNone(_tool_annotations({"http_method": "GET"}))

    def test_registered_tool_exposes_its_annotations(self):
        from bridge_mcp_ghidra import state
        from bridge_mcp_ghidra.registry import _register_tool_def
        from bridge_mcp_ghidra.server import mcp

        name = "annotation_probe_tool"
        try:
            self.assertTrue(
                _register_tool_def({
                    "name": name,
                    "endpoint": "/annotation_probe",
                    "http_method": "GET",
                    "description": "probe",
                    "input_schema": {"type": "object", "properties": {}},
                    "read_only": True,
                    "destructive": False,
                })
            )
            tool = mcp._tool_manager._tools[name]
            self.assertTrue(tool.annotations.readOnlyHint)
        finally:
            mcp._tool_manager._tools.pop(name, None)
            if name in state._dynamic_tool_names:
                state._dynamic_tool_names.remove(name)


class TestFailureDetection(unittest.TestCase):
    """A failed call must not look like a successful one.

    Every failure — transport, non-200, "not connected", a refused write —
    arrives as an ordinary 200 body, so without this the tool result carried
    isError=False and a client branching on it saw every call succeed.
    """

    def _msg(self, text):
        from bridge_mcp_ghidra.dispatch import failure_message

        return failure_message(text)

    def test_err_envelope_is_a_failure(self):
        self.assertEqual(self._msg('{"error": "No function at 0xdead"}'), "No function at 0xdead")

    def test_bridge_transport_failure_is_a_failure(self):
        self.assertEqual(
            self._msg('{"error": "No Ghidra instance connected. Use connect_instance() first."}'),
            "No Ghidra instance connected. Use connect_instance() first.",
        )

    def test_success_false_payload_is_a_failure(self):
        # /open_program reports this way through Response.ok.
        msg = self._msg('{"success": false, "error": "not checked out", "diagnostics": {}}')
        self.assertEqual(msg, "not checked out")

    def test_rejected_status_is_a_failure(self):
        # A plate comment refused by the naming conventions, also via Response.ok.
        msg = self._msg('{"status": "rejected", "error": "first line too short"}')
        self.assertEqual(msg, "first line too short")

    def test_a_rejection_reports_its_reason_not_just_its_code(self):
        """Found live: rename_symbol's rejection reached the caller as a bare
        "name_quality", its message and suggestion dropped."""
        msg = self._msg('{"status": "rejected", "error": "name_quality", '
                        '"issue": "missing_g_prefix", '
                        '"message": "Global \'x\' must start with \'g_\'.", '
                        '"suggestion": "Prepend g_."}')
        self.assertEqual(msg, "name_quality — Global 'x' must start with 'g_'. — Prepend g_.")

    def test_a_failed_script_reports_its_reason(self):
        """Found live: run_script_inline failed with an NPE and the agent saw only
        "the server reported failure", then guessed the cause and gave up."""
        body = ('{"success": false, "error": "NullPointerException: Cannot invoke '
                '\\"Project.getProjectData()\\" (SyncLabels2.java:15)", "console_output": "..."}')
        self.assertIn("SyncLabels2.java:15", self._msg(body))

    def test_without_a_reason_field_the_end_of_the_output_is_quoted(self):
        output = "x" * 5000 + "\nError: NullPointerException: getProject() is null"
        msg = self._msg(json.dumps({"success": False, "console_output": output}))
        self.assertIn("NullPointerException: getProject() is null", msg)
        self.assertLess(len(msg), 2000)

    def test_successful_payloads_are_not_failures(self):
        for body in (
            '{"status": "success", "message": "renamed"}',
            '{"functions": ["a", "b"]}',
            '{"error": ""}',            # present but empty
            '{"error": null}',
            "[]",
            '["a", "b"]',
            "plain text, not JSON",
            "",
        ):
            self.assertIsNone(self._msg(body), body)

    def test_per_item_error_is_not_a_call_failure(self):
        """/get_bulk_xrefs reports "No instruction at address" per entry; the
        call itself succeeded and must not be marked isError."""
        body = '{"results": [{"address": "0x1", "error": "No instruction at address"}]}'
        self.assertIsNone(self._msg(body))

    def test_raise_on_failure_passes_success_through(self):
        from bridge_mcp_ghidra.dispatch import raise_on_failure

        body = '{"status": "success"}'
        self.assertEqual(raise_on_failure(body), body)

    def test_dynamic_tool_call_raises_so_fastmcp_sets_is_error(self):
        from mcp.server.fastmcp.exceptions import ToolError

        from bridge_mcp_ghidra import dispatch, state
        from bridge_mcp_ghidra.registry import _register_tool_def
        from bridge_mcp_ghidra.server import mcp

        name = "failing_probe_tool"
        try:
            _register_tool_def({
                "name": name,
                "endpoint": "/failing_probe",
                "http_method": "GET",
                "description": "probe",
                "input_schema": {"type": "object", "properties": {}},
                "read_only": True,
                "destructive": False,
            })
            with mock.patch.object(
                dispatch, "dispatch_get", return_value='{"error": "No function at 0xdead"}'
            ):
                with self.assertRaises(ToolError) as caught:
                    asyncio.run(mcp._tool_manager.call_tool(name, {}))
            self.assertIn("No function at 0xdead", str(caught.exception))
        finally:
            mcp._tool_manager._tools.pop(name, None)
            if name in state._dynamic_tool_names:
                state._dynamic_tool_names.remove(name)

    def test_dynamic_tool_call_returns_a_successful_body_unchanged(self):
        from bridge_mcp_ghidra import dispatch, state
        from bridge_mcp_ghidra.registry import _register_tool_def
        from bridge_mcp_ghidra.server import mcp

        name = "passing_probe_tool"
        body = '{"functions": ["main"]}'
        try:
            _register_tool_def({
                "name": name,
                "endpoint": "/passing_probe",
                "http_method": "GET",
                "description": "probe",
                "input_schema": {"type": "object", "properties": {}},
                "read_only": True,
                "destructive": False,
            })
            with mock.patch.object(dispatch, "dispatch_get", return_value=body):
                self.assertEqual(asyncio.run(mcp._tool_manager.call_tool(name, {})), body)
        finally:
            mcp._tool_manager._tools.pop(name, None)
            if name in state._dynamic_tool_names:
                state._dynamic_tool_names.remove(name)


class TestToolListPagination(unittest.TestCase):
    """Opt-in `tools/list` paging.

    Off by default on purpose: paging is optional in the spec and a client that
    ignores nextCursor would see only the first page of ~250 tools.
    """

    def setUp(self):
        from mcp import types

        from bridge_mcp_ghidra.server import mcp

        self._types = types
        self._saved = mcp._mcp_server.request_handlers.get(types.ListToolsRequest)
        self._registered = []

    def tearDown(self):
        from bridge_mcp_ghidra import state
        from bridge_mcp_ghidra.server import mcp

        if self._saved is not None:
            mcp._mcp_server.request_handlers[self._types.ListToolsRequest] = self._saved
        for name in self._registered:
            mcp._tool_manager._tools.pop(name, None)
            if name in state._dynamic_tool_names:
                state._dynamic_tool_names.remove(name)

    def _add_tools(self, count):
        from bridge_mcp_ghidra.registry import _register_tool_def

        for i in range(count):
            name = f"pagination_probe_{i:02d}"
            _register_tool_def({
                "name": name,
                "endpoint": f"/probe_{i}",
                "http_method": "GET",
                "description": "probe",
                "input_schema": {"type": "object", "properties": {}},
                "read_only": True,
                "destructive": False,
            })
            self._registered.append(name)

    def _list(self, cursor=None):
        from bridge_mcp_ghidra.server import mcp

        types = self._types
        handler = mcp._mcp_server.request_handlers[types.ListToolsRequest]
        params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
        request = types.ListToolsRequest(method="tools/list", params=params)
        return asyncio.run(handler(request)).root

    def test_default_is_a_single_unpaginated_page(self):
        self._add_tools(6)
        result = self._list()
        self.assertIsNone(result.nextCursor)
        names = [t.name for t in result.tools]
        self.assertEqual(len([n for n in names if n.startswith("pagination_probe_")]), 6)

    def test_pages_cover_every_tool_exactly_once(self):
        from bridge_mcp_ghidra.server import enable_tool_pagination

        self._add_tools(11)
        enable_tool_pagination(4)
        seen, cursor, pages = [], None, 0
        while True:
            result = self._list(cursor)
            seen.extend(t.name for t in result.tools)
            cursor = result.nextCursor
            pages += 1
            self.assertLess(pages, 20, "pagination did not terminate")
            if not cursor:
                break
        self.assertGreater(pages, 1)
        self.assertEqual(len(seen), len(set(seen)), "a tool appeared on two pages")
        probes = [n for n in seen if n.startswith("pagination_probe_")]
        self.assertEqual(len(probes), 11, "a tool was skipped between pages")

    def test_cursor_is_a_name_so_a_changed_list_does_not_skip(self):
        """An index cursor would skip or repeat entries, and the tool list is not
        fixed here — load_tool_group and a reconnect both rewrite it."""
        from bridge_mcp_ghidra.server import enable_tool_pagination

        self._add_tools(8)
        enable_tool_pagination(3)
        first = self._list()
        self.assertEqual(first.nextCursor, first.tools[-1].name)
        after = self._list(first.nextCursor)
        self.assertTrue(all(t.name > first.nextCursor for t in after.tools))

    def test_stale_cursor_continues_instead_of_failing(self):
        from bridge_mcp_ghidra.server import enable_tool_pagination

        self._add_tools(6)
        enable_tool_pagination(3)
        result = self._list("pagination_probe_02_gone")
        self.assertTrue(all(t.name > "pagination_probe_02_gone" for t in result.tools))


class TestProgressHeartbeat(unittest.TestCase):
    """Long calls report that they are still working.

    Endpoint timeouts reach 600s (dispatch.get_timeout scales batch renames and
    comment writes by item count) and nothing was sent during the wait, so a
    client could not tell a long decompile from a hung session.
    """

    def _ctx(self, progress_token="tok-1"):
        sent = []

        class Session:
            async def send_progress_notification(self, **kwargs):
                sent.append(kwargs)

        meta = SimpleNamespace(progressToken=progress_token) if progress_token else None
        request_context = SimpleNamespace(
            meta=meta, session=Session(), request_id="req-7"
        )
        return SimpleNamespace(request_context=request_context), sent

    def test_no_heartbeat_without_a_context(self):
        from bridge_mcp_ghidra.registry import _start_progress_heartbeat

        self.assertIsNone(_start_progress_heartbeat(None, "some_tool"))

    def test_no_heartbeat_when_the_client_did_not_ask(self):
        """Without a progressToken the notification is dropped anyway, so
        spawning a task per call would be pure overhead."""
        from bridge_mcp_ghidra.registry import _start_progress_heartbeat

        ctx, _ = self._ctx(progress_token=None)
        self.assertIsNone(_start_progress_heartbeat(ctx, "some_tool"))

    def test_heartbeat_ticks_and_stops_with_the_call(self):
        from bridge_mcp_ghidra import dispatch, registry, state
        from bridge_mcp_ghidra.registry import _register_tool_def
        from bridge_mcp_ghidra.server import mcp

        name = "heartbeat_probe_tool"
        ctx, sent = self._ctx()
        saved_interval = registry._PROGRESS_INTERVAL_SECONDS
        registry._PROGRESS_INTERVAL_SECONDS = 0.05
        try:
            _register_tool_def({
                "name": name,
                "endpoint": "/heartbeat_probe",
                "http_method": "GET",
                "description": "probe",
                "input_schema": {"type": "object", "properties": {}},
                "read_only": True,
                "destructive": False,
            })
            fn = mcp._tool_manager._tools[name].fn
            with mock.patch.object(
                dispatch, "dispatch_get",
                side_effect=lambda *a, **k: (time.sleep(0.3), '{"ok": 1}')[1],
            ):
                result = asyncio.run(fn(ctx=ctx))
            self.assertEqual(result, '{"ok": 1}')
            self.assertGreaterEqual(len(sent), 2)
            first = sent[0]
            self.assertEqual(first["progress_token"], "tok-1")
            # Without related_request_id the transport routes the notification to
            # the standalone GET stream, where a POST-only client never sees it.
            self.assertEqual(first["related_request_id"], "req-7")
            # No total: nothing the server returns could produce a fraction.
            self.assertIsNone(first.get("total"))
            self.assertLess(sent[0]["progress"], sent[-1]["progress"])
            # The heartbeat must not outlive the call.
            count_at_return = len(sent)
            time.sleep(0.2)
            self.assertEqual(len(sent), count_at_return)
        finally:
            registry._PROGRESS_INTERVAL_SECONDS = saved_interval
            mcp._tool_manager._tools.pop(name, None)
            if name in state._dynamic_tool_names:
                state._dynamic_tool_names.remove(name)

    def test_ctx_is_not_exposed_as_a_tool_parameter(self):
        from bridge_mcp_ghidra import state
        from bridge_mcp_ghidra.registry import _register_tool_def
        from bridge_mcp_ghidra.server import mcp

        name = "ctx_hidden_probe_tool"
        try:
            _register_tool_def({
                "name": name,
                "endpoint": "/ctx_probe",
                "http_method": "GET",
                "description": "probe",
                "input_schema": {
                    "type": "object",
                    "properties": {"address": {"type": "string"}},
                },
                "read_only": True,
                "destructive": False,
            })
            schema = mcp._tool_manager._tools[name].parameters
            self.assertIn("address", schema["properties"])
            self.assertNotIn("ctx", schema["properties"])
        finally:
            mcp._tool_manager._tools.pop(name, None)
            if name in state._dynamic_tool_names:
                state._dynamic_tool_names.remove(name)


class TestNoFakeOutputSchema(unittest.TestCase):
    """No tool may advertise an output schema it does not have.

    Every tool returns the server's response body as text. Inferred from the
    `-> str` annotation, FastMCP declares outputSchema
    {"result": {"type": "string"}} and wraps the body in structuredContent
    {"result": "<the json>"} — a structured shape whose one field is an opaque
    string, so a client reading `result` still has to parse the JSON. Truthful
    per-tool schemas need response shapes declared server-side; until then none
    is the honest answer, hence structured_output=False everywhere.
    """

    def test_static_tools_declare_no_output_schema(self):
        from bridge_mcp_ghidra import config
        from bridge_mcp_ghidra.server import mcp

        offenders = []
        for name in sorted(config.STATIC_TOOL_NAMES):
            tool = mcp._tool_manager._tools.get(name)
            if tool is not None and tool.output_schema is not None:
                offenders.append(name)
        self.assertEqual(offenders, [])

    def test_dynamic_tool_declares_no_output_schema(self):
        from bridge_mcp_ghidra import state
        from bridge_mcp_ghidra.registry import _register_tool_def
        from bridge_mcp_ghidra.server import mcp

        name = "output_schema_probe_tool"
        try:
            _register_tool_def({
                "name": name,
                "endpoint": "/probe",
                "http_method": "GET",
                "description": "probe",
                "input_schema": {"type": "object", "properties": {}},
                "read_only": True,
                "destructive": False,
            })
            self.assertIsNone(mcp._tool_manager._tools[name].output_schema)
        finally:
            mcp._tool_manager._tools.pop(name, None)
            if name in state._dynamic_tool_names:
                state._dynamic_tool_names.remove(name)


class TestStaticToolsAreAllClassified(unittest.TestCase):
    def test_every_static_tool_declares_annotations(self):
        """A static tool with no annotations is unusable while planning."""
        from bridge_mcp_ghidra.server import mcp
        from bridge_mcp_ghidra import config

        missing = []
        for name in sorted(config.STATIC_TOOL_NAMES):
            tool = mcp._tool_manager._tools.get(name)
            if tool is None:
                continue  # not registered in this process (debugger proxies are off by default)
            if tool.annotations is None or tool.annotations.readOnlyHint is None:
                missing.append(name)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()

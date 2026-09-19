"""The real bridge, over a real socket, against the strict fake.

This is what issue #112 was actually missing. ``tests/unit/`` covers the bridge
by patching ``transport.do_request`` and ``dispatch.dispatch_get``, which means
the pieces that decide *what goes on the wire* -- schema parsing, handler
construction, query-vs-body routing, address sanitisation, the retry ladder --
are each verified against a mock's idea of the server. Nothing checks them
against the catalog. Here they run end to end with no Ghidra installed, and the
fake refuses anything the catalog does not describe.

The fake runs STRICT in this module on purpose: the bridge is the code under
test, and a bridge that violates the contract must fail loudly rather than be
tolerated.
"""

from __future__ import annotations

import json

import pytest

from bridge_mcp_ghidra import discovery, dispatch, registry, state, transport
from bridge_mcp_ghidra.schema import _parse_schema
from bridge_mcp_ghidra.server import mcp


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


@pytest.fixture
def connected(fake_ghidra):
    """Point the bridge's global connection state at the fake, then restore it.

    The bridge keeps its transport target in module-level state, so anything
    that touches it has to put it back or it poisons every later test in the
    process.
    """
    before = state.get_connection_snapshot()
    state.set_connection_snapshot(
        "tcp", active_tcp=fake_ghidra.url, connected_project=fake_ghidra.project
    )
    try:
        yield fake_ghidra
    finally:
        state.set_connection_snapshot(
            before.mode,
            active_socket=before.active_socket,
            active_tcp=before.active_tcp,
            connected_project=before.connected_project,
        )


@pytest.fixture
def clean_registry():
    """Restore FastMCP's tool table and the bridge's schema cache."""
    tools_before = dict(mcp._tool_manager._tools)
    dynamic_before = list(state._dynamic_tool_names)
    schema_before = list(state._full_schema)
    groups_before = set(state._loaded_groups)
    lazy_before = state._lazy_mode
    try:
        yield
    finally:
        mcp._tool_manager._tools.clear()
        mcp._tool_manager._tools.update(tools_before)
        state._dynamic_tool_names[:] = dynamic_before
        state._full_schema[:] = schema_before
        state._loaded_groups.clear()
        state._loaded_groups.update(groups_before)
        state._lazy_mode = lazy_before


def _tool_defs(connection) -> dict[str, dict]:
    """Fetch and parse /mcp/schema over real HTTP, keyed by endpoint."""
    text, status = transport.do_request("GET", "/mcp/schema", timeout=10)
    assert status == 200
    return {d["endpoint"]: d for d in _parse_schema(json.loads(text))}


def _handler_for(defs: dict, endpoint: str):
    d = defs[endpoint]
    return registry._build_tool_function(
        d["endpoint"], d["http_method"], d["input_schema"]
    )


# ---------------------------------------------------------------------------
# Schema discovery and tool registration
# ---------------------------------------------------------------------------


class TestSchemaRegistration:
    def test_schema_is_fetched_and_parsed_over_http(self, connected):
        defs = _tool_defs(connected)
        assert len(defs) == 235
        assert "/decompile_function" in defs
        assert defs["/add_function_tag"]["http_method"] == "POST"

    def test_every_tool_registers(self, connected, clean_registry):
        count = registry._fetch_and_register_schema(load_all=True)
        # Static bridge tools (list_instances, import_file, ...) win any name
        # collision, so a handful of schema tools are deliberately skipped.
        assert count > 200
        assert count == len(state._dynamic_tool_names)
        assert "decompile_function" in mcp._tool_manager._tools

    def test_lazy_mode_registers_only_the_default_groups(self, connected, clean_registry):
        state._lazy_mode = True
        count = registry._fetch_and_register_schema()
        assert state._loaded_groups <= state._default_groups
        assert count < 235, "lazy mode must not load everything"

        # And a group loads on demand from the cached schema.
        groups = {d.get("category") for d in state._full_schema}
        target = sorted(groups - state._default_groups)[0]
        newly = registry._load_group(target)
        assert newly, f"loading group {target!r} registered nothing"
        assert target in state._loaded_groups


# ---------------------------------------------------------------------------
# What actually goes on the wire
# ---------------------------------------------------------------------------


class TestWireFormat:
    def test_get_parameters_go_in_the_query_string(self, connected):
        handler = _handler_for(_tool_defs(connected), "/decompile_function")
        connected.reset()
        handler(address="0x10001000", program="Benchmark.dll")

        call = connected.calls_to("/decompile_function")[0]
        assert call.method == "GET"
        assert call.query["program"] == ["Benchmark.dll"]
        assert call.body is None

    def test_post_sends_query_sourced_params_in_the_url_not_the_body(self, connected):
        """The wrong-binary guard, proven end to end.

        `@Param(value = "program")` defaults to ParamSource.QUERY. The bridge
        splits a POST's arguments by the schema's `source`, and if it ever
        stopped doing so `program` would land in the body, be ignored by the
        plugin, and the write would silently hit the CURRENT program instead.
        The strict fake returns 400 for that, so this test fails at the wire
        rather than passing with the bug present.
        """
        handler = _handler_for(_tool_defs(connected), "/add_function_tag")
        connected.reset()
        result = handler(function="0x10001000", tags="crc", program="Benchmark.dll")

        assert "param_in_wrong_place" not in result
        call = connected.calls_to("/add_function_tag")[0]
        assert call.status == 200
        assert call.query["program"] == ["Benchmark.dll"]
        assert "program" not in (call.body or {})
        assert call.body["function"] == "0x10001000"
        assert call.body["tags"] == "crc"

    def test_addresses_are_sanitised_before_dispatch(self, connected):
        handler = _handler_for(_tool_defs(connected), "/decompile_function")
        connected.reset()
        handler(address="  0x10001000  ", program="Benchmark.dll")
        sent = connected.calls_to("/decompile_function")[0].query["address"][0]
        assert sent == "0x10001000"

    def test_empty_strings_are_dropped_unless_the_param_allows_them(self, connected):
        """Codex's MCP client sends every schema default, including "". The
        bridge drops empty strings so the plugin does not reject a
        present-but-empty argument -- except where a parameter declares
        allow_empty, because clearing a comment IS the empty string."""
        defs = _tool_defs(connected)

        dropped = _handler_for(defs, "/decompile_function")
        connected.reset()
        dropped(address="0x10001000", program="")
        assert "program" not in connected.calls_to("/decompile_function")[0].query

        # /set_comment declares allow_empty on `comment` -- clearing a comment
        # is unreachable through MCP if the bridge filters it out.
        kept = _handler_for(defs, "/set_comment")
        connected.reset()
        kept(address="0x10001000", comment="", program="Benchmark.dll")
        body = connected.calls_to("/set_comment")[0].body
        assert body["comment"] == "", "allow_empty parameter was dropped"

    def test_synthetic_dry_run_goes_out_as_a_query_param(self, connected):
        handler = _handler_for(_tool_defs(connected), "/add_function_tag")
        connected.reset()
        handler(
            function="0x10001000", tags="crc", program="Benchmark.dll", dry_run=True
        )
        call = connected.calls_to("/add_function_tag")[0]
        assert call.query["dry_run"] == ["true"]
        assert "dry_run" not in (call.body or {})

    def test_strict_selector_mode_refuses_before_reaching_the_wire(self, connected):
        handler = _handler_for(_tool_defs(connected), "/decompile_function")
        connected.reset()
        state._require_selectors = True
        try:
            result = handler(address="0x10001000")
        finally:
            state._require_selectors = False
        assert "Missing required program selector" in result
        assert connected.calls_to("/decompile_function") == []


# ---------------------------------------------------------------------------
# Failure handling -- the paths a mock cannot make real
# ---------------------------------------------------------------------------


class TestFailureHandling:
    def test_get_retries_a_5xx_and_recovers(self, connected):
        connected.reset()
        connected.fail_next(500, path="/check_connection")
        result = dispatch.dispatch_get("/check_connection")
        assert "Connected" in result
        assert len(connected.calls_to("/check_connection")) == 2

    def test_get_surfaces_a_persistent_5xx_as_an_error_envelope(self, connected):
        connected.reset()
        connected.fail_next(503, times=5, path="/check_connection")
        result = dispatch.dispatch_get("/check_connection")
        assert json.loads(result)["error"].startswith("HTTP 503")

    def test_post_is_never_retried_after_the_server_answered(self, connected):
        """A POST that reached the server may already have applied the write.
        Resending it risks double-applying, so the only safe retry is one that
        failed before any bytes were sent."""
        connected.reset()
        connected.fail_next(500, times=5, path="/add_function_tag")
        result = dispatch.dispatch_post(
            "/add_function_tag",
            data={"function": "0x10001000", "tags": "crc"},
            query_params={"program": "Benchmark.dll"},
        )
        assert json.loads(result)["error"].startswith("HTTP 500")
        assert len(connected.calls_to("/add_function_tag")) == 1

    def test_a_dropped_response_is_reported_as_outcome_unknown(self, connected):
        connected.reset()
        connected.drop_next(path="/add_function_tag")
        result = dispatch.dispatch_post(
            "/add_function_tag",
            data={"function": "0x10001000", "tags": "crc"},
            query_params={"program": "Benchmark.dll"},
        )
        message = json.loads(result)["error"]
        assert "may have been applied" in message
        assert len(connected.calls_to("/add_function_tag")) == 1

    def test_a_refused_connection_raises_the_retry_safe_error(self, connected):
        """connect() failed, so no request bytes were sent -- the one case
        where a retry is safe, and the type is how dispatch knows that."""
        dead = state.build_connection_snapshot(
            mode="tcp", active_tcp="http://127.0.0.1:1", connected_project=None
        )
        with pytest.raises(transport.RequestNotSentError):
            transport.do_request("GET", "/check_connection", timeout=2, connection=dead)


# ---------------------------------------------------------------------------
# Instance discovery
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_tcp_probe_identifies_the_instance(self, fake_ghidra):
        """The bridge's TCP port scanner reads /mcp/instance_info to work out
        which project lives on which port (#175)."""
        found = discovery._probe_tcp_port(fake_ghidra.port, timeout=5, cancel_handle=None)
        assert found is not None
        url, info = found
        assert url == f"http://127.0.0.1:{fake_ghidra.port}"
        assert info["project"] == fake_ghidra.project
        assert info["tcp_port"] == fake_ghidra.port

    def test_tcp_probe_returns_none_on_a_dead_port(self):
        assert discovery._probe_tcp_port(1, timeout=1, cancel_handle=None) is None

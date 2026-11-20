"""connect_instance's failure signalling (#652) and TCP project verification (#655).

#652: every refused selection used to come back as a successful tool result
whose text happened to be ``{"error": ...}``, so a client branching on the MCP
``isError`` flag saw ``connect_instance(project="no_such_project")`` succeed.
The FastMCP tests below go through the real protocol path (an in-memory client
session against the bridge's own server) because the unit-level assertion that
a Python exception is raised says nothing about what the client receives.

#655: a TCP URL the bridge did not find BY project -- ``GHIDRA_MCP_URL``,
pinned or not, and the ``DEFAULT_TCP_URL`` fallback after a missed port scan --
was connected to without asking which project it holds, reporting
``connected: true`` for a project the listener did not have open. The matrix
below covers each of those three URL sources against every answer
``/mcp/instance_info`` can give.

Mock-patch targets are the callee's own module (CLAUDE.md): connect.py calls
``transport.tcp_request``, ``discovery.discover_instances`` and
``registry._fetch_schema`` module-qualified.
"""

import asyncio
import json
import os
from unittest.mock import patch

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

import bridge_mcp_ghidra as bridge
from bridge_mcp_ghidra import config, connect, discovery, dispatch, registry, server, state, transport

CONFIGURED_URL = "http://127.0.0.1:18311"


@pytest.fixture(autouse=True)
def isolated_state():
    """Snapshot and restore everything connect_instance can rewrite."""
    saved_tools = dict(bridge.mcp._tool_manager._tools)
    saved_dynamic = list(state._dynamic_tool_names)
    saved_schema = list(state._full_schema)
    saved_loaded = set(state._loaded_groups)
    saved_conn = (
        state._active_socket,
        state._active_tcp,
        state._transport_mode,
        state._connected_project,
    )
    state.set_connection_snapshot("none")
    env = {k: v for k, v in os.environ.items() if k not in ("GHIDRA_MCP_URL", "GHIDRA_MCP_PIN_URL")}
    with patch.dict(os.environ, env, clear=True):
        yield
    bridge.mcp._tool_manager._tools.clear()
    bridge.mcp._tool_manager._tools.update(saved_tools)
    state._dynamic_tool_names[:] = saved_dynamic
    state._full_schema = saved_schema
    state._loaded_groups.clear()
    state._loaded_groups.update(saved_loaded)
    (
        state._active_socket,
        state._active_tcp,
        state._transport_mode,
        state._connected_project,
    ) = saved_conn


def _info(project):
    """A /mcp/instance_info body as Response.ok renders it."""
    data = {"pid": 4242, "server_kind": "headless", "programs": []}
    if project is not None:
        data["project"] = project
    return json.dumps({"data": data}), 200


# ---------------------------------------------------------------------------
# #652 -- failures reach the client as isError
# ---------------------------------------------------------------------------


async def _call_tool(name, arguments):
    async with create_connected_server_and_client_session(server.mcp._mcp_server) as client:
        result = await client.call_tool(name, arguments)
        return result.isError, result.content[0].text


def test_no_match_is_an_mcp_tool_error_through_fastmcp():
    """The exact shape #652 reported: one UDS instance, a project that matches nothing."""
    one = [{"project": "ErrorFlagFixture", "socket": "/tmp/ghidra-1.sock", "pid": 1}]
    with (
        patch.object(discovery, "discover_instances", return_value=one),
        patch.object(discovery, "_scan_tcp_for_project") as scan,
        patch.object(registry, "_fetch_schema") as fetch,
    ):
        is_error, text = asyncio.run(_call_tool("connect_instance", {"project": "no_such_project"}))

    assert is_error is True
    assert "No instance matching 'no_such_project'" in text
    assert "ErrorFlagFixture" in text, "the refusal should still name what is available"
    scan.assert_not_called()
    fetch.assert_not_called()
    assert state._transport_mode == "none"


def test_successful_selection_stays_a_non_error_through_fastmcp():
    """The control: fixing the error flag must not flag a successful selection."""
    one = [{"project": "ErrorFlagFixture", "socket": "/tmp/ghidra-1.sock", "pid": 1}]
    with (
        patch.object(discovery, "discover_instances", return_value=one),
        patch.object(transport, "uds_supported", return_value=True),
        patch.object(registry, "_fetch_schema", return_value=[]),
        patch.object(registry, "register_tools_from_schema", return_value=0),
    ):
        is_error, text = asyncio.run(_call_tool("connect_instance", {"project": "ErrorFlagFixture"}))

    assert is_error is False
    payload = json.loads(text)
    assert payload["connected"] is True
    assert payload["project"] == "ErrorFlagFixture"


def test_project_mismatch_on_configured_url_is_an_mcp_tool_error_through_fastmcp():
    """#655 through the protocol: the refusal is isError, not connected: true."""
    os.environ["GHIDRA_MCP_URL"] = CONFIGURED_URL
    with (
        patch.object(discovery, "discover_instances", return_value=[]),
        patch.object(transport, "tcp_request", return_value=_info("ProjectUrlFixture")),
        patch.object(registry, "_fetch_schema") as fetch,
    ):
        is_error, text = asyncio.run(_call_tool("connect_instance", {"project": "NoSuchProjectUrlProbe"}))

    assert is_error is True
    assert CONFIGURED_URL in text
    assert "ProjectUrlFixture" in text
    fetch.assert_not_called()


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("list_tool_groups", {}),
        ("load_tool_group", {"group": "function"}),
        ("check_tools", {"tools": " , "}),
        ("search_tools", {"query": "  "}),
    ],
)
def test_other_static_tool_refusals_are_mcp_tool_errors(tool, arguments):
    state._full_schema = []
    is_error, _text = asyncio.run(_call_tool(tool, arguments))
    assert is_error is True


def test_unloading_a_default_group_is_an_mcp_tool_error():
    group = sorted(state._default_groups)[0]
    is_error, text = asyncio.run(_call_tool("unload_tool_group", {"group": group}))
    assert is_error is True
    assert "Cannot unload default group" in text


# ---------------------------------------------------------------------------
# #655 -- a TCP URL not found by project is asked for its project first
# ---------------------------------------------------------------------------

# How each URL source is set up, and the URL it should land on.
SOURCES = {
    # GHIDRA_MCP_URL with a non-matching local instance discovered -- the
    # configured URL wins over discovery, exactly as in the report.
    "configured": (
        {"GHIDRA_MCP_URL": CONFIGURED_URL},
        [{"project": "SomeLocalProject", "socket": "/tmp/ghidra-7.sock", "pid": 7}],
        CONFIGURED_URL,
    ),
    # GHIDRA_MCP_PIN_URL: discovery is skipped entirely (real discover_instances).
    "pinned": (
        {"GHIDRA_MCP_URL": CONFIGURED_URL, "GHIDRA_MCP_PIN_URL": "1"},
        None,
        CONFIGURED_URL,
    ),
    # Nothing discovered and the port scan missed: DEFAULT_TCP_URL.
    "default": ({}, [], config.DEFAULT_TCP_URL),
}


def _run(source, project, tcp_request):
    env, instances, url = SOURCES[source]
    os.environ.update(env)
    discover = (
        patch.object(discovery, "discover_instances", return_value=instances)
        if instances is not None
        else patch.object(transport, "get_socket_dir_candidates", side_effect=AssertionError("pinned: no UDS scan"))
    )
    with (
        discover,
        patch.object(discovery, "_scan_tcp_for_project", return_value=None) as scan,
        patch.object(transport, "tcp_request", **tcp_request) as info_request,
        patch.object(registry, "_fetch_schema", return_value=[]) as fetch,
        patch.object(registry, "register_tools_from_schema", return_value=0),
    ):
        try:
            outcome = asyncio.run(bridge.connect_instance(project))
        except dispatch.GhidraToolError as e:
            outcome = e
    return url, outcome, info_request, fetch, scan


@pytest.mark.parametrize("source", sorted(SOURCES))
@pytest.mark.parametrize("project", ["ProjectUrlFixture", "UrlFixture"], ids=["exact", "substring"])
def test_matching_project_connects_and_records_it(source, project):
    url, outcome, info_request, fetch, _scan = _run(
        source, project, {"return_value": _info("ProjectUrlFixture")}
    )

    assert not isinstance(outcome, Exception), outcome
    payload = json.loads(outcome)
    assert payload["connected"] is True
    assert payload["url"] == url
    assert payload["project"] == "ProjectUrlFixture"
    assert state._transport_mode == "tcp"
    assert state._active_tcp == url
    # Recorded from what the server reported, not from what the caller typed.
    assert state._connected_project == "ProjectUrlFixture"
    info_request.assert_called_once_with(url, "GET", "/mcp/instance_info", timeout=5)
    assert fetch.call_args.kwargs["connection"].connected_project == "ProjectUrlFixture"


@pytest.mark.parametrize("source", sorted(SOURCES))
def test_project_mismatch_is_refused(source):
    url, outcome, _info_request, fetch, _scan = _run(
        source, "NoSuchProjectUrlProbe", {"return_value": _info("ProjectUrlFixture")}
    )

    assert isinstance(outcome, dispatch.GhidraToolError)
    message = str(outcome)
    assert url in message
    assert "'NoSuchProjectUrlProbe'" in message
    assert "has project 'ProjectUrlFixture' open" in message
    fetch.assert_not_called()
    assert state._transport_mode == "none"
    assert state._connected_project is None


@pytest.mark.parametrize("source", sorted(SOURCES))
@pytest.mark.parametrize("reported", [None, ""], ids=["absent", "empty"])
def test_server_with_no_project_is_refused(source, reported):
    url, outcome, _info_request, fetch, _scan = _run(source, "ProjectUrlFixture", {"return_value": _info(reported)})

    assert isinstance(outcome, dispatch.GhidraToolError)
    assert url in str(outcome)
    assert "reports no open project" in str(outcome)
    fetch.assert_not_called()
    assert state._transport_mode == "none"


@pytest.mark.parametrize("source", sorted(SOURCES))
@pytest.mark.parametrize(
    ("tcp_request", "reason"),
    [
        ({"side_effect": transport.RequestNotSentError("Could not connect")}, "could not be reached"),
        ({"side_effect": TimeoutError("timed out")}, "could not be reached"),
        ({"return_value": ('{"error": "Unknown endpoint"}', 404)}, "returned HTTP 404"),
        ({"return_value": ("<html>not json</html>", 200)}, "not JSON"),
        ({"return_value": ('["a", "list"]', 200)}, "reports no open project"),
    ],
    ids=["unreachable", "timeout", "unsupported", "not-json", "not-an-object"],
)
def test_unconfirmable_project_fails_closed(source, tcp_request, reason):
    """The caller named a project, so a server that cannot say which one it
    holds is refused rather than assumed to be the right one."""
    url, outcome, _info_request, fetch, _scan = _run(source, "ProjectUrlFixture", tcp_request)

    assert isinstance(outcome, dispatch.GhidraToolError)
    assert url in str(outcome)
    assert reason in str(outcome)
    fetch.assert_not_called()
    assert state._transport_mode == "none"


def test_scan_hit_is_not_asked_twice():
    """A port-scan hit was already chosen by project via /mcp/instance_info;
    the default-fallback check must not fire for it."""
    with (
        patch.object(discovery, "discover_instances", return_value=[]),
        patch.object(discovery, "_scan_tcp_for_project", return_value="http://127.0.0.1:8092"),
        patch.object(transport, "tcp_request") as info_request,
        patch.object(registry, "_fetch_schema", return_value=[]),
        patch.object(registry, "register_tools_from_schema", return_value=0),
    ):
        payload = json.loads(asyncio.run(bridge.connect_instance("ProjectUrlFixture")))

    assert payload["url"] == "http://127.0.0.1:8092"
    info_request.assert_not_called()


def test_invalid_configured_url_is_refused_before_any_request():
    os.environ["GHIDRA_MCP_URL"] = "http://10.0.0.5:8089"
    with (
        patch.object(discovery, "discover_instances", return_value=[]),
        patch.object(transport, "tcp_request") as info_request,
        pytest.raises(dispatch.GhidraToolError, match="invalid TCP URL"),
    ):
        asyncio.run(bridge.connect_instance("ProjectUrlFixture"))
    info_request.assert_not_called()


def test_match_project_rule_is_shared():
    """One matcher for both transports: exact first, then substring, case-insensitive."""
    instances = [{"project": "diablo2_beta"}, {"project": "diablo2"}]
    assert connect._match_project("diablo2", instances)["project"] == "diablo2"
    assert connect._match_project("BETA", instances)["project"] == "diablo2_beta"
    assert connect._match_project("nope", instances) is None
    assert connect._match_project("x", [{"socket": "/tmp/s.sock"}]) is None

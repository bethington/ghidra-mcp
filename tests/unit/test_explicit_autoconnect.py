"""Startup selection must honor an explicit endpoint without discovery fallback."""

import threading
from unittest.mock import Mock

import pytest

from bridge_mcp_ghidra import registry, schema, state, static_tools, transport
from bridge_mcp_ghidra.server import mcp

URL = "http://localhost:19001"
TOOLS = schema._parse_schema(
    {
        "tools": [
            {"path": "/fixture_read", "method": "GET", "category": "function", "params": []},
        ]
    }
)


@pytest.fixture(autouse=True)
def isolated_bridge(monkeypatch):
    saved = state.get_connection_snapshot()
    tools = dict(mcp._tool_manager._tools)
    for name, value in {
        "_full_schema": [],
        "_dynamic_tool_names": [],
        "_loaded_groups": set(),
        "_expose_mode": "full",
        "_lazy_mode": False,
        "_default_groups": {"function"},
    }.items():
        monkeypatch.setattr(state, name, value)
    monkeypatch.delenv("GHIDRA_MCP_URL", raising=False)
    state.set_connection_snapshot("none")
    # No test may accidentally contact a real server or scan the host.
    monkeypatch.setattr(transport, "do_request", Mock(side_effect=AssertionError("unexpected network")))
    monkeypatch.setattr(transport, "tcp_request", Mock(side_effect=AssertionError("unexpected network")))
    monkeypatch.setattr(static_tools.discovery, "_iter_tcp_instances", Mock(return_value=[]))
    monkeypatch.setattr(static_tools.discovery, "discover_instances", Mock(return_value=[]))
    yield
    mcp._tool_manager._tools.clear()
    mcp._tool_manager._tools.update(tools)
    state.set_connection_snapshot(
        saved.mode,
        active_socket=saved.active_socket,
        active_tcp=saved.active_tcp,
        connected_project=saved.connected_project,
    )


@pytest.mark.parametrize(
    "instances",
    [
        [],
        [{"project": "other", "socket": "/other.sock"}],
        [{"project": "one", "socket": "/one.sock"}, {"project": "two", "socket": "/two.sock"}],
    ],
)
def test_url_precedes_discovery(monkeypatch, instances):
    monkeypatch.setenv("GHIDRA_MCP_URL", f"  {URL}  ")
    static_tools.discovery.discover_instances.return_value = instances
    fetch = Mock(return_value=TOOLS)
    monkeypatch.setattr(registry, "_fetch_schema", fetch)
    assert static_tools._auto_connect()
    static_tools.discovery.discover_instances.assert_not_called()
    connection = fetch.call_args.kwargs["connection"]
    assert connection.mode == "tcp" and connection.active_tcp == URL
    assert state.get_connection_snapshot().active_tcp == URL
    assert "fixture_read" in state._dynamic_tool_names


@pytest.mark.parametrize("url", ["https://localhost:19001", "http://remote.example:19001", "localhost:19001"])
def test_invalid_url_fails_before_discovery(monkeypatch, url):
    monkeypatch.setenv("GHIDRA_MCP_URL", url)
    fetch = Mock()
    monkeypatch.setattr(registry, "_fetch_schema", fetch)
    assert not static_tools._auto_connect()
    static_tools.discovery.discover_instances.assert_not_called()
    fetch.assert_not_called()
    assert state.get_connection_snapshot().mode == "none"


def test_unreachable_url_never_falls_back(monkeypatch):
    monkeypatch.setenv("GHIDRA_MCP_URL", URL)
    fetch = Mock(side_effect=OSError("unreachable"))
    monkeypatch.setattr(registry, "_fetch_schema", fetch)
    assert not static_tools._auto_connect()
    static_tools.discovery.discover_instances.assert_not_called()
    fetch.assert_called_once()
    assert fetch.call_args.kwargs["connection"].active_tcp == URL
    assert state.get_connection_snapshot().mode == "none"


@pytest.mark.parametrize("blank", ["", "  "])
def test_blank_url_keeps_default_tcp(monkeypatch, blank):
    monkeypatch.setenv("GHIDRA_MCP_URL", blank)
    fetch = Mock(return_value=TOOLS)
    monkeypatch.setattr(registry, "_fetch_schema", fetch)
    assert static_tools._auto_connect()
    assert fetch.call_args.kwargs["connection"].active_tcp == static_tools.DEFAULT_TCP_URL


@pytest.mark.parametrize("mode", ["full", "hybrid", "facade"])
def test_empty_schema_does_not_attach(monkeypatch, mode):
    monkeypatch.setenv("GHIDRA_MCP_URL", URL)
    monkeypatch.setattr(state, "_expose_mode", mode)
    monkeypatch.setattr(registry, "_fetch_schema", Mock(return_value=[]))
    assert not static_tools._auto_connect()
    assert state.get_connection_snapshot().mode == "none"
    assert state._full_schema == []


@pytest.mark.parametrize("mode", ["full", "hybrid", "facade"])
def test_nonempty_schema_attaches_in_each_surface(monkeypatch, mode):
    monkeypatch.setenv("GHIDRA_MCP_URL", URL)
    monkeypatch.setattr(state, "_expose_mode", mode)
    monkeypatch.setattr(registry, "_fetch_schema", Mock(return_value=TOOLS))
    assert static_tools._auto_connect()
    assert state._full_schema
    assert bool(state._dynamic_tool_names) == (mode != "facade")


def test_registration_failure_restores_catalog(monkeypatch):
    registry.register_tools_from_schema(TOOLS)
    previous_tools = dict(mcp._tool_manager._tools)
    previous_schema = state._full_schema
    monkeypatch.setenv("GHIDRA_MCP_URL", URL)
    monkeypatch.setattr(registry, "_fetch_schema", Mock(return_value=TOOLS))
    monkeypatch.setattr(registry, "_register_tool_def", Mock(side_effect=ValueError("cannot register")))
    assert not static_tools._auto_connect()
    assert state.get_connection_snapshot().mode == "none"
    assert mcp._tool_manager._tools == previous_tools
    assert state._full_schema == previous_schema
    assert state._dynamic_tool_names == ["fixture_read"]


def test_late_retry_does_not_overwrite_manual_connection(monkeypatch):
    monkeypatch.setenv("GHIDRA_MCP_URL", URL)
    fetching = threading.Event()
    release = threading.Event()

    def fetch(**kwargs):
        fetching.set()
        assert release.wait(2)
        return TOOLS

    monkeypatch.setattr(registry, "_fetch_schema", fetch)
    outcome = []
    worker = threading.Thread(target=lambda: outcome.append(static_tools._auto_connect()))
    worker.start()
    try:
        assert fetching.wait(2)
        with state._tool_registry_lock:
            state.set_connection_snapshot("tcp", active_tcp="http://localhost:19002")
        release.set()
        worker.join(2)
        assert not worker.is_alive()
        assert state.get_connection_snapshot().active_tcp == "http://localhost:19002"
        assert not state._dynamic_tool_names
    finally:
        release.set()
        worker.join(2)


def test_retry_keeps_configured_endpoint_until_schema_arrives(monkeypatch):
    monkeypatch.setenv("GHIDRA_MCP_URL", URL)
    fetch = Mock(side_effect=[[], TOOLS])
    notify = Mock()
    monkeypatch.setattr(registry, "_fetch_schema", fetch)
    monkeypatch.setattr(state, "notify_tools_changed_from_worker", notify)
    thread = static_tools._start_auto_connect_retry(interval=0.001)
    thread.join(2)
    assert not thread.is_alive()
    assert fetch.call_count == 2
    assert all(call.kwargs["connection"].active_tcp == URL for call in fetch.call_args_list)
    notify.assert_called_once()


@pytest.mark.parametrize(
    "reply,status,expected",
    [
        ({"data": {"project": "chosen"}}, 200, True),
        ({"project": "other"}, 200, False),
        ({"project": "chosen extra"}, 200, False),
        ({"project": "chosen"}, 503, False),
    ],
)
def test_url_with_project_checks_only_configured_listener(monkeypatch, reply, status, expected):
    import json

    monkeypatch.setenv("GHIDRA_MCP_URL", f" {URL} ")
    info = Mock(return_value=(json.dumps(reply), status))
    monkeypatch.setattr(transport, "tcp_request", info)
    fetch = Mock(return_value=TOOLS)
    monkeypatch.setattr(registry, "_fetch_schema", fetch)
    assert static_tools._auto_connect(project="chosen") == expected
    info.assert_called_once_with(URL, "GET", "/mcp/instance_info", timeout=5)
    static_tools.discovery.discover_instances.assert_not_called()
    assert fetch.call_count == int(expected)
    if expected:
        assert state.get_connection_snapshot().connected_project == "chosen"
    else:
        assert state.get_connection_snapshot().mode == "none"


@pytest.mark.parametrize("request_method", ["GET", "POST"])
def test_configured_connection_retries_same_url_without_rediscovery(monkeypatch, request_method):
    import json
    from bridge_mcp_ghidra import dispatch

    monkeypatch.setenv("GHIDRA_MCP_URL", f" {URL} ")
    state.set_connection_snapshot("tcp", active_tcp=URL, connected_project="chosen")
    request = Mock(side_effect=transport.RequestNotSentError("unreachable"))
    monkeypatch.setattr(transport, "do_request", request)
    monkeypatch.setattr(dispatch.time, "sleep", Mock())
    result = (
        dispatch.dispatch_get("/fixture_read", retries=2)
        if request_method == "GET"
        else (dispatch.dispatch_post("/fixture_write", {}, retries=2))
    )
    assert "error" in json.loads(result)
    assert request.call_count == 2
    assert all(call.kwargs["connection"].active_tcp == URL for call in request.call_args_list)
    static_tools.discovery.discover_instances.assert_not_called()


def test_different_manual_connection_can_still_reconnect(monkeypatch):
    from bridge_mcp_ghidra import dispatch

    monkeypatch.setenv("GHIDRA_MCP_URL", URL)
    old = state.build_connection_snapshot(mode="tcp", active_tcp="http://localhost:19002", connected_project="manual")
    new = state.build_connection_snapshot(mode="uds", active_socket="/manual.sock", connected_project="manual")
    discover = Mock(return_value=new)
    monkeypatch.setattr(dispatch, "_discover_project_connection", discover)
    assert dispatch._try_reconnect(old) == new
    discover.assert_called_once_with("manual")


@pytest.mark.parametrize("blank", ["", "  "])
def test_blank_url_keeps_project_discovery(monkeypatch, blank):
    monkeypatch.setenv("GHIDRA_MCP_URL", blank)
    static_tools.discovery.discover_instances.return_value = [{"project": "chosen", "socket": "/chosen.sock"}]
    monkeypatch.setattr(transport, "uds_supported", Mock(return_value=True))
    monkeypatch.setattr(registry, "_fetch_schema", Mock(return_value=TOOLS))
    assert static_tools._auto_connect(project="chosen")
    assert state.get_connection_snapshot().active_socket == "/chosen.sock"
    transport.tcp_request.assert_not_called()


def test_lazy_mode_registers_default_group(monkeypatch):
    monkeypatch.setenv("GHIDRA_MCP_URL", URL)
    monkeypatch.setattr(state, "_lazy_mode", True)
    monkeypatch.setattr(registry, "_fetch_schema", Mock(return_value=TOOLS))
    assert static_tools._auto_connect()
    assert state._loaded_groups == {"function"}
    assert state._dynamic_tool_names == ["fixture_read"]

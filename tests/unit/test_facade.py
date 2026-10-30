"""PR527 merge coverage against the live CLI, registry, and schema parser."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from unittest.mock import AsyncMock, Mock

import pytest

from bridge_mcp_ghidra import cli, facade, registry, schema, state, static_tools
from bridge_mcp_ghidra.server import mcp


@pytest.fixture(autouse=True)
def restore_bridge(monkeypatch):
    tools = dict(mcp._tool_manager._tools)
    settings = mcp.settings.model_copy(deep=True)
    for name, value in {
        "_expose_mode": "full", "_lazy_mode": True, "_default_groups": {"function"},
        "_full_schema": [], "_dynamic_tool_names": [], "_loaded_groups": set(),
    }.items():
        monkeypatch.setattr(state, name, value)
    monkeypatch.delenv("GHIDRA_MCP_BRIDGE_EXPOSE", raising=False)
    monkeypatch.delenv("GHIDRA_MCP_BRIDGE_LAZY", raising=False)
    monkeypatch.delenv("GHIDRA_MCP_BRIDGE_PROJECT", raising=False)
    monkeypatch.delenv("GHIDRA_MCP_BRIDGE_SERVER_URL", raising=False)
    try:
        yield
    finally:
        mcp._tool_manager._tools.clear()
        mcp._tool_manager._tools.update(tools)
        mcp.settings = settings


@pytest.fixture
def catalog():
    return schema._parse_schema({"tools": [
        {"path": "/read_function", "method": "GET", "category": "function", "description": "Read one function",
         "params": [{"name": "function", "type": "string", "required": True,
                     "aliases": ["address"], "description": "Function name or address"}]},
        {"path": "/list_types", "method": "GET", "category": "datatype", "params": []},
    ]})


def run_cli(monkeypatch, catalog, *args):
    def connect(**kwargs):
        registry.register_tools_from_schema(catalog, groups=state._default_groups if state._lazy_mode else None)
        return True
    connected = Mock(side_effect=connect)
    monkeypatch.setattr(cli, "_auto_connect", connected)
    monkeypatch.setattr(cli, "_start_auto_connect_retry", Mock())
    monkeypatch.setattr(mcp, "run", Mock())
    monkeypatch.setattr(cli.uvicorn, "run", Mock())
    monkeypatch.setattr(cli, "_build_http_app", Mock())
    monkeypatch.setattr(sys, "argv", ["bridge-mcp-ghidra", *args])
    cli.main()
    return connected


@pytest.mark.parametrize("mode", ["full", "facade", "hybrid"])
def test_cli_mode_registers_expected_surface_and_keeps_resources(monkeypatch, catalog, mode):
    templates = list(mcp._resource_manager.list_templates())
    assert templates, "dev resources must still be imported"
    run_cli(monkeypatch, catalog, "--expose", mode, "--default-groups", "function", "--project", "chosen")
    names = set(mcp._tool_manager._tools)
    assert state._expose_mode == mode
    assert bool(names & facade.FACADE_TOOL_NAMES) == (mode != "full")
    assert ("connect_instance" in names) == (mode != "facade")
    assert ("read_function" in names) == (mode != "facade")
    assert "list_types" not in names
    assert len(state._full_schema) == 2
    assert list(mcp._resource_manager.list_templates()) == templates
    mcp.run.assert_called_once_with(transport="stdio")


def test_cli_default_full_and_dev_flags_are_independent(monkeypatch, catalog):
    run_cli(monkeypatch, catalog, "--no-lazy", "--default-groups", "function,datatype",
            "--tools-page-size", "0", "--transport", "streamable-http", "--json-response", "--stateless-http")
    assert state._expose_mode == "full"
    assert state._lazy_mode is False
    assert state._default_groups == {"function", "datatype"}
    assert {"read_function", "list_types"} <= set(mcp._tool_manager._tools)
    assert mcp.settings.json_response and mcp.settings.stateless_http
    cli.uvicorn.run.assert_called_once()


def test_expose_environment_and_explicit_flag_precedence(monkeypatch, catalog):
    monkeypatch.setenv("GHIDRA_MCP_BRIDGE_EXPOSE", "facade")
    run_cli(monkeypatch, catalog, "--expose", "hybrid")
    assert state._expose_mode == "hybrid"
    assert facade.FACADE_TOOL_NAMES <= set(mcp._tool_manager._tools)


def test_expose_env_does_not_replace_lazy_env(monkeypatch, catalog):
    monkeypatch.setenv("GHIDRA_MCP_BRIDGE_EXPOSE", "hybrid")
    monkeypatch.setenv("GHIDRA_MCP_BRIDGE_LAZY", "0")
    run_cli(monkeypatch, catalog)
    assert state._expose_mode == "hybrid"
    assert not state._lazy_mode
    assert "list_types" in mcp._tool_manager._tools


def test_facade_auto_connect_caches_complete_schema_without_dynamic_tools(monkeypatch, catalog):
    facade.apply_expose_mode("facade")
    monkeypatch.setattr(static_tools.discovery, "discover_instances", lambda: [])
    monkeypatch.setattr(static_tools.discovery, "discover_active_tcp_instance", lambda: None)
    fetched = Mock(return_value=catalog)
    monkeypatch.setattr(registry, "_fetch_schema", fetched)
    snapshot = state.get_connection_snapshot()
    try:
        assert static_tools._auto_connect()
        assert fetched.call_count == 1
        assert state._transport_mode == "tcp"
        assert len(state._full_schema) == 2
        assert state._dynamic_tool_names == []
        assert set(mcp._tool_manager._tools) == facade.FACADE_TOOL_NAMES
        found = json.loads(facade.ghidra_search("types"))
        assert found["matches"][0]["name"] == "list_types"
        described = json.loads(facade.ghidra_describe("read_function"))
        assert described["input_schema"]["properties"]["function"]["description"] == "Function name or address"
        assert fetched.call_count == 1, "search/describe must reuse the cached catalog"
    finally:
        state.set_connection_snapshot(snapshot.mode, active_socket=snapshot.active_socket,
            active_tcp=snapshot.active_tcp, connected_project=snapshot.connected_project)


def test_facade_accepts_current_registry_parameter_aliases(monkeypatch, catalog):
    dispatch = Mock(return_value='{"ok": true}')
    monkeypatch.setattr(registry.dispatch, "dispatch_get", dispatch)
    result = facade._call_catalog_sync(catalog[0], {"address": "0x1000"})
    assert json.loads(result) == {"ok": True}
    assert dispatch.call_args.args[0] == "/read_function"


def test_import_default_is_full_without_facade_tools():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "python")
    code = "import json; from bridge_mcp_ghidra.server import mcp; print(json.dumps(sorted(mcp._tool_manager._tools)))"
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=30, check=True)
    names = set(json.loads(result.stdout.strip()))
    assert "connect_instance" in names
    assert not names & facade.FACADE_TOOL_NAMES


def test_facade_write_preserves_dev_resource_invalidation(monkeypatch, catalog):
    from bridge_mcp_ghidra import invalidation
    tool = dict(catalog[0], name="rename_function", endpoint="/rename_function", http_method="POST", read_only=False)
    state._full_schema = [tool]
    response = '{"status": "success", "program": "sample"}'
    monkeypatch.setattr(facade, "_call_catalog_sync", Mock(return_value=response))
    invalidated = AsyncMock()
    monkeypatch.setattr(invalidation, "after_successful_write", invalidated)
    params = {"function": "0x1000"}
    assert asyncio.run(facade.ghidra_call("rename_function", params)) == response
    invalidated.assert_awaited_once_with(tool, params, None, response)


def test_facade_dispatch_failures_have_mcp_error_semantics(monkeypatch, catalog):
    from bridge_mcp_ghidra import dispatch, invalidation
    state._full_schema = catalog
    monkeypatch.setattr(facade, "_call_catalog_sync", Mock(return_value='{"error": "rejected by Ghidra"}'))
    invalidated = AsyncMock()
    monkeypatch.setattr(invalidation, "after_successful_write", invalidated)
    with pytest.raises(dispatch.GhidraToolError, match="rejected by Ghidra"):
        asyncio.run(facade.ghidra_call("read_function", {"function": "0x1000"}))
    invalidated.assert_not_awaited()


@pytest.mark.parametrize("dry_run", [True, "true", "1", "yes"])
def test_static_import_preview_is_refused_without_dispatch(monkeypatch, dry_run):
    dispatched = Mock(return_value='{"status": "success"}')
    monkeypatch.setattr(facade.dispatch, "dispatch_post", dispatched)
    # The synchronous helper itself must refuse before even the mocked write.
    result = facade._call_import_file_sync({"file_path": "mock-only.dll", "dry_run": dry_run})
    dispatched.assert_not_called()
    assert "dry_run" in json.loads(result)["error"]


@pytest.mark.parametrize("dry_run", [False, "false", "0"])
def test_static_import_false_preview_preserves_payload_and_result(monkeypatch, dry_run):
    response = '{"status": "success", "data": {"name": "mock-only.dll"}}'
    dispatched = Mock(return_value=response)
    monkeypatch.setattr(facade.dispatch, "dispatch_post", dispatched)
    result = asyncio.run(facade.ghidra_call("import_file", {
        "file_path": "mock-only.dll", "project_folder": "/mock", "language": "x86:LE:32:default",
        "compiler_spec": "gcc", "auto_analyze": False, "dry_run": dry_run,
    }))
    assert result == response
    dispatched.assert_called_once_with("/import_file", {
        "file_path": "mock-only.dll", "project_folder": "/mock", "language": "x86:LE:32:default",
        "compiler_spec": "gcc", "auto_analyze": False,
    })


def test_static_import_failures_have_dev_mcp_error_semantics(monkeypatch):
    from bridge_mcp_ghidra import dispatch
    monkeypatch.setattr(facade.dispatch, "dispatch_post", Mock(return_value='{"error": "import refused"}'))
    with pytest.raises(dispatch.GhidraToolError, match="import refused"):
        asyncio.run(facade.ghidra_call("import_file", {"file_path": "mock-only.dll"}))


def test_static_import_cancellation_aborts_registered_mock_connection(monkeypatch):
    started, released = threading.Event(), threading.Event()
    handles, snapshots = [], []
    connection = Mock()
    connection.close.side_effect = released.set

    def blocking_mock_dispatch(*args, **kwargs):
        handle = state.get_request_cancel_handle()
        handles.append(handle)
        snapshots.append(state.get_request_connection_snapshot())
        if handle is not None:
            handle.register_connection(connection)
        started.set()
        released.wait(3)
        return '{"status": "success"}'

    monkeypatch.setattr(facade.dispatch, "dispatch_post", blocking_mock_dispatch)

    async def cancel_call():
        task = asyncio.create_task(facade.ghidra_call("import_file", {"file_path": "mock-only.dll"}))
        try:
            assert await asyncio.to_thread(started.wait, 2), "mock write never started"
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            released.set()

    asyncio.run(cancel_call())
    assert handles and handles[0] is not None, "static dispatch bypassed request cancellation binding"
    assert handles[0].aborted
    assert snapshots[0] is not None
    connection.close.assert_called_once()


def test_static_import_preview_error_propagates_without_dispatch(monkeypatch):
    from bridge_mcp_ghidra import dispatch
    dispatched = Mock(return_value='{"status": "success"}')
    monkeypatch.setattr(facade.dispatch, "dispatch_post", dispatched)
    with pytest.raises(dispatch.GhidraToolError, match="dry_run is not supported"):
        asyncio.run(facade.ghidra_call("import_file", {"file_path": "mock-only.dll", "dry_run": True}))
    dispatched.assert_not_called()

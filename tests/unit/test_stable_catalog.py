"""Exercise one MCP session across absent, switched and restarted instances."""

import asyncio
import copy
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from bridge_mcp_ghidra import catalog, cli, connections, discovery, dispatch, registry, state, transport
from bridge_mcp_ghidra.server import mcp


@pytest.fixture
def stable():
    saved = (
        dict(mcp._tool_manager._tools),
        list(state._dynamic_tool_names),
        set(state._loaded_groups),
        state._full_schema,
        state._catalog_frozen,
        state.get_connection_snapshot(),
    )
    state._catalog_frozen = False
    catalog.initialize()
    state.set_connection_snapshot("none")
    yield
    tools, names, groups, schema, frozen, route = saved
    mcp._tool_manager._tools = tools
    state._dynamic_tool_names[:] = names
    state._loaded_groups.clear()
    state._loaded_groups.update(groups)
    state._full_schema = schema
    state._catalog_frozen = frozen
    state.set_connection_snapshot(
        route.mode,
        active_socket=route.active_socket,
        active_tcp=route.active_tcp,
        connected_project=route.connected_project,
        binding=route.binding,
    )


def instance(name, pid, port):
    return {
        "project": name,
        "project_path": f"/projects/{name}",
        "pid": pid,
        "url": f"http://127.0.0.1:{port}",
        "transport": "tcp",
    }


@pytest.fixture
def world(stable, monkeypatch):
    live, schemas, calls = [], {}, []
    monkeypatch.setattr(connections, "instances", lambda: list(live))

    def request(method, endpoint, *, connection, **kwargs):
        target = next((i for i in live if i["url"] == connection.active_tcp), None)
        if target is None:
            raise transport.RequestNotSentError("instance stopped")
        if endpoint == "/mcp/instance_info":
            return json.dumps(target), 200
        calls.append((target["project"], method, endpoint))
        return json.dumps({"project": target["project"], "result": "ok"}), 200

    monkeypatch.setattr(transport, "do_request", request)
    monkeypatch.setattr(registry, "_fetch_schema", lambda connection: schemas[connection.active_tcp])
    return live, schemas, calls


@pytest.mark.asyncio
async def test_same_mcp_session_before_ghidra_start_switch_and_restart(world):
    live, schemas, calls = world
    async with create_connected_server_and_client_session(mcp) as client:
        initial = (await client.list_tools()).model_dump()
        names = {t["name"] for t in initial["tools"]}
        assert {"decompile_function", "rename_function", "disassemble_function"} <= names
        assert "call_analysis_tool" not in names
        assert not json.loads((await client.call_tool("list_instances")).content[0].text)["instances"]
        before = await client.call_tool("decompile_function", {"address": "0x1000", "program": "a"})
        assert "No Ghidra instance connected" in str(before.content)
        assert calls == []
        a, b = instance("alpha", 1, 9001), instance("beta", 2, 9002)
        live.extend([a, b])
        for i in live:
            schemas[i["url"]] = copy.deepcopy(state._full_schema)
        for name in ("alpha", "beta"):
            result = await client.call_tool("connect_instance", {"project": name})
            assert json.loads(result.content[0].text)["connected"]
            result = await client.call_tool("decompile_function", {"address": "0x1000", "program": name})
            assert json.loads(result.content[0].text)["project"] == name
            assert (await client.list_tools()).model_dump() == initial
        # Restart beta at a new port/PID while the MCP client remains open.
        live.remove(b)
        replacement = instance("beta", 3, 9003)
        live.append(replacement)
        schemas[replacement["url"]] = schemas[b["url"]]
        result = await client.call_tool("decompile_function", {"address": "0x1000", "program": "beta"})
        assert json.loads(result.content[0].text)["project"] == "beta"
        assert state.get_connection_snapshot().active_tcp == replacement["url"]
        assert (await client.list_tools()).model_dump() == initial
        result = await client.call_tool("unload_tool_group", {"group": "comment"})
        assert result.isError
        assert (await client.list_tools()).model_dump() == initial


def test_missing_and_incompatible_write_never_sent(world):
    live, schemas, calls = world
    a = instance("alpha", 1, 9001)
    live.append(a)
    schemas[a["url"]] = [t for t in copy.deepcopy(state._full_schema) if t["endpoint"] != "/rename_function"]
    assert connections.connect("alpha")["connected"]
    assert "unavailable" in dispatch.dispatch_post("/rename_function", {"address": "0x1", "new_name": "x"})
    changed = next(t for t in copy.deepcopy(state._full_schema) if t["endpoint"] == "/rename_function")
    changed["input_schema"]["properties"]["program"]["type"] = "integer"
    schemas[a["url"]].append(changed)
    assert connections.connect("alpha")["connected"]
    assert "Incompatible schema" in dispatch.dispatch_post("/rename_function", {"address": "0x1", "new_name": "x"})
    assert calls == []


@pytest.mark.asyncio
async def test_inflight_request_retains_route_and_capabilities_after_switch(world):
    live, schemas, calls = world
    a, b = instance("alpha", 1, 9001), instance("beta", 2, 9002)
    live.extend([a, b])
    schemas[a["url"]] = copy.deepcopy(state._full_schema)
    schemas[b["url"]] = []
    assert connections.connect("alpha")["connected"]
    entered, release = threading.Event(), threading.Event()

    def work():
        entered.set()
        assert release.wait(5)
        return dispatch.dispatch_get("/decompile_function", {"address": "0x1", "program": "a"})

    task = asyncio.create_task(state.run_blocking_ghidra_call(work))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        assert connections.connect("beta")["connected"]
    finally:
        release.set()
    assert json.loads(await task)["project"] == "alpha"
    assert state.get_connection_snapshot().connected_project == "beta"
    assert calls == [("alpha", "GET", "/decompile_function")]


def test_ambiguous_names_and_wrong_identity_leave_connection_untouched(world, monkeypatch):
    live, schemas, calls = world
    a, b = instance("same", 1, 9001), instance("same", 2, 9002)
    b["project_path"] = "/other/same"
    live.extend([a, b])
    schemas[a["url"]] = copy.deepcopy(state._full_schema)
    assert "error" in connections.connect("same")
    assert connections.connect(a["project_path"])["connected"]
    old = state.get_connection_snapshot()
    monkeypatch.setattr(transport, "do_request", lambda *args, **kwargs: (json.dumps(b), 200))
    assert "error" in connections.connect(a["project_path"])
    assert state.get_connection_snapshot() == old


def test_reconnect_of_old_request_does_not_replace_new_selection(world):
    live, schemas, calls = world
    a, b = instance("alpha", 1, 9001), instance("beta", 2, 9002)
    live.extend([a, b])
    for i in live:
        schemas[i["url"]] = copy.deepcopy(state._full_schema)
    connections.connect("alpha")
    old = state.get_connection_snapshot()
    connections.connect("beta")
    live.remove(a)
    fresh = instance("alpha", 3, 9003)
    live.append(fresh)
    schemas[fresh["url"]] = schemas[a["url"]]
    assert connections.reconnect(old).active_tcp == fresh["url"]
    assert state.get_connection_snapshot().connected_project == "beta"


def test_reused_port_never_sends_operation_to_wrong_project(world):
    live, schemas, calls = world
    a = instance("alpha", 1, 9001)
    live.append(a)
    schemas[a["url"]] = copy.deepcopy(state._full_schema)
    connections.connect("alpha")
    live[:] = [instance("beta", 2, 9001)]
    result = dispatch.dispatch_post("/rename_function", {"program": "a"})
    assert "original project unavailable" in result
    assert calls == []


def test_same_port_restart_rechecks_schema_before_write(world):
    live, schemas, calls = world
    a = instance("alpha", 1, 9001)
    live.append(a)
    schemas[a["url"]] = copy.deepcopy(state._full_schema)
    connections.connect("alpha")
    live[:] = [instance("alpha", 2, 9001)]
    schemas[a["url"]] = []
    assert "unavailable" in dispatch.dispatch_post("/rename_function", {"program": "a"})
    assert calls == []


def test_tcp_identity_mismatch_uses_only_verified_socket(stable, monkeypatch):
    a = dict(instance("alpha", 1, 9001), socket="/sockets/alpha.sock")
    monkeypatch.setattr(transport, "uds_supported", lambda: True)
    monkeypatch.setattr(
        transport,
        "do_request",
        lambda *args, connection, **kwargs: (
            json.dumps(a if connection.mode == "uds" else instance("beta", 2, 9001)),
            200,
        ),
    )
    monkeypatch.setattr(registry, "_fetch_schema", lambda connection: [])
    selected = connections.prepare(a)
    assert selected.mode == "uds"
    assert json.loads(selected.binding)["identity"]["project"] == "alpha"


def test_cli_eager_initializes_without_discovery(monkeypatch):
    seen = []
    # main() sets this global; restore it even when this test precedes lazy-mode tests.
    monkeypatch.setattr(state, "_lazy_mode", state._lazy_mode)
    monkeypatch.setattr(sys, "argv", ["bridge-mcp-ghidra", "--no-lazy"])
    monkeypatch.setattr(catalog, "initialize", lambda: seen.append("catalog"))
    monkeypatch.setattr(cli, "_auto_connect", lambda: pytest.fail("startup must not discover instances"))
    monkeypatch.setattr(mcp, "run", lambda **kw: seen.append("serve"))
    cli.main()
    assert seen == ["catalog", "serve"]


def test_headless_project_creation_requires_explicit_reselection(world):
    live, schemas, calls = world
    empty = dict(instance("unknown", 1, 9001), project_path="")
    live.append(empty)
    schemas[empty["url"]] = copy.deepcopy(state._full_schema)
    assert connections.connect(empty["url"])["connected"]
    opened = instance("alpha", 1, 9001)
    live[:] = [opened]
    # An empty server's binding must not silently follow a new project.
    result = dispatch.dispatch_get("/list_open_programs", {})
    assert "error" in result.lower()
    assert calls == []
    assert connections.connect(opened["project_path"])["connected"]
    assert json.loads(dispatch.dispatch_get("/list_open_programs", {}))["project"] == "alpha"


@pytest.mark.parametrize("port", [-1, 0, None, 65536])
def test_socket_only_ignores_unusable_tcp_port(stable, monkeypatch, port):
    identity = dict(instance("alpha", 1, 9001), tcp_port=port, socket="/sockets/alpha.sock")
    del identity["url"]
    monkeypatch.setattr(transport, "uds_supported", lambda: True)
    modes = []

    def request(*args, connection, **kwargs):
        modes.append(connection.mode)
        return json.dumps(identity), 200

    monkeypatch.setattr(transport, "do_request", request)
    monkeypatch.setattr(registry, "_fetch_schema", lambda connection: [])
    assert connections.prepare(identity).mode == "uds"
    assert modes == ["uds"]


@pytest.mark.parametrize("with_cancel", [False, True])
def test_authenticated_tcp_discovery_without_configured_url(monkeypatch, with_cancel):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            self.send_response(200 if seen[-1] == "Bearer regression-token" else 401)
            self.end_headers()
            self.wfile.write(json.dumps(instance("alpha", 1, self.server.server_port)).encode())

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(transport, "AUTH_TOKEN", "regression-token")
    monkeypatch.delenv("GHIDRA_MCP_URL", raising=False)
    monkeypatch.setattr(discovery, "discover_instances", lambda: [])
    monkeypatch.setattr(
        state, "get_request_cancel_handle", lambda: state.RequestCancelHandle() if with_cancel else None
    )
    scan = discovery._iter_tcp_instances
    monkeypatch.setattr(discovery, "_iter_tcp_instances", lambda: scan(server.server_port, 1))
    try:
        assert connections.select("alpha", connections.instances())["project"] == "alpha"
        assert seen == ["Bearer regression-token"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("replacement_project", ["alpha", "wrong-project"])
def test_explicit_unscanned_url_restart_revalidates_project(world, monkeypatch, replacement_project):
    live, schemas, calls = world
    original = instance("alpha", 1, 29089)
    live.append(original)
    schemas[original["url"]] = copy.deepcopy(state._full_schema)
    assert connections.connect(original["url"])["connected"]
    before = state.get_connection_snapshot()
    live[:] = [instance(replacement_project, 2, 29089)]
    monkeypatch.setattr(connections, "instances", lambda: [])
    result = dispatch.dispatch_post("/rename_function", {"program": "alpha"})
    if replacement_project == "alpha":
        assert json.loads(result)["project"] == "alpha"
        assert json.loads(state.get_connection_snapshot().binding)["identity"]["pid"] == 2
    else:
        assert "original project unavailable" in result
        assert calls == []
        assert state.get_connection_snapshot() == before


def test_catalog_startup_under_non_utf8_locale():
    env = dict(os.environ, LC_ALL="C", PYTHONUTF8="0", PYTHONCOERCECLOCALE="0")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from bridge_mcp_ghidra import catalog, state; catalog.initialize(); assert state._catalog_frozen",
        ],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")

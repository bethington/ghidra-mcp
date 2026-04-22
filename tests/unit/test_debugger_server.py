"""
Unit tests for debugger/server.py HTTP routing and response shapes.

Tests the HTTP layer with a mocked DebugEngine — no pybag, no dbgeng, no live
process required. These run fully offline as part of the standard unit suite.

Coverage targets:
  - GET /debugger/status (detached and attached states)
  - POST /debugger/attach (missing param, valid call)
  - POST /debugger/detach
  - GET /debugger/breakpoints (empty and populated)
  - POST /debugger/breakpoint (set)
  - DELETE /debugger/breakpoint/<id> (valid and invalid id)
  - GET /debugger/modules
  - Unknown route → 404
  - Malformed / missing JSON body → 400
"""

from __future__ import annotations

import importlib
import json
import sys
import threading
import types
from http.server import HTTPServer
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from urllib.parse import urlencode

import pytest

# ---------------------------------------------------------------------------
# Full pybag stub — must be installed before ANY debugger.* import.
# Mirrors the pattern in test_debugger_engine.py, including every attribute
# that engine.py copies onto AllDbg at class-definition time.
# ---------------------------------------------------------------------------

def _install_pybag_stubs():
    for name in list(sys.modules):
        if name.startswith("pybag") or name.startswith("debugger"):
            del sys.modules[name]

    fake_pybag = types.ModuleType("pybag")
    fake_pydbg = types.ModuleType("pybag.pydbg")

    class FakeDebuggerBase:
        pass

    fake_pydbg.DebuggerBase = FakeDebuggerBase

    fake_userdbg = types.ModuleType("pybag.userdbg")

    class FakeUserDbg:
        def proc_list(self):
            return []

        def ps(self):
            return []

        def pids_by_name(self, _name):
            return []

        def create(self, *args, **kwargs):
            return None

        def attach(self, *args, **kwargs):
            return None

        def detach(self, *args, **kwargs):
            return None

        def terminate(self, *args, **kwargs):
            return None

    fake_userdbg.UserDbg = FakeUserDbg

    fake_dbgeng = types.ModuleType("pybag.dbgeng")
    fake_core = types.ModuleType("pybag.dbgeng.core")
    fake_core.DEBUG_INTERRUPT_ACTIVE = 1
    fake_core.DEBUG_STATUS_GO = 2
    fake_core.DEBUG_BREAKPOINT_CODE = 3
    fake_core.DEBUG_BREAKPOINT_ENABLED = 4
    fake_core.DEBUG_BREAKPOINT_ONE_SHOT = 8
    fake_core.DEBUG_BREAKPOINT_DATA = 16
    fake_core.DEBUG_STATUS_NO_CHANGE = 0

    fake_exception = types.ModuleType("pybag.dbgeng.exception")

    class FakeDbgEngTimeout(Exception):
        pass

    fake_exception.DbgEngTimeout = FakeDbgEngTimeout

    fake_pybag.pydbg = fake_pydbg
    fake_pybag.userdbg = fake_userdbg
    fake_pybag.dbgeng = fake_dbgeng
    fake_dbgeng.core = fake_core
    fake_dbgeng.exception = fake_exception

    sys.modules["pybag"] = fake_pybag
    sys.modules["pybag.pydbg"] = fake_pydbg
    sys.modules["pybag.userdbg"] = fake_userdbg
    sys.modules["pybag.dbgeng"] = fake_dbgeng
    sys.modules["pybag.dbgeng.core"] = fake_core
    sys.modules["pybag.dbgeng.exception"] = fake_exception


# Install stubs before any debugger.* import.
_install_pybag_stubs()

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from debugger.protocol import BreakpointInfo, BreakpointType, DebuggerState, ModuleInfo
from debugger.address_map import AddressMapper
from debugger.server import DebuggerHTTPServer, DebuggerServer, RequestHandler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_engine(state: DebuggerState = DebuggerState.DETACHED) -> MagicMock:
    engine = MagicMock()
    engine.get_state.return_value = state
    engine.get_target_pid.return_value = None
    engine.get_target_name.return_value = None
    engine.list_breakpoints.return_value = []
    engine.get_modules.return_value = []
    engine.read_memory.return_value = b"\x00" * 16
    engine.get_registers.return_value = {}
    engine.get_stack_trace.return_value = []
    return engine


def _make_debugger_server(engine=None) -> DebuggerServer:
    ds = MagicMock(spec=DebuggerServer)
    ds.engine = engine or _make_mock_engine()
    ds.mapper = AddressMapper()
    ds.tracer = None
    return ds


# ---------------------------------------------------------------------------
# Fixture: live DebuggerHTTPServer backed by mocked engine
# ---------------------------------------------------------------------------

@pytest.fixture()
def debug_server():
    """Start a real DebuggerHTTPServer on a random port with mocked internals."""
    mock_ds = _make_debugger_server()
    httpd = DebuggerHTTPServer(("127.0.0.1", 0), RequestHandler, mock_ds)

    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    port = httpd.server_address[1]
    base = f"http://127.0.0.1:{port}"

    yield base, mock_ds

    httpd.shutdown()


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(base: str, path: str, params: Optional[dict] = None) -> tuple[int, dict]:
    url = base + path
    if params:
        url += "?" + urlencode(params)
    try:
        with urlopen(Request(url), timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _post(base: str, path: str, body: Optional[dict] = None) -> tuple[int, dict]:
    data = json.dumps(body or {}).encode()
    req = Request(base + path, data=data,
                  headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _delete(base: str, path: str) -> tuple[int, dict]:
    req = Request(base + path, method="DELETE")
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


# ---------------------------------------------------------------------------
# Tests: status
# ---------------------------------------------------------------------------

class TestStatusEndpoint:

    def test_status_detached_returns_200(self, debug_server):
        base, ds = debug_server
        ds.engine.get_state.return_value = DebuggerState.DETACHED
        status, body = _get(base, "/debugger/status")
        assert status == 200

    def test_status_detached_state_value(self, debug_server):
        base, ds = debug_server
        ds.engine.get_state.return_value = DebuggerState.DETACHED
        _, body = _get(base, "/debugger/status")
        assert body.get("state") == DebuggerState.DETACHED.value

    def test_status_attached_state_value(self, debug_server):
        base, ds = debug_server
        ds.engine.get_state.return_value = DebuggerState.ATTACHED
        ds.engine.get_target_pid.return_value = 1234
        ds.engine.get_target_name.return_value = "game.exe"
        ds.engine.get_modules.return_value = []
        ds.engine.list_breakpoints.return_value = []
        _, body = _get(base, "/debugger/status")
        assert body.get("state") == DebuggerState.ATTACHED.value

    def test_status_has_state_key(self, debug_server):
        base, ds = debug_server
        ds.engine.get_state.return_value = DebuggerState.DETACHED
        _, body = _get(base, "/debugger/status")
        assert "state" in body


# ---------------------------------------------------------------------------
# Tests: attach
# ---------------------------------------------------------------------------

class TestAttachEndpoint:

    def test_attach_missing_target_returns_400(self, debug_server):
        base, _ = debug_server
        status, body = _post(base, "/debugger/attach", {})
        assert status == 400
        assert "error" in body

    def test_attach_calls_engine_with_target(self, debug_server):
        base, ds = debug_server
        ds.engine.attach.return_value = {"status": "attached", "pid": 9999}
        status, _ = _post(base, "/debugger/attach", {"target": "game.exe"})
        assert status == 200
        ds.engine.attach.assert_called_once_with("game.exe")

    def test_attach_with_pid_field_calls_engine(self, debug_server):
        base, ds = debug_server
        ds.engine.attach.return_value = {"status": "attached", "pid": 1234}
        status, _ = _post(base, "/debugger/attach", {"pid": "1234"})
        assert status == 200
        ds.engine.attach.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: detach
# ---------------------------------------------------------------------------

class TestDetachEndpoint:

    def test_detach_calls_engine(self, debug_server):
        base, ds = debug_server
        ds.engine.detach.return_value = {"status": "detached"}
        status, _ = _post(base, "/debugger/detach")
        assert status == 200
        ds.engine.detach.assert_called_once()

    def test_detach_stops_active_tracer(self, debug_server):
        base, ds = debug_server
        tracer = MagicMock()
        ds.tracer = tracer
        ds.engine.detach.return_value = {"status": "detached"}
        _post(base, "/debugger/detach")
        tracer.stop_all.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: breakpoints
# ---------------------------------------------------------------------------

class TestBreakpointEndpoints:

    def test_list_breakpoints_returns_200(self, debug_server):
        base, ds = debug_server
        ds.engine.list_breakpoints.return_value = []
        status, body = _get(base, "/debugger/breakpoints")
        assert status == 200
        assert "breakpoints" in body

    def test_list_breakpoints_empty(self, debug_server):
        base, ds = debug_server
        ds.engine.list_breakpoints.return_value = []
        _, body = _get(base, "/debugger/breakpoints")
        assert body["breakpoints"] == []

    def test_list_breakpoints_serializes_breakpoint(self, debug_server):
        base, ds = debug_server
        # list_breakpoints returns dicts (engine serializes internally)
        bp_dict = {"id": 1, "address": "0x00401000", "type": "software",
                   "enabled": True, "oneshot": False, "hit_count": 0}
        ds.engine.list_breakpoints.return_value = [bp_dict]
        _, body = _get(base, "/debugger/breakpoints")
        bps = body.get("breakpoints", [])
        assert len(bps) == 1
        assert bps[0]["id"] == 1

    def test_set_breakpoint_calls_engine(self, debug_server):
        base, ds = debug_server
        ds.engine.set_breakpoint.return_value = 1  # returns bp_id
        status, _ = _post(base, "/debugger/breakpoint", {"runtime_address": "0x401000"})
        assert status == 200

    def test_delete_breakpoint_calls_engine(self, debug_server):
        base, ds = debug_server
        ds.engine.remove_breakpoint.return_value = {"removed": True}
        status, _ = _delete(base, "/debugger/breakpoint/1")
        assert status == 200

    def test_delete_breakpoint_invalid_id_returns_400(self, debug_server):
        base, _ = debug_server
        status, _ = _delete(base, "/debugger/breakpoint/notanumber")
        assert status == 400


# ---------------------------------------------------------------------------
# Tests: modules
# ---------------------------------------------------------------------------

class TestModulesEndpoint:

    def test_modules_returns_200(self, debug_server):
        base, ds = debug_server
        ds.engine.get_modules.return_value = []
        status, body = _get(base, "/debugger/modules")
        assert status == 200
        assert "modules" in body
        assert "count" in body

    def test_modules_count_matches_list_length(self, debug_server):
        base, ds = debug_server
        ds.engine.get_modules.return_value = [
            ModuleInfo(name="game.exe", runtime_base=0x400000, size=0x100000),
        ]
        _, body = _get(base, "/debugger/modules")
        assert body["count"] == len(body["modules"])


# ---------------------------------------------------------------------------
# Tests: routing
# ---------------------------------------------------------------------------

class TestRouting:

    def test_unknown_get_route_returns_404(self, debug_server):
        base, _ = debug_server
        status, _ = _get(base, "/debugger/nonexistent")
        assert status == 404

    def test_unknown_post_route_returns_404(self, debug_server):
        base, _ = debug_server
        status, _ = _post(base, "/debugger/nonexistent")
        assert status == 404

    def test_unknown_delete_route_returns_404(self, debug_server):
        base, _ = debug_server
        status, _ = _delete(base, "/debugger/nonexistent")
        assert status == 404

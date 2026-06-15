"""Connection/HTTP-layer integration tests against a live Ghidra instance.

These exercise the bridge's request plumbing directly (no MCP client): URL
routing, schema fetch/registration, and read-only GET dispatch. Nothing here
mutates the open program.
"""

import json

from ghidra_mcp_bridge import connection, registry
from ghidra_mcp_bridge.config import STATIC_TOOL_NAMES


def test_instance_info_round_trips(live_bridge: int) -> None:
    text, status = connection.do_request("GET", "/mcp/instance_info", timeout=5)
    assert status == 200
    info = json.loads(text)
    assert "project" in info
    assert info["tcp_port"] == 8089


def test_schema_registers_tools(live_bridge: int) -> None:
    # live_bridge already fetched + registered; re-fetch should be consistent.
    count = registry.fetch_and_register_schema()
    assert count == live_bridge
    assert count == len(registry.dynamic_tool_names())
    assert count > 0

    # Every registered dynamic tool count should match the raw catalog minus
    # any tools whose name collides with a reserved static bridge tool.
    raw_text, raw_status = connection.do_request("GET", "/mcp/schema", timeout=10)
    assert raw_status == 200
    raw_count = len(json.loads(raw_text)["tools"])
    assert raw_count - len(STATIC_TOOL_NAMES) <= count <= raw_count


def test_list_open_programs(live_bridge: int) -> None:
    result = json.loads(connection.dispatch_get("/list_open_programs"))
    assert "error" not in result
    assert isinstance(result["programs"], list)
    assert result["current_program"]


def test_dynamic_get_tool_round_trips(live_bridge: int) -> None:
    # analysis_status is a read-only GET tool returning JSON.
    result = json.loads(connection.dispatch_get("/analysis_status"))
    assert "error" not in result
    assert "analyzed" in result
    assert isinstance(result["function_count"], int)

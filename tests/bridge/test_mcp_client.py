"""Full MCP-layer integration tests via an in-memory FastMCP client.

These drive the real MCP surface of the singleton bridge app: the BM25 search
transform (search_tools / call_tool), the always-visible bridge tools, and
round-tripping a read-only dynamic Ghidra tool through the call_tool proxy.
"""

import json

import pytest


def _text(result) -> str:
    """Extract the textual payload from a CallToolResult."""
    return result.content[0].text


async def test_always_visible_tools(mcp_client) -> None:
    names = {t.name for t in await mcp_client.list_tools()}
    # The BM25 transform collapses the large catalog to these synthetic +
    # always-visible tools (see app.py).
    assert names == {"search_tools", "call_tool", "list_instances", "connect_instance"}


async def test_list_instances_reports_tcp_connection(mcp_client) -> None:
    result = await mcp_client.call_tool("list_instances", {})
    payload = _text(result)
    assert "8089" in payload  # the connected TCP instance is reported


async def test_search_tools_finds_decompile(mcp_client) -> None:
    result = await mcp_client.call_tool("search_tools", {"query": "decompile"})
    matches = json.loads(_text(result))
    assert isinstance(matches, list)
    assert matches
    assert any("decompile" in m["name"].lower() for m in matches)


async def test_call_tool_proxy_invokes_dynamic_tool(mcp_client) -> None:
    # get_metadata is a read-only tool; invoke it through the synthetic proxy.
    result = await mcp_client.call_tool(
        "call_tool", {"name": "get_metadata", "arguments": {}}
    )
    payload = _text(result)
    assert "error" not in payload.lower()
    assert "Program Name:" in payload


async def test_call_tool_rejects_synthetic_names(mcp_client) -> None:
    # The proxy must refuse to call itself or the search tool.
    with pytest.raises(Exception):
        await mcp_client.call_tool(
            "call_tool", {"name": "search_tools", "arguments": {"query": "x"}}
        )

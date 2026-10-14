"""Defaults inserted by FastMCP must not mask a supplied parameter alias."""

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from mcp.server.fastmcp.tools.base import Tool

from bridge_mcp_ghidra.registry import _build_tool_function
from bridge_mcp_ghidra.schema import _parse_schema


def schema_tool(path):
    snapshot = Path(__file__).parents[1] / "conformance/snapshots/mcp_schema.snap"
    raw = json.loads(snapshot.read_text(encoding="utf-8"))
    definition = next(t for t in _parse_schema(raw) if t["endpoint"] == path)
    handler = _build_tool_function(path, definition["http_method"], definition["input_schema"])
    return Tool.from_function(handler, name="alias_default_test", structured_output=False)


@pytest.mark.parametrize(
    "arguments,expected",
    [
        ({"call_context_window": 9}, "9"),
        ({"call_context_lines": 5, "call_context_window": 9}, "5"),
        ({}, "3"),
    ],
)
def test_call_context_alias_and_default(arguments, expected):
    tool = schema_tool("/get_functions")
    with patch("bridge_mcp_ghidra.dispatch.dispatch_get", return_value='{"ok":true}') as get:
        asyncio.run(tool.run({"function": "main", **arguments}))
    params = get.call_args.kwargs["params"]
    assert params["call_context_lines"] == expected
    assert "call_context_window" not in params


def test_nonempty_array_default_does_not_mask_alias():
    handler = _build_tool_function(
        "/aliased_array",
        "POST",
        {
            "properties": {"items": {"type": "array", "source": "body", "default": "[]", "aliases": ["entries"]}},
        },
    )
    tool = Tool.from_function(handler, name="array_alias_test", structured_output=False)
    value = [{"ordinal": 0, "name": "arg"}]
    with patch("bridge_mcp_ghidra.dispatch.dispatch_post", return_value='{"ok":true}') as post:
        asyncio.run(tool.run({"entries": value}))
    assert post.call_args.kwargs["data"]["items"] == value


def test_documentation_parameters_alias_reaches_http_body():
    tool = schema_tool("/apply_documentation")
    value = [{"ordinal": 0, "name": "pBuffer", "type": "void *"}]
    arguments = {
        "address": "0x1000",
        "parameters": value,
        "variable_types": {},
        "variable_renames": {},
        "tag_comments": {},
    }
    with patch("bridge_mcp_ghidra.dispatch.dispatch_post", return_value='{"ok":true}') as post:
        asyncio.run(tool.run(arguments))
    assert post.call_args.kwargs["data"]["params"] == value
    assert "parameters" not in post.call_args.kwargs["data"]

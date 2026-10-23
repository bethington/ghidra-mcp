"""Exercise Java Object parameters through FastMCP's real argument validation."""

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
    return Tool.from_function(handler, name="any_parameter_test", structured_output=False)


@pytest.mark.parametrize("definition", [{"type": "dword"}, {"count": 4, "element_type": "byte"}])
def test_classification_accepts_native_object(definition):
    tool = schema_tool("/apply_data_classification")
    arguments = {"address": "0x1000", "classification": "PRIMITIVE", "type_definition": definition}
    with patch("bridge_mcp_ghidra.dispatch.dispatch_post", return_value='{"ok":true}') as post:
        asyncio.run(tool.run(arguments))
    assert post.call_args.kwargs["data"]["type_definition"] == definition
    assert isinstance(post.call_args.kwargs["data"]["type_definition"], dict)


@pytest.mark.parametrize("sources", [["0x1000", "ram:2000"], "0x1000,ram:2000"])
def test_assembly_context_preserves_both_supported_shapes(sources):
    tool = schema_tool("/get_assembly_context")
    with patch("bridge_mcp_ghidra.dispatch.dispatch_post", return_value='{"ok":true}') as post:
        asyncio.run(tool.run({"xref_sources": sources}))
    assert post.call_args.kwargs["data"]["xref_sources"] == sources


@pytest.mark.parametrize("value", [False, 7, 1.5, [1, {"key": True}], {"nested": [None, False]}])
def test_any_binding_preserves_json_values(value):
    handler = _build_tool_function(
        "/object_echo",
        "POST",
        {
            "properties": {"value": {"type": "any", "source": "body"}},
            "required": ["value"],
        },
    )
    tool = Tool.from_function(handler, name="any_echo_test", structured_output=False)
    with patch("bridge_mcp_ghidra.dispatch.dispatch_post", return_value='{"ok":true}') as post:
        asyncio.run(tool.run({"value": value}))
    assert post.call_args.kwargs["data"]["value"] == value

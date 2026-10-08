"""Structure descriptions reuse set_comment without requiring a memory address."""

from unittest.mock import patch

import pytest

from bridge_mcp_ghidra import _build_tool_function


@pytest.mark.parametrize("comment", ["Object metadata\nContains café", ""])
def test_struct_description_dispatch_preserves_text_and_needs_no_address(comment):
    schema = {
        "properties": {
            "address": {"type": "string", "source": "body", "param_type": "address", "default": ""},
            "comment": {"type": "string", "source": "body", "allow_empty": True},
            "type": {"type": "string", "source": "body", "default": "plate"},
            "program": {"type": "string", "source": "query", "default": ""},
            "struct_name": {"type": "string", "source": "body", "default": ""},
        },
        "required": ["comment"],
    }
    tool = _build_tool_function("/set_comment", "POST", schema)
    with patch("bridge_mcp_ghidra.dispatch.dispatch_post", return_value="ok") as dispatch:
        assert tool(type="struct", struct_name="/Types/S", comment=comment, program="sample") == "ok"
    dispatch.assert_called_once_with(
        "/set_comment",
        data={"type": "struct", "struct_name": "/Types/S", "comment": comment},
        query_params={"program": "sample"},
    )

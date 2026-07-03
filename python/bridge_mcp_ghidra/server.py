"""The FastMCP server singleton and its initialization-options patch."""

from mcp.server.fastmcp import FastMCP, Context  # noqa: F401  (Context re-exported)
from mcp.server.lowlevel.server import NotificationOptions

# The MCP server singleton. All static and dynamically registered tools attach
# to this object.
mcp = FastMCP("ghidra-mcp")

# Enable tools/list_changed notifications so clients re-fetch tools after
# dynamic registration.
_orig_init_options = mcp._mcp_server.create_initialization_options


def _patched_init_options(**kwargs):
    return _orig_init_options(
        notification_options=NotificationOptions(tools_changed=True), **kwargs
    )


mcp._mcp_server.create_initialization_options = _patched_init_options

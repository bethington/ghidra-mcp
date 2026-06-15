"""The shared FastMCP application instance.

Kept in its own module so every other module can import the singleton without
creating import cycles through ``server.py`` (which wires everything together).
"""

from fastmcp import FastMCP
from fastmcp.server.transforms.search import BM25SearchTransform

# fastmcp 3.x advertises tools.listChanged=True by default and auto-emits
# notifications/tools/list_changed when tools are added/removed, so no
# initialization-options monkeypatch is needed here.
#
# The catalog is large and variable (static bridge/debugger tools plus dozens
# of dynamic Ghidra tools registered on connect). Rather than flooding the
# client's context with every tool, the BM25 search transform collapses
# list_tools to two synthetic tools -- search_tools and call_tool -- while
# keeping every real tool registered and callable. Clients discover tools on
# demand via search_tools (which returns full schemas) and invoke them via
# call_tool. The bridge essentials below stay directly visible so a client can
# always orient and connect without searching first.
mcp = FastMCP(
    "ghidra-mcp",
    transforms=[
        BM25SearchTransform(
            max_results=10,  # catalog is large; the default of 5 is tight
            always_visible=["list_instances", "connect_instance"],
        )
    ],
)

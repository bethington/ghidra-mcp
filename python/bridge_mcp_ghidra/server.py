"""The FastMCP server singleton and its initialization-options patch."""

from mcp import types
from mcp.server.fastmcp import FastMCP, Context  # noqa: F401  (Context re-exported)
from mcp.server.lowlevel.server import NotificationOptions

# `state` imports only from `config`, so this cannot cycle back through here.
from . import state as _state

# The MCP server singleton. All static and dynamically registered tools attach
# to this object.
mcp = FastMCP("ghidra-mcp")

# Enable tools/list_changed notifications so clients re-fetch tools after
# dynamic registration.
_orig_init_options = mcp._mcp_server.create_initialization_options


def _patched_init_options(**kwargs):
    options = _orig_init_options(
        notification_options=NotificationOptions(tools_changed=True), **kwargs
    )
    _drop_unimplemented_capabilities(options)
    return options


def _drop_unimplemented_capabilities(options) -> None:
    """Stop advertising `prompts` and `resources` while there are none.

    FastMCP registers handlers for both unconditionally, so the handshake
    claimed both capabilities and then answered `prompts/list` and
    `resources/list` with empty arrays — clients render dead sections for
    features this bridge does not provide. Gated on emptiness rather than
    hardcoded off, so the capability reappears by itself if a prompt or
    resource is ever registered.
    """
    capabilities = getattr(options, "capabilities", None)
    if capabilities is None:  # pragma: no cover - SDK shape changed
        return
    if not mcp._prompt_manager.list_prompts():
        capabilities.prompts = None
    resources = mcp._resource_manager.list_resources()
    templates = mcp._resource_manager.list_templates()
    if not resources and not templates:
        capabilities.resources = None


def enable_tool_pagination(page_size: int) -> None:
    """Serve `tools/list` in pages of ``page_size``.

    Off unless asked for, and that is not timidity: pagination is optional in the
    spec, a client that ignores ``nextCursor`` sees only the first page, and this
    server exposes ~250 tools. Claude Code, for instance, has explicit cursor
    loops for ``resources/list`` and ``skills/list`` but none for ``tools/list``,
    so defaulting this on would hide most of the toolset from it. Turn it on for
    a client that cannot take a single ~100KB response (159 tools measured at
    98,834 bytes).

    The cursor is the last name returned, over a name-sorted list, rather than an
    index: the tool list is not fixed here — ``load_tool_group`` and a reconnect
    both rewrite it — and an index cursor would then skip or repeat entries.
    Resuming after a name works even if that tool has since been unloaded, so a
    stale cursor degrades to a correct continuation instead of an error.
    """

    @mcp._mcp_server.list_tools()
    async def _list_tools_paginated(
        request: types.ListToolsRequest,
    ) -> types.ListToolsResult:
        tools = sorted(await mcp.list_tools(), key=lambda t: t.name)
        cursor = request.params.cursor if request.params else None
        if cursor:
            tools = [tool for tool in tools if tool.name > cursor]
        page = tools[:page_size]
        remaining = len(tools) > page_size
        return types.ListToolsResult(
            tools=page,
            nextCursor=page[-1].name if (page and remaining) else None,
        )


mcp._mcp_server.create_initialization_options = _patched_init_options


# Capture the client's session the first time it lists tools.
#
# Enabling the tools_changed capability above is only half of it: something has
# to hold a reference to the session so a background thread can actually send
# the notification. That reference used to be captured only inside
# connect_instance/load_tool_group/unload_tool_group/import_file, i.e. only
# after the client called one of those tools -- which it never does when the
# tools it wants are the ones still missing. tools/list is the one request
# every MCP client issues right after initialize, so capturing here guarantees
# a target exists before the auto-connect retry thread can succeed.
_orig_list_tools = mcp.list_tools


async def _list_tools_capturing_session():
    try:
        # Set by the low-level server for every request, including this one.
        _state.remember_tools_changed_session(mcp._mcp_server.request_context.session)
    except (LookupError, AttributeError):
        # No active request context (direct call, e.g. from a test) -- nothing
        # to capture, and listing tools must not fail because of it.
        pass
    return await _orig_list_tools()


mcp.list_tools = _list_tools_capturing_session
mcp._mcp_server.list_tools()(_list_tools_capturing_session)

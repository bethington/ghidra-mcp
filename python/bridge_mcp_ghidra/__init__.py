"""GhidraMCP Bridge — thin MCP↔HTTP multiplexer.

On startup: exposes list_instances + connect_instance (plus tool-group and
debugger proxy tools). On connect_instance: fetches /mcp/schema from the Ghidra
server and dynamically registers every analysis tool as a generic HTTP
dispatcher.

Supports two transports to Ghidra:
  - UDS (Unix domain sockets) — preferred for local instances
  - TCP (HTTP) — fallback for headless/remote servers

This package was split out of the historical single-file ``bridge_mcp_ghidra.py``.
The public names below are re-exported for backwards compatibility; mutable
runtime state lives in :mod:`bridge_mcp_ghidra.state` and must be read/written
through that module.
"""

# Import submodules in dependency order. Importing static_tools and debugger
# runs their mcp tool decorators, registering the static tools on the server
# — matching the original single-module import-time behavior.
from . import config  # noqa: F401
from . import state  # noqa: F401
from . import server  # noqa: F401
from . import validation  # noqa: F401
from . import transport  # noqa: F401
from . import discovery  # noqa: F401
from . import schema  # noqa: F401
from . import dispatch  # noqa: F401
from . import registry  # noqa: F401
from . import static_tools  # noqa: F401
from . import debugger  # noqa: F401
from . import cli  # noqa: F401

# --- Public re-exports (backwards-compatible flat API) --------------------

from .config import (  # noqa: F401
    CORE_GROUPS,
    DEBUGGER_URL,
    DEBUGGER_TOOL_NAMES,
    DEFAULT_TCP_PORT,
    DEFAULT_TCP_URL,
    ENDPOINT_TIMEOUTS,
    MANAGEMENT_TOOL_NAMES,
    STATIC_TOOL_NAMES,
    TCP_PORT_SCAN_RANGE,
    _ALL_STATIC_TOOL_NAMES,
    logger,
)
from .server import Context, mcp  # noqa: F401
from .validation import (  # noqa: F401
    HEX_ADDRESS_PATTERN,
    MAX_TOOL_NAME_LENGTH,
    SEGMENT_ADDR_WITH_0X_PATTERN,
    SEGMENT_ADDRESS_PATTERN,
    TOOL_NAME_PATTERN,
    _allocate_tool_name,
    is_pid_alive,
    sanitize_address,
    sanitize_tool_name,
    validate_hex_address,
    validate_server_url,
    validate_tool_name,
)
from .transport import (  # noqa: F401
    UnixHTTPConnection,
    do_request,
    get_socket_dir,
    get_socket_dir_candidates,
    tcp_request,
    uds_request,
)
from .discovery import (  # noqa: F401
    _scan_tcp_for_project,
    _unwrap_response_data,
    discover_active_tcp_instance,
    discover_instances,
)
from .schema import _normalize_tool_def_names, _parse_schema  # noqa: F401
from .dispatch import (  # noqa: F401
    _ensure_connected,
    _try_reconnect,
    dispatch_get,
    dispatch_post,
    get_timeout,
)
from .registry import (  # noqa: F401
    _build_tool_function,
    _fetch_and_register_schema,
    _get_group_info,
    _load_group,
    _notify_tools_changed,
    _register_tool_def,
    _unload_group,
    register_tools_from_schema,
)
from .static_tools import (  # noqa: F401
    _auto_connect,
    check_tools,
    connect_instance,
    import_file,
    list_instances,
    list_tool_groups,
    load_tool_group,
    search_tools,
    unload_tool_group,
)
from .debugger import (  # noqa: F401
    _DEBUGGER_ACTIVE,
    _debugger_enabled,
    _debugger_request,
    _debugger_tool,
    debugger_attach,
    debugger_continue,
    debugger_detach,
    debugger_list_breakpoints,
    debugger_modules,
    debugger_read_args,
    debugger_read_memory,
    debugger_registers,
    debugger_remove_breakpoint,
    debugger_resolve_ordinal,
    debugger_set_breakpoint,
    debugger_stack_trace,
    debugger_status,
    debugger_step_into,
    debugger_step_over,
    debugger_trace_function,
    debugger_trace_list,
    debugger_trace_log,
    debugger_trace_stop,
    debugger_watch_log,
    debugger_watch_memory,
    debugger_watch_stop,
)

# These two are only ever mutated in place (clear/append/add/discard), so the
# re-exported references stay valid. Reassigned state (_transport_mode,
# _active_socket, _full_schema, _lazy_mode, …) is intentionally NOT re-exported
# here — read/write it through ``bridge_mcp_ghidra.state`` to avoid stale binds.
from .state import _dynamic_tool_names, _loaded_groups  # noqa: F401

from .cli import main  # noqa: F401

try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("ghidra-mcp-bridge")
except Exception:  # running from source without an installed distribution
    __version__ = "5.15.0"

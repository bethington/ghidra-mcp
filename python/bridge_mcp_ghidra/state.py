"""Mutable connection and tool-registration state shared across the bridge.

All cross-module readers and writers reference these names through this module
object (e.g. ``state._transport_mode``) so a single source of truth is mutated.
Functions in other modules never use ``global`` on these names — they assign
``state.<name> = ...`` instead.
"""

import threading

from .config import CORE_GROUPS

# --------------------------------------------------------------------------
# Connection state
# --------------------------------------------------------------------------

_active_socket: str | None = None  # UDS socket path
_active_tcp: str | None = None  # TCP base URL (e.g. "http://127.0.0.1:8089")
_transport_mode: str = "none"  # "uds", "tcp", or "none"
_connected_project: str | None = None  # Project name for auto-reconnect

# Serialization lock for Ghidra HTTP calls — prevents stdout corruption when
# multiple MCP tool calls arrive concurrently (see GitHub issue #91).
_ghidra_lock = threading.Lock()

# --------------------------------------------------------------------------
# Tool-registration state
# --------------------------------------------------------------------------

# NOTE: _dynamic_tool_names and _loaded_groups are only ever mutated in place
# (clear/append/add/discard) so external references stay valid. _full_schema,
# _lazy_mode, and _default_groups ARE reassigned — always read them through
# this module.
_dynamic_tool_names: list[str] = []
_full_schema: list[dict] = []  # Complete parsed schema
_loaded_groups: set[str] = set()

# CLI-configurable: --lazy keeps only default groups, otherwise load all
_lazy_mode = False  # default: eager (load all groups on connect)
_default_groups: set[str] = set(CORE_GROUPS)

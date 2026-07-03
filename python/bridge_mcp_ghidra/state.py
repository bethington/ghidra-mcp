"""Mutable connection and tool-registration state shared across the bridge.

All cross-module readers and writers reference these names through this module
object (e.g. ``state._transport_mode``) so a single source of truth is mutated.
Functions in other modules never use ``global`` on these names — they assign
``state.<name> = ...`` instead.
"""

import os
import threading

from .config import CORE_GROUPS, logger

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
# Strict program routing
# --------------------------------------------------------------------------

# When GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1, the bridge refuses any
# program-scoped call that omits a program selector, so a forgotten one fails
# loudly instead of silently running against the server's mutable "current
# program" and hitting the wrong binary. Off by default. (Full rationale in
# commit 6f85c5e / README.)
_require_selectors: bool = False


def _init_require_selectors() -> None:
    """Read GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS once, at import. Set it to 1 to enable."""
    global _require_selectors
    _require_selectors = (os.getenv("GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS") or "").strip() == "1"
    if _require_selectors:
        logger.info(
            "Strict program routing enabled (GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1); "
            "program-scoped calls missing a program selector will be refused"
        )


_init_require_selectors()

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

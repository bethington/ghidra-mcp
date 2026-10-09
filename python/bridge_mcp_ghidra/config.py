"""Configuration constants, timeouts, environment, and logging for the bridge."""

import logging
import os

from mcp.types import ToolAnnotations

# ==========================================================================
# MCP tool annotations
# ==========================================================================
# The hints clients act on. Claude Code derives read-only-ness solely from
# readOnlyHint (absent ⇒ false) and, in plan mode, forces a permission prompt
# for every MCP tool that is not read-only — a prompt no allow-rule can
# suppress. It gates parallel execution on the same flag. Every statically
# defined tool therefore declares one of these three.
#
# openWorldHint is left unset throughout: it would be false for nearly every
# tool but not all of them, and no client gates behaviour on it.
READ_ONLY_TOOL = ToolAnnotations(readOnlyHint=True, destructiveHint=False)
WRITE_TOOL = ToolAnnotations(readOnlyHint=False, destructiveHint=False)
DESTRUCTIVE_TOOL = ToolAnnotations(readOnlyHint=False, destructiveHint=True)

# ==========================================================================
# Request timeouts
# ==========================================================================

# Per-endpoint timeout overrides for expensive operations
ENDPOINT_TIMEOUTS = {
    "rename_variables": 120,
    "batch_rename_variables": 120,
    "batch_set_comments": 120,
    "analyze_function_complete": 120,
    "batch_rename_function_components": 120,
    "set_variables": 90,
    "analyze_data_region": 90,
    "create_label": 60,
    "delete_label": 60,
    "disassemble_bytes": 120,
    "bulk_fuzzy_match": 180,
    "find_similar_functions_fuzzy": 60,
    "import_file": 300,
    "run_ghidra_script": 1800,
    "run_script_inline": 1800,
    # Ghidra's default decompile cap is 60s. The bridge must outlive it so the
    # plugin can return a structured timeout instead of writing into a closed
    # socket after the client has already gone away.
    "get_functions": 75,
    "set_function_prototype": 45,
    "rename_function": 45,
    "consolidate_duplicate_types": 60,
    "analyze_function_completeness": 120,
    "apply_documentation": 90,
    # get_timeout() keys on the LAST path segment, so "/debugger/launch"
    # looks up "launch" here, not "debugger_launch" -- easy to miss when
    # adding overrides for nested debugger/* routes.
    "launch": 120,
    "default": 30,
}

REQUEST_TIMEOUT_GRACE_SECONDS = 15
# Long-running endpoints may legitimately ask Ghidra to spend 1800 seconds on
# work (for example run_script_inline/run_ghidra_script or a user-raised
# decompile timeout). Keep the transport alive slightly longer so the bridge can
# receive and forward Ghidra's final status instead of closing first.
MAX_REQUEST_TIMEOUT_SECONDS = 1815

try:
    MAX_CONCURRENT_GHIDRA_REQUESTS = max(1, int(os.getenv("GHIDRA_MCP_MAX_CONCURRENT_REQUESTS", "4")))
except ValueError:
    MAX_CONCURRENT_GHIDRA_REQUESTS = 4

DEFAULT_TCP_URL = "http://127.0.0.1:8089"
DEFAULT_TCP_PORT = 8089
# When set, forwarded to the Ghidra server as `Authorization: Bearer <token>`.
# Same env var the plugin/headless server enforces (v5.4.1+); unset = no header.
AUTH_TOKEN = (os.getenv("GHIDRA_MCP_AUTH_TOKEN") or "").strip()
# Bridge-side TCP port scan range. Mirrors the plugin's
# TCP_PORT_FALLBACK_RANGE so a TCP-only multi-instance setup (e.g. Windows
# 10 pre-1803 where AF_UNIX is unavailable) can still be discovered without
# having to set GHIDRA_MCP_URL per instance. See issue #175 + Copilot review.
TCP_PORT_SCAN_RANGE = 16

# Debugger proxy target: an external dbgeng (WinDbg engine) debugger server,
# not part of this repo. DEBUGGER_URL_EXPLICIT records whether the operator
# actually set GHIDRA_DEBUGGER_URL: the 22 debugger proxy tools are off by
# default and only register when it is set (or GHIDRA_DEBUGGER_TOOLS is truthy).
# The fallback URL below is a default port, not evidence that a server exists.
# A blank value counts as unset.
_DEBUGGER_URL_ENV = (os.getenv("GHIDRA_DEBUGGER_URL") or "").strip()
DEBUGGER_URL_EXPLICIT = bool(_DEBUGGER_URL_ENV)
DEBUGGER_URL = _DEBUGGER_URL_ENV or "http://127.0.0.1:8099"

# ==========================================================================
# Logging
# ==========================================================================

LOG_LEVEL = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("bridge_mcp_ghidra")

# ==========================================================================
# Tool-group / static-tool catalog constants
# ==========================================================================

MANAGEMENT_TOOL_NAMES = {
    "list_instances",
    "connect_instance",
    "list_tool_groups",
    "load_tool_group",
    "unload_tool_group",
    "check_tools",
    "search_tools",
    "import_file",
}

# WinDbg debugger proxy tools. They forward to an external dbgeng debugger
# server (not part of this repo) and are OFF BY DEFAULT: registered only when
# GHIDRA_DEBUGGER_URL is set or GHIDRA_DEBUGGER_TOOLS is truthy; see
# debugger._debugger_enabled(). The names are always listed in
# _ALL_STATIC_TOOL_NAMES (validated at import, counted by the catalog tests);
# collision handling uses the ACTIVE set (STATIC_TOOL_NAMES): while the proxies
# are off, Ghidra's own TraceRmi /debugger/status registers as debugger_status;
# when they are on, the proxy holds that name and the TraceRmi tool registers as
# debugger_status_2 (its raw name "debugger/status" is not an exact match, so
# schema._normalize_tool_def_names allocates a suffix instead of skipping it).
DEBUGGER_TOOL_NAMES = {
    "debugger_attach",
    "debugger_detach",
    "debugger_status",
    "debugger_modules",
    "debugger_resolve_ordinal",
    "debugger_set_breakpoint",
    "debugger_remove_breakpoint",
    "debugger_list_breakpoints",
    "debugger_continue",
    "debugger_step_into",
    "debugger_step_over",
    "debugger_registers",
    "debugger_read_memory",
    "debugger_stack_trace",
    "debugger_read_args",
    "debugger_trace_function",
    "debugger_trace_stop",
    "debugger_trace_log",
    "debugger_trace_list",
    "debugger_watch_memory",
    "debugger_watch_stop",
    "debugger_watch_log",
}

# Full structural set: every tool name the bridge may define. Used for
# name validation and the catalog tests; collision detection uses STATIC_TOOL_NAMES.
_ALL_STATIC_TOOL_NAMES = MANAGEMENT_TOOL_NAMES | DEBUGGER_TOOL_NAMES

# Active set: static tools actually registered with this process. Debugger names
# are added by bridge_mcp_ghidra.debugger only when the debugger proxy is
# enabled (see debugger._debugger_enabled()). Used for runtime availability
# reporting (check_tools etc.). Mutated in place (|=), never rebound, so modules
# that imported this name earlier still see the update.
STATIC_TOOL_NAMES = set(MANAGEMENT_TOOL_NAMES)

# Core groups always loaded on connect (essential for basic RE workflow)
CORE_GROUPS = {"listing", "function", "program"}

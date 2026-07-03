"""Configuration constants, timeouts, environment, and logging for the bridge."""

import logging
import os

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
    "batch_set_variable_types": 90,
    "analyze_data_region": 90,
    "batch_create_labels": 60,
    "batch_delete_labels": 60,
    "disassemble_bytes": 120,
    "bulk_fuzzy_match": 180,
    "find_similar_functions_fuzzy": 60,
    "import_file": 300,
    "run_ghidra_script": 1800,
    "run_script_inline": 1800,
    "decompile_function": 45,
    "set_function_prototype": 45,
    "rename_function": 45,
    "rename_function_by_address": 45,
    "consolidate_duplicate_types": 60,
    "batch_analyze_completeness": 120,
    "apply_function_documentation": 60,
    "default": 30,
}

DEFAULT_TCP_URL = "http://127.0.0.1:8089"
DEFAULT_TCP_PORT = 8089
# Bridge-side TCP port scan range. Mirrors the plugin's
# TCP_PORT_FALLBACK_RANGE so a TCP-only multi-instance setup (e.g. Windows
# 10 pre-1803 where AF_UNIX is unavailable) can still be discovered without
# having to set GHIDRA_MCP_URL per instance. See issue #175 + Copilot review.
TCP_PORT_SCAN_RANGE = 16

# Debugger proxy target (debugger/server.py). Empty/default points at the
# standalone debugger server's default port.
DEBUGGER_URL = os.getenv("GHIDRA_DEBUGGER_URL", "http://127.0.0.1:8099")

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

# WinDbg debugger proxy tools (Phase 1+2+3). The standalone debugger server
# (debugger/server.py) wraps dbgeng via pybag and only runs on Windows, so these
# are registered conditionally — see debugger._debugger_enabled(). The names stay
# reserved in _ALL_STATIC_TOOL_NAMES on every platform so dynamic-tool naming is
# identical everywhere (a Ghidra /debugger/status endpoint -> debugger_status_2
# regardless of whether our proxy is active on this host).
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
# name-collision detection / reservation so dynamic tool names are platform-stable.
_ALL_STATIC_TOOL_NAMES = MANAGEMENT_TOOL_NAMES | DEBUGGER_TOOL_NAMES

# Active set: static tools actually registered with this process. Debugger names
# are added by bridge_mcp_ghidra.debugger (once DEBUGGER_URL is known) only when
# the debugger backend is usable on this host. Used for runtime availability
# reporting (check_tools etc.). Mutated in place (|=), never rebound, so modules
# that imported this name earlier still see the update.
STATIC_TOOL_NAMES = set(MANAGEMENT_TOOL_NAMES)

# Core groups always loaded on connect (essential for basic RE workflow)
CORE_GROUPS = {"listing", "function", "program"}

"""Configuration constants, logging setup, and shared regex patterns."""

import logging
import os
import re

# ==========================================================================
# Request timeouts
# ==========================================================================

REQUEST_TIMEOUT = 30

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

# ==========================================================================
# Transport defaults
# ==========================================================================

DEFAULT_TCP_URL = "http://127.0.0.1:8089"
DEFAULT_TCP_PORT = 8089
# Bridge-side TCP port scan range. Mirrors the plugin's
# TCP_PORT_FALLBACK_RANGE so a TCP-only multi-instance setup (e.g. Windows
# 10 pre-1803 where AF_UNIX is unavailable) can still be discovered without
# having to set GHIDRA_MCP_URL per instance. See issue #175 + Copilot review.
TCP_PORT_SCAN_RANGE = 16

# Debugger proxy server (debugger/server.py)
DEBUGGER_URL = os.getenv("GHIDRA_DEBUGGER_URL", "http://127.0.0.1:8099")

# ==========================================================================
# Static tools
# ==========================================================================

# Static tool names that must not be overwritten by dynamic registration.
# Kept here (rather than in registry) so schema normalization and registration
# can both reference it without an import cycle.
STATIC_TOOL_NAMES = {
    "list_instances",
    "connect_instance",
    "import_file",
    # Debugger tools (Phase 1+2+3)
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

# ==========================================================================
# Logging
# ==========================================================================

LOG_LEVEL = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ghidra_mcp_bridge")

# ==========================================================================
# Input validation patterns
# ==========================================================================

HEX_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]+$")
SEGMENT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*:[0-9a-fA-F]+$")
# Handles space:0xHEX form (e.g., mem:0x1000, code:0xFF00).
# Must be checked BEFORE SEGMENT_ADDRESS_PATTERN because the 'x' in '0x' is not
# in [0-9a-fA-F], so the existing pattern rejects this form entirely.
SEGMENT_ADDR_WITH_0X_PATTERN = re.compile(
    r"^([a-zA-Z_][a-zA-Z0-9_]*):0[xX]([0-9a-fA-F]+)$"
)
FUNCTION_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
TOOL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
MAX_TOOL_NAME_LENGTH = 64
INVALID_TOOL_NAME_CHARS = re.compile(r"[^a-zA-Z0-9_-]+")
REPEATED_UNDERSCORES = re.compile(r"_+")

# ==========================================================================
# JSON type → Python type mapping (schema parsing)
# ==========================================================================

TYPE_MAP = {
    "string": str,
    "json": str,
    "integer": int,
    "boolean": bool,
    "number": float,
    "object": dict,
    "array": list,
    "any": str,
    "address": str,
}

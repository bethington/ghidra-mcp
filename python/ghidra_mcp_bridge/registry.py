"""Dynamic MCP tool registration from a connected instance's /mcp/schema."""

import json
import sys

from . import connection
from .app import mcp
from .config import STATIC_TOOL_NAMES, logger
from .schema import _normalize_tool_def_names, build_tool_function, parse_schema
from .validation import validate_tool_name

# Fail fast if any static tool name is not CAPI-safe.
for _static_tool_name in STATIC_TOOL_NAMES:
    validate_tool_name(_static_tool_name)

# ==========================================================================
# Registration state
# ==========================================================================

_dynamic_tool_names: list[str] = []
_full_schema: list[dict] = []  # Complete parsed schema


def full_schema() -> list[dict]:
    """Return a shallow copy of the parsed schema so callers can't mutate
    registry state through the returned list."""
    return list(_full_schema)


def dynamic_tool_names() -> list[str]:
    """Return a copy of the registered dynamic tool names so callers can't
    mutate registry state through the returned list."""
    return list(_dynamic_tool_names)


# ==========================================================================
# Registration helpers
# ==========================================================================


def _register_tool_def(tool_def: dict) -> bool:
    """Register a single tool from a schema definition. Returns True if registered."""
    name = tool_def["name"]
    validate_tool_name(name)
    if name in STATIC_TOOL_NAMES:
        return False  # Don't overwrite static tools
    description = tool_def.get("description", "")
    endpoint = tool_def["endpoint"]
    http_method = tool_def.get("http_method", "GET")
    input_schema = tool_def.get("input_schema", {"type": "object", "properties": {}})

    handler = build_tool_function(endpoint, http_method, input_schema)
    handler.__name__ = name
    handler.__doc__ = description

    # Keep the upstream category as a tag so the taxonomy survives as queryable
    # metadata (e.g. for tag-based browsing/filtering) even though it no longer
    # gates loading.
    category = tool_def.get("category", "unknown")
    mcp.tool(name=name, description=description, tags={category})(handler)
    _dynamic_tool_names.append(name)
    return True


def _report_tool_registration_failures(failures: list[str]) -> None:
    """Emit a compact stderr diagnostic for schema tools that could not load."""
    if not failures:
        return

    shown = "; ".join(failures[:8])
    suffix = "..." if len(failures) > 8 else ""
    sys.stderr.write(
        f"[ghidra_mcp_bridge] {len(failures)} tool(s) failed to register: "
        f"{shown}{suffix}\n"
    )
    sys.stderr.flush()


def register_tools_from_schema(schema: list[dict]) -> int:
    """Register all MCP tools from parsed schema.

    Every tool stays registered; the BM25 search transform (see app.py) keeps
    them out of the default list_tools view while leaving them callable.

    Returns: count of registered tools.
    """
    global _full_schema

    # Normalize first, before touching live state. If this raises we must not
    # have already torn down the previously registered tools — that would leave
    # the bridge with the old transport active but no tools registered.
    normalized = _normalize_tool_def_names(schema)

    # Remove previously registered dynamic tools. fastmcp's public remove_tool
    # also emits the tools/list_changed notification for us.
    for name in _dynamic_tool_names:
        try:
            mcp.local_provider.remove_tool(name)
        except Exception as e:
            logger.warning("Failed to unregister dynamic tool %r: %s", name, e)
    _dynamic_tool_names.clear()

    _full_schema = normalized

    count = 0
    failures: list[str] = []
    for tool_def in _full_schema:
        try:
            if _register_tool_def(tool_def):
                count += 1
        except Exception as e:
            name = tool_def.get("name", "<unnamed>")
            failures.append(f"{name}: {e}")

    _report_tool_registration_failures(failures)

    return count


def fetch_and_register_schema() -> int:
    """Fetch /mcp/schema from the connected instance and register all tools.

    Returns: count of registered tools.
    """
    text, status = connection.do_request("GET", "/mcp/schema", timeout=10)
    if status != 200:
        raise RuntimeError(f"Failed to fetch schema: HTTP {status}")
    raw = json.loads(text)
    schema = parse_schema(raw)
    return register_tools_from_schema(schema)

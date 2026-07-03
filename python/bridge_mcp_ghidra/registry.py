"""Dynamic tool registration from /mcp/schema, plus tool-group management."""

import inspect
import json
import sys

from . import dispatch
from . import state
from . import transport
from .config import STATIC_TOOL_NAMES, _ALL_STATIC_TOOL_NAMES, logger
from .schema import _TYPE_MAP, _normalize_tool_def_names, _parse_schema
from .server import Context, mcp
from .validation import sanitize_address, validate_tool_name

# Fail fast at import time if any static tool name is not CAPI-safe. Validates
# every structurally-possible name (including debugger tools), not just the
# ones active on this platform.
for _static_tool_name in _ALL_STATIC_TOOL_NAMES:
    validate_tool_name(_static_tool_name)


def _build_tool_function(endpoint: str, http_method: str, params_schema: dict):
    """Build a callable that dispatches to the Ghidra HTTP endpoint."""
    properties = params_schema.get("properties", {})
    required = set(params_schema.get("required", []))
    # Program selectors: params that pick which open program a call operates on.
    # Most tools use plain `program=`; the cross-program tools (diff_functions,
    # bulk_fuzzy_match, find_similar_functions_fuzzy) use `source_program`/
    # `target_program` or `program_a`/`program_b`. All match this name pattern.
    # We deliberately do NOT filter by the schema's `required` flag: those
    # selectors are declared required yet the server still falls back to the
    # *current* program when one arrives empty (getProgramOrError), which is the
    # wrong-binary hazard strict mode closes. (open_program/close_program use
    # path/name, so they have no selector here and are unaffected.)
    program_selectors = [
        name for name in properties
        if name == "program" or name.endswith("_program") or name.startswith("program_")
    ]
    is_post = http_method.upper() == "POST"
    has_schema_dry_run = "dry_run" in properties
    use_synthetic_dry_run = is_post and not has_schema_dry_run

    def is_truthy(value) -> bool:
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def handler(**kwargs):
        # Sanitize address parameters before dispatch
        for pname, pdef in properties.items():
            if (
                pdef.get("param_type") == "address"
                and pname in kwargs
                and kwargs[pname] is not None
            ):
                kwargs[pname] = sanitize_address(str(kwargs[pname]))
        # Synthetic bridge dry-run goes as a query param. Schema-declared
        # dry_run must stay in kwargs so its declared source (query/body) wins.
        dry_run = kwargs.pop("dry_run", None) if use_synthetic_dry_run else None
        # Filter out None AND empty strings. Codex's MCP client passes schema
        # default values (including "") to every call, which the Ghidra
        # handler treats as "present but empty" and fails on params that
        # require a real value (e.g. /get_function_callers rejects empty
        # name/address). minimax avoids this by only sending params the LLM
        # explicitly provided, but the bridge is schema-driven and doesn't
        # know which were defaults. Empty string is not a meaningful value
        # for any current Ghidra endpoint — safe to filter.
        filtered = {
            k: v
            for k, v in kwargs.items()
            if v is not None and not (isinstance(v, str) and v == "")
        }
        # Strict mode: refuse if any program selector is missing, so a forgotten
        # one fails loudly instead of running against the server's current
        # program. filtered has already dropped None and "", so absence is the
        # test (an empty selector counts as omitted).
        if state._require_selectors and program_selectors:
            missing = [p for p in program_selectors if p not in filtered]
            if missing:
                names = ", ".join(f"`{p}=`" for p in missing)
                return json.dumps({
                    "error": (
                        f"Missing required program selector(s): {names} "
                        "(GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS is set). "
                        "Pass each explicitly to target the intended open program(s)."
                    )
                })
        if http_method == "GET":
            str_params = {k: str(v) for k, v in filtered.items()}
            if use_synthetic_dry_run and is_truthy(dry_run):
                str_params["dry_run"] = "true"
            return dispatch.dispatch_get(
                endpoint, params=str_params if str_params else None
            )
        else:
            body_data = {}
            query_params = {}
            for key, value in filtered.items():
                if properties.get(key, {}).get("source") == "query":
                    query_params[key] = str(value)
                else:
                    body_data[key] = value
            if use_synthetic_dry_run and is_truthy(dry_run):
                query_params["dry_run"] = "true"
            return dispatch.dispatch_post(
                endpoint,
                data=body_data,
                query_params=query_params or None,
            )

    # Build function signature with proper types and defaults
    # Params with defaults must come after params without defaults
    required_params = []
    optional_params = []
    for pname, pdef in properties.items():
        json_type = pdef.get("type", "string")
        py_type = _TYPE_MAP.get(json_type, str)
        default = pdef.get("default", inspect.Parameter.empty)
        if pname not in required and default is inspect.Parameter.empty:
            default = None
            py_type = py_type | None if py_type != str else str | None

        param = inspect.Parameter(
            pname, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=py_type
        )
        if default is inspect.Parameter.empty:
            required_params.append(param)
        else:
            optional_params.append(param)

    sig_params = required_params + optional_params
    # Add dry_run parameter for POST (write) endpoints
    if use_synthetic_dry_run:
        sig_params.append(
            inspect.Parameter(
                "dry_run",
                inspect.Parameter.KEYWORD_ONLY,
                default=False,
                annotation=bool,
            )
        )
    handler.__signature__ = inspect.Signature(sig_params, return_annotation=str)
    handler.__annotations__ = {p.name: p.annotation for p in sig_params}
    handler.__annotations__["return"] = str

    return handler


def _register_tool_def(tool_def: dict) -> bool:
    """Register a single tool from a schema definition. Returns True if registered."""
    name = tool_def["name"]
    validate_tool_name(name)
    if name in STATIC_TOOL_NAMES:
        return False  # Don't overwrite an *active* static tool of the same name
    description = tool_def.get("description", "")
    endpoint = tool_def["endpoint"]
    http_method = tool_def.get("http_method", "GET")
    input_schema = tool_def.get("input_schema", {"type": "object", "properties": {}})

    handler = _build_tool_function(endpoint, http_method, input_schema)
    handler.__name__ = name
    handler.__doc__ = description

    mcp.tool(name=name, description=description)(handler)
    state._dynamic_tool_names.append(name)
    return True


def _report_tool_registration_failures(failures: list[str]) -> None:
    """Emit a compact stderr diagnostic for schema tools that could not load."""
    if not failures:
        return

    shown = "; ".join(failures[:8])
    suffix = "..." if len(failures) > 8 else ""
    sys.stderr.write(
        f"[bridge_mcp_ghidra] {len(failures)} tool(s) failed to register: "
        f"{shown}{suffix}\n"
    )
    sys.stderr.flush()


def register_tools_from_schema(
    schema: list[dict], groups: set[str] | None = None
) -> int:
    """Register MCP tools from parsed schema.

    Args:
        schema: List of parsed tool definitions.
        groups: If provided, only register tools in these groups. None = register all.

    Returns: count of registered tools.
    """
    # Remove previously registered dynamic tools
    for name in state._dynamic_tool_names:
        try:
            mcp._tool_manager._tools.pop(name, None)
        except Exception as e:
            # Reaches into FastMCP internals; if its private structure changes this
            # would silently leak tools across reloads. Log so the breakage is visible.
            logger.warning(
                "Failed to unregister dynamic tool %r via mcp._tool_manager._tools "
                "(FastMCP internals may have changed): %s", name, e)
    state._dynamic_tool_names.clear()
    state._loaded_groups.clear()

    # Store full schema for lazy loading
    state._full_schema = _normalize_tool_def_names(schema)

    count = 0
    failures: list[str] = []
    for tool_def in state._full_schema:
        category = tool_def.get("category", "unknown")
        if groups is not None and category not in groups:
            continue
        try:
            if _register_tool_def(tool_def):
                state._loaded_groups.add(category)
                count += 1
        except Exception as e:
            name = tool_def.get("name", "<unnamed>")
            failures.append(f"{name}: {e}")

    _report_tool_registration_failures(failures)

    return count


def _load_group(group_name: str) -> list[str]:
    """Load tools for a specific group from cached schema. Returns list of newly loaded tool names."""
    loaded_names: list[str] = []
    failures: list[str] = []
    for tool_def in state._full_schema:
        if tool_def.get("category") != group_name:
            continue
        name = tool_def["name"]
        if name in state._dynamic_tool_names:
            continue  # Already loaded
        try:
            if _register_tool_def(tool_def):
                loaded_names.append(name)
        except Exception as e:
            failures.append(f"{name}: {e}")
    if loaded_names:
        state._loaded_groups.add(group_name)
    _report_tool_registration_failures(failures)
    return loaded_names


def _unload_group(group_name: str) -> int:
    """Unload tools for a specific group. Returns count of removed tools."""
    if group_name in state._default_groups:
        return 0  # Default groups can't be unloaded

    to_remove = []
    for tool_def in state._full_schema:
        if tool_def.get("category") == group_name:
            name = tool_def["name"]
            if name in state._dynamic_tool_names:
                to_remove.append(name)

    for name in to_remove:
        try:
            mcp._tool_manager._tools.pop(name, None)
            state._dynamic_tool_names.remove(name)
        except Exception as e:
            # See unregister note above: FastMCP-internals access, log on failure.
            logger.warning(
                "Failed to unload tool %r via mcp._tool_manager._tools "
                "(FastMCP internals may have changed): %s", name, e)

    if to_remove:
        state._loaded_groups.discard(group_name)
    return len(to_remove)


def _get_group_info() -> list[dict]:
    """Get info about all tool groups from cached schema."""
    groups: dict[str, list[str]] = {}
    descriptions: dict[str, str] = {}
    for tool_def in state._full_schema:
        cat = tool_def.get("category", "unknown")
        groups.setdefault(cat, []).append(tool_def["name"])
        if cat not in descriptions and tool_def.get("category_description"):
            descriptions[cat] = tool_def["category_description"]

    result = []
    for name, tools in sorted(groups.items()):
        info: dict = {
            "group": name,
            "tool_count": len(tools),
            "loaded": name in state._loaded_groups,
            "default": name in state._default_groups,
        }
        if name in descriptions:
            info["description"] = descriptions[name]
        info["tools"] = sorted(tools)
        result.append(info)
    return result


def _fetch_and_register_schema(load_all: bool = False) -> int:
    """Fetch /mcp/schema from connected instance and register tools.

    Args:
        load_all: If True, register all tools. If False, only default groups.

    Returns: count of registered tools.
    """
    if not load_all:
        load_all = not state._lazy_mode
    text, status = transport.do_request("GET", "/mcp/schema", timeout=10)
    if status != 200:
        raise RuntimeError(f"Failed to fetch schema: HTTP {status}")
    raw = json.loads(text)
    schema = _parse_schema(raw)
    groups = None if load_all else state._default_groups
    return register_tools_from_schema(schema, groups=groups)


async def _notify_tools_changed(ctx: Context | None) -> None:
    """Send tools/list_changed notification if context is available."""
    if ctx is not None and ctx._request_context is not None:
        await ctx.request_context.session.send_tool_list_changed()

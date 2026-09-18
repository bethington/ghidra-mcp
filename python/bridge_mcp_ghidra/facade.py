"""Facade mode for Copilot-style clients: 5 stable tools instead of 250+ dynamic ones.

Problem this solves: with ``--lazy`` the planner only sees the tools from
startup (8 static + 3 default groups). Everything else is invisible until
``load_tool_group`` + a ``tools/list_changed`` re-list that Copilot VS Code
does not reliably honor. The result is tool blindness and
``not_loaded -> load -> no re-list -> fail`` loops.

In facade mode (``--expose facade``) the bridge registers ONLY these 5 tools::

    ghidra_status    connection + catalog summary (replaces list_instances)
    ghidra_connect   connect to a project (wraps connect_instance)
    ghidra_search    fuzzy search over the full /mcp/schema catalog
    ghidra_describe  full input_schema + example for one tool
    ghidra_call      dispatch any catalog action by name + args dict

The full ``/mcp/schema`` is still fetched on connect and kept in
``state._full_schema``; nothing dynamic is registered, so there is no
``tools/list_changed`` dependency at all. Typical flow::

    ghidra_status -> ghidra_connect(project) -> ghidra_search("rename function")
    -> [ghidra_describe(tool)] -> ghidra_call(tool, args)

``ghidra_call`` reuses :func:`registry._build_tool_function` so address
sanitization, empty-string filtering, synthetic ``dry_run``, strict program
selectors and timeout handling behave exactly like a direct dynamic-tool call.
Unknown/hallucinated names get fuzzy resolution with ``did_you_mean`` plus an
alias map, and every error is a machine-readable JSON object naming the fix.
"""

from __future__ import annotations

import difflib
import json

from . import dispatch
from . import registry
from . import state
from .config import logger
from .server import mcp

# --------------------------------------------------------------------------
# Public catalog names (also used by apply_expose_mode for pruning).
# --------------------------------------------------------------------------

FACADE_TOOL_NAMES = frozenset(
    {
        "ghidra_status",
        "ghidra_connect",
        "ghidra_search",
        "ghidra_describe",
        "ghidra_call",
    }
)

# Common hallucinations / shorthand -> canonical catalog name. Applied only
# when the target actually exists in the fetched schema, so a stale alias can
# never misroute; it just falls through to fuzzy matching.
_TOOL_ALIASES = {
    "decompile": "decompile_function",
    "disassemble": "disassemble_function",
    "disasm": "disassemble_function",
    "get_disassembly": "disassemble_function",
    "rename": "rename_function",
    "xref": "get_xrefs_to",
    "xrefs": "get_xrefs_to",
    "xrefs_to": "get_xrefs_to",
    "xrefs_from": "get_xrefs_from",
    "callers": "get_function_callers",
    "callees": "get_function_callees",
    "strings": "list_strings",
    "imports": "list_imports",
    "exports": "list_exports",
    "segments": "list_segments",
    "functions": "list_methods",
    "methods": "list_methods",
    "comment": "get_comment",
    "set_comment": "set_comment",
    "run_script": "run_ghidra_script",
}

_DESC_TRUNCATE = 160
_SEARCH_DEFAULT_LIMIT = 10
_SEARCH_MAX_LIMIT = 50


def _facade_tool(*dargs, **dkwargs):
    """Register a facade tool on the shared FastMCP server.

    Named distinctly from the management decorator so the catalog test
    counting static decorators against MANAGEMENT_TOOL_NAMES keeps passing:
    facade tools are a separate surface, functionally identical.
    """
    registrar = mcp.tool(*dargs, **dkwargs)

    def _register(fn):
        registrar(fn)
        return fn

    return _register


# --------------------------------------------------------------------------
# Name resolution (anti-hallucination layer)
# --------------------------------------------------------------------------


def _catalog_names() -> list[str]:
    return [td.get("name", "") for td in state._full_schema if td.get("name")]


def _resolve_tool_name(query: str) -> tuple[str | None, list[str]]:
    """Resolve a possibly-hallucinated tool name against the live catalog.

    Returns (resolved_name_or_None, suggestions). Matching order: exact,
    case-insensitive, alias map, sanitized (spaces/dashes -> underscores),
    difflib fuzzy, substring. Suggestions are offered on failure so the
    caller can self-heal in one step instead of looping on search.
    """
    names = _catalog_names()
    if not names:
        return None, []
    q = (query or "").strip()
    if not q:
        return None, []
    if q in names:
        return q, []

    lowered = {n.lower(): n for n in names}
    if q.lower() in lowered:
        return lowered[q.lower()], []

    alias_target = _TOOL_ALIASES.get(q.lower())
    if alias_target and alias_target in names:
        return alias_target, []
    if alias_target and alias_target.lower() in lowered:
        return lowered[alias_target.lower()], []

    sanitized = "".join(c if (c.isalnum() or c == "_") else "_" for c in q.lower()).strip("_")
    while "__" in sanitized:
        sanitized = sanitized.replace("__", "_")
    if sanitized in names:
        return sanitized, []
    if sanitized in lowered:
        return lowered[sanitized], []

    fuzzy = difflib.get_close_matches(q, names, n=3, cutoff=0.6)
    if fuzzy:
        # get_close_matches is case-sensitive; retry lowered on miss.
        return fuzzy[0], fuzzy
    fuzzy_lower = difflib.get_close_matches(q.lower(), list(lowered), n=3, cutoff=0.6)
    if fuzzy_lower:
        resolved = lowered[fuzzy_lower[0]]
        return resolved, [lowered[s] for s in fuzzy_lower]

    substr = [n for n in names if sanitized and sanitized in n.lower()]
    if substr:
        return substr[0], substr[:3]
    return None, []


def _score_tool(tool_def: dict, terms: list[str]) -> int:
    name = str(tool_def.get("name", "")).lower()
    category = str(tool_def.get("category", "unknown")).lower()
    desc = str(tool_def.get("description", "") or "").lower()
    score = 0
    for term in terms:
        if term in name:
            score += 3
        elif term in category or term in desc:
            score += 1
    return score


def _required_params(tool_def: dict) -> list[str]:
    schema = tool_def.get("input_schema", {}) or {}
    return list(schema.get("required", []) or [])


def _example_args(tool_def: dict) -> dict:
    """Build a minimal example args dict from required params."""
    schema = tool_def.get("input_schema", {}) or {}
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    example: dict = {}
    for pname in required:
        pdef = props.get(pname, {}) if isinstance(props.get(pname), dict) else {}
        ptype = str(pdef.get("type", "string"))
        if pdef.get("param_type") == "address" or "address" in pname:
            example[pname] = "0x00401000"
        elif "program" in pname:
            example[pname] = "<program_name>"
        elif ptype == "integer":
            example[pname] = 0
        elif ptype == "boolean":
            example[pname] = False
        elif ptype == "array":
            example[pname] = []
        elif ptype == "object":
            example[pname] = {}
        elif ptype == "number":
            example[pname] = 0.0
        else:
            example[pname] = f"<{pname}>"
    return example


def _tool_brief(tool_def: dict) -> dict:
    desc = str(tool_def.get("description", "") or "")
    return {
        "name": tool_def.get("name", ""),
        "group": tool_def.get("category", "unknown"),
        "description": desc[:_DESC_TRUNCATE],
        "required_params": _required_params(tool_def),
        "method": tool_def.get("http_method", "GET"),
    }


# --------------------------------------------------------------------------
# Static (non-catalog) dispatch: import_file + debugger/oracle proxies.
# --------------------------------------------------------------------------


def _call_import_file_sync(args: dict) -> str:
    """Sync import_file equivalent (no ctx polling) for facade dispatch."""
    if not args.get("file_path"):
        return json.dumps(
            {
                "error": "Missing required parameter: file_path",
                "tool": "import_file",
                "expected_schema": {
                    "file_path": "string (required, absolute path on disk)",
                    "project_folder": "string (optional, default '/')",
                    "language": "string (optional, e.g. 'ARM:LE:32:Cortex')",
                    "compiler_spec": "string (optional, e.g. 'default')",
                    "auto_analyze": "boolean (optional, default true)",
                },
                "fix": 'ghidra_call(tool="import_file", args={"file_path": "C:/path/to/binary"})',
            }
        )
    payload: dict = {
        "file_path": args.get("file_path"),
        "project_folder": args.get("project_folder", "/"),
        "auto_analyze": args.get("auto_analyze", True),
    }
    if args.get("language"):
        payload["language"] = args.get("language")
    if args.get("compiler_spec"):
        payload["compiler_spec"] = args.get("compiler_spec")
    return dispatch.dispatch_post("/import_file", payload)


def _call_static_sync(name: str, args: dict) -> str | None:
    """Dispatch hidden static tools. Returns None when `name` is not static."""
    if name == "import_file":
        return _call_import_file_sync(args)
    if name.startswith("debugger_"):
        from . import debugger as _dbg

        fn = getattr(_dbg, name, None)
        if fn is None or not callable(fn):
            return None
        try:
            return str(fn(**args))
        except TypeError as e:
            return json.dumps(
                {
                    "error": f"Bad arguments for {name}: {e}",
                    "fix": f'ghidra_describe("{name}") is unavailable in facade mode; '
                    "call with the documented debugger_* parameters.",
                }
            )
    if name.startswith("oracle_"):
        from . import oracle as _or

        fn = getattr(_or, name, None)
        if fn is None or not callable(fn):
            return None
        try:
            return str(fn(**args))
        except TypeError as e:
            return json.dumps({"error": f"Bad arguments for {name}: {e}"})
    return None


def _call_catalog_sync(tool_def: dict, args: dict) -> str:
    """Validate args against the catalog schema, then reuse the registry handler."""
    schema = tool_def.get("input_schema", {}) or {}
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    allow_empty = {k for k, v in props.items() if isinstance(v, dict) and v.get("allow_empty")}

    unknown = [k for k in args if k != "dry_run" and k not in props]
    if unknown:
        return json.dumps(
            {
                "error": f"Unknown parameter(s) for {tool_def['name']}: {', '.join(unknown)}",
                "tool": tool_def["name"],
                "valid_params": sorted(props),
                "required": required,
                "example": _example_args(tool_def),
                "fix": f'ghidra_describe("{tool_def["name"]}") for the full schema, '
                "then retry ghidra_call with corrected args.",
            }
        )
    missing = [
        r
        for r in required
        if r not in args or args[r] is None or (isinstance(args[r], str) and args[r] == "" and r not in allow_empty)
    ]
    if missing:
        return json.dumps(
            {
                "error": f"Missing required parameter(s) for {tool_def['name']}: {', '.join(missing)}",
                "tool": tool_def["name"],
                "required": required,
                "example": _example_args(tool_def),
                "fix": f'ghidra_describe("{tool_def["name"]}") for the full schema, '
                "then retry ghidra_call with all required args.",
            }
        )
    handler = registry._build_tool_function(
        tool_def["endpoint"],
        tool_def.get("http_method", "GET"),
        schema,
    )
    try:
        return handler(**args)
    except TypeError as e:
        return json.dumps(
            {
                "error": f"Argument error for {tool_def['name']}: {e}",
                "required": required,
                "example": _example_args(tool_def),
            }
        )


# --------------------------------------------------------------------------
# Facade tools
# --------------------------------------------------------------------------


@_facade_tool()
async def ghidra_status() -> str:
    """Connection + catalog summary. Call this FIRST in every session.

    Reports whether a Ghidra instance is connected, which project is active,
    how many catalog actions are reachable via ghidra_call, and the category
    list for ghidra_search filtering. Never guess a tool name: search first.

    Workflow: ghidra_status -> ghidra_connect(project) -> ghidra_search(query)
    -> [ghidra_describe(tool)] -> ghidra_call(tool, args).
    """
    from . import discovery

    instances = await state.run_in_worker(discovery.discover_instances)
    tcp_instance = await state.run_in_worker(discovery.discover_active_tcp_instance)
    if tcp_instance:
        instances.append(tcp_instance)
    categories = sorted({td.get("category", "unknown") for td in state._full_schema})
    return json.dumps(
        {
            "connected": state._transport_mode != "none",
            "transport": state._transport_mode,
            "project": state._connected_project,
            "instances": len(instances),
            "tool_count": len(state._full_schema),
            "categories": categories,
            "expose_mode": state._expose_mode,
            "workflow": "ghidra_connect(project) -> ghidra_search(query) "
            "-> [ghidra_describe(tool)] -> ghidra_call(tool, args)",
        },
        indent=2,
    )


@_facade_tool()
async def ghidra_connect(project: str) -> str:
    """Connect the bridge to a Ghidra instance by project name.

    Fetches /mcp/schema into memory (no dynamic tool registration in facade
    mode). Use ghidra_status first to see what is available.

    Args:
        project: Project name (or substring) to connect to.
    """
    from . import static_tools as _st

    result = await state.run_blocking_ghidra_call(
        _st._connect_instance_sync,
        project,
        bind_connection=False,
    )
    if isinstance(result, dict) and result.get("connected"):
        # _connect_instance_sync writes a lazy-mode note naming
        # load_tool_group, which is hidden in facade mode. Replace it.
        result = dict(result)
        result["note"] = (
            f"Connected in facade mode: {len(state._full_schema)} catalog actions "
            "reachable via ghidra_search/ghidra_call. No tool loading needed."
        )
        result["workflow"] = 'ghidra_search("what you want") -> ghidra_call(tool, args)'
    return json.dumps(result, indent=2)


@_facade_tool()
def ghidra_search(query: str, category: str | None = None, limit: int = _SEARCH_DEFAULT_LIMIT) -> str:
    """Fuzzy-search the full Ghidra catalog (all groups, always complete).

    Use this instead of guessing a tool name. Matches name, category and
    description; name hits rank highest. Each hit lists required_params so
    simple calls can skip ghidra_describe.

    Args:
        query: Space-separated keywords, e.g. "rename function", "xref struct".
        category: Optional category filter, e.g. "function", "datatype".
        limit: Max hits to return (default 10, max 50).
    """
    if not state._full_schema:
        return json.dumps(
            {
                "error": "No instance connected — catalog is empty.",
                "fix": "ghidra_status() then ghidra_connect(project).",
            }
        )
    terms = [t.lower() for t in str(query or "").replace("_", " ").replace("-", " ").split() if t.strip()]
    if not terms:
        return json.dumps({"error": "Provide one or more search keywords."})
    try:
        lim = max(1, min(int(limit), _SEARCH_MAX_LIMIT))
    except (TypeError, ValueError):
        lim = _SEARCH_DEFAULT_LIMIT

    scored: list[tuple[int, dict]] = []
    for td in state._full_schema:
        if category and td.get("category", "unknown") != category:
            continue
        score = _score_tool(td, terms)
        if score == 0:
            continue
        scored.append((score, _tool_brief(td)))
    scored.sort(key=lambda x: x[0], reverse=True)
    matches = [r for _, r in scored[:lim]]
    out: dict = {
        "query": query,
        "match_count": len(scored),
        "returned": len(matches),
        "matches": matches,
    }
    if category and not scored:
        out["available_categories"] = sorted({td.get("category", "unknown") for td in state._full_schema})
    return json.dumps(out, indent=2)


@_facade_tool()
def ghidra_describe(tool: str) -> str:
    """Full schema + example for ONE catalog action. Call before ghidra_call
    when ghidra_search's required_params are not enough.

    Args:
        tool: Exact or approximate tool name, e.g. "rename_function".
    """
    if not state._full_schema:
        return json.dumps(
            {
                "error": "No instance connected — catalog is empty.",
                "fix": "ghidra_status() then ghidra_connect(project).",
            }
        )
    resolved, suggestions = _resolve_tool_name(tool)
    if resolved is None:
        return json.dumps(
            {
                "error": f"Unknown tool: {tool!r}. Never invent names.",
                "did_you_mean": suggestions,
                "fix": f'ghidra_search("{tool}") to find the right action.',
            }
        )
    tool_def = next(td for td in state._full_schema if td.get("name") == resolved)
    schema = tool_def.get("input_schema", {}) or {}
    return json.dumps(
        {
            "name": resolved,
            "group": tool_def.get("category", "unknown"),
            "description": tool_def.get("description", ""),
            "endpoint": tool_def.get("endpoint", ""),
            "http_method": tool_def.get("http_method", "GET"),
            "input_schema": schema,
            "required": list(schema.get("required", []) or []),
            "example": _example_args(tool_def),
            "call": f'ghidra_call(tool="{resolved}", args={json.dumps(_example_args(tool_def))})',
        },
        indent=2,
    )


@_facade_tool()
async def ghidra_call(tool: str, args: dict | None = None) -> str:
    """Call ANY catalog action by name. The only way to act on Ghidra.

    Never invent a tool name: resolve via ghidra_search first. Unknown names
    return did_you_mean instead of failing silently; missing/unknown params
    return the expected schema + example.

    Args:
        tool: Catalog action name, e.g. "decompile_function".
        args: Arguments object matching the action's input_schema,
            e.g. {"address": "0x00401000"}. Omit to use {}.
    """
    params = dict(args or {}) if isinstance(args, dict) else {}
    if not isinstance(args, dict) and args is not None:
        return json.dumps(
            {
                "error": "args must be an object, e.g. {\"address\": \"0x00401000\"}.",
                "tool": tool,
                "fix": f'ghidra_describe("{tool}") for the expected schema.',
            }
        )
    # Hidden static tools (import/debugger/oracle) stay reachable here so the
    # 5-tool surface covers 100% of the old surface.
    static_hit = await state.run_in_worker(_call_static_sync, tool, params)
    if static_hit is not None:
        return static_hit
    if not state._full_schema:
        return json.dumps(
            {
                "error": "No instance connected — catalog is empty.",
                "fix": "ghidra_status() then ghidra_connect(project).",
            }
        )
    resolved, suggestions = _resolve_tool_name(tool)
    if resolved is None:
        return json.dumps(
            {
                "error": f"Unknown tool: {tool!r}. Never invent names.",
                "did_you_mean": suggestions,
                "fix": f'ghidra_search("{tool}") to find the right action, '
                "then retry ghidra_call with an exact name.",
            }
        )
    tool_def = next(td for td in state._full_schema if td.get("name") == resolved)
    if resolved != tool:
        logger.info("ghidra_call: resolved %r -> %r", tool, resolved)
    return await state.run_blocking_ghidra_call(_call_catalog_sync, tool_def, params)


# --------------------------------------------------------------------------
# Expose-mode pruning (called once from cli.main after arg parsing).
# --------------------------------------------------------------------------


def apply_expose_mode(mode: str) -> dict:
    """Prune the FastMCP tool table to `mode` and remember it in state.

    full:   legacy surface (management + debugger/oracle + dynamic), no facade.
    facade: ONLY the 5 ghidra_* tools (Copilot default).
    hybrid: everything (migration/debugging).
    """
    normalized = (mode or "full").strip().lower()
    if normalized not in ("full", "facade", "hybrid"):
        raise ValueError(f"Unknown expose mode {mode!r}; expected full|facade|hybrid")
    state._expose_mode = normalized
    try:
        tools = mcp._tool_manager._tools  # type: ignore[attr-defined]
    except AttributeError:
        logger.warning("apply_expose_mode: FastMCP internals changed; cannot prune tools")
        return {"mode": normalized, "pruned": False}
    if normalized == "hybrid":
        return {"mode": normalized, "visible": sorted(tools)}
    if normalized == "facade":
        for name in [n for n in tools if n not in FACADE_TOOL_NAMES]:
            tools.pop(name, None)
        state._dynamic_tool_names.clear()
        state._loaded_groups.clear()
        # If a schema was already cached (tests, re-exec), mark its groups
        # available so legacy inspectors see the full catalog, not emptiness.
        for td in state._full_schema:
            state._loaded_groups.add(td.get("category", "unknown"))
    else:  # full
        for name in [n for n in tools if n in FACADE_TOOL_NAMES]:
            tools.pop(name, None)
    logger.info("Expose mode %r: %d tools visible", normalized, len(tools))
    return {"mode": normalized, "visible": sorted(tools)}

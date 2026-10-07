"""Dynamic tool registration from /mcp/schema, plus tool-group management."""

import asyncio
import inspect
import json
import sys
from typing import Annotated

from pydantic import Field

from mcp.types import ToolAnnotations

from . import dispatch
from . import state
from . import transport
from .config import (
    DESTRUCTIVE_TOOL,
    READ_ONLY_TOOL,
    STATIC_TOOL_NAMES,
    WRITE_TOOL,
    _ALL_STATIC_TOOL_NAMES,
    logger,
)
from .schema import _TYPE_MAP, _normalize_tool_def_names, _parse_schema
from .server import Context, mcp
from .validation import sanitize_address, validate_tool_name

# How often an in-flight call reports that it is still working. Short enough to
# beat a client's idle timer, long enough not to spam a 600s batch write.
_PROGRESS_INTERVAL_SECONDS = 5.0

# Fail fast at import time if any static tool name is not CAPI-safe. Validates
# every structurally-possible name (including debugger tools), not just the
# ones active in this process.
for _static_tool_name in _ALL_STATIC_TOOL_NAMES:
    validate_tool_name(_static_tool_name)


def _build_tool_function(endpoint: str, http_method: str, params_schema: dict):
    """Build a callable that dispatches to the Ghidra HTTP endpoint."""
    properties = params_schema.get("properties", {})
    required = set(params_schema.get("required", []))
    # Back-compat parameter spellings. `@Param(aliases = {...})` names spellings
    # the server genuinely serves -- AnnotationScanner tries the canonical name
    # and then each alias -- and /mcp/schema publishes them as of 7.0.0.
    #
    # The bridge has to declare them too. FastMCP validates arguments against
    # this signature with a pydantic model whose `extra` policy is `ignore`, so
    # an alias the signature does not name was SILENTLY DROPPED here and the
    # request went out without the value; and when the canonical name was
    # required, the call was rejected client-side for a spelling the server
    # accepts. Declaring each alias as an optional parameter and folding it onto
    # the canonical name is what makes the published contract reachable.
    alias_to_canonical: dict[str, str] = {}
    for _canonical, _pdef in properties.items():
        for _alias in _pdef.get("aliases") or ():
            # Never shadow a real parameter, and never let a second declaration
            # steal an alias already claimed: first declaration wins, which is
            # the order the Java resolver walks.
            if _alias in properties or _alias in alias_to_canonical:
                continue
            alias_to_canonical[_alias] = _canonical
    # A required parameter that has aliases cannot stay required in the
    # signature -- the alias IS the value. The check moves into the handler,
    # after folding, so it still fails loudly but on the real condition.
    aliased_required = {c for c in required if c in set(alias_to_canonical.values())}
    signature_required = required - aliased_required
    # Parameters where "" is itself the intent (see the filtering note in
    # handler). Hoisted out of the handler so alias folding shares one answer.
    allow_empty = {name for name, pdef in properties.items() if pdef.get("allow_empty")}

    def is_absent(value, name: str) -> bool:
        """True when `value` would not survive the empty-argument filter below."""
        if value is None:
            return True
        return isinstance(value, str) and value == "" and name not in allow_empty

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
        name for name in properties if name == "program" or name.endswith("_program") or name.startswith("program_")
    ]
    is_post = http_method.upper() == "POST"
    has_schema_dry_run = "dry_run" in properties
    use_synthetic_dry_run = is_post and not has_schema_dry_run

    def is_truthy(value) -> bool:
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def handler(**kwargs):
        # Fold back-compat spellings onto their canonical parameter before
        # anything else reads kwargs. Resolution order matches the Java side:
        # the canonical name wins when the caller supplied one, otherwise the
        # first alias that carries a value, in declaration order.
        for alias, canonical in alias_to_canonical.items():
            value = kwargs.pop(alias, None)
            if value is None:
                continue
            if is_absent(kwargs.get(canonical), canonical):
                kwargs[canonical] = value
        # Required-but-aliased params are optional in the signature (an alias may
        # be carrying the value), so enforce them here instead.
        unfilled = sorted(c for c in aliased_required if is_absent(kwargs.get(c), c))
        if unfilled:
            spellings = {c: [c] + [a for a, target in alias_to_canonical.items() if target == c] for c in unfilled}
            return json.dumps(
                {
                    "error": "Missing required parameter(s): "
                    + "; ".join(f"`{c}` (or {', '.join(f'`{s}`' for s in alts[1:])})" for c, alts in spellings.items())
                }
            )
        # Sanitize address parameters before dispatch
        for pname, pdef in properties.items():
            if pdef.get("param_type") == "address" and pname in kwargs and kwargs[pname] is not None:
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
        # know which were defaults.
        #
        # Exception: a parameter may declare `allow_empty` when "" is itself
        # the intent. This used to be a blanket rule on the claim that empty
        # was meaningless for every endpoint, which made clearing a comment
        # unreachable through MCP -- set_comment(comment="") was dropped here,
        # arrived as null, and came back "Comment text is required". Whether
        # empty is meaningful is a property of the parameter, so the parameter
        # declares it (@Param(allowEmpty = true)) rather than the bridge
        # guessing.
        filtered = {
            k: v
            for k, v in kwargs.items()
            if v is not None
            and not (isinstance(v, str) and v == "" and k not in allow_empty)
        }
        # Strict mode: refuse if any program selector is missing, so a forgotten
        # one fails loudly instead of running against the server's current
        # program. filtered has already dropped None and "", so absence is the
        # test (an empty selector counts as omitted).
        if state._require_selectors and program_selectors:
            missing = [p for p in program_selectors if p not in filtered]
            if missing:
                names = ", ".join(f"`{p}=`" for p in missing)
                return json.dumps(
                    {
                        "error": (
                            f"Missing required program selector(s): {names} "
                            "(GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS is set). "
                            "Pass each explicitly to target the intended open program(s)."
                        )
                    }
                )
        if http_method == "GET":
            str_params = {k: str(v) for k, v in filtered.items()}
            if use_synthetic_dry_run and is_truthy(dry_run):
                str_params["dry_run"] = "true"
            return dispatch.dispatch_get(endpoint, params=str_params if str_params else None)
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
        if pname not in signature_required and default is inspect.Parameter.empty:
            default = None
            py_type = py_type | None if py_type != str else str | None

        # Carry the @Param description from /mcp/schema into the MCP inputSchema.
        # FastMCP derives inputSchema from this signature via pydantic, so a bare
        # annotation drops the text the server already published and the model
        # sees a nameless, undocumented parameter.
        pdesc = pdef.get("description")
        annotation = Annotated[py_type, Field(description=pdesc)] if pdesc else py_type

        param = inspect.Parameter(pname, inspect.Parameter.KEYWORD_ONLY, default=default, annotation=annotation)
        if default is inspect.Parameter.empty:
            required_params.append(param)
        else:
            optional_params.append(param)

    # Declared back-compat spellings, always optional. Without these the pydantic
    # arg model drops them before `handler` ever sees them.
    for alias, canonical in alias_to_canonical.items():
        py_type = _TYPE_MAP.get(properties[canonical].get("type", "string"), str)
        optional_params.append(
            inspect.Parameter(
                alias,
                inspect.Parameter.KEYWORD_ONLY,
                default=None,
                annotation=py_type | None,
            )
        )

    sig_params = required_params + optional_params
    # Add dry_run parameter for POST (write) endpoints
    if use_synthetic_dry_run:
        sig_params.append(
            inspect.Parameter(
                "dry_run",
                inspect.Parameter.KEYWORD_ONLY,
                default=False,
                annotation=Annotated[
                    bool,
                    Field(
                        description=(
                            "Preview the change without applying it. When true the server "
                            "validates the request and reports what would happen, leaving the "
                            "program unmodified. Defaults to false."
                        )
                    ),
                ],
            )
        )
    handler.__signature__ = inspect.Signature(sig_params, return_annotation=str)
    handler.__annotations__ = {p.name: p.annotation for p in sig_params}
    handler.__annotations__["return"] = str

    return handler


def _signature_with_context(signature: inspect.Signature) -> inspect.Signature:
    """Append the FastMCP `ctx` parameter, which it keeps out of inputSchema."""
    ctx_param = inspect.Parameter(
        "ctx",
        inspect.Parameter.KEYWORD_ONLY,
        default=None,
        annotation=Context | None,
    )
    return signature.replace(parameters=[*signature.parameters.values(), ctx_param])


def _start_progress_heartbeat(ctx: Context | None, tool_name: str):
    """Tick progress notifications while a call is in flight, or return None.

    Endpoint timeouts here reach 600s (`dispatch.get_timeout` scales batch
    renames and comment writes by item count), and nothing was sent during the
    wait: a client had no way to tell a long decompile from a hung session, and
    some give up on their own idle timer.

    Started only when the client actually asked for progress — the notification
    is silently dropped without a progressToken, so spawning a task per call for
    a client that never asked would be pure overhead.
    """
    if ctx is None:
        return None
    try:
        meta = ctx.request_context.meta
    except (AttributeError, ValueError):
        # No active request context (direct call, or a test harness).
        return None
    if meta is None or meta.progressToken is None:
        return None
    token = meta.progressToken
    session = ctx.request_context.session
    request_id = ctx.request_context.request_id

    async def _tick() -> None:
        elapsed = 0.0
        try:
            while True:
                await asyncio.sleep(_PROGRESS_INTERVAL_SECONDS)
                elapsed += _PROGRESS_INTERVAL_SECONDS
                # Sent through the session rather than ctx.report_progress()
                # because that helper omits related_request_id, and without it
                # the streamable-HTTP transport routes the notification to the
                # standalone GET stream — where it is dropped outright for a
                # client that only POSTs. Tying it to the request puts it on
                # that call's own stream, which every client is already reading.
                #
                # No `total`: the server reports nothing a fraction could be
                # computed from, and inventing one would misreport completion.
                await session.send_progress_notification(
                    progress_token=token,
                    progress=elapsed,
                    message=f"{tool_name} still running ({int(elapsed)}s)",
                    related_request_id=request_id,
                )
        except asyncio.CancelledError:
            pass
        except Exception as e:  # a dead session must not fail the tool call
            logger.debug("Progress heartbeat for %s stopped: %s", tool_name, e)

    return asyncio.ensure_future(_tick())


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

    sync_handler = _build_tool_function(endpoint, http_method, input_schema)

    async def handler(ctx: Context | None = None, **kwargs):
        # A heartbeat runs alongside the call, never around it: the await below
        # is left exactly as it was so cancellation still reaches
        # run_blocking_ghidra_call and aborts the in-flight Ghidra socket.
        heartbeat = _start_progress_heartbeat(ctx, name)
        try:
            # FastMCP calls synchronous tools directly on its event loop. Keep
            # the blocking Ghidra HTTP lifecycle in a worker thread so one slow
            # request cannot close or starve the entire MCP session.
            result = await state.run_blocking_ghidra_call(sync_handler, **kwargs)
        finally:
            if heartbeat is not None:
                heartbeat.cancel()
        # Failures arrive as an ordinary 200 body; raising is what makes the
        # tool result carry isError instead of looking like a success.
        return dispatch.raise_on_failure(result)

    handler.__signature__ = _signature_with_context(sync_handler.__signature__)
    handler.__annotations__ = dict(sync_handler.__annotations__, ctx=Context | None)
    handler.__name__ = name
    handler.__doc__ = description

    mcp.tool(
        name=name,
        description=description,
        annotations=_tool_annotations(tool_def),
        # Every tool here returns the server's response body as text. Left to
        # infer from the `-> str` annotation, FastMCP declares
        # outputSchema {"result": {"type": "string"}} and wraps the body in
        # structuredContent {"result": "<the json>"} — a structured shape whose
        # single field is an opaque string. That advertises a contract the tool
        # does not have; a client reading `result` still has to parse the JSON
        # itself. Declaring truthful per-tool output schemas needs response
        # shapes described on the Java side, which no endpoint does yet, so the
        # honest option is to declare none.
        structured_output=False,
    )(handler)
    state._dynamic_tool_names.append(name)
    return True


def _tool_annotations(tool_def: dict) -> ToolAnnotations | None:
    """Map the server's `access` classification onto MCP tool annotations.

    Clients act on these, and not only cosmetically: Claude Code reads a tool's
    read-only-ness solely from ``readOnlyHint`` (absent ⇒ false) and, in plan
    mode, forces a permission prompt for every MCP tool that is not read-only —
    one no allow-rule can suppress, since the plan gate is evaluated ahead of
    allow-rules and returns early. The same flag decides whether calls may run
    concurrently. So an unannotated read is a tool that cannot be used
    unattended and cannot be parallelised.

    A tool the server has not classified gets no annotations at all: guessing
    read-only from the HTTP method would be wrong for the mutating GETs
    (``/switch_program``, ``/save_program``, ``/open_program``,
    ``/save_all_programs``) and letting one of those run unprompted while an
    agent is still planning is the failure this is meant to avoid.
    """
    if "read_only" not in tool_def:
        return None
    if tool_def["read_only"]:
        return READ_ONLY_TOOL
    return DESTRUCTIVE_TOOL if tool_def.get("destructive") else WRITE_TOOL


def _report_tool_registration_failures(failures: list[str]) -> None:
    """Emit a compact stderr diagnostic for schema tools that could not load."""
    if not failures:
        return

    shown = "; ".join(failures[:8])
    suffix = "..." if len(failures) > 8 else ""
    sys.stderr.write(f"[bridge_mcp_ghidra] {len(failures)} tool(s) failed to register: " f"{shown}{suffix}\n")
    sys.stderr.flush()


def register_tools_from_schema(schema: list[dict], groups: set[str] | None = None) -> int:
    """Register MCP tools from parsed schema.

    Args:
        schema: List of parsed tool definitions.
        groups: If provided, only register tools in these groups. None = register all.

    Returns: count of registered tools.
    """
    with state._tool_registry_lock:
        # Remove previously registered dynamic tools
        for name in state._dynamic_tool_names:
            try:
                mcp._tool_manager._tools.pop(name, None)
            except Exception as e:
                # Reaches into FastMCP internals; if its private structure changes this
                # would silently leak tools across reloads. Log so the breakage is visible.
                logger.warning(
                    "Failed to unregister dynamic tool %r via mcp._tool_manager._tools "
                    "(FastMCP internals may have changed): %s",
                    name,
                    e,
                )
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
    with state._tool_registry_lock:
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

    with state._tool_registry_lock:
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
                    "Failed to unload tool %r via mcp._tool_manager._tools " "(FastMCP internals may have changed): %s",
                    name,
                    e,
                )

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


def _fetch_and_register_schema(
    load_all: bool = False,
    connection: state.ConnectionSnapshot | None = None,
) -> int:
    """Fetch /mcp/schema from connected instance and register tools.

    Args:
        load_all: If True, register all tools. If False, only default groups.

    Returns: count of registered tools.
    """
    if not load_all:
        load_all = not state._lazy_mode
    schema = _fetch_schema(connection=connection)
    groups = None if load_all else state._default_groups
    return register_tools_from_schema(schema, groups=groups)


def _fetch_schema(connection: state.ConnectionSnapshot | None = None) -> list[dict]:
    """Fetch and parse /mcp/schema without mutating registered tools."""
    text, status = transport.do_request(
        "GET",
        "/mcp/schema",
        timeout=10,
        connection=connection,
    )
    if status != 200:
        raise RuntimeError(f"Failed to fetch schema: HTTP {status}")
    raw = json.loads(text)
    return _parse_schema(raw)


async def _notify_tools_changed(ctx: Context | None) -> None:
    """Send tools/list_changed notification if context is available."""
    if ctx is not None and ctx._request_context is not None:
        state.remember_tools_changed_context(ctx)
        await ctx.request_context.session.send_tool_list_changed()

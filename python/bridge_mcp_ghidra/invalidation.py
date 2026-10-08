"""Write-triggered MCP resource invalidation.

After a mutating tool succeeds, figure out which resource URIs may have changed
and emit ``resources/updated`` (and ``resources/list_changed`` when a listing
row's label moved). Read-only tools return immediately.

Tier resolution runs in Ghidra, not in the agent: LOCAL resolves the write's own
target, CALLERS adds ``/get_functions?fields=callers``, TYPE asks ``/find_type_users``
(``DataTypeReferenceFinder``, off the EDT) and degrades to the program's known
URIs if that errors or times out. UNBOUNDED always degrades, plus list_changed.
NONE is for writes no resource body reports — saving above all, which happens
after nearly every other write.

Checkout *files* are not refreshed here. A DomainObjectListener on the Java
side (TreeObserver → DirtyQueue → TreeReconciler) sees MCP writes, GUI
edits, scripts, and analyzers — one writer for the tree, no double-splice.
``ENDPOINT_TIER`` still drives ``ghidra://function/...`` resource invalidation
and ``resources/updated``, which is a different concern from on-disk files.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import quote

from . import dispatch
from . import state
from . import subscriptions
from .config import logger
from .resources import canonical_function_uri

# Cap per-write fan-out. Beyond this, a single list_changed is cheaper than a
# storm of updated notifications the client will re-list for anyway.
_MAX_URI_FANOUT = 64


class InvalidationTier(str, Enum):
    NONE = "none"            # cannot change any resource body
    LOCAL = "local"          # the write's own target function
    CALLERS = "callers"      # target + functions that call it
    TYPE = "type"            # DataTypeReferenceFinder, or known URIs on failure
    UNBOUNDED = "unbounded"  # create/destroy functions or rewrite the program


# Every non-read-only tool path must appear here. The coverage test fails CI
# when a new write endpoint is added without a tier, so silent non-invalidation
# cannot ship. Tiers gate ghidra://function notifications only — checkout files
# are owned by Java's TreeObserver.
ENDPOINT_TIER: dict[str, InvalidationTier] = {
    # --- NONE: mutates something no resource body reports ---
    # Saving is the important one: it is called after nearly every write, and
    # invalidating on it would drop the whole cache this feature exists to build.
    "/save_program": InvalidationTier.NONE,
    "/save_all_programs": InvalidationTier.NONE,
    "/checkin_program": InvalidationTier.NONE,
    # Server connection, repository administration and adding a file to version control
    # change nothing a program's resources report.
    "/server/connect": InvalidationTier.NONE,
    "/server/authenticate": InvalidationTier.NONE,
    # The process ends; nothing survives to be stale.
    "/exit_ghidra": InvalidationTier.NONE,
    # Moves a CodeBrowser's cursor; no program resource reports where a window is looking.
    "/tool/goto_address": InvalidationTier.NONE,
    "/server/disconnect": InvalidationTier.NONE,
    "/server/repository/create": InvalidationTier.NONE,
    "/server/admin/set_permissions": InvalidationTier.NONE,
    "/server/admin/terminate_all_checkouts": InvalidationTier.NONE,
    "/server/version_control/add": InvalidationTier.NONE,
    "/export_program": InvalidationTier.NONE,
    "/prompt_policy": InvalidationTier.NONE,
    # Analysis options are program state, but no function or program body reports them.
    "/configure_analyzer": InvalidationTier.NONE,
    "/set_bookmark": InvalidationTier.NONE,
    "/delete_bookmark": InvalidationTier.NONE,
    "/archive_ingest_function": InvalidationTier.NONE,
    "/archive_ingest_program": InvalidationTier.NONE,
    # Checkout writes mutate the host filesystem only — never program state — so
    # no ghidra://function or ghidra://program body moves.
    "/decompile_tree_create": InvalidationTier.NONE,
    "/decompile_tree_configure": InvalidationTier.NONE,
    "/decompile_tree_run": InvalidationTier.NONE,
    "/decompile_tree_delete": InvalidationTier.NONE,
    "/decompile_tree_refresh": InvalidationTier.NONE,
    # Placement metadata on the program; no ghidra://function body reports it.
    # The next sweep/reconcile reads the pin — Stage A does not splice on pin alone.
    "/decompile_tree_pin_module": InvalidationTier.NONE,
    # Debugger writes land in a trace, never in the program database.
    "/debugger/launch": InvalidationTier.NONE,
    "/debugger/set_breakpoint": InvalidationTier.NONE,
    "/debugger/remove_breakpoint": InvalidationTier.NONE,
    "/debugger/resume": InvalidationTier.NONE,
    "/debugger/interrupt": InvalidationTier.NONE,
    "/debugger/step": InvalidationTier.NONE,
    # --- LOCAL: body/docs of one function, callers' decompilations untouched ---
    "/set_comment": InvalidationTier.LOCAL,
    "/batch_set_comments": InvalidationTier.LOCAL,
    "/clear_function_comments": InvalidationTier.LOCAL,
    "/set_variables": InvalidationTier.LOCAL,
    "/rename_variables": InvalidationTier.LOCAL,
    "/set_variable_type": InvalidationTier.LOCAL,
    "/set_variable_storage": InvalidationTier.LOCAL,
    "/add_function_tag": InvalidationTier.LOCAL,
    "/remove_function_tag": InvalidationTier.LOCAL,
    "/set_function_tag_comment": InvalidationTier.LOCAL,
    "/batch_rename_function_components": InvalidationTier.LOCAL,
    "/clear_instruction_flow_override": InvalidationTier.LOCAL,
    "/add_memory_reference": InvalidationTier.LOCAL,
    "/remove_reference": InvalidationTier.LOCAL,
    # --- CALLERS: signature/name visible at call sites ---
    "/rename_function": InvalidationTier.CALLERS,
    "/rename_symbol": InvalidationTier.CALLERS,
    "/create_label": InvalidationTier.CALLERS,
    "/delete_label": InvalidationTier.CALLERS,
    "/set_function_prototype": InvalidationTier.CALLERS,
    # Renames and re-types the function, so the widest tier of the steps it composes.
    "/apply_documentation": InvalidationTier.CALLERS,
    "/set_function_this_type": InvalidationTier.CALLERS,
    "/set_function_no_return": InvalidationTier.CALLERS,
    "/apply_data_type": InvalidationTier.CALLERS,
    "/create_function": InvalidationTier.CALLERS,
    "/delete_function": InvalidationTier.CALLERS,
    "/delete_function_tag": InvalidationTier.CALLERS,
    # --- TYPE: struct/enum/typedef edits (precise fan-out in commit 7) ---
    "/add_struct_field": InvalidationTier.TYPE,
    "/remove_struct_field": InvalidationTier.TYPE,
    "/create_derived_type": InvalidationTier.TYPE,
    "/modify_struct_field": InvalidationTier.TYPE,
    "/create_struct": InvalidationTier.TYPE,
    "/recreate_struct": InvalidationTier.TYPE,
    "/resize_struct": InvalidationTier.TYPE,
    "/create_enum": InvalidationTier.TYPE,
    "/create_union": InvalidationTier.TYPE,
    "/create_function_signature": InvalidationTier.TYPE,
    "/create_data_type_category": InvalidationTier.TYPE,
    "/clone_data_type": InvalidationTier.TYPE,
    "/delete_data_type": InvalidationTier.TYPE,
    "/rename_data_type": InvalidationTier.TYPE,
    "/move_data_type_to_category": InvalidationTier.TYPE,
    "/import_data_types": InvalidationTier.TYPE,
    "/resolve_duplicate_type": InvalidationTier.TYPE,
    "/apply_data_classification": InvalidationTier.TYPE,
    "/set_global": InvalidationTier.TYPE,
    # --- UNBOUNDED: analysis, scripts, program lifecycle, project ops ---
    # Every function reading the block may decompile differently.
    "/set_memory_block": InvalidationTier.UNBOUNDED,
    "/reanalyze": InvalidationTier.UNBOUNDED,
    "/run_analysis": InvalidationTier.UNBOUNDED,
    "/analyze_data_region": InvalidationTier.UNBOUNDED,
    "/detect_array_bounds": InvalidationTier.UNBOUNDED,
    "/run_ghidra_script": InvalidationTier.UNBOUNDED,
    "/run_script_inline": InvalidationTier.UNBOUNDED,
    "/disassemble_bytes": InvalidationTier.UNBOUNDED,
    "/clear_flow_and_repair": InvalidationTier.UNBOUNDED,
    "/set_image_base": InvalidationTier.UNBOUNDED,
    "/create_memory_block": InvalidationTier.UNBOUNDED,
    "/open_program": InvalidationTier.UNBOUNDED,
    "/close_program": InvalidationTier.UNBOUNDED,
    "/switch_program": InvalidationTier.UNBOUNDED,
    "/import_file": InvalidationTier.UNBOUNDED,
    # These swap or discard a program's local working copy, so anything cached from it
    # may no longer be true.
    "/server/version_control/checkout": InvalidationTier.UNBOUNDED,
    "/server/version_control/undo_checkout": InvalidationTier.UNBOUNDED,
    "/server/admin/terminate_checkout": InvalidationTier.UNBOUNDED,
    "/set_program_option": InvalidationTier.UNBOUNDED,
    "/remove_program_option": InvalidationTier.UNBOUNDED,
    "/set_property": InvalidationTier.UNBOUNDED,
    "/remove_property": InvalidationTier.UNBOUNDED,
    "/create_property_map": InvalidationTier.UNBOUNDED,
    "/delete_property_map": InvalidationTier.UNBOUNDED,
    "/create_folder": InvalidationTier.UNBOUNDED,
    "/move_folder": InvalidationTier.UNBOUNDED,
    "/move_file": InvalidationTier.UNBOUNDED,
    "/delete_file": InvalidationTier.UNBOUNDED,
    "/merge_program_documentation": InvalidationTier.UNBOUNDED,
    "/create_project": InvalidationTier.UNBOUNDED,
    "/delete_project": InvalidationTier.UNBOUNDED,
    "/close_project": InvalidationTier.UNBOUNDED,
    "/restore_project": InvalidationTier.UNBOUNDED,
    "/archive_project": InvalidationTier.UNBOUNDED,
    "/open_project": InvalidationTier.UNBOUNDED,
    "/import_program": InvalidationTier.UNBOUNDED,
}


# Checkout writes are NONE in ENDPOINT_TIER (they never move a function body)
# but the tree *resource* itself must refresh. Emitting here — before the
# NONE early-return — rides the write's own request so related_request_id still
# reaches a streamable-HTTP client before its SSE stream is torn down.
_CHECKOUT_WRITE_ENDPOINTS = frozenset({
    "/decompile_tree_create",
    "/decompile_tree_configure",
    "/decompile_tree_run",
    "/decompile_tree_delete",
    "/decompile_tree_refresh",
})


@dataclass(frozen=True)
class BlastRadius:
    """Resolved invalidation scope for one successful write.

    ``uris`` is the pre-filter notification set (interest intersect + fan-out
    collapse still happen in ``_invalidate``). Checkout file refresh is owned
    by Java — this struct is notification-only.
    """

    endpoint: str
    tier: InvalidationTier
    program: str | None
    uris: frozenset[str]
    list_changed: bool
    degraded: bool


async def after_successful_write(tool_def: dict, kwargs: dict, ctx, result: str) -> None:
    """Awaited by the registry hook once ``raise_on_failure`` accepted ``result``.

    Awaited rather than fired-and-forgotten, because ``related_request_id`` only
    reaches the client while the request is still open: streamable-HTTP tears a
    request's SSE stream down as soon as its response is sent, and a notification
    arriving after that is dropped outright (``streamable_http.py`` logs
    "Request stream … not found" and moves on). LOCAL/CALLERS cost one or two
    Ghidra GETs, which is noise next to the write itself. TYPE is the exception —
    the finder can run for seconds, so it goes to the background and emits with
    no related id, landing on the session's standalone stream instead of a closed
    one.
    """
    if tool_def.get("read_only"):
        return
    endpoint = tool_def.get("endpoint") or ""

    if endpoint in _CHECKOUT_WRITE_ENDPOINTS:
        await _emit_tree_updated(kwargs, result, ctx)
        return

    tier = ENDPOINT_TIER.get(endpoint)
    if tier is None:
        logger.debug("No invalidation tier for %s; skipping", endpoint)
        return
    if tier is InvalidationTier.NONE:
        return

    related_id = None
    if ctx is not None and getattr(ctx, "_request_context", None) is not None:
        try:
            # Remember the session so the change-token poller has somewhere to
            # send to even when this write's own fan-out turns out empty.
            state.remember_resource_interest(ctx.request_context.session)
            related_id = ctx.request_context.request_id
        except Exception:
            pass

    if tier is InvalidationTier.TYPE:
        _spawn(_invalidate_guarded(endpoint, tier, kwargs, None))
        return
    await _invalidate_guarded(endpoint, tier, kwargs, related_id)


async def _emit_tree_updated(kwargs: dict, result: str, ctx) -> None:
    """Best-effort: a failed emit must never turn a successful tree write into an error."""
    try:
        related_id = None
        if ctx is not None and getattr(ctx, "_request_context", None) is not None:
            try:
                state.remember_resource_interest(ctx.request_context.session)
                related_id = ctx.request_context.request_id
            except Exception:
                pass
        uri = _tree_uri_from_write(kwargs, result)
        if not uri:
            return
        # only_known=True (default): unread tree URIs get zero notifications.
        await subscriptions.emit_resource_updated(
            uri, related_request_id=related_id
        )
    except Exception as e:
        logger.debug("Tree resource invalidation failed: %s", e)


def _tree_uri_from_write(kwargs: dict, result: str) -> str | None:
    # Prefer the response: create has no tree kwarg, and the selector may
    # be a program name rather than the id that forms the URI.
    if isinstance(result, str) and result:
        try:
            payload = json.loads(result)
        except Exception:
            payload = None
        if isinstance(payload, dict):
            uri = payload.get("resource_uri")
            if isinstance(uri, str) and uri.startswith("ghidra://decompile-tree/"):
                return uri
            cid = payload.get("tree_id")
            if cid:
                return f"ghidra://decompile-tree/{cid}"
    selector = kwargs.get("tree")
    if isinstance(selector, str) and selector.startswith("tree_"):
        return f"ghidra://decompile-tree/{selector}"
    return None


# Strong references: a bare create_task() may be garbage-collected mid-flight.
_background_tasks: set[asyncio.Task] = set()


def _spawn(coro) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        coro.close()
        return
    task = loop.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def _invalidate_guarded(
    endpoint: str,
    tier: InvalidationTier,
    kwargs: dict,
    related_request_id,
) -> None:
    """Invalidation is best-effort: it must never turn a successful write into an error."""
    try:
        blast = await resolve_blast_radius(endpoint, tier, kwargs)
        await _invalidate(blast, related_request_id)
    except Exception as e:
        logger.debug("Resource invalidation after %s failed: %s", endpoint, e)


async def resolve_blast_radius(
    endpoint: str,
    tier: InvalidationTier,
    kwargs: dict,
) -> BlastRadius:
    """Compute notification URIs for one successful write."""
    program = _program_name(kwargs)
    uris: set[str] = set()
    list_changed = False
    degraded = False

    if tier is InvalidationTier.LOCAL:
        addr = await _resolve_target_address(program, kwargs)
        if addr and program:
            uris.add(canonical_function_uri(program, addr))
    elif tier is InvalidationTier.CALLERS:
        addr = await _resolve_target_address(program, kwargs)
        callers = await _caller_entries(program, kwargs)
        if addr and program:
            uris.add(canonical_function_uri(program, addr))
        uri_callers = 0
        for entry in callers:
            caddr = entry.get("address")
            if not caddr or not program:
                continue
            if uri_callers < _MAX_URI_FANOUT:
                uris.add(canonical_function_uri(program, str(caddr)))
                uri_callers += 1
        if endpoint in ("/rename_function", "/rename_symbol"):
            list_changed = True
            uris |= _by_name_uris(program, kwargs)
    elif tier is InvalidationTier.TYPE:
        type_addrs = await _type_user_addresses(program, kwargs)
        if type_addrs is None:
            uris |= _known_uris_for_program(program)
            list_changed = True
            degraded = True
        elif program:
            for a in type_addrs:
                uris.add(canonical_function_uri(program, a))
    else:  # UNBOUNDED
        uris |= _known_uris_for_program(program)
        list_changed = True
        degraded = True

    if endpoint in ("/open_program", "/close_program", "/switch_program", "/import_file"):
        uris.add("ghidra://programs")
        list_changed = True

    return BlastRadius(
        endpoint=endpoint,
        tier=tier,
        program=program,
        uris=frozenset(uris),
        list_changed=list_changed,
        degraded=degraded,
    )


async def _invalidate(blast: BlastRadius, related_request_id) -> None:
    """Emit notifications from a resolved blast radius."""
    uris = set(blast.uris)
    list_changed = blast.list_changed

    uris = _intersect_with_interest(uris)
    if len(uris) > _MAX_URI_FANOUT:
        logger.debug(
            "Invalidation fan-out for %s is %d (>%d); collapsing to list_changed",
            blast.endpoint, len(uris), _MAX_URI_FANOUT,
        )
        list_changed = True
        uris = set()

    for uri in sorted(uris):
        await subscriptions.emit_resource_updated(
            uri, related_request_id=related_request_id
        )
    if list_changed:
        await subscriptions.emit_resource_list_changed(
            related_request_id=related_request_id
        )


def _program_name(kwargs: dict) -> str | None:
    value = kwargs.get("program")
    if value is None or value == "":
        return None
    return str(value)


def _intersect_with_interest(uris: set[str]) -> set[str]:
    known = state.known_resource_uris()
    if not known:
        return set()
    return uris & known


def _known_uris_for_program(program: str | None) -> set[str]:
    known = state.known_resource_uris()
    if not program:
        return set(known)
    # Match both raw and percent-encoded program segments.
    markers = (f"/{program}/", f"/{quote(program, safe='')}/")
    return {u for u in known if any(m in u for m in markers) or u == "ghidra://programs"}


def _by_name_uris(program: str | None, kwargs: dict) -> set[str]:
    if not program:
        return set()
    out: set[str] = set()
    for key in ("old_name", "new_name", "name", "symbol_name"):
        value = kwargs.get(key)
        if value:
            out.add(
                f"ghidra://function/{quote(program, safe='')}/by-name/{quote(str(value), safe='')}"
            )
    return out


async def _caller_entries(program: str | None, kwargs: dict) -> list[dict]:
    """Caller list capped for notification fan-out (not for tree files)."""
    if not program:
        return []
    name = _first(kwargs, "old_name", "name", "function", "function_name")
    address = _first(
        kwargs, "function_address", "address", "entry", "entry_point"
    )
    params: dict[str, Any] = {"program": program, "limit": _MAX_URI_FANOUT}
    if address:
        params["address"] = address
    elif name:
        params["name"] = name
    else:
        return []
    try:
        raw = await state.run_blocking_ghidra_call(
            lambda: dispatch.raise_on_failure(
                dispatch.dispatch_get(
                    "/get_functions",
                    params={**params, "fields": "callers", "include_call_context": "false"},
                )
            )
        )
        payload = json.loads(raw)
    except Exception as e:
        logger.debug("get_functions(callers) for invalidation failed: %s", e)
        return []
    callers = payload.get("callers", []) if isinstance(payload, dict) else []
    if not isinstance(callers, list):
        return []
    return [c for c in callers if isinstance(c, dict)]


async def _type_user_addresses(program: str | None, kwargs: dict) -> set[str] | None:
    """Return precise addresses for a TYPE-tier write, or None to degrade.

    ``None`` means the finder timed out / errored / could not resolve the type
    name — the notification path falls back to known URIs.
    An empty set means the finder ran and found no users.
    """
    type_name = _first(
        kwargs,
        "type_name",
        "name",
        "struct_name",
        "data_type",
        "datatype",
        "enum_name",
        "old_name",
    )
    if not type_name or not program:
        return None
    field = _first(kwargs, "field", "field_name", "member", "member_name")
    params: dict[str, Any] = {
        "type_name": type_name,
        "program": program,
        "timeout_seconds": 10,
    }
    if field:
        params["field"] = field
    try:
        raw = await state.run_blocking_ghidra_call(
            lambda: dispatch.raise_on_failure(
                dispatch.dispatch_get("/find_type_users", params=params)
            )
        )
        payload = json.loads(raw)
    except Exception as e:
        logger.debug("find_type_users for invalidation failed: %s", e)
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("timed_out"):
        logger.debug("find_type_users timed out for %s; degrading", type_name)
        return None
    functions = payload.get("functions", [])
    addrs: set[str] = set()
    if isinstance(functions, list):
        for item in functions:
            if not isinstance(item, dict) or not item.get("address"):
                continue
            addrs.add(str(item["address"]))
    return addrs


async def _resolve_target_address(program: str | None, kwargs: dict) -> str | None:
    """Best-effort entry point for the function a write touched."""
    direct = _first(
        kwargs,
        "function_address",
        "address",
        "entry",
        "entry_point",
    )
    name = _first(
        kwargs,
        "old_name",
        "function",
        "function_name",
        "name",
    )
    locator = direct or name
    if not locator:
        return None
    # resolveFunction accepts names; fields=entry_point keeps this cheap (no decompile).
    params: dict[str, Any] = {"address": locator, "fields": "entry_point"}
    if program:
        params["program"] = program
    try:
        raw = await state.run_blocking_ghidra_call(
            lambda: dispatch.raise_on_failure(
                dispatch.dispatch_get("/get_functions", params=params)
            )
        )
        payload = json.loads(raw)
        if isinstance(payload, dict) and payload.get("address"):
            return str(payload["address"])
    except Exception as e:
        logger.debug("resolve target for invalidation failed: %s", e)
    return str(direct) if direct else None


def _first(kwargs: dict, *keys: str) -> str | None:
    for key in keys:
        value = kwargs.get(key)
        if value is not None and value != "":
            return str(value)
    return None

"""Static MCP tools that are always available, plus startup auto-connect."""

import asyncio
import json
import os

from . import discovery
from . import dispatch
from . import registry
from . import state
from . import transport
from .config import DEFAULT_TCP_URL, STATIC_TOOL_NAMES, logger
from .server import Context, mcp
from .validation import validate_server_url


@mcp.tool()
def list_instances() -> str:
    """
    List known Ghidra instances from UDS discovery and the active TCP fallback.

    Returns JSON with each instance's project name, PID, open programs, and
    socket path or TCP URL. Also shows which instance is currently connected.
    """
    instances = discovery.discover_instances()
    tcp_instance = discovery.discover_active_tcp_instance()
    if tcp_instance:
        instances.append(tcp_instance)

    if not instances:
        return json.dumps(
            {"instances": [], "note": "No running Ghidra instances found."}
        )

    for inst in instances:
        if inst.get("transport") == "tcp":
            inst["connected"] = (
                state._transport_mode == "tcp" and inst.get("url") == state._active_tcp
            )
        else:
            # UDS-discovered instances may carry a TCP url too (Windows
            # enrichment) — either transport counts as connected.
            inst["connected"] = inst["socket"] == state._active_socket or (
                state._transport_mode == "tcp"
                and bool(inst.get("url"))
                and inst.get("url") == state._active_tcp
            )

    return json.dumps({"instances": instances}, indent=2)


@mcp.tool()
async def connect_instance(project: str, ctx: Context | None = None) -> str:
    """
    Switch the MCP bridge to a different Ghidra instance by project name.

    IMPORTANT: Before calling this function only the static bridge tools are
    exposed (list_instances, connect_instance, tool-group management,
    debugger proxy). After a successful connect the bridge fetches the
    instance's /mcp/schema and registers Ghidra analysis tools dynamically.
    By default all tool groups are loaded on connect. When started with
    --lazy, only the default groups are loaded initially and clients may need
    to call load_tool_group() for additional categories. Clients that cache
    the initial tools/list and don't honor tools/list_changed must re-list
    tools after this call.

    Use list_instances() first to see available instances.

    Args:
        project: Project name (or substring) to connect to
    """
    instances = discovery.discover_instances()

    # Try UDS instances first
    match = None
    matched_tcp_url = None
    if instances:
        for inst in instances:
            if inst.get("project", "") == project:
                match = inst
                break
        if not match:
            for inst in instances:
                if project.lower() in inst.get("project", "").lower():
                    match = inst
                    break
        if match and not transport.uds_supported():
            # Windows CPython can't dial the socket it just matched; the
            # discovery enrichment recorded the instance's TCP url — route
            # the connection there instead of failing the UDS handshake.
            matched_tcp_url = match.get("url")
        elif match:
            state._active_socket = match["socket"]
            state._active_tcp = None
            state._transport_mode = "uds"
            state._connected_project = match.get("project")

            try:
                count = registry._fetch_and_register_schema()
                total = len(state._full_schema)
                note = (
                    f"Loaded {count}/{total} tools (default groups). Use load_tool_group() for more."
                    if state._lazy_mode
                    else f"Loaded all {count} tools on connect."
                )
                await registry._notify_tools_changed(ctx)
                return json.dumps(
                    {
                        "connected": True,
                        "transport": "uds",
                        "project": state._connected_project,
                        "socket": match["socket"],
                        "pid": match.get("pid"),
                        "tools_registered": count,
                        "tools_total": total,
                        "loaded_groups": sorted(state._loaded_groups),
                        "note": note,
                    }
                )
            except Exception as e:
                return json.dumps(
                    {"error": f"Schema fetch failed: {e}", "socket": state._active_socket}
                )

    # Try TCP fallback. The behavior depends on what UDS discovery returned:
    #
    #   * If GHIDRA_MCP_URL is set, it always wins (explicit user override).
    #   * If a UDS instance matched but Python can't dial UDS (Windows), use
    #     the TCP url discovery recorded for that exact instance.
    #   * If UDS found one or more instances with project metadata and none
    #     matched the project, refuse to fall back to TCP -- that's how we
    #     previously silently connected to the wrong instance (Copilot #196
    #     review item).
    #   * If UDS found no usable project metadata, scan the TCP port range
    #     looking for a /mcp/instance_info that matches the project. Handles
    #     TCP-only and native Windows cases where AF_UNIX is unavailable.
    #   * If no scan match either, try the default port as a last resort.
    env_tcp = os.getenv("GHIDRA_MCP_URL")
    if env_tcp:
        tcp_url = env_tcp
    elif matched_tcp_url:
        tcp_url = matched_tcp_url
    elif match is None and instances and any(inst.get("project") for inst in instances):
        # UDS found instances but none matched the requested project. Don't
        # randomly pick another instance's tcp_port — that connects to the
        # wrong project. Return the "no match" error directly.
        available = [inst.get("project", "unknown") for inst in instances]
        return json.dumps(
            {
                "error": (
                    f"No instance matching '{project}' (UDS: {len(instances)} found, "
                    f"none matched). Refusing to use any instance's tcp_port — would "
                    f"connect to the wrong project. Use list_instances() to see what's "
                    f"available."
                ),
                "available": available,
            }
        )
    else:
        # No usable UDS project metadata. Scan the TCP port range to find one
        # matching the project. _scan_tcp_for_project returns the URL of the
        # first matching instance, or None if nothing matched.
        scanned = discovery._scan_tcp_for_project(project)
        tcp_url = scanned if scanned else DEFAULT_TCP_URL
    if not validate_server_url(tcp_url):
        return json.dumps(
            {
                "error": f"Refusing to connect to invalid TCP URL: {tcp_url}. Expected http://<127.0.0.1|localhost|::1>:<port> (http scheme and an explicit port are required)."
            }
        )
    try:
        state._active_tcp = tcp_url
        state._active_socket = None
        state._transport_mode = "tcp"
        state._connected_project = match.get("project") if match else None
        count = registry._fetch_and_register_schema()
        total = len(state._full_schema)
        note = (
            f"Loaded {count}/{total} tools (default groups). Use load_tool_group() for more."
            if state._lazy_mode
            else f"Loaded all {count} tools on connect."
        )
        await registry._notify_tools_changed(ctx)
        return json.dumps(
            {
                "connected": True,
                "transport": "tcp",
                "url": tcp_url,
                "tools_registered": count,
                "tools_total": total,
                "loaded_groups": sorted(state._loaded_groups),
                "note": note,
            }
        )
    except Exception as e:
        state._transport_mode = "none"
        state._active_tcp = None
        available = [inst.get("project", "unknown") for inst in instances]
        return json.dumps(
            {
                "error": f"No instance matching '{project}' (UDS: {len(instances)} found, TCP {tcp_url}: {e})",
                "available": available,
            }
        )


@mcp.tool()
def list_tool_groups() -> str:
    """
    List all available tool groups with their tool counts and loaded status.

    Returns each category with: tool count, loaded status, and tool names.
    Use load_tool_group(group) to load a group's tools.
    """
    if not state._full_schema:
        return json.dumps(
            {"error": "No instance connected. Use connect_instance() first."}
        )
    groups = registry._get_group_info()
    return json.dumps({"groups": groups, "total_tools": len(state._full_schema)}, indent=2)


@mcp.tool()
async def load_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Load all tools in a category. Accepts a category name or "all" to load everything.

    Use list_tool_groups() to see available categories.

    Args:
        group: Category name (e.g. "function", "datatype") or "all"
    """
    if not state._full_schema:
        return json.dumps(
            {"error": "No instance connected. Use connect_instance() first."}
        )

    if group == "all":
        # Load all unloaded groups
        all_groups = {td.get("category", "unknown") for td in state._full_schema}
        all_loaded: list[str] = []
        for g in sorted(all_groups):
            all_loaded.extend(registry._load_group(g))
        if all_loaded:
            await registry._notify_tools_changed(ctx)
        return json.dumps(
            {
                "loaded": "all",
                "new_tools": len(all_loaded),
                "new_tool_names": sorted(all_loaded),
                "total_loaded": len(state._dynamic_tool_names),
            }
        )

    loaded_names = registry._load_group(group)
    if not loaded_names:
        available = sorted({td.get("category", "unknown") for td in state._full_schema})
        if group in state._loaded_groups:
            # Already loaded — return the tool names so the agent knows what's callable
            already = sorted(
                td["name"] for td in state._full_schema if td.get("category") == group
            )
            return json.dumps(
                {
                    "message": f"Group '{group}' is already loaded.",
                    "tools": already,
                    "loaded_groups": sorted(state._loaded_groups),
                }
            )
        return json.dumps(
            {
                "error": f"No tools found for group '{group}'",
                "available_groups": available,
            }
        )

    await registry._notify_tools_changed(ctx)
    return json.dumps(
        {
            "loaded": group,
            "new_tools": len(loaded_names),
            "tools": sorted(loaded_names),
            "total_loaded": len(state._dynamic_tool_names),
            "loaded_groups": sorted(state._loaded_groups),
        }
    )


@mcp.tool()
async def unload_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Unload all tools in a category. Default groups are protected from unloading.

    Args:
        group: Category name to unload
    """
    if group in state._default_groups:
        return json.dumps(
            {
                "error": f"Cannot unload default group '{group}'",
                "default_groups": sorted(state._default_groups),
            }
        )

    removed = registry._unload_group(group)
    if removed == 0:
        return json.dumps(
            {"message": f"Group '{group}' is not loaded or has no tools."}
        )

    await registry._notify_tools_changed(ctx)
    return json.dumps(
        {
            "unloaded": group,
            "removed_tools": removed,
            "total_loaded": len(state._dynamic_tool_names),
            "loaded_groups": sorted(state._loaded_groups),
        }
    )


@mcp.tool()
async def check_tools(tools: str) -> str:
    """
    Check if specific tools are callable right now. Returns status for each tool:
    "callable", "not_loaded" (exists but group not loaded), or "not_found" (doesn't exist).

    Args:
        tools: Comma-separated tool names, e.g. "rename_or_label,batch_set_comments,analyze_function_completeness"
    """
    tool_names = [t.strip() for t in tools.split(",") if t.strip()]
    if not tool_names:
        return json.dumps({"error": "Provide comma-separated tool names"})

    # Build lookup of all known tools -> their group
    all_known: dict[str, str] = {}
    for td in state._full_schema:
        all_known[td["name"]] = td.get("category", "unknown")

    # Check each tool
    results: dict[str, dict] = {}
    for name in tool_names:
        if name in STATIC_TOOL_NAMES:
            results[name] = {"status": "callable", "type": "static"}
        elif name in state._dynamic_tool_names:
            results[name] = {
                "status": "callable",
                "group": all_known.get(name, "unknown"),
            }
        elif name in all_known:
            group = all_known[name]
            results[name] = {
                "status": "not_loaded",
                "group": group,
                "fix": f'load_tool_group("{group}")',
            }
        else:
            results[name] = {"status": "not_found"}

    callable_count = sum(1 for r in results.values() if r["status"] == "callable")
    return json.dumps(
        {
            "results": results,
            "summary": f"{callable_count}/{len(tool_names)} callable",
        }
    )


@mcp.tool()
async def search_tools(query: str, limit: int = 15) -> str:
    """
    Search the full Ghidra tool catalog by keyword — including tools whose group
    is not currently loaded. Use this to discover the right tool without paying
    the context cost of loading all groups (run the bridge with --lazy and search
    on demand). Matches against tool name, description, and category.

    Each result reports whether the tool is callable right now; if not, it
    includes the exact load_tool_group(...) call needed to make it callable.

    Args:
        query: Space-separated keywords, e.g. "rename function" or "xref struct".
        limit: Maximum number of results to return (default 15).
    """
    terms = [t.lower() for t in query.split() if t.strip()]
    if not terms:
        return json.dumps({"error": "Provide one or more search keywords"})

    scored: list[tuple[int, dict]] = []
    for td in state._full_schema:
        name = td.get("name", "")
        category = td.get("category", "unknown")
        desc = td.get("description", "") or ""
        haystack = f"{name} {category} {desc}".lower()
        score = 0
        for term in terms:
            if term in name.lower():
                score += 3  # name hits rank highest
            elif term in haystack:
                score += 1
        if score == 0:
            continue
        loaded = name in state._dynamic_tool_names or name in STATIC_TOOL_NAMES
        result = {
            "name": name,
            "group": category,
            "status": "callable" if loaded else "not_loaded",
            "description": desc[:160],
        }
        if not loaded:
            result["fix"] = f'load_tool_group("{category}")'
        scored.append((score, result))

    scored.sort(key=lambda x: x[0], reverse=True)
    matches = [r for _, r in scored[: max(1, limit)]]
    return json.dumps(
        {
            "query": query,
            "match_count": len(scored),
            "returned": len(matches),
            "matches": matches,
        }
    )


@mcp.tool()
async def import_file(
    file_path: str,
    project_folder: str = "/",
    language: str | None = None,
    compiler_spec: str | None = None,
    auto_analyze: bool = True,
    ctx: Context | None = None,
) -> str:
    """
    Import a binary file from disk into the current Ghidra project.

    Imports the file, opens it in the CodeBrowser, and optionally starts auto-analysis.
    When analysis is enabled, sends a log notification when analysis completes.

    For raw firmware binaries, specify language (e.g. "ARM:LE:32:Cortex") and
    optionally compiler_spec (e.g. "default"). Without language, Ghidra auto-detects
    the format (works for ELF, PE, Mach-O, etc.).

    Args:
        file_path: Absolute path to the binary file on disk
        project_folder: Destination folder in the Ghidra project (default: "/")
        language: Language ID for raw binaries (e.g. "ARM:LE:32:Cortex", "x86:LE:64:default")
        compiler_spec: Compiler spec ID (e.g. "default", "gcc"). Uses language default if omitted.
        auto_analyze: Start auto-analysis after import (default: true)
    """
    payload: dict = {
        "file_path": file_path,
        "project_folder": project_folder,
        "auto_analyze": auto_analyze,
    }
    if language:
        payload["language"] = language
    if compiler_spec:
        payload["compiler_spec"] = compiler_spec

    result = dispatch.dispatch_post("/import_file", payload)

    # Parse result to check if analysis was started
    try:
        data = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return result

    if data.get("data", {}).get("analyzing") and ctx is not None:
        program_name = data["data"].get("name", "unknown")
        # Capture the session before the tool call returns
        session = ctx.request_context.session

        async def _poll_analysis():
            """Poll analysis_status until analysis completes, then send log notification."""
            await asyncio.sleep(5)  # Initial delay
            for _ in range(360):  # Up to 30 minutes
                try:
                    status_text = dispatch.dispatch_get(
                        "/analysis_status", {"program": program_name}
                    )
                    status = json.loads(status_text)
                    status_data = status.get("data", status)
                    if not status_data.get("analyzing", True):
                        fn_count = status_data.get("function_count", "?")
                        await session.send_log_message(
                            level="info",
                            data=f"Analysis complete for {program_name}: {fn_count} functions found",
                        )
                        return
                except Exception as e:
                    logger.debug(f"Analysis poll error for {program_name}: {e}")
                await asyncio.sleep(5)

        asyncio.create_task(_poll_analysis())

    return result


def _auto_connect():
    """Try to auto-connect to a single running instance on startup."""
    # Try UDS first
    instances = discovery.discover_instances()
    if len(instances) == 1:
        inst = instances[0]
        if transport.uds_supported():
            state._active_socket = inst["socket"]
            state._transport_mode = "uds"
            state._connected_project = inst.get("project")
            logger.info(f"Auto-connecting via UDS to {state._connected_project or 'unknown'}")
            try:
                count = registry._fetch_and_register_schema()
                logger.info(
                    f"Auto-registered {count} tools from {state._connected_project or 'unknown'}"
                )
                return
            except Exception as e:
                logger.warning(f"UDS auto-connect schema fetch failed: {e}")
                state._active_socket = None
                state._transport_mode = "none"
        elif inst.get("url") and validate_server_url(inst["url"]):
            # Windows CPython can't dial the discovered socket; discovery
            # enriched it with the instance's TCP url — connect there.
            state._active_tcp = inst["url"]
            state._transport_mode = "tcp"
            state._connected_project = inst.get("project")
            logger.info(
                f"Auto-connecting via TCP ({inst['url']}) to "
                f"{state._connected_project or 'unknown'} (UDS unavailable on this Python)"
            )
            try:
                count = registry._fetch_and_register_schema()
                logger.info(
                    f"Auto-registered {count} tools from {state._connected_project or 'unknown'}"
                )
                return
            except Exception as e:
                logger.warning(f"TCP auto-connect schema fetch failed: {e}")
                state._active_tcp = None
                state._transport_mode = "none"
    elif len(instances) > 1:
        names = ", ".join(
            i.get("project") or i.get("socket") or "?" for i in instances
        )
        logger.info(
            f"Multiple UDS instances found ({len(instances)}: {names}). "
            "Use connect_instance() to choose."
        )
        # Do NOT fall through to the TCP fallback — that would silently
        # connect to whichever Ghidra happened to bind 8089 (possibly a
        # third instance entirely) right after telling the user to choose.
        # Stay unconnected until connect_instance() is called explicitly,
        # matching connect_instance's own multi-instance refusal logic.
        return

    # Try TCP fallback
    tcp_url = os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)
    if not validate_server_url(tcp_url):
        logger.warning(f"Refusing to auto-connect to non-local URL: {tcp_url}")
        return
    try:
        state._active_tcp = tcp_url
        state._transport_mode = "tcp"
        count = registry._fetch_and_register_schema()
        logger.info(f"Auto-connected via TCP to {tcp_url}, registered {count} tools")
    except Exception:
        state._active_tcp = None
        state._transport_mode = "none"
        if not instances:
            logger.info(
                "No Ghidra instances found. Tools will be registered on connect_instance()."
            )

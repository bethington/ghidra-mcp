"""Static MCP tools that are always available (instance & tool-group management)."""

import asyncio
import json
import os

from fastmcp import Context

from . import connection, discovery, registry
from .app import mcp
from .config import DEFAULT_TCP_URL, logger
from .validation import validate_server_url


def _connect_result(transport: str, count: int, **extra) -> str:
    """Build the JSON payload shared by the UDS and TCP connect paths."""
    payload = {
        "connected": True,
        "transport": transport,
        "tools_registered": count,
        "note": (
            f"Registered {count} tools. They are hidden from list_tools to save "
            "context; use search_tools(query=...) to discover tools and call_tool "
            "to invoke them."
        ),
    }
    payload.update(extra)
    return json.dumps(payload)


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

    active_socket = connection.active_socket()
    active_tcp = connection.active_tcp()
    transport_mode = connection.transport_mode()
    for inst in instances:
        if inst.get("transport") == "tcp":
            inst["connected"] = transport_mode == "tcp" and inst.get("url") == active_tcp
        else:
            inst["connected"] = inst["socket"] == active_socket

    return json.dumps({"instances": instances}, indent=2)


@mcp.tool()
async def connect_instance(project: str) -> str:
    """
    Switch the MCP bridge to a different Ghidra instance by project name.

    After a successful connect the bridge fetches the instance's /mcp/schema
    and registers all Ghidra analysis tools. To keep the context small,
    list_tools only ever shows list_instances, connect_instance, and the
    synthetic search_tools/call_tool: use search_tools(query=...) to discover
    the analysis and debugger tools and call_tool to invoke them. Clients that
    cache the initial tools/list and don't honor tools/list_changed must
    re-list tools after this call.

    Use list_instances() first to see available instances.

    Args:
        project: Project name (or substring) to connect to
    """
    instances = discovery.discover_instances()

    # Try UDS instances first
    if instances:
        match = None
        for inst in instances:
            if inst.get("project", "") == project:
                match = inst
                break
        if not match:
            for inst in instances:
                if project.lower() in inst.get("project", "").lower():
                    match = inst
                    break
        if match:
            connection.activate_uds(match["socket"], match.get("project"))
            try:
                count = registry.fetch_and_register_schema()
                return _connect_result(
                    "uds",
                    count,
                    project=connection.connected_project(),
                    socket=match["socket"],
                    pid=match.get("pid"),
                )
            except Exception as e:
                return json.dumps(
                    {"error": f"Schema fetch failed: {e}", "socket": match["socket"]}
                )

    # Try TCP fallback. The behavior depends on what UDS discovery returned:
    #
    #   * If GHIDRA_MCP_URL is set, it always wins (explicit user override).
    #   * If UDS found one or more instances and none matched the project,
    #     refuse to fall back to TCP -- that's how we previously silently
    #     connected to the wrong instance (Copilot #196 review item).
    #   * If UDS found NOTHING (no instances at all), scan the TCP port range
    #     looking for a /mcp/instance_info that matches the project. Handles
    #     the TCP-only multi-instance case (e.g. Windows pre-1803 without
    #     AF_UNIX).
    #   * If no scan match either, try the default port as a last resort.
    env_tcp = os.getenv("GHIDRA_MCP_URL")
    if env_tcp:
        tcp_url = env_tcp
    elif instances:
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
        # No UDS instances. Scan the TCP port range to find one matching
        # the project. _scan_tcp_for_project returns the URL of the first
        # matching instance, or None if nothing matched.
        scanned = discovery._scan_tcp_for_project(project)
        tcp_url = scanned if scanned else DEFAULT_TCP_URL
    if not validate_server_url(tcp_url):
        return json.dumps(
            {
                "error": f"Refusing to connect to non-local URL: {tcp_url}. "
                "Only 127.0.0.1, localhost, and ::1 are allowed."
            }
        )
    try:
        connection.activate_tcp(tcp_url)
        count = registry.fetch_and_register_schema()
        return _connect_result("tcp", count, url=tcp_url)
    except Exception as e:
        connection.reset()
        available = [inst.get("project", "unknown") for inst in instances]
        return json.dumps(
            {
                "error": f"No instance matching '{project}' "
                f"(UDS: {len(instances)} found, TCP {tcp_url}: {e})",
                "available": available,
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

    result = connection.dispatch_post("/import_file", payload)

    # Parse result to check if analysis was started
    try:
        data = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return result

    if data.get("data", {}).get("analyzing") and ctx is not None:
        program_name = data["data"].get("name", "unknown")

        async def _poll_analysis():
            """Poll analysis_status until analysis completes, then send log notification."""
            await asyncio.sleep(5)  # Initial delay
            for _ in range(360):  # Up to 30 minutes
                try:
                    status_text = connection.dispatch_get(
                        "/analysis_status", {"program": program_name}
                    )
                    status = json.loads(status_text)
                    status_data = status.get("data", status)
                    if not status_data.get("analyzing", True):
                        fn_count = status_data.get("function_count", "?")
                        await ctx.info(
                            f"Analysis complete for {program_name}: "
                            f"{fn_count} functions found"
                        )
                        return
                except Exception as e:
                    logger.debug(f"Analysis poll error for {program_name}: {e}")
                await asyncio.sleep(5)

        asyncio.create_task(_poll_analysis())

    return result

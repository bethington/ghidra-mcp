"""connect_instance's blocking body: pick an instance for a project and connect to it.

Every failure raises ``dispatch.GhidraToolError`` so FastMCP marks the result
``isError`` (#652). Returning the error dict as a successful result made a
refused selection indistinguishable from a successful one at the protocol
level: a client branching on ``isError`` saw ``connect_instance(project=X)``
succeed while the bridge stayed on whatever it was connected to before.

A TCP URL the bridge did not find BY project — ``GHIDRA_MCP_URL`` (pinned or
not) and the ``DEFAULT_TCP_URL`` fallback after a missed port scan — is asked
for its project before anything is registered (#655). Without that check the
call reported ``connected: true`` for a project the listener did not have
open, and the next call answered from a different project.
"""

import os

from . import discovery
from . import registry
from . import state
from . import transport
from .config import DEFAULT_TCP_URL
from .dispatch import GhidraToolError
from .validation import validate_server_url


def _match_project(project: str, instances: list[dict]) -> dict | None:
    """Return the instance whose project is ``project`` exactly, else the first substring match.

    The one rule connect_instance selects by, on every transport: a UDS
    instance and a TCP listener's ``/mcp/instance_info`` are judged the same
    way, so ``connect_instance("diablo")`` means the same thing however the
    instance was reached.
    """
    for inst in instances:
        if inst.get("project", "") == project:
            return inst
    project_lower = project.lower()
    for inst in instances:
        if project_lower in (inst.get("project") or "").lower():
            return inst
    return None


def _available(instances: list[dict]) -> str:
    names = [inst.get("project") or "unknown" for inst in instances]
    return f" Available: {', '.join(names)}." if names else ""


def _verify_tcp_project(project: str, tcp_url: str, how: str) -> str:
    """Return the project ``tcp_url`` has open if it matches ``project``; raise otherwise.

    Fails CLOSED: the caller named a project, so a listener that cannot say
    which project it holds — unreachable, an older server without
    ``/mcp/instance_info``, a malformed answer, or no project open — is
    refused rather than assumed to be the right one. ``how`` names where the
    URL came from, so the refusal says why this URL was tried at all.
    """
    prefix = f"Refusing to connect to {tcp_url} ({how}) for project '{project}'"
    try:
        text, status = transport.tcp_request(tcp_url, "GET", "/mcp/instance_info", timeout=5)
    except Exception as e:
        raise GhidraToolError(
            f"{prefix}: /mcp/instance_info could not be reached ({e}), so the project "
            f"it has open cannot be confirmed."
        ) from e
    if status != 200:
        raise GhidraToolError(
            f"{prefix}: /mcp/instance_info returned HTTP {status}, so the project it has "
            f"open cannot be confirmed."
        )
    try:
        info = discovery._unwrap_response_data(text)
    except ValueError as e:
        raise GhidraToolError(f"{prefix}: /mcp/instance_info returned a body that is not JSON ({e}).") from e
    reported = info.get("project") if isinstance(info, dict) else None
    if not isinstance(reported, str) or not reported:
        raise GhidraToolError(
            f"{prefix}: the server there reports no open project. Open the project on that "
            f"server, or use list_instances() to find the instance that has it."
        )
    if _match_project(project, [{"project": reported}]) is None:
        raise GhidraToolError(
            f"{prefix}: the server there has project '{reported}' open. "
            f"Use list_instances() to see what's available."
        )
    return reported


def _loaded_note(count: int, total: int) -> str:
    if state._lazy_mode:
        return f"Loaded {count}/{total} tools (default groups). Use load_tool_group() for more."
    return f"Loaded all {count} tools on connect."


def _connect_instance_sync(project: str) -> dict:
    """Blocking connect_instance implementation for worker-thread execution.

    Returns the success payload; raises ``GhidraToolError`` on every failure.
    """
    cancel_handle = state.get_request_cancel_handle()

    def _commit_if_live(func, /, *args, **kwargs):
        if cancel_handle is None:
            return func(*args, **kwargs)
        return cancel_handle.run_if_not_aborted(func, *args, **kwargs)

    def _raise_if_cancelled():
        if cancel_handle is not None and cancel_handle.aborted:
            raise GhidraToolError("connect_instance cancelled before commit")

    instances = discovery.discover_instances()

    # Try UDS instances first
    match = _match_project(project, instances) if instances else None
    matched_tcp_url = None
    if match and not transport.uds_supported():
        matched_tcp_url = match.get("url")
    elif match:
        candidate = state.build_connection_snapshot(
            mode="uds",
            active_socket=match["socket"],
            connected_project=match.get("project"),
        )
        try:
            schema = registry._fetch_schema(connection=candidate)
        except Exception as e:
            raise GhidraToolError(f"Schema fetch failed: {e} (socket {match['socket']})") from e
        _raise_if_cancelled()
        with state._tool_registry_lock:
            result = _commit_if_live(
                lambda: (
                    registry.register_tools_from_schema(
                        schema,
                        groups=None if not state._lazy_mode else state._default_groups,
                    ),
                    state.set_connection_snapshot(
                        "uds",
                        active_socket=match["socket"],
                        active_tcp=None,
                        connected_project=match.get("project"),
                    ),
                )
            )
            if result is None:
                raise GhidraToolError("connect_instance cancelled before commit")
            count, installed = result
        total = len(state._full_schema)
        return {
            "connected": True,
            "transport": "uds",
            "project": installed.connected_project,
            "socket": match["socket"],
            "pid": match.get("pid"),
            "tools_registered": count,
            "tools_total": total,
            "loaded_groups": sorted(state._loaded_groups),
            "note": _loaded_note(count, total),
        }

    # `verify` names where an unverified URL came from; None means the URL was
    # already chosen BY project (a discovered instance's own url, or a port
    # scan hit judged by _match_project's rule) and needs no second look.
    verify = None
    env_tcp = os.getenv("GHIDRA_MCP_URL")
    if env_tcp:
        tcp_url = env_tcp
        verify = "GHIDRA_MCP_URL, pinned" if discovery.url_is_pinned() else "GHIDRA_MCP_URL"
    elif matched_tcp_url:
        tcp_url = matched_tcp_url
    elif match is None and instances and any(inst.get("project") for inst in instances):
        raise GhidraToolError(
            f"No instance matching '{project}' (UDS: {len(instances)} found, "
            f"none matched). Refusing to use any instance's tcp_port - would "
            f"connect to the wrong project. Use list_instances() to see what's "
            f"available.{_available(instances)}"
        )
    else:
        scanned = discovery._scan_tcp_for_project(project)
        if scanned:
            tcp_url = scanned
        else:
            tcp_url = DEFAULT_TCP_URL
            verify = "default URL; no instance matched in the TCP port scan"
    if not validate_server_url(tcp_url):
        raise GhidraToolError(
            f"Refusing to connect to invalid TCP URL: {tcp_url}. Expected "
            f"http://<127.0.0.1|localhost|::1>:<port> (http scheme and an explicit port are required)."
        )

    connected_project = match.get("project") if match else None
    if verify is not None and project:
        connected_project = _verify_tcp_project(project, tcp_url, verify)

    candidate = state.build_connection_snapshot(
        mode="tcp",
        active_tcp=tcp_url,
        connected_project=connected_project,
    )
    try:
        schema = registry._fetch_schema(connection=candidate)
    except Exception as e:
        raise GhidraToolError(
            f"No instance matching '{project}' (UDS: {len(instances)} found, TCP {tcp_url}: {e})."
            f"{_available(instances)}"
        ) from e
    _raise_if_cancelled()

    with state._tool_registry_lock:
        result = _commit_if_live(
            lambda: (
                registry.register_tools_from_schema(
                    schema,
                    groups=None if not state._lazy_mode else state._default_groups,
                ),
                state.set_connection_snapshot(
                    "tcp",
                    active_socket=None,
                    active_tcp=tcp_url,
                    connected_project=connected_project,
                ),
            )
        )
        if result is None:
            raise GhidraToolError("connect_instance cancelled before commit")
        count, _installed = result

    total = len(state._full_schema)
    payload = {
        "connected": True,
        "transport": "tcp",
        "url": tcp_url,
        "tools_registered": count,
        "tools_total": total,
        "loaded_groups": sorted(state._loaded_groups),
        "note": _loaded_note(count, total),
    }
    if connected_project:
        payload["project"] = connected_project
    return payload

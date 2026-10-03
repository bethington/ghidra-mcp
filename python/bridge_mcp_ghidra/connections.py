"""Instance selection and immutable capability bindings for the stable catalog."""

import json
import os
from dataclasses import replace

from . import discovery, registry, state, transport
from .validation import validate_server_url


def instances() -> list[dict]:
    found = discovery.discover_instances()
    # Include TCP-only/headless instances. Deduplicate listeners of one process.
    for url, info in discovery._iter_tcp_instances():
        info = dict(info, url=url, transport="tcp")
        previous = next((i for i in found if i.get("pid") is not None and i.get("pid") == info.get("pid")), None)
        if previous is None:
            found.append(info)
        elif (previous.get("project"), previous.get("project_path")) == (info.get("project"), info.get("project_path")):
            previous["url"] = url
    configured = os.getenv("GHIDRA_MCP_URL")
    if configured and validate_server_url(configured) and not any(i.get("url") == configured for i in found):
        try:
            text, status = transport.tcp_request(configured, "GET", "/mcp/instance_info", timeout=5)
            if status == 200:
                info = discovery._unwrap_response_data(text)
                if not any(
                    i.get("pid") == info.get("pid") and i.get("project_path") == info.get("project_path") for i in found
                ):
                    found.append(dict(info, url=configured, transport="tcp"))
        except (OSError, ValueError):
            pass
    return found


def select(project: str, found: list[dict]) -> dict:
    if not project.strip():
        raise ValueError("Specify a project name, full project path, or instance socket/URL from list_instances().")
    exact = [i for i in found if project in (i.get("project"), i.get("project_path"), i.get("socket"), i.get("url"))]
    matches = exact or [i for i in found if project.casefold() in i.get("project", "").casefold()]
    if len(matches) != 1:
        raise ValueError(
            f"Expected one instance matching {project!r}, found {len(matches)}. "
            "Use list_instances() and an unambiguous project path or socket/URL."
        )
    return matches[0]


def prepare(instance: dict) -> state.ConnectionSnapshot:
    """Verify identity on each transport; prefer TCP's full GUI endpoint surface."""
    candidates = []
    url = instance.get("url")
    port = instance.get("tcp_port")
    if not url and isinstance(port, int) and 1 <= port <= 65535:
        url = f"http://127.0.0.1:{port}"
    if url:
        if not validate_server_url(url):
            raise ValueError("Invalid selected instance TCP URL")
        candidates.append(
            state.build_connection_snapshot(mode="tcp", active_tcp=url, connected_project=instance.get("project"))
        )
    if instance.get("socket") and transport.uds_supported():
        candidates.append(
            state.build_connection_snapshot(
                mode="uds", active_socket=instance["socket"], connected_project=instance.get("project")
            )
        )
    errors = []
    for candidate in candidates:
        try:
            text, status = transport.do_request("GET", "/mcp/instance_info", timeout=5, connection=candidate)
            if status != 200:
                raise ValueError(f"instance info HTTP {status}")
            identity = discovery._unwrap_response_data(text)
            if not identity.get("project") or not (identity.get("pid") or identity.get("project_path")):
                raise ValueError("Instance did not provide verifiable project identity")
            for key in ("pid", "project", "project_path"):
                if instance.get(key) is not None and identity.get(key) != instance[key]:
                    raise ValueError(f"Instance identity changed: {key}")
            schema = registry._fetch_schema(connection=candidate)
            identity = {k: identity.get(k) for k in ("pid", "project", "project_path")}
            return replace(
                candidate,
                connected_project=identity["project"],
                binding=json.dumps({"identity": identity, "schema": schema}, sort_keys=True),
            )
        except Exception as error:
            errors.append(f"{candidate.mode}: {error}")
    raise ValueError("Could not verify selected instance: " + "; ".join(errors))


def connect(project: str) -> dict:
    try:
        selected = {"url": project} if validate_server_url(project) else select(project, instances())
        candidate = prepare(selected)

        def install() -> state.ConnectionSnapshot:
            return state.set_connection_snapshot(
                candidate.mode,
                active_socket=candidate.active_socket,
                active_tcp=candidate.active_tcp,
                connected_project=candidate.connected_project,
                binding=candidate.binding,
            )

        cancel = state.get_request_cancel_handle()
        installed = cancel.run_if_not_aborted(install) if cancel else install()
        if installed is None:
            return {"error": "connect_instance cancelled before commit"}
        return {
            "connected": True,
            "project": installed.connected_project,
            "transport": installed.mode,
            "tools_registered": len(state._dynamic_tool_names),
            "instance_tools": len(json.loads(installed.binding)["schema"]),
            "note": "Connection and capabilities updated; named tool definitions remain unchanged.",
        }
    except Exception as error:
        return {"error": str(error)}


def reconnect(previous: state.ConnectionSnapshot) -> state.ConnectionSnapshot | None:
    if not previous.binding:
        return None
    try:
        identity = json.loads(previous.binding)["identity"]
        # Process IDs change on restart; the full project path must stay the same.
        path = identity.get("project_path")
        if not path:
            return None
        candidate = None
        # Explicit URLs need not belong to the discovery scan range. Reverify
        # the previous listener, allowing a new PID but never a different project.
        if previous.active_tcp:
            try:
                candidate = prepare({"url": previous.active_tcp, "project_path": path})
            except Exception:
                pass
        if candidate is None:
            found = [i for i in instances() if i.get("project_path") == path]
            if len(found) != 1:
                return None
            candidate = prepare(found[0])
        return state.maybe_promote_connection_snapshot(previous, candidate) or candidate
    except Exception:
        return None


def refresh_if_changed(connection: state.ConnectionSnapshot) -> state.ConnectionSnapshot:
    """Detect a restarted process or a recycled TCP port before the operation."""
    if not state._catalog_frozen or not connection.binding:
        return connection
    expected = json.loads(connection.binding)["identity"]
    text, status = transport.do_request("GET", "/mcp/instance_info", timeout=5, connection=connection)
    if status != 200:
        raise ConnectionError("Cannot verify selected Ghidra instance identity; operation not sent")
    actual = discovery._unwrap_response_data(text)
    if all(actual.get(k) == v for k, v in expected.items()):
        return connection
    refreshed = reconnect(connection)
    if refreshed is None:
        raise ConnectionError("Selected Ghidra instance changed; original project unavailable. Operation not sent")
    return refreshed

"""Live Ghidra connection state, request routing, and HTTP dispatch.

This module owns the mutable connection state (which transport is active and
where it points) together with the functions that mutate it. Other modules read
the state through the accessor functions and change it through ``activate_uds``,
``activate_tcp``, and ``reset`` rather than rebinding these globals directly.
"""

import json
import threading
import time

from .config import ENDPOINT_TIMEOUTS, logger
from .transport import tcp_request, uds_request

# ==========================================================================
# Connection state
# ==========================================================================

_active_socket: str | None = None  # UDS socket path
_active_tcp: str | None = None  # TCP base URL (e.g. "http://127.0.0.1:8089")
_transport_mode: str = "none"  # "uds", "tcp", or "none"
_connected_project: str | None = None  # Project name for auto-reconnect

# Serialization lock for Ghidra HTTP calls — prevents stdout corruption when
# multiple MCP tool calls arrive concurrently (see GitHub issue #91).
_ghidra_lock = threading.Lock()


def transport_mode() -> str:
    return _transport_mode


def active_socket() -> str | None:
    return _active_socket


def active_tcp() -> str | None:
    return _active_tcp


def connected_project() -> str | None:
    return _connected_project


def activate_uds(socket_path: str, project: str | None) -> None:
    """Make a UDS socket the active transport."""
    global _active_socket, _active_tcp, _transport_mode, _connected_project
    _active_socket = socket_path
    _active_tcp = None
    _transport_mode = "uds"
    _connected_project = project


def activate_tcp(url: str, project: str | None = None) -> None:
    """Make a TCP base URL the active transport."""
    global _active_socket, _active_tcp, _transport_mode, _connected_project
    _active_tcp = url
    _active_socket = None
    _transport_mode = "tcp"
    if project is not None:
        _connected_project = project


def reset() -> None:
    """Drop the active transport (leaves _connected_project for reconnect)."""
    global _active_socket, _active_tcp, _transport_mode
    _active_socket = None
    _active_tcp = None
    _transport_mode = "none"


# ==========================================================================
# Unified request routing
# ==========================================================================


def do_request(
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Route request to the active transport (UDS or TCP).

    All requests are serialized via _ghidra_lock to prevent concurrent
    responses from corrupting JSON-RPC framing on stdio (GitHub #91).
    """
    with _ghidra_lock:
        if _transport_mode == "uds" and _active_socket:
            return uds_request(
                _active_socket, method, endpoint, params, json_data, timeout
            )
        elif _transport_mode == "tcp" and _active_tcp:
            return tcp_request(
                _active_tcp, method, endpoint, params, json_data, timeout
            )
        else:
            raise ConnectionError(
                "No Ghidra instance connected. Use connect_instance() first."
            )


# ==========================================================================
# Timeouts and payload normalization
# ==========================================================================


def get_timeout(endpoint: str, payload: dict | None = None) -> int:
    """Get timeout for an endpoint, with dynamic scaling for batch ops."""
    name = endpoint.strip("/").split("/")[-1]
    base = ENDPOINT_TIMEOUTS.get(name, ENDPOINT_TIMEOUTS["default"])

    if not payload:
        return base

    if name in {"rename_variables", "batch_rename_variables"}:
        count = len(payload.get("variable_renames", {}))
        return min(base + count * 38, 600)

    if name == "batch_set_comments":
        count = len(payload.get("decompiler_comments", []))
        count += len(payload.get("disassembly_comments", []))
        count += 1 if payload.get("plate_comment") else 0
        return min(base + count * 8, 600)

    return base


def _coerce_comment_entries(value):
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        try:
            return _coerce_comment_entries(json.loads(stripped))
        except (TypeError, ValueError, json.JSONDecodeError):
            return value
    items = (
        value
        if isinstance(value, list)
        else [value]
        if isinstance(value, dict) and "address" in value
        else None
    )
    if items is not None:
        return [
            {"address": str(item["address"]), "comment": str(item["comment"])}
            for item in items
            if isinstance(item, dict)
            and item.get("address") is not None
            and item.get("comment") is not None
        ]
    if isinstance(value, dict):
        return [
            {
                "address": str(address),
                "comment": str(
                    comment.get("comment") if isinstance(comment, dict) else comment
                ),
            }
            for address, comment in value.items()
            if (comment.get("comment") if isinstance(comment, dict) else comment)
            is not None
        ]
    return value


def _normalize_post_payload(endpoint: str, data: dict) -> dict:
    if endpoint.strip("/").split("/")[-1] == "batch_set_comments":
        data = dict(data)
        for key in ("decompiler_comments", "disassembly_comments"):
            data[key] = _coerce_comment_entries(data.get(key, []))
    return data


# ==========================================================================
# Reconnect / connection guards
# ==========================================================================


def _try_reconnect() -> bool:
    """Try to reconnect to the previously connected project after Ghidra restarts.

    Scans for UDS instances matching _connected_project. If found, updates the
    active socket and re-fetches the schema. Returns True if reconnected.
    """
    # Imported lazily to avoid an import cycle (discovery and registry both
    # import this module for connection state).
    from .discovery import discover_instances
    from .registry import fetch_and_register_schema

    if not _connected_project:
        return False

    instances = discover_instances()

    def _attempt(inst: dict) -> bool:
        activate_uds(inst["socket"], _connected_project)
        try:
            fetch_and_register_schema()
            logger.info(
                f"Reconnected to project '{inst.get('project', _connected_project)}' "
                f"via {inst['socket']}"
            )
            return True
        except Exception as e:
            logger.warning(f"Reconnect schema fetch failed: {e}")
            return False

    # Exact match first, then substring.
    for inst in instances:
        if inst.get("project", "") == _connected_project:
            return _attempt(inst)
    for inst in instances:
        if _connected_project.lower() in inst.get("project", "").lower():
            return _attempt(inst)

    return False


def _ensure_connected() -> str | None:
    """Check connection and attempt reconnect if needed. Returns error string or None."""
    if _transport_mode == "none":
        if _connected_project:
            if _try_reconnect():
                return None
            return (
                f"Ghidra instance for project '{_connected_project}' is not running. "
                "Start Ghidra and open the project, then retry."
            )
        return "No Ghidra instance connected. Use connect_instance() first."
    return None


# ==========================================================================
# Dispatch
# ==========================================================================


def dispatch_get(endpoint: str, params: dict | None = None, retries: int = 3) -> str:
    """GET request via active transport. Returns raw response text."""
    err = _ensure_connected()
    if err:
        return json.dumps({"error": err})

    timeout = get_timeout(endpoint)
    for attempt in range(retries):
        try:
            text, status = do_request("GET", endpoint, params=params, timeout=timeout)
            if status == 200:
                return text
            if status >= 500 and attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except (ConnectionError, OSError) as e:
            # Connection lost — try reconnect once, then retry
            if attempt == 0 and _try_reconnect():
                continue
            if attempt < retries - 1:
                continue
            return json.dumps({"error": str(e)})
        except Exception as e:
            if attempt < retries - 1:
                continue
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})


def dispatch_post(
    endpoint: str, data: dict, retries: int = 3, query_params: dict | None = None
) -> str:
    """POST JSON request via active transport. Returns raw response text."""
    err = _ensure_connected()
    if err:
        return json.dumps({"error": err})

    data = _normalize_post_payload(endpoint, data)
    timeout = get_timeout(endpoint, data)
    # POST endpoints are non-idempotent (rename/create/set/delete/batch writes). Unlike GET,
    # they must NOT be blindly retried: if the request reached the server it may have already
    # applied the write, so resending after a 5xx or a mid-flight drop risks double-applying.
    # The only safe retry is re-establishing a connection that failed before the request was
    # sent — attempted once on the first iteration. Everything else surfaces as an error.
    for attempt in range(retries):
        try:
            text, status = do_request(
                "POST", endpoint, params=query_params, json_data=data, timeout=timeout
            )
            if status == 200:
                return text.strip()
            # Request reached the server (got an HTTP status) — do not retry a write.
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except (ConnectionError, OSError) as e:
            # Pre-send connection failure: re-establish once and retry. A drop after the
            # request was sent is indistinguishable here, so we only ever try this once.
            if attempt == 0 and _try_reconnect():
                continue
            return json.dumps({"error": str(e)})
        except Exception as e:
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})

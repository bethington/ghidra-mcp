"""HTTP dispatch: timeout scaling, reconnection, and GET/POST helpers."""

import json
import time

from . import discovery
from . import registry
from . import state
from . import transport
from .config import ENDPOINT_TIMEOUTS, logger


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
    items = value if isinstance(value, list) else [value] if isinstance(value, dict) and "address" in value else None
    if items is not None:
        return [
            {"address": str(item["address"]), "comment": str(item["comment"])}
            for item in items
            if isinstance(item, dict) and item.get("address") is not None and item.get("comment") is not None
        ]
    if isinstance(value, dict):
        return [
            {"address": str(address), "comment": str(comment.get("comment") if isinstance(comment, dict) else comment)}
            for address, comment in value.items()
            if (comment.get("comment") if isinstance(comment, dict) else comment) is not None
        ]
    return value


def _normalize_post_payload(endpoint: str, data: dict) -> dict:
    if endpoint.strip("/").split("/")[-1] == "batch_set_comments":
        data = dict(data)
        for key in ("decompiler_comments", "disassembly_comments"):
            data[key] = _coerce_comment_entries(data.get(key, []))
    return data


def _reconnect_via(inst: dict) -> bool:
    """Point the active transport at `inst` and re-fetch the schema.

    Uses UDS when this Python can dial it; otherwise falls back to the TCP
    url discovery recorded for the instance (Windows CPython lacks AF_UNIX).
    Returns True on success.
    """
    if transport.uds_supported():
        state._active_socket = inst["socket"]
        state._active_tcp = None
        state._transport_mode = "uds"
        target = inst["socket"]
    elif inst.get("url"):
        state._active_tcp = inst["url"]
        state._active_socket = None
        state._transport_mode = "tcp"
        target = inst["url"]
    else:
        return False
    try:
        registry._fetch_and_register_schema()
        logger.info(f"Reconnected to project '{inst.get('project')}' via {target}")
        return True
    except Exception as e:
        logger.warning(f"Reconnect schema fetch failed: {e}")
        return False


def _try_reconnect() -> bool:
    """Try to reconnect to the previously connected project after Ghidra restarts.

    Scans for instances matching _connected_project. If found, updates the
    active transport and re-fetches the schema. Returns True if reconnected.
    """
    if not state._connected_project:
        return False

    instances = discovery.discover_instances()
    for inst in instances:
        if inst.get("project", "") == state._connected_project:
            return _reconnect_via(inst)

    # Exact match failed, try substring
    for inst in instances:
        if state._connected_project.lower() in inst.get("project", "").lower():
            return _reconnect_via(inst)

    return False


def _ensure_connected() -> str | None:
    """Check connection and attempt reconnect if needed. Returns error string or None."""
    if state._transport_mode == "none":
        if state._connected_project:
            if _try_reconnect():
                return None
            return (
                f"Ghidra instance for project '{state._connected_project}' is not running. "
                "Start Ghidra and open the project, then retry."
            )
        return "No Ghidra instance connected. Use connect_instance() first."
    return None


def dispatch_get(endpoint: str, params: dict | None = None, retries: int = 3) -> str:
    """GET request via active transport. Returns raw response text."""
    err = _ensure_connected()
    if err:
        return json.dumps({"error": err})

    timeout = get_timeout(endpoint)
    for attempt in range(retries):
        try:
            text, status = transport.do_request(
                "GET", endpoint, params=params, timeout=timeout
            )
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
            text, status = transport.do_request(
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

"""HTTP dispatch: timeout scaling, reconnection, and GET/POST helpers."""

import json
import time

from . import discovery
from . import registry
from . import state
from . import transport
from .config import (
    ENDPOINT_TIMEOUTS,
    MAX_REQUEST_TIMEOUT_SECONDS,
    REQUEST_TIMEOUT_GRACE_SECONDS,
    logger,
)


def get_timeout(endpoint: str, payload: dict | None = None) -> int:
    """Get timeout for an endpoint, with dynamic scaling for batch ops."""
    name = endpoint.strip("/").split("/")[-1]
    base = ENDPOINT_TIMEOUTS.get(name, ENDPOINT_TIMEOUTS["default"])

    if not payload:
        return base

    requested_timeout = payload.get("timeout")
    if requested_timeout is None:
        requested_timeout = payload.get("timeout_seconds")
    if requested_timeout is not None:
        try:
            requested_seconds = int(requested_timeout)
        except (TypeError, ValueError):
            requested_seconds = 0
        if requested_seconds > 0:
            effective_requested_seconds = min(
                requested_seconds,
                MAX_REQUEST_TIMEOUT_SECONDS - REQUEST_TIMEOUT_GRACE_SECONDS,
            )
            return max(base, effective_requested_seconds + REQUEST_TIMEOUT_GRACE_SECONDS)

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


def _normalize_timeout_fields(payload: dict | None) -> dict | None:
    if not payload:
        return payload

    normalized = dict(payload)
    max_requested_seconds = MAX_REQUEST_TIMEOUT_SECONDS - REQUEST_TIMEOUT_GRACE_SECONDS
    for key in ("timeout", "timeout_seconds"):
        raw = normalized.get(key)
        if raw is None:
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value > 0:
            capped = min(value, max_requested_seconds)
            normalized[key] = str(capped) if isinstance(raw, str) else capped
    return normalized


def _discover_project_connection(project_name: str) -> state.ConnectionSnapshot | None:
    """Discover a live transport target for one Ghidra project."""
    instances = discovery.discover_instances()
    for inst in instances:
        if inst.get("project", "") == project_name:
            if transport.uds_supported():
                return state.build_connection_snapshot(
                    mode="uds",
                    active_socket=inst["socket"],
                    connected_project=inst.get("project"),
                )
            if inst.get("url"):
                return state.build_connection_snapshot(
                    mode="tcp",
                    active_tcp=inst["url"],
                    connected_project=inst.get("project"),
                )
            return None
    for inst in instances:
        project = inst.get("project", "")
        if project_name.lower() in project.lower():
            if transport.uds_supported():
                return state.build_connection_snapshot(
                    mode="uds",
                    active_socket=inst["socket"],
                    connected_project=inst.get("project"),
                )
            if inst.get("url"):
                return state.build_connection_snapshot(
                    mode="tcp",
                    active_tcp=inst["url"],
                    connected_project=inst.get("project"),
                )
            return None
    return None


def _try_reconnect(
    connection: state.ConnectionSnapshot | None = None,
) -> state.ConnectionSnapshot | None:
    """Reconnect one request to its original project without clobbering a switch."""
    base = connection or state.get_connection_snapshot()
    if not base.connected_project:
        return None

    candidate = _discover_project_connection(base.connected_project)
    if candidate is None:
        return None

    current = state.get_connection_snapshot()
    if current != base:
        target = candidate.active_socket or candidate.active_tcp
        logger.info(
            "Reconnected request-scoped project '%s' via %s without changing the global route",
            candidate.connected_project,
            target,
        )
        return candidate

    try:
        schema = registry._fetch_schema(connection=candidate)
    except Exception as e:
        logger.warning(
            "Reconnect schema fetch failed for project '%s': %s",
            candidate.connected_project,
            e,
        )
        return None

    with state._tool_registry_lock:
        promoted = state.maybe_promote_connection_snapshot(base, candidate)
        if promoted is not None:
            registry.register_tools_from_schema(
                schema,
                groups=None if not state._lazy_mode else state._default_groups,
            )
            state.notify_tools_changed_from_worker()
            target = promoted.active_socket or promoted.active_tcp
            logger.info(
                "Reconnected project '%s' via %s and refreshed the global schema",
                promoted.connected_project,
                target,
            )
            return promoted
    return candidate


def _resolve_connection_for_request(
    connection: state.ConnectionSnapshot | None = None,
) -> tuple[state.ConnectionSnapshot | None, str | None]:
    """Resolve the concrete transport target for one request."""
    resolved = connection or state.get_request_connection_snapshot() or state.get_connection_snapshot()
    if resolved.mode != "none":
        return resolved, None
    if resolved.connected_project:
        reconnected = _try_reconnect(resolved)
        if reconnected is not None:
            return reconnected, None
        return (
            None,
            f"Ghidra instance for project '{resolved.connected_project}' is not running. "
            "Start Ghidra and open the project, then retry.",
        )
    return None, "No Ghidra instance connected. Use connect_instance() first."


def _ensure_connected() -> str | None:
    """Check connection and attempt reconnect if needed. Returns error string or None."""
    _resolved, err = _resolve_connection_for_request()
    return err


def dispatch_get(endpoint: str, params: dict | None = None, retries: int = 3) -> str:
    """GET request via active transport. Returns raw response text."""
    connection, err = _resolve_connection_for_request()
    if err:
        return json.dumps({"error": err})

    params = _normalize_timeout_fields(params)
    timeout = get_timeout(endpoint, params)
    for attempt in range(retries):
        try:
            text, status = transport.do_request(
                "GET",
                endpoint,
                params=params,
                timeout=timeout,
                connection=connection,
            )
            if status == 200:
                return text
            if status >= 500 and attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except transport.RequestNotSentError as e:
            # Safe to retry only because connect() failed before request bytes
            # were sent. Re-discover once in case Ghidra restarted.
            reconnected = _try_reconnect(connection)
            if reconnected is not None:
                connection = reconnected
                continue
            if attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            return json.dumps({"error": str(e)})
        except transport.RequestOutcomeUnknownError as e:
            logger.warning("Ghidra request outcome unknown; not retrying %s: %s", endpoint, e)
            return json.dumps({"error": f"{e}. The request may still be running in Ghidra and was not retried."})
        except (ConnectionError, OSError) as e:
            return json.dumps({"error": str(e)})
        except Exception as e:
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})


def dispatch_post(endpoint: str, data: dict, retries: int = 3, query_params: dict | None = None) -> str:
    """POST JSON request via active transport. Returns raw response text."""
    connection, err = _resolve_connection_for_request()
    if err:
        return json.dumps({"error": err})

    data = _normalize_post_payload(endpoint, data)
    data = _normalize_timeout_fields(data)
    query_params = _normalize_timeout_fields(query_params)
    timeout = get_timeout(endpoint, data)
    # POST endpoints are non-idempotent (rename/create/set/delete/batch writes). Unlike GET,
    # they must NOT be blindly retried: if the request reached the server it may have already
    # applied the write, so resending after a 5xx or a mid-flight drop risks double-applying.
    # The only safe retry is re-establishing a connection that failed before the request was
    # sent — attempted once on the first iteration. Everything else surfaces as an error.
    for attempt in range(retries):
        try:
            text, status = transport.do_request(
                "POST",
                endpoint,
                params=query_params,
                json_data=data,
                timeout=timeout,
                connection=connection,
            )
            if status == 200:
                return text.strip()
            # Request reached the server (got an HTTP status) — do not retry a write.
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except transport.RequestNotSentError as e:
            reconnected = _try_reconnect(connection)
            if reconnected is not None:
                connection = reconnected
                continue
            if attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            return json.dumps({"error": str(e)})
        except transport.RequestOutcomeUnknownError as e:
            logger.warning("Ghidra write outcome unknown; not retrying %s: %s", endpoint, e)
            return json.dumps({"error": f"{e}. The write may have been applied in Ghidra and was not retried."})
        except (ConnectionError, OSError) as e:
            return json.dumps({"error": str(e)})
        except Exception as e:
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})

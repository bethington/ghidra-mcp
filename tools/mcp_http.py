"""Shared urllib client for tools/ talking to a Ghidra MCP HTTP server."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

try:
    from bridge_mcp_ghidra.keys import env_name as _env_name
except ImportError:  # pragma: no cover - bare python without the wheel
    def _env_name(key: str) -> str:
        return "GHIDRA_MCP_" + key.upper().replace(".", "_")

# auth.token's environment name (GHIDRA_MCP_AUTH_TOKEN).
AUTH_TOKEN_ENV = _env_name("auth.token")

# How much of a failed call's console output to quote when it gave no other reason.
# Kept in lockstep with bridge_mcp_ghidra.dispatch._FAILURE_OUTPUT_TAIL.
_FAILURE_OUTPUT_TAIL = 1500


def failure_message(text: str) -> str | None:
    """Return the error message if this response body reports a failure.

    Same predicates as ``bridge_mcp_ghidra.dispatch.failure_message``: a non-empty
    ``error`` string, ``success is False``, or ``status == "rejected"``. Kept as a
    tools/ copy so upgrade/health/deploy do not import the bridge's MCP stack;
    ``tests/unit/test_mcp_http.py`` pins the two against one payload table.
    """
    stripped = text.strip() if text else ""
    if not stripped.startswith("{"):
        return None
    try:
        payload = json.loads(stripped)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    error = payload.get("error")
    failed = (
        (isinstance(error, str) and error.strip())
        or payload.get("success") is False
        or payload.get("status") == "rejected"
    )
    if not failed:
        return None
    parts = []
    for key in ("error", "message", "suggestion"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip() and value.strip() not in parts:
            parts.append(value.strip())
    if parts:
        return " — ".join(parts)
    output = payload.get("console_output")
    if isinstance(output, str) and output.strip():
        tail = output.strip()[-_FAILURE_OUTPUT_TAIL:]
        return "the server reported failure; end of its output:\n" + tail
    status = payload.get("status")
    return status if isinstance(status, str) and status.strip() else "the server reported failure"


def bearer_token(
    *,
    explicit: str | None = None,
    environ: Mapping[str, str] | None = None,
    env_values: Mapping[str, str] | None = None,
) -> str | None:
    """Resolve a Bearer token: explicit wins, then env_values, then environ."""
    if explicit is not None:
        token = explicit.strip()
        return token or None
    if env_values is not None and AUTH_TOKEN_ENV in env_values:
        token = str(env_values.get(AUTH_TOKEN_ENV, "")).strip()
        return token or None
    source = environ if environ is not None else os.environ
    token = str(source.get(AUTH_TOKEN_ENV, "")).strip()
    return token or None


def _unwrap_result(payload: object) -> object:
    if isinstance(payload, dict) and "result" in payload:
        inner = payload["result"]
        if isinstance(inner, str):
            try:
                return json.loads(inner)
            except json.JSONDecodeError:
                return inner
        return inner
    return payload


def request(
    base_url: str,
    path: str = "",
    *,
    method: str = "GET",
    data: dict | None = None,
    params: Mapping[str, Any] | None = None,
    timeout: float = 10,
    auth_token: str | None = None,
    unwrap_result: bool = False,
    return_status: bool = False,
    return_headers: bool = False,
    parse_json: bool = True,
    max_body_bytes: int | None = None,
    retain_http_error: bool = False,
) -> Any:
    """HTTP JSON client for Ghidra MCP endpoints.

    ``base_url`` may be a host root (``http://127.0.0.1:8089``) or a full URL
    when ``path`` is empty. ``auth_token`` is the Bearer secret already resolved
    (use :func:`bearer_token`); ``None`` sends no Authorization header.
    """
    url = base_url.rstrip("/")
    if path:
        url = f"{url}/{path.lstrip('/')}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"

    headers: dict[str, str] = {}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    body: bytes | None = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    # Plain GET with no headers keeps urlopen(url, timeout=) so existing health
    # probes that patch urlopen with a string-first signature still work.
    use_request_object = bool(headers) or body is not None or method.upper() != "GET"
    http_request: urllib.request.Request | str
    if use_request_object:
        http_request = urllib.request.Request(url, data=body, headers=headers, method=method)
    else:
        http_request = url

    response_headers: Mapping[str, str] = {}
    try:
        with urllib.request.urlopen(http_request, timeout=timeout) as response:
            raw = (
                response.read(max_body_bytes)
                if max_body_bytes is not None
                else response.read()
            )
            text = raw.decode("utf-8", errors="replace")
            status = response.status
            if return_headers:
                response_headers = (
                    dict(response.headers.items()) if response.headers else {}
                )
    except urllib.error.HTTPError as exc:
        if not retain_http_error:
            raise
        raw = (
            exc.read(max_body_bytes)
            if max_body_bytes is not None
            else exc.read()
        )
        text = raw.decode("utf-8", errors="replace")
        status = exc.code
        if return_headers:
            response_headers = dict(exc.headers.items()) if exc.headers else {}

    if parse_json:
        try:
            parsed: object = json.loads(text)
        except ValueError:
            parsed = text
        if unwrap_result:
            parsed = _unwrap_result(parsed)
        payload: object = parsed
    else:
        payload = text

    if return_headers and return_status:
        return status, payload, response_headers
    if return_status:
        return status, payload
    if return_headers:
        return payload, response_headers
    return payload


def ensure_ok(path: str, payload: object) -> None:
    """Raise ``RuntimeError`` when ``payload`` is a Ghidra MCP failure body."""
    if isinstance(payload, str):
        message = failure_message(payload)
    elif isinstance(payload, dict):
        message = failure_message(json.dumps(payload))
    else:
        message = None
    if message is not None:
        raise RuntimeError(f"{path} failed: {message}")

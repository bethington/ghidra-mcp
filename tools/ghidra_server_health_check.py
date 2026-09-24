#!/usr/bin/env python3
"""Bounded Ghidra MCP health probe with an opt-in layered doctor mode.

The default command remains the original /check_connection probe. Doctor mode
adds read-only checks for the plugin connection, instance metadata, server
health, the advertised schema, and (when supplied) an MCP HTTP route. It never
starts, stops, reconnects, mutates, or configures a process.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

DEFAULT_HEALTH_URL = "http://127.0.0.1:8089/check_connection"
DEFAULT_BASE_URL = "http://127.0.0.1:8089"
# Keep the original health probe bounded to a small response.  The doctor
# deliberately has a separate, still-bounded cap because /mcp/schema can
# contain the complete generated catalog (hundreds of tools).
MAX_HEALTH_BODY_BYTES = 4096
MAX_DOCTOR_BODY_BYTES = 1024 * 1024
# Internal compatibility alias for callers/tests that referenced the old
# constant; health requests continue to use the legacy limit.
MAX_BODY_BYTES = MAX_HEALTH_BODY_BYTES
MCP_TRANSPORTS = ("auto", "streamable-http", "sse")
SERVER_KINDS = ("auto", "gui", "headless")


def _probe(url: str, timeout: float) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        body = response.read(MAX_HEALTH_BODY_BYTES).decode("utf-8", "replace")
        return response.status, body


def _probe_request(
    url: str,
    timeout: float,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
) -> tuple[int, str, Mapping[str, str]]:
    """Issue a bounded request and retain HTTP error status for diagnosis."""

    request = urllib.request.Request(url, method=method, headers=dict(headers or {}))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_DOCTOR_BODY_BYTES).decode("utf-8", "replace")
            response_headers = dict(response.headers.items()) if response.headers else {}
            return response.status, body, response_headers
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_DOCTOR_BODY_BYTES).decode("utf-8", "replace")
        response_headers = dict(exc.headers.items()) if exc.headers else {}
        return exc.code, body, response_headers


def _normalise_url(value: str, *, strip_endpoint: bool) -> tuple[str | None, str | None, dict[str, Any]]:
    """Validate an HTTP URL without ever returning embedded credentials."""

    if not isinstance(value, str) or not value.strip():
        return None, "empty_url", {}

    try:
        parsed = urllib.parse.urlsplit(value.strip())
        hostname = parsed.hostname
    except ValueError:
        return None, "invalid_url", {}

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not hostname:
        return None, "http_url_required", {}
    if parsed.username or parsed.password:
        return None, "embedded_credentials_not_allowed", {}
    if parsed.query or parsed.fragment:
        return None, "query_or_fragment_not_allowed", {}

    path = parsed.path.rstrip("/")
    if strip_endpoint:
        for suffix in ("/check_connection", "/mcp/health", "/mcp/instance_info", "/mcp/schema"):
            if path.endswith(suffix):
                path = path[: -len(suffix)].rstrip("/")
                break

    normalised = urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, path, "", "")).rstrip("/")
    if not normalised:
        normalised = f"{parsed.scheme.lower()}://{parsed.netloc}"

    return (
        normalised,
        None,
        {
            "scheme": parsed.scheme.lower(),
            "host": hostname,
            "loopback": _is_loopback_host(hostname),
            "path": path or "/",
        },
    )


def _normalise_base_url(value: str) -> tuple[str | None, str | None, dict[str, Any]]:
    return _normalise_url(value, strip_endpoint=True)


def _normalise_endpoint_url(value: str) -> tuple[str | None, str | None, dict[str, Any]]:
    return _normalise_url(value, strip_endpoint=False)


def _is_loopback_host(hostname: str) -> bool:
    host = hostname.lower().strip("[]")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _join_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _unwrap_json_object(body: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict):
        return parsed["data"]
    return parsed if isinstance(parsed, dict) else None


def _validate_connection(
    status: int, body: str, _headers: Mapping[str, str]
) -> tuple[bool, str | None, dict[str, Any]]:
    if status != 200:
        return False, f"unexpected_http_status:{status}", {}
    lowered = body.lower()
    if "connected:" in lowered:
        server_kind = "gui"
    elif "connection ok" in lowered and "headless" in lowered:
        server_kind = "headless"
    else:
        return False, "unexpected_response", {}
    return True, None, {"connected": True, "server_kind": server_kind}


def _validate_instance_info(
    status: int, body: str, _headers: Mapping[str, str]
) -> tuple[bool, str | None, dict[str, Any]]:
    if status != 200:
        return False, f"unexpected_http_status:{status}", {}
    payload = _unwrap_json_object(body)
    if payload is None:
        return False, "invalid_json", {}
    pid = payload.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False, "missing_pid", {}
    if "project" not in payload or not isinstance(payload.get("programs"), list):
        return False, "invalid_instance_shape", {}
    tcp_port = payload.get("tcp_port")
    if isinstance(tcp_port, bool) or not isinstance(tcp_port, int):
        return False, "missing_tcp_port", {}
    project = payload.get("project")
    return (
        True,
        None,
        {
            "project_known": bool(project and project != "unknown"),
            "program_count": len(payload["programs"]),
            "tcp_port_known": tcp_port >= 0,
        },
    )


def _validate_server_health(
    status: int, body: str, _headers: Mapping[str, str]
) -> tuple[bool, str | None, dict[str, Any]]:
    if status != 200:
        return False, f"unexpected_http_status:{status}", {}
    payload = _unwrap_json_object(body)
    if payload is None:
        return False, "invalid_json", {}
    state = str(payload.get("status", "")).lower()
    if state not in {"ok", "healthy", "connected"}:
        return False, "unhealthy_status", {"status": state or "unknown"}
    return True, None, {"status": state}


def _validate_schema(status: int, body: str, _headers: Mapping[str, str]) -> tuple[bool, str | None, dict[str, Any]]:
    if status != 200:
        return False, f"unexpected_http_status:{status}", {}
    payload = _unwrap_json_object(body)
    if payload is None:
        return False, "invalid_json", {}
    tools = payload.get("tools")
    if not isinstance(tools, list):
        return False, "invalid_schema_shape", {}
    count = len(tools)
    advertised = payload.get("count")
    details: dict[str, Any] = {"tool_count": count}
    if isinstance(advertised, int) and not isinstance(advertised, bool):
        details["advertised_count"] = advertised
    if count == 0:
        return False, "empty_schema", details
    return True, None, details


def _validate_mcp_route(
    expected_transport: str,
) -> Callable[[int, str, Mapping[str, str]], tuple[bool, str | None, dict[str, Any]]]:
    def validate(status: int, _body: str, headers: Mapping[str, str]) -> tuple[bool, str | None, dict[str, Any]]:
        if status not in {200, 204}:
            reason = "wrong_transport_or_path" if status in {404, 405} else f"unexpected_http_status:{status}"
            return False, reason, {}
        lower_headers = {str(key).lower(): str(value) for key, value in headers.items()}
        return (
            True,
            None,
            {
                "transport": expected_transport,
                "cors_header_present": "access-control-allow-origin" in lower_headers,
            },
        )

    return validate


def _detect_mcp_transport(url: str, requested: str) -> str:
    if requested != "auto":
        return requested
    path = urllib.parse.urlsplit(url).path.rstrip("/")
    if path.endswith("/mcp"):
        return "streamable-http"
    if path.endswith("/sse"):
        return "sse"
    return "unknown"


DoctorProbe = Callable[[str, float, str, Mapping[str, str] | None], tuple[int, str, Mapping[str, str]]]


def _not_applicable_check(name: str, reason: str, details: Mapping[str, Any]) -> dict[str, Any]:
    """Represent a mode-specific endpoint that must not be requested."""

    return {
        "name": name,
        "path": None,
        "ok": True,
        "status": None,
        "attempts": 0,
        "elapsed_ms": 0.0,
        "reason": reason,
        "details": dict(details),
    }


def _run_check(
    *,
    name: str,
    path: str,
    url: str,
    validator: Callable[[int, str, Mapping[str, str]], tuple[bool, str | None, dict[str, Any]]],
    timeout: float,
    retries: int,
    retry_delay: float,
    probe: DoctorProbe,
    sleep_fn: Callable[[float], None],
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": name,
        "path": path,
        "ok": False,
        "status": None,
        "attempts": 0,
        "elapsed_ms": 0.0,
        "reason": None,
        "details": {},
    }
    for attempt in range(1, retries + 1):
        result["attempts"] = attempt
        started = time.monotonic()
        try:
            status, body, response_headers = probe(url, timeout, method, headers)
            result["status"] = status
            ok, reason, details = validator(status, body, response_headers)
        except Exception as exc:  # noqa: BLE001 - doctor must return a stable report
            ok, reason, details = False, f"transport_error:{type(exc).__name__}", {}
        result["elapsed_ms"] = round(max(0.0, time.monotonic() - started) * 1000, 1)
        result["ok"] = ok
        result["reason"] = reason
        result["details"] = details
        if ok:
            break
        if attempt < retries:
            sleep_fn(retry_delay)
    return result


def run_doctor(
    base_url: str = DEFAULT_BASE_URL,
    *,
    mcp_url: str | None = None,
    mcp_transport: str = "auto",
    timeout: float = 5.0,
    retries: int = 3,
    retry_delay: float = 0.5,
    auth_token: str | None = None,
    server_kind: str = "auto",
    probe: DoctorProbe | None = None,
    sleep_fn: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """Run read-only, layered checks and return a stable report dictionary."""

    report: dict[str, Any] = {
        "doctor_version": 1,
        "ok": False,
        "http_healthy": False,
        "mcp_initialize_healthy": None,
        "detected_transport": "unknown",
        "server_kind": "unknown",
        "target": {"base_url": None, "loopback": None, "mcp_path": None},
        "checks": [],
        "recommended_next_action": "Validate the target URL before probing the server.",
    }

    if retries < 1:
        report["checks"].append(
            {
                "name": "configuration",
                "path": None,
                "ok": False,
                "status": None,
                "attempts": 0,
                "elapsed_ms": 0.0,
                "reason": "retries_must_be_positive",
                "details": {},
            }
        )
        return report

    if server_kind not in SERVER_KINDS:
        report["checks"].append(
            {
                "name": "configuration",
                "path": None,
                "ok": False,
                "status": None,
                "attempts": 0,
                "elapsed_ms": 0.0,
                "reason": "unsupported_server_kind",
                "details": {"server_kind": server_kind},
            }
        )
        return report

    normalised_base, base_error, base_details = _normalise_base_url(base_url)
    if base_error or normalised_base is None:
        report["checks"].append(
            {
                "name": "url",
                "path": None,
                "ok": False,
                "status": None,
                "attempts": 0,
                "elapsed_ms": 0.0,
                "reason": base_error or "invalid_url",
                "details": {},
            }
        )
        report["recommended_next_action"] = "Provide an http(s) URL without embedded credentials, query, or fragment."
        return report

    report["target"]["base_url"] = normalised_base
    report["target"]["loopback"] = base_details["loopback"]
    report["checks"].append(
        {
            "name": "url",
            "path": base_details["path"],
            "ok": True,
            "status": None,
            "attempts": 0,
            "elapsed_ms": 0.0,
            "reason": None,
            "details": {
                "scheme": base_details["scheme"],
                "loopback": base_details["loopback"],
            },
        }
    )

    probe_fn = probe or (
        lambda url, request_timeout, method, headers: _probe_request(
            url, request_timeout, method=method, headers=headers
        )
    )
    sleep = sleep_fn or time.sleep
    request_headers: dict[str, str] = {}
    if auth_token:
        # Accept the token only as an in-memory request credential.  It is
        # intentionally absent from the report, diagnostics, and CLI output.
        request_headers["Authorization"] = f"Bearer {auth_token}"
    connection_check = _run_check(
        name="plugin_connection",
        path="/check_connection",
        url=_join_url(normalised_base, "/check_connection"),
        validator=_validate_connection,
        timeout=timeout,
        retries=retries,
        retry_delay=retry_delay,
        probe=probe_fn,
        sleep_fn=sleep,
        headers=request_headers,
    )
    report["checks"].append(connection_check)

    inferred_kind = connection_check["details"].get("server_kind")
    effective_kind = server_kind
    if effective_kind == "auto" and inferred_kind in {"gui", "headless"}:
        effective_kind = inferred_kind
    report["server_kind"] = effective_kind

    if effective_kind == "headless":
        report["checks"].append(
            _not_applicable_check(
                "instance_info",
                "not_applicable:headless",
                {"server_kind": "headless"},
            )
        )
        health_path = "/health"
    else:
        report["checks"].append(
            _run_check(
                name="instance_info",
                path="/mcp/instance_info",
                url=_join_url(normalised_base, "/mcp/instance_info"),
                validator=_validate_instance_info,
                timeout=timeout,
                retries=retries,
                retry_delay=retry_delay,
                probe=probe_fn,
                sleep_fn=sleep,
                headers=request_headers,
            )
        )
        health_path = "/mcp/health"

    report["checks"].append(
        _run_check(
            name="server_health",
            path=health_path,
            url=_join_url(normalised_base, health_path),
            validator=_validate_server_health,
            timeout=timeout,
            retries=retries,
            retry_delay=retry_delay,
            probe=probe_fn,
            sleep_fn=sleep,
            headers=request_headers,
        )
    )
    report["checks"].append(
        _run_check(
            name="schema",
            path="/mcp/schema",
            url=_join_url(normalised_base, "/mcp/schema"),
            validator=_validate_schema,
            timeout=timeout,
            retries=retries,
            retry_delay=retry_delay,
            probe=probe_fn,
            sleep_fn=sleep,
            headers=request_headers,
        )
    )

    direct_checks = {check["name"]: check for check in report["checks"] if check["name"] != "url"}
    required_http_checks = ["plugin_connection", "server_health"]
    if effective_kind != "headless":
        required_http_checks.insert(1, "instance_info")
    report["http_healthy"] = all(direct_checks[name]["ok"] for name in required_http_checks)

    if mcp_url is not None:
        normalised_mcp, mcp_error, mcp_details = _normalise_endpoint_url(mcp_url)
        if mcp_error or normalised_mcp is None:
            report["checks"].append(
                {
                    "name": "mcp_transport",
                    "path": None,
                    "ok": False,
                    "status": None,
                    "attempts": 0,
                    "elapsed_ms": 0.0,
                    "reason": mcp_error or "invalid_url",
                    "details": {},
                }
            )
        else:
            path_transport = _detect_mcp_transport(normalised_mcp, "auto")
            detected = _detect_mcp_transport(normalised_mcp, mcp_transport)
            report["detected_transport"] = detected
            report["target"]["mcp_path"] = mcp_details["path"]
            if path_transport == "unknown":
                reason = "unsupported_mcp_path"
            elif mcp_transport != "auto" and path_transport != mcp_transport:
                reason = "transport_path_mismatch"
            else:
                reason = None
            if reason is not None:
                report["checks"].append(
                    {
                        "name": "mcp_transport",
                        "path": mcp_details["path"],
                        "ok": False,
                        "status": None,
                        "attempts": 0,
                        "elapsed_ms": 0.0,
                        "reason": reason,
                        "details": {
                            "transport": detected,
                            "path_transport": path_transport,
                        },
                    }
                )
            else:
                mcp_headers = {
                    "Origin": "http://localhost",
                    "Access-Control-Request-Method": "POST",
                }
                mcp_headers.update(request_headers)
                report["checks"].append(
                    _run_check(
                        name="mcp_transport",
                        path=mcp_details["path"],
                        url=normalised_mcp,
                        validator=_validate_mcp_route(detected),
                        timeout=timeout,
                        retries=retries,
                        retry_delay=retry_delay,
                        probe=probe_fn,
                        sleep_fn=sleep,
                        method="OPTIONS",
                        headers=mcp_headers,
                    )
                )
    else:
        report["detected_transport"] = "http-plugin"

    failed = next((check for check in report["checks"] if not check["ok"]), None)
    report["ok"] = failed is None
    if failed is not None:
        if failed["name"] == "plugin_connection":
            report["recommended_next_action"] = "Inspect the Ghidra/plugin listener, URL, authentication, or lifecycle."
        elif failed["name"] == "instance_info":
            report["recommended_next_action"] = (
                "HTTP is reachable but instance metadata is unavailable; inspect transport or server version."
            )
        elif failed["name"] == "server_health":
            report["recommended_next_action"] = (
                "Inspect the Ghidra-side HTTP server health and listener before debugging the MCP client."
            )
        elif failed["name"] == "schema":
            report["recommended_next_action"] = (
                "Ghidra health is reachable but the advertised schema is unavailable or empty; inspect catalog registration."
            )
        elif failed["name"] == "mcp_transport":
            report["recommended_next_action"] = (
                "Ghidra checks passed or partially passed; inspect the bridge MCP transport and session endpoint."
            )
    else:
        report["recommended_next_action"] = (
            "Ghidra/plugin HTTP and schema checks passed; inspect the MCP client/session if tools are still missing."
        )
    return report


def _print_doctor_text(report: Mapping[str, Any]) -> None:
    print(f"DOCTOR={'PASS' if report['ok'] else 'FAIL'}")
    print(f"TRANSPORT={report['detected_transport']}")
    for check in report["checks"]:
        state = "PASS" if check["ok"] else "FAIL"
        status = "" if check["status"] is None else f" STATUS={check['status']}"
        reason = "" if not check["reason"] else f" REASON={check['reason']}"
        print(f"CHECK={check['name']} {state} ATTEMPTS={check['attempts']}{status}{reason}")
    print(f"NEXT={report['recommended_next_action']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe Ghidra MCP server health")
    parser.add_argument(
        "--url",
        default=DEFAULT_HEALTH_URL,
        help="Health endpoint URL (default: %(default)s); doctor mode normalises it to a base URL",
    )
    parser.add_argument(
        "--mode",
        choices=("health", "doctor"),
        default="health",
        help="health preserves the original single probe; doctor runs layered read-only checks",
    )
    parser.add_argument(
        "--doctor",
        dest="mode",
        action="store_const",
        const="doctor",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Base HTTP URL for doctor mode (overrides --url)",
    )
    parser.add_argument(
        "--mcp-url",
        default=None,
        help="Optional streamable HTTP or SSE endpoint to probe with a safe OPTIONS request",
    )
    parser.add_argument(
        "--mcp-transport",
        choices=MCP_TRANSPORTS,
        default="auto",
        help="MCP route type for --mcp-url (default: %(default)s)",
    )
    parser.add_argument(
        "--auth-token-env",
        default="GHIDRA_MCP_AUTH_TOKEN",
        help="Environment variable containing an optional bearer token for doctor requests",
    )
    parser.add_argument(
        "--server-kind",
        choices=SERVER_KINDS,
        default="auto",
        help="Ghidra server mode for doctor routing (default: %(default)s)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format for doctor mode (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-request timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=10,
        help="Number of attempts before failing (default: %(default)s)",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Delay between attempts in seconds (default: %(default)s)",
    )
    args = parser.parse_args()

    if args.mode != "doctor" and args.format != "text":
        parser.error("--format json is only valid with --mode doctor")

    if args.mode == "doctor":
        report = run_doctor(
            args.base_url or args.url,
            mcp_url=args.mcp_url,
            mcp_transport=args.mcp_transport,
            timeout=args.timeout,
            retries=args.retries,
            retry_delay=args.retry_delay,
            auth_token=(os.environ.get(args.auth_token_env) if args.auth_token_env else None),
            server_kind=args.server_kind,
        )
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            _print_doctor_text(report)
        return 0 if report["ok"] else 1

    last_error = None
    for attempt in range(1, args.retries + 1):
        try:
            status, body = _probe(args.url, args.timeout)
            if args.format == "json":
                print(json.dumps({"ok": status == 200, "status": status, "body": body}))
            else:
                print(f"STATUS={status}")
                print(body)
                if status == 200:
                    try:
                        parsed = json.loads(body)
                        if isinstance(parsed, dict):
                            state = parsed.get("status") or parsed.get("message") or "ok"
                            print(f"HEALTH={state}")
                    except json.JSONDecodeError:
                        pass
            if status == 200:
                return 0
            last_error = f"Unexpected HTTP status {status}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)

        if attempt < args.retries:
            print(f"Attempt {attempt}/{args.retries} failed: {last_error}")
            time.sleep(args.retry_delay)

    if args.format == "json":
        print(json.dumps({"ok": False, "error": last_error}))
    else:
        print(f"ERROR={last_error}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

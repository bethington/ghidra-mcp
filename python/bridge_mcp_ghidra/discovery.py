"""Discovery of running Ghidra instances over UDS and TCP."""

import concurrent.futures
import http.client
import json

from . import state
from . import transport
from . import validation
from .config import DEFAULT_TCP_PORT, TCP_PORT_SCAN_RANGE, logger

# Upper bound on threads used to probe the TCP scan range. The scan is pure
# wait (a dropped connection costs the full timeout), so the cap only exists
# to keep thread churn bounded on a wide range_size.
_TCP_SCAN_MAX_WORKERS = 16


def _unwrap_response_data(text: str) -> dict:
    """Unwrap Response.ok() payloads while preserving plain JSON responses."""
    data = json.loads(text)
    if isinstance(data, dict) and "data" in data:
        return data["data"]
    return data


def discover_instances() -> list[dict]:
    """Scan every plausible socket directory and query each live instance.

    Searches *all* candidates returned by `get_socket_dir_candidates()`. This
    handles issue #170: when Claude Desktop spawns the bridge without
    forwarding `$TMPDIR`, the bridge falls back to `/tmp` while the plugin
    (with `$TMPDIR` set) wrote its socket to `/var/folders/.../T/...`. By
    scanning every candidate, the bridge finds instances regardless of which
    side knows about `$TMPDIR`. A socket discovered under one candidate dir
    is de-duplicated by absolute path.
    """
    seen_paths: set[str] = set()
    instances: list[dict] = []
    uds_ok = transport.uds_supported()
    tcp_by_pid: dict[int, dict] | None = None

    for socket_dir in transport.get_socket_dir_candidates():
        if not socket_dir.exists():
            continue
        for sock_file in sorted(socket_dir.glob("*.sock")):
            abs_path = str(sock_file.resolve())
            if abs_path in seen_paths:
                continue
            seen_paths.add(abs_path)

            name = sock_file.stem  # ghidra-<pid>
            dash = name.rfind("-")
            if dash < 0:
                continue
            try:
                pid = int(name[dash + 1 :])
            except ValueError:
                continue

            if not validation.is_pid_alive(pid):
                logger.debug(f"Cleaning up stale socket: {sock_file}")
                try:
                    sock_file.unlink(missing_ok=True)
                except OSError:
                    pass
                continue

            info: dict = {"socket": str(sock_file), "pid": pid}
            if uds_ok:
                try:
                    text, status = transport.uds_request(str(sock_file), "GET", "/mcp/instance_info", timeout=5)
                    if status == 200:
                        info.update(_unwrap_response_data(text))
                except Exception as e:
                    logger.debug(f"Could not query {sock_file}: {e}")
            else:
                # CPython on Windows can't dial UDS (see
                # transport.uds_supported), so the socket file only proves
                # the instance is alive. Fetch its metadata — project name,
                # programs, tcp_port — over the plugin's TCP listener
                # instead, matched by PID.
                if tcp_by_pid is None:
                    tcp_by_pid = _tcp_instances_by_pid()
                if pid in tcp_by_pid:
                    info.update(tcp_by_pid[pid])

            instances.append(info)

    return instances


def _probe_tcp_port(port: int, timeout: float, cancel_handle) -> tuple[str, dict] | None:
    """Probe one port for a Ghidra plugin; return (url, instance_info) or None.

    `cancel_handle` is passed in rather than read from `state` because this
    runs on a worker thread: the handle lives in a ContextVar, and ContextVars
    are not inherited by ThreadPoolExecutor workers, so an in-thread lookup
    would silently always return None and defeat request cancellation.
    """
    url = f"http://127.0.0.1:{port}"
    conn = None
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        if cancel_handle is not None and not cancel_handle.register_connection(conn):
            return None
        try:
            conn.connect()
            if cancel_handle is not None and cancel_handle.aborted:
                return None
            if cancel_handle is not None:
                with cancel_handle.hold_send_window(conn) as can_send:
                    if not can_send:
                        return None
                    conn.request("GET", "/mcp/instance_info")
            else:
                conn.request("GET", "/mcp/instance_info")
            resp = conn.getresponse()
            if resp.status != 200:
                return None
            body = resp.read().decode("utf-8", errors="replace")
        finally:
            if cancel_handle is not None and conn is not None:
                cancel_handle.unregister_connection(conn)
            conn.close()
        info = _unwrap_response_data(body)
        if isinstance(info, dict):
            return url, info
    except Exception:
        # Connection refused / timeout / non-JSON response — not an instance.
        if cancel_handle is not None and conn is not None:
            cancel_handle.unregister_connection(conn)
    return None


def _iter_tcp_instances(
    start_port: int = DEFAULT_TCP_PORT, range_size: int = TCP_PORT_SCAN_RANGE, timeout: float = 1.0
):
    """Yield (url, instance_info) for every Ghidra plugin in the TCP scan range.

    For each port in [start_port, start_port + range_size), issues
    `GET /mcp/instance_info` with a short timeout; unreachable ports and
    non-JSON responders are skipped silently.

    Ports are probed CONCURRENTLY, but results are yielded in ascending port
    order so callers keep their deterministic "lowest matching port wins"
    semantics (`_scan_tcp_for_project`'s exact match, `_tcp_instances_by_pid`'s
    first-pid-wins). Concurrency is not a micro-optimization: a port that is
    *dropped* rather than *refused* costs the full timeout, and on a Windows
    host whose firewall drops, a serial scan of the default 16-port range
    measured 15.2s of the bridge's 16.8s startup — close enough to an MCP
    client's start timeout to fail the connection outright, which presents as
    "the Ghidra tools are missing" with nothing in the logs.

    Uses http.client (stdlib) rather than `requests` to keep the bridge's
    dependency footprint minimal -- see test_project_consistency.
    """
    ports = list(range(start_port, start_port + range_size))
    if not ports:
        return

    cancel_handle = state.get_request_cancel_handle()
    found: dict[int, tuple[str, dict]] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(len(ports), _TCP_SCAN_MAX_WORKERS),
        thread_name_prefix="GhidraMCP-PortScan",
    ) as pool:
        futures = {pool.submit(_probe_tcp_port, port, timeout, cancel_handle): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except Exception:
                result = None
            if result is not None:
                found[futures[future]] = result

    for port in ports:
        if port in found:
            yield found[port]


def _tcp_instances_by_pid(
    start_port: int = DEFAULT_TCP_PORT, range_size: int = TCP_PORT_SCAN_RANGE, timeout: float = 1.0
) -> dict[int, dict]:
    """Map pid -> {"url": ..., **instance_info} for TCP-reachable instances.

    Used to enrich UDS socket-file discovery on hosts where Python can't
    dial UDS (Windows CPython): the socket filename carries the plugin's
    PID, and /mcp/instance_info reports its own pid, so the two can be
    joined without guessing.
    """
    by_pid: dict[int, dict] = {}
    for url, info in _iter_tcp_instances(start_port, range_size, timeout):
        pid = info.get("pid")
        if isinstance(pid, int) and pid not in by_pid:
            by_pid[pid] = {"url": url, **info}
    return by_pid


def _scan_tcp_for_project(
    project: str, start_port: int = DEFAULT_TCP_PORT, range_size: int = TCP_PORT_SCAN_RANGE, timeout: float = 1.0
) -> str | None:
    """Scan a small TCP port range for a Ghidra plugin matching `project`.

    Used when UDS discovery returns nothing (e.g., TCP-only multi-instance
    setups on Windows pre-1803). The first instance whose `project` field
    matches exactly wins; a substring match is used as fallback. Returns
    None if no match found.

    Project matching mirrors connect_instance's UDS match order so the same
    `connect_instance("D2Common")` call selects the same instance regardless
    of which transport found it.
    """
    if not project:
        return None
    project_lower = project.lower()
    substring_url: str | None = None
    for url, info in _iter_tcp_instances(start_port, range_size, timeout):
        inst_project = info.get("project", "")
        if inst_project == project:
            # Exact match — return immediately.
            return url
        if not substring_url and project_lower in inst_project.lower():
            substring_url = url
    return substring_url


def discover_active_tcp_instance() -> dict | None:
    """Return the active TCP fallback connection as an instance-like record."""
    if state._transport_mode != "tcp" or not state._active_tcp:
        return None

    info: dict = {
        "transport": "tcp",
        "url": state._active_tcp,
        "discovery": "active-tcp",
    }
    if state._connected_project:
        info["project"] = state._connected_project

    try:
        text, status = transport.tcp_request(state._active_tcp, "GET", "/mcp/instance_info", timeout=5)
        if status == 200:
            info.update(_unwrap_response_data(text))
            return info
    except Exception as e:
        logger.debug(f"Could not query TCP instance info for {state._active_tcp}: {e}")

    try:
        text, status = transport.tcp_request(state._active_tcp, "GET", "/list_open_programs", timeout=5)
        if status == 200:
            data = _unwrap_response_data(text)
            if isinstance(data, dict):
                for key in ("programs", "count", "current_program"):
                    if key in data:
                        info[key] = data[key]
    except Exception as e:
        logger.debug(f"Could not query open programs for active TCP instance {state._active_tcp}: {e}")

    return info

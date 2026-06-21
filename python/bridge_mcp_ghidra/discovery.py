"""Discovery of running Ghidra instances over UDS and TCP."""

import http.client
import json

from . import state
from . import transport
from . import validation
from .config import DEFAULT_TCP_PORT, TCP_PORT_SCAN_RANGE, logger


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
                pid = int(name[dash + 1:])
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
            try:
                text, status = transport.uds_request(
                    str(sock_file), "GET", "/mcp/instance_info", timeout=5
                )
                if status == 200:
                    info.update(_unwrap_response_data(text))
            except Exception as e:
                logger.debug(f"Could not query {sock_file}: {e}")

            instances.append(info)

    return instances


def _scan_tcp_for_project(project: str, start_port: int = DEFAULT_TCP_PORT,
                          range_size: int = TCP_PORT_SCAN_RANGE,
                          timeout: float = 1.0) -> str | None:
    """Scan a small TCP port range for a Ghidra plugin matching `project`.

    Used when UDS discovery returns nothing (e.g., TCP-only multi-instance
    setups on Windows pre-1803). For each port in [start_port, start_port +
    range_size), issues `GET /mcp/instance_info` with a short timeout. The
    first one whose `project` field matches (exact wins; substring used as
    fallback) returns its URL. Returns None if no match found.

    Project matching mirrors connect_instance's UDS match order so the same
    `connect_instance("D2Common")` call selects the same instance regardless
    of which transport found it.

    Uses http.client (stdlib) rather than `requests` to keep the bridge's
    dependency footprint minimal -- see test_project_consistency.
    """
    if not project:
        return None
    project_lower = project.lower()
    substring_url: str | None = None
    for port in range(start_port, start_port + range_size):
        url = f"http://127.0.0.1:{port}"
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
            try:
                conn.request("GET", "/mcp/instance_info")
                resp = conn.getresponse()
                if resp.status != 200:
                    continue
                body = resp.read().decode("utf-8", errors="replace")
            finally:
                conn.close()
            info = _unwrap_response_data(body)
            if not isinstance(info, dict):
                continue
            inst_project = info.get("project", "")
            if inst_project == project:
                # Exact match — return immediately.
                return url
            if not substring_url and project_lower in inst_project.lower():
                substring_url = url
        except Exception:
            # Connection refused / timeout / non-JSON response — try next port.
            continue
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
        text, status = transport.tcp_request(
            state._active_tcp, "GET", "/mcp/instance_info", timeout=5
        )
        if status == 200:
            info.update(_unwrap_response_data(text))
            return info
    except Exception as e:
        logger.debug(f"Could not query TCP instance info for {state._active_tcp}: {e}")

    try:
        text, status = transport.tcp_request(
            state._active_tcp, "GET", "/list_open_programs", timeout=5
        )
        if status == 200:
            data = _unwrap_response_data(text)
            if isinstance(data, dict):
                for key in ("programs", "count", "current_program"):
                    if key in data:
                        info[key] = data[key]
    except Exception as e:
        logger.debug(
            f"Could not query open programs for active TCP instance {state._active_tcp}: {e}"
        )

    return info

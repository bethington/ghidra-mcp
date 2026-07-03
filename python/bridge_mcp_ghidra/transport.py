"""HTTP transports to the Ghidra plugin: Unix domain sockets and TCP.

``do_request`` routes to the active transport based on the shared connection
state in :mod:`bridge_mcp_ghidra.state`.
"""

import http.client
import json
import os
import socket
from pathlib import Path
from urllib.parse import urlencode, urlparse

from . import state
from .config import AUTH_TOKEN, logger


def _auth_headers() -> dict[str, str]:
    """Authorization header for the Ghidra server, when ``AUTH_TOKEN`` is set."""
    return {"Authorization": f"Bearer {AUTH_TOKEN}"} if AUTH_TOKEN else {}


# ==========================================================================
# UDS Transport
# ==========================================================================


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP connection over a Unix domain socket."""

    def __init__(self, socket_path: str, timeout: int = 30):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def get_socket_dir() -> Path:
    """Get the primary GhidraMCP socket runtime directory.

    Kept for backwards compatibility. For instance discovery prefer
    `get_socket_dir_candidates()` -- when Claude Desktop spawns the bridge
    without forwarding `$TMPDIR`, the bridge would fall through to `/tmp`
    while the plugin (with `$TMPDIR` set) wrote sockets to
    `/var/folders/.../T/ghidra-mcp-<user>/` (issue #170).
    """
    return get_socket_dir_candidates()[0]


def get_socket_dir_candidates() -> list[Path]:
    """All plausible socket runtime directories the bridge should search.

    Superset of what the Java plugin's `ServerManager.getSocketDir()`
    actually picks (which is `XDG_RUNTIME_DIR` → `TMPDIR` → `/tmp` with
    `System.getProperty("user.name")` as the user component). The Python
    side covers additional locations the plugin's `$TMPDIR` could *resolve
    to* at runtime even when the bridge inherits a different environment
    -- specifically the macOS per-user temp under `/var/folders/...` and
    its `/private` symlink, which is what `$TMPDIR` points at when the
    parent shell or Ghidra had it set but Claude Desktop spawned the
    bridge without forwarding the variable (issue #170).

    Username component is derived from `$USER` (POSIX) or `$USERNAME`
    (Windows); the Java side uses `user.name` which may differ in edge
    cases (e.g., headless services). Falls back to "unknown" if neither
    env var is set. Duplicates removed; order matters (most-likely first).
    """
    user = os.getenv("USER") or os.getenv("USERNAME") or "unknown"
    candidates: list[Path] = []

    def _add(p):
        if p is None:
            return
        p = Path(p)
        if p not in candidates:
            candidates.append(p)

    # Linux: XDG_RUNTIME_DIR / /run/user/<uid>
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        _add(Path(xdg) / "ghidra-mcp")
    getuid = getattr(os, "getuid", None)
    if callable(getuid):
        run_user_dir = Path(f"/run/user/{getuid()}")
        try:
            if run_user_dir.exists():
                _add(run_user_dir / "ghidra-mcp")
        except OSError:
            logger.debug("Ignoring unusable runtime dir candidate: %s", run_user_dir)

    # Per-user TMPDIR (the macOS Claude Desktop gap)
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        _add(Path(tmpdir) / f"ghidra-mcp-{user}")

    # macOS per-user temp -- $TMPDIR resolves to
    #   /var/folders/<2-char-hash>/<random-id>/T/
    # (note: TWO directory levels before `T`, the Copilot fix). On macOS
    # `/var` is itself a symlink to `/private/var`, so socket files may
    # appear under either prefix depending on how the parent walked the
    # filesystem -- cover both. Globbing returns whatever exists.
    for prefix in ("/var/folders", "/private/var/folders"):
        var_folders = Path(prefix)
        try:
            if not var_folders.exists():
                continue
            # */*/T/ghidra-mcp-<user> is the canonical macOS shape.
            for hit in var_folders.glob(f"*/*/T/ghidra-mcp-{user}"):
                _add(hit)
        except OSError:
            pass

    # POSIX fallback
    _add(Path(f"/tmp/ghidra-mcp-{user}"))

    # Windows fallback — Java's java.io.tmpdir is typically %TEMP%
    win_temp = os.environ.get("TEMP") or os.environ.get("TMP")
    if win_temp:
        _add(Path(win_temp) / f"ghidra-mcp-{user}")

    return candidates


def uds_request(
    socket_path: str,
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Make an HTTP request over a Unix domain socket. Returns (body, status)."""
    conn = UnixHTTPConnection(socket_path, timeout=timeout)
    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if params:
        path = f"{path}?{urlencode(params)}"

    headers = _auth_headers()
    body = None
    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if body:
        headers["Content-Length"] = str(len(body))

    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = response.read().decode("utf-8")
        status = response.status
        conn.close()
        return result, status
    except Exception:
        conn.close()
        raise


# ==========================================================================
# TCP Transport
# ==========================================================================


def tcp_request(
    base_url: str,
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Make an HTTP request over TCP. Returns (body, status)."""
    parsed = urlparse(base_url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)

    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if params:
        path = f"{path}?{urlencode(params)}"

    headers = _auth_headers()
    body = None
    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if body:
        headers["Content-Length"] = str(len(body))

    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = response.read().decode("utf-8")
        status = response.status
        conn.close()
        return result, status
    except Exception:
        conn.close()
        raise


# ==========================================================================
# Unified request function
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
    with state._ghidra_lock:
        if state._transport_mode == "uds" and state._active_socket:
            return uds_request(
                state._active_socket, method, endpoint, params, json_data, timeout
            )
        elif state._transport_mode == "tcp" and state._active_tcp:
            return tcp_request(
                state._active_tcp, method, endpoint, params, json_data, timeout
            )
        else:
            raise ConnectionError(
                "No Ghidra instance connected. Use connect_instance() first."
            )

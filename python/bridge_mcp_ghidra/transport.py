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


class RequestNotSentError(ConnectionError):
    """The transport could not connect, so the request was not sent."""


class RequestOutcomeUnknownError(ConnectionError):
    """The request may have reached Ghidra, but no complete response arrived."""


def _request_over_connection(
    conn: http.client.HTTPConnection,
    method: str,
    path: str,
    body: bytes | None,
    headers: dict[str, str],
) -> tuple[str, int]:
    """Execute one request while preserving whether retrying is safe."""
    cancel_handle = state.get_request_cancel_handle()
    if cancel_handle is not None and not cancel_handle.register_connection(conn):
        raise RequestOutcomeUnknownError(f"Request aborted before start for {method} {path}")
    try:
        conn.connect()
    except Exception as exc:
        conn.close()
        raise RequestNotSentError(f"Could not connect for {method} {path}: {exc}") from exc

    if cancel_handle is not None and cancel_handle.aborted:
        conn.close()
        raise RequestOutcomeUnknownError(f"Request aborted before send for {method} {path}")

    try:
        if cancel_handle is not None:
            with cancel_handle.hold_send_window(conn) as can_send:
                if not can_send:
                    raise RequestOutcomeUnknownError(f"Request aborted before send for {method} {path}")
                conn.request(method, path, body=body, headers=headers)
        else:
            conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = response.read().decode("utf-8")
        return result, response.status
    except Exception as exc:
        raise RequestOutcomeUnknownError(f"No complete response for {method} {path}: {exc}") from exc
    finally:
        if cancel_handle is not None:
            cancel_handle.unregister_connection(conn)
        conn.close()


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


def uds_supported() -> bool:
    """Whether this Python can dial Unix domain sockets.

    CPython on Windows doesn't expose socket.AF_UNIX (python/cpython#77589)
    even though the OS and the Java plugin support them. On such hosts the
    socket file still marks a live instance, but all traffic must go over
    the plugin's TCP listener.
    """
    return hasattr(socket, "AF_UNIX")


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

    if os.name == "nt":
        for candidate in _windows_drive_tmp_candidates(user):
            _add(candidate)

    return candidates


def _windows_drive_tmp_candidates(user: str) -> list[Path]:
    """Backward-compat sweep of every mounted drive for <drive>:\\tmp\\ghidra-mcp-<user>.

    Plugin JARs before the java.io.tmpdir fallback resolved the literal
    "/tmp" against the JVM's working drive (e.g. F:\\tmp when Ghidra runs
    from F:), while the bare /tmp candidate resolves against the *bridge's*
    working drive. Scanning every drive root finds sockets on other drives.
    Only existing directories are returned so the candidate list isn't
    flooded with junk paths for every drive letter.
    """
    listdrives = getattr(os, "listdrives", None)  # Python 3.12+
    if callable(listdrives):
        try:
            drives = listdrives()
        except OSError:
            drives = []
    else:
        drives = [f"{letter}:\\" for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]

    hits: list[Path] = []
    for drive in drives:
        candidate = Path(drive) / "tmp" / f"ghidra-mcp-{user}"
        try:
            if candidate.exists():
                hits.append(candidate)
        except OSError:
            pass
    return hits


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

    return _request_over_connection(conn, method, path, body, headers)


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

    return _request_over_connection(conn, method, path, body, headers)


# ==========================================================================
# Unified request function
# ==========================================================================


def do_request(
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
    connection: state.ConnectionSnapshot | None = None,
) -> tuple[str, int]:
    """Route a request to the active transport.

    Routing is by an immutable request-bound connection snapshot when present,
    not by whatever global target happens to be current when the worker finally
    runs. This keeps in-flight requests pinned to the project they were
    admitted against even if connect_instance() switches the bridge later.
    """
    connection = connection or state.get_request_connection_snapshot() or state.get_connection_snapshot()
    if connection.mode == "uds" and connection.active_socket:
        return uds_request(connection.active_socket, method, endpoint, params, json_data, timeout)
    elif connection.mode == "tcp" and connection.active_tcp:
        return tcp_request(connection.active_tcp, method, endpoint, params, json_data, timeout)
    else:
        raise ConnectionError("No Ghidra instance connected. Use connect_instance() first.")

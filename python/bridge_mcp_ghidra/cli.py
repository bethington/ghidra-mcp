"""Command-line entry point for the GhidraMCP bridge."""

import argparse
import hmac
import json
import os
import re
import secrets
import socket

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.cors import CORSMiddleware

from . import server
from . import state
from .config import AUTH_TOKEN, logger
from .server import mcp
from .static_tools import _auto_connect, _start_auto_connect_retry

# Largest body we will buffer while sniffing a session-less POST for the
# `initialize` handshake. A real initialize is a few hundred bytes; anything
# past this is either abuse or a client that lost its session id, and both get
# the same "Missing session ID" answer the SDK would have given.
_INITIALIZE_SNIFF_LIMIT = 256 * 1024

_ALLOWED_HTTP_METHODS = "GET, POST, DELETE, OPTIONS"

# Shared secret required on inbound HTTP requests when set. Unset = no inbound
# authentication, which is the historical behaviour and fine on loopback.
_INBOUND_TOKEN_ENV = "GHIDRA_MCP_INBOUND_TOKEN"


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _local_machine_hosts() -> set[str]:
    """Every name this machine legitimately answers to.

    Hostname, FQDN, and every address the hostname resolves to (covers
    multi-NIC). Used for a 0.0.0.0/:: bind, where legitimate remote
    clients put the real hostname/IP in the Host header while a
    DNS-rebinding attacker puts a name he controls.
    """
    hosts: set[str] = set()
    try:
        hn = socket.gethostname()
        if hn:
            hosts.add(hn)
            try:
                hosts.add(socket.getfqdn(hn))
            except OSError:
                pass
            try:
                for info in socket.getaddrinfo(hn, None):
                    addr = info[4][0]
                    if addr:
                        hosts.add(addr)
            except OSError:
                pass
    except OSError:
        pass
    return hosts


def _policy_hosts(bind_host: str) -> set[str]:
    """The ONE host set every request gate is derived from.

    Two independent gates read the Origin header of every non-preflight
    request -- ``CORSMiddleware`` (browser-facing, answers the preflight)
    and the SDK's ``TransportSecurityMiddleware`` (DNS-rebinding, runs
    inside the transport app). They are separate mechanisms with separate
    syntaxes, so when their allowlists are hand-maintained side by side
    they drift, and a request the preflight approved is then refused by
    the inner gate -- a 200 preflight followed by a 421/403 on the real
    POST, which reads to the operator as a network fault rather than a
    policy one. Deriving both from this function is what stops that.

    Bare names only here: no scheme, no port, no brackets. The two
    encodings are added by ``_host_header_forms`` / ``_origin_forms``.
    """
    hosts = set(_LOOPBACK_HOSTS)
    if bind_host in {"0.0.0.0", "::"}:
        hosts |= _local_machine_hosts()
    elif bind_host not in _LOOPBACK_HOSTS:
        hosts.add(bind_host)
    # The escape hatch operators reach for when a legitimate client is
    # refused. It must extend BOTH gates, or it fixes one and not the other.
    extra = os.environ.get("GHIDRA_MCP_ALLOWED_HOSTS", "")
    hosts.update(h.strip() for h in extra.split(",") if h.strip())
    return hosts


def _bracketed(hosts) -> set[str]:
    """Add RFC 3986 bracketed forms for bare IPv6 literals.

    IPv6 appears bracketed in both Host headers and origins
    (``[::1]:8089``, ``http://[::1]:6274``), so the bare form alone never
    matches a real request.
    """
    out = set(hosts)
    for h in hosts:
        if ":" in h and not h.startswith("["):
            out.add(f"[{h}]")
    return out


def _host_header_forms(hosts) -> list[str]:
    """Host-header allowlist entries: portless AND ``:*`` for every host.

    BOTH forms are required. The SDK matches ``host:*`` only when the Host
    header actually carries a port, and a reverse proxy terminating on a
    default port (443 for https, 80 for http) forwards a PORTLESS Host --
    so a ``host:*``-only allowlist rejects every proxied request with 421
    Misdirected Request.
    """
    out: list[str] = []
    for h in sorted(_bracketed(hosts)):
        out.append(h)
        out.append(f"{h}:*")
    return out


def _origin_forms(hosts) -> list[str]:
    """Origin allowlist entries: {http,https} x {portless, ``:*``}.

    Mirrors ``_cors_origin_regex``'s ``^https?://host(:\\d+)?$`` exactly.
    Dropping https here is the same 421-class trap as dropping the
    portless host: anything behind TLS termination sends an https Origin,
    the preflight approves it, and the SDK gate then answers 403.
    """
    out: list[str] = []
    for h in sorted(_bracketed(hosts)):
        for scheme in ("http", "https"):
            out.append(f"{scheme}://{h}")
            out.append(f"{scheme}://{h}:*")
    return out


def _wildcard_allowed_hosts() -> list[str]:
    """Allowed-Host list for a 0.0.0.0/:: bind."""
    return _host_header_forms(set(_LOOPBACK_HOSTS) | _local_machine_hosts())


def _transport_security(bind_host: str) -> TransportSecuritySettings:
    """DNS-rebinding settings for a non-loopback bind.

    Built from ``_policy_hosts`` -- the same set ``_cors_origin_regex``
    uses -- so the browser-facing gate and this one cannot disagree.
    """
    hosts = _policy_hosts(bind_host)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_host_header_forms(hosts),
        allowed_origins=_origin_forms(hosts),
    )


def _cors_origin_regex(bind_host: str) -> str:
    """Build the allowed-Origin regex for the HTTP transports.

    CORS only gates browsers -- native MCP clients never send a preflight
    -- so this mirrors the Host-header policy: loopback origins on any
    port are always allowed (browser tools like MCP Inspector serve their
    UI from ``http://localhost:<port>``), a non-loopback bind additionally
    allows the bind host itself, a wildcard bind allows the machine's own
    hostnames/IPs, and ``GHIDRA_MCP_ALLOWED_HOSTS`` extends the list.
    """
    alternatives = "|".join(sorted(re.escape(h) for h in _bracketed(_policy_hosts(bind_host))))
    return rf"^https?://({alternatives})(:\d+)?$"


class _BearerAuthMiddleware:
    """Require the backend bearer token from clients of an exposed bridge."""

    def __init__(self, app, token: str):
        self.app = app
        self.expected = f"Bearer {token}".encode("utf-8")

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("method") != "OPTIONS":
            headers = dict(scope.get("headers", ()))
            supplied = headers.get(b"authorization", b"")
            if not hmac.compare_digest(supplied, self.expected):
                body = b"Unauthorized"
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", str(len(body)).encode("ascii")),
                            (b"www-authenticate", b"Bearer"),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)
async def _send_json_rpc_error(send, status: int, message: str) -> None:
    """Reply with the same JSON-RPC error envelope the SDK's transport uses."""
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "server-error",
            "error": {"code": -32600, "message": message},
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _buffer_body(receive, limit: int) -> bytes | None:
    """Drain the request body, or return None if it exceeds ``limit``.

    None also covers a client that disconnects mid-body — the caller treats
    both as "not an initialize request".
    """
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            return None
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


async def _drop_session(session_id: str) -> None:
    """Tear down a session whose creating request was rejected.

    ``StreamableHTTPSessionManager`` registers the new transport *before* the
    transport validates the request, so a handshake refused for a bad ``Accept``
    header, an unsupported ``MCP-Protocol-Version`` or unparseable JSON leaves a
    live session behind. The SDK's own reaper (``session_idle_timeout``) is
    never enabled by FastMCP, so nothing else collects them.
    """
    manager = getattr(mcp, "_session_manager", None)
    instances = getattr(manager, "_server_instances", None)
    if not isinstance(instances, dict):
        logger.warning(
            "Cannot drop session %s: no _server_instances dict on the session "
            "manager (SDK internals may have changed)",
            session_id,
        )
        return
    transport = instances.pop(session_id, None)
    owners = getattr(manager, "_session_owners", None)
    if isinstance(owners, dict):
        owners.pop(session_id, None)
    if transport is None:
        return
    try:
        await transport.terminate()
    except Exception as e:
        logger.warning("Failed to terminate rejected session %s: %s", session_id, e)


def _is_initialize_request(body: bytes) -> bool:
    """True when this body is the JSON-RPC ``initialize`` handshake."""
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return False
    # JSON-RPC batching was removed in protocol 2025-11-25, and the SDK never
    # accepted a batched initialize, so only a lone object can be one.
    return isinstance(payload, dict) and payload.get("method") == "initialize"


class BearerTokenGuard:
    """Require ``Authorization: Bearer <token>`` when a token is configured.

    The HTTP transports had no inbound authentication at all: anything that could
    reach the port could drive every Ghidra tool, including the writes. That is
    defensible on loopback and indefensible the moment ``--mcp-host`` is not
    local, which the DNS-rebinding protection does not address — it stops a
    browser being tricked into making the request, not a client that simply
    connects.

    This is a static shared secret, deliberately **not** the spec's OAuth 2.1
    resource-server flow: that needs an authorization server and metadata
    documents, which is disproportionate for a locally-run RE tool. So no
    ``/.well-known/oauth-protected-resource`` is served and no OAuth discovery is
    claimed — a 401 here means "send the token the operator gave you".

    ``OPTIONS`` stays open: a CORS preflight cannot carry credentials, and the
    method probe it answers reveals nothing but the allowed verbs.
    """

    def __init__(self, app, *, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return

        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        supplied = headers.get(b"authorization", b"").decode("latin-1")
        prefix = "Bearer "
        presented = supplied[len(prefix):] if supplied.startswith(prefix) else ""
        # compare_digest on both branches: a plain != would leak the token's
        # length and prefix through response timing.
        if not secrets.compare_digest(presented, self.token):
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "server-error",
                    "error": {"code": -32600, "message": "Unauthorized"},
                }
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (b"www-authenticate", b'Bearer realm="ghidra-mcp"'),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)


class TransportEdgeGuard:
    """ASGI wrapper doing two things the SDK's transport app does not.

    **Answer a bare ``OPTIONS``.** The transport routes only GET/POST/DELETE,
    so a plain capability probe drew a 405 whose own ``Allow`` header did not
    even list OPTIONS. Non-browser clients probe exactly this way before
    connecting (issue #399, Open WebUI), and ``CORSMiddleware`` does not help
    them: it answers only a real preflight, which needs both ``Origin`` and
    ``Access-Control-Request-Method``. CORS sits *outside* this guard, so
    genuine preflights are handled there and never arrive here.

    **Refuse session-less requests before the session manager sees them.**
    ``StreamableHTTPSessionManager`` creates a live transport for every request
    that arrives with no session id — including the ones it is about to reject
    — and never reaps them. Measured: 50 bare OPTIONS plus 50 session-less
    pings left 100 permanent sessions, each with its own task group, and a
    session id handed out with a 405 was afterwards fully usable. A request
    carrying an *unknown* session id is already handled correctly upstream
    (404, nothing created), so only a missing header is intercepted here.
    """

    def __init__(self, app, *, guard_sessions: bool):
        self.app = app
        self.guard_sessions = guard_sessions

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        if method == "OPTIONS":
            await send(
                {
                    "type": "http.response.start",
                    "status": 204,
                    "headers": [
                        (b"allow", _ALLOWED_HTTP_METHODS.encode()),
                        (b"content-length", b"0"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return

        if not self.guard_sessions or method not in {"GET", "POST", "DELETE"}:
            await self.app(scope, receive, send)
            return

        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        if b"mcp-session-id" in headers:
            await self.app(scope, receive, send)
            return

        missing = "Bad Request: Missing session ID"
        if method != "POST":
            await _send_json_rpc_error(send, 400, missing)
            return

        # Only `initialize` may arrive without a session id. Buffering happens
        # solely on this path, so an established session never pays for it.
        body = await _buffer_body(receive, _INITIALIZE_SNIFF_LIMIT)
        if body is None or not _is_initialize_request(body):
            await _send_json_rpc_error(send, 400, missing)
            return

        replayed = False

        async def replay():
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        # A handshake the transport goes on to reject still leaves its freshly
        # registered session behind, so watch the status and clean up. Only
        # sessions created by *this* request can be dropped here.
        new_session: str | None = None
        rejected = False

        async def watch(message):
            nonlocal new_session, rejected
            if message["type"] == "http.response.start":
                rejected = message["status"] >= 400
                for key, value in message.get("headers", []):
                    if key.lower() == b"mcp-session-id":
                        new_session = value.decode("latin-1")
            await send(message)

        await self.app(scope, replay, watch)
        if rejected and new_session:
            await _drop_session(new_session)


def _build_http_app(transport: str, bind_host: str):
    """Return the transport's Starlette app wrapped in the bridge's middleware.

    Browser-based clients (MCP Inspector) send an OPTIONS preflight before
    every POST and can only read the ``mcp-session-id`` response header if
    it is explicitly exposed. The SDK's stock ``mcp.run()`` apps carry no
    CORS middleware at all, so the preflight got a 405 and the session
    header was invisible to scripts — this wrapper is why the bridge runs
    uvicorn itself instead of delegating to ``mcp.run()``.

    Ordering matters: ``CORSMiddleware`` is added last and therefore runs
    outermost, so it claims real preflights before ``TransportEdgeGuard``
    sees them.
    """
    app = mcp.sse_app() if transport == "sse" else mcp.streamable_http_app()
    # The SSE transport carries its session in a query parameter and has no
    # `mcp-session-id` header; stateless streamable-HTTP has no session at
    # all. Neither can be guarded by header presence.
    guard_sessions = transport == "streamable-http" and not mcp.settings.stateless_http
    app.add_middleware(TransportEdgeGuard, guard_sessions=guard_sessions)
    # Sits outside TransportEdgeGuard so an unauthenticated request never
    # reaches the session manager, and inside CORS so a browser still gets its
    # preflight answered (which cannot carry credentials).
    token = os.environ.get(_INBOUND_TOKEN_ENV, "")
    if token:
        app.add_middleware(BearerTokenGuard, token=token)
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=_cors_origin_regex(bind_host),
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["mcp-session-id", "mcp-protocol-version"],
        max_age=3600,
    )
    if AUTH_TOKEN and bind_host not in {"127.0.0.1", "localhost", "::1"}:
        # The bridge reuses this credential for its backend requests.  Do not
        # let an unauthenticated network client turn it into a confused deputy.
        app = _BearerAuthMiddleware(app, AUTH_TOKEN)
    return app


def main():
    parser = argparse.ArgumentParser(description="GhidraMCP Bridge -- MCP<->HTTP multiplexer")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host for HTTP transport (streamable-http or sse)",
    )
    parser.add_argument("--mcp-port", type=int, help="Port for HTTP transport (streamable-http or sse)")
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse", "streamable-http"],
        help="MCP transport: stdio (default, recommended for AI tools), "
        "streamable-http (recommended for web/HTTP clients), "
        "sse (deprecated, use streamable-http instead)",
    )
    parser.add_argument(
        "--lazy",
        action="store_true",
        default=None,
        help="Only load default tool groups on connect (default). Keeps the "
        "advertised tool set small enough for providers that cap function "
        "declarations; use search_tools/load_tool_group to pull in more.",
    )
    parser.add_argument(
        "--no-lazy",
        dest="lazy",
        action="store_false",
        help="Load all tool groups on connect. Needed only by clients that "
        "ignore tools/list_changed; rejected outright by the Gemini API "
        "(400 INVALID_ARGUMENT, too many states for serving). "
        "GHIDRA_MCP_LAZY=0 does the same where argv is not yours to set.",
    )
    parser.add_argument(
        "--default-groups",
        type=str,
        default=None,
        help="Comma-separated list of default tool groups to load on connect " "(default: listing,function,program)",
    )
    parser.add_argument(
        "--tools-page-size",
        type=int,
        default=0,
        help="Serve tools/list in pages of this many tools (0 = one page, the "
        "default). Only enable it for a client that cannot take a single large "
        "response: pagination is optional in the MCP spec, and a client that "
        "ignores nextCursor will see only the first page.",
    )
    parser.add_argument(
        "--json-response",
        action="store_true",
        default=False,
        help="streamable-http: answer POSTs with a plain JSON body instead of an "
        "SSE stream, for clients that cannot read text/event-stream. Rules out "
        "server-initiated messages on the response, so tools/list_changed and "
        "progress notifications are not delivered.",
    )
    parser.add_argument(
        "--stateless-http",
        action="store_true",
        default=False,
        help="streamable-http: treat every request as standalone — no session id "
        "and no server-initiated notifications. Needed to run several bridge "
        "workers behind a load balancer.",
    )
    args = parser.parse_args()

    # An explicit --lazy/--no-lazy wins; otherwise GHIDRA_MCP_LAZY decides, and
    # only then the built-in default. Argparse leaves args.lazy as None when
    # neither flag was given, which is what makes the three levels separable —
    # a store_true default of True would make "not passed" and "passed --lazy"
    # indistinguishable and swallow the env var.
    state._lazy_mode = args.lazy if args.lazy is not None else state.lazy_mode_from_env()
    if args.default_groups is not None:
        state._default_groups = {g.strip() for g in args.default_groups.split(",") if g.strip()}

    if not state._lazy_mode:
        logger.info("Loading all tool groups on startup (clients that don't support tools/list_changed need this)")
    else:
        logger.info(
            "Lazy tool loading: only %s on connect. "
            "Call search_tools()/load_tool_group() for the rest, or pass "
            "--no-lazy (or set GHIDRA_MCP_LAZY=0) to advertise every group up front.",
            ",".join(sorted(state._default_groups)),
        )
    if args.tools_page_size < 0:
        parser.error("--tools-page-size must be 0 (no pagination) or a positive count")
    if args.tools_page_size:
        server.enable_tool_pagination(args.tools_page_size)
        logger.info(
            "tools/list paginated at %d per page; a client that ignores "
            "nextCursor will see only the first page",
            args.tools_page_size,
        )
    if not _auto_connect():
        # Ghidra may simply not be up yet. Keep looking in the background so a
        # bridge that wins the startup race still gets its tools, instead of
        # serving only the static ones for the life of the process.
        logger.info("No Ghidra tools registered at startup; retrying in the background")
        _start_auto_connect_retry()

    mcp.settings.log_level = "INFO"
    mcp.settings.host = args.mcp_host
    if args.mcp_port:
        mcp.settings.port = args.mcp_port
    # Both are read when the transport app is constructed, so they have to be
    # installed before _build_http_app() runs.
    mcp.settings.json_response = args.json_response
    mcp.settings.stateless_http = args.stateless_http
    if (args.json_response or args.stateless_http) and args.transport != "streamable-http":
        logger.warning(
            "--json-response/--stateless-http only affect streamable-http; ignored for %s",
            args.transport,
        )
    if args.stateless_http and state._lazy_mode:
        logger.warning(
            "Stateless HTTP cannot deliver tools/list_changed, so a group loaded by "
            "load_tool_group() stays invisible to the client. Pass --no-lazy (or set "
            "GHIDRA_MCP_LAZY=0) when running stateless; lazy loading is the default."
        )

    _host = args.mcp_host
    if (
        args.transport in ("sse", "streamable-http")
        and _host not in {"127.0.0.1", "localhost", "::1"}
        and not os.environ.get(_INBOUND_TOKEN_ENV)
    ):
        # Not fatal: refusing to start would break existing remote setups on
        # upgrade. But DNS-rebinding protection does not cover this — it stops a
        # browser being tricked into making the request, not a client that just
        # connects to the port and starts renaming things.
        logger.warning(
            "Binding %s with NO inbound authentication: anything that can reach "
            "this port can drive every Ghidra tool, writes included. Set %s=<secret> "
            "to require Authorization: Bearer <secret>.",
            _host,
            _INBOUND_TOKEN_ENV,
        )
    _has_extra_hosts = any(
        host.strip() for host in os.environ.get("GHIDRA_MCP_ALLOWED_HOSTS", "").split(",")
    )
    if _host not in _LOOPBACK_HOSTS or _has_extra_hosts:
        # Wildcard bind is the MOST exposed configuration — keep
        # DNS-rebinding protection ON and allow only the machine's actual
        # hostnames/IPs. Previously this branch disabled protection
        # entirely, which is inverted: a malicious page could DNS-rebind
        # to this host and drive every Ghidra tool from the victim's
        # browser.
        #
        # Legitimate remote clients use the real hostname/IP, so they
        # pass the Host-header check. Operators with custom DNS can
        # extend the list via GHIDRA_MCP_ALLOWED_HOSTS (comma-separated),
        # or explicitly opt back into the old unprotected behavior with
        # GHIDRA_MCP_DISABLE_REBIND_PROTECTION=1 (wildcard bind only).
        if _host in {"0.0.0.0", "::"} and os.environ.get("GHIDRA_MCP_DISABLE_REBIND_PROTECTION") == "1":
            logger.warning(
                "DNS-rebinding protection DISABLED for wildcard bind via "
                "GHIDRA_MCP_DISABLE_REBIND_PROTECTION=1 — any page in the "
                "user's browser can drive this server."
            )
            mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
        else:
            security = _transport_security(_host)
            logger.info(
                "Bind %s with DNS-rebinding protection ON; allowed Host "
                "headers: %s. Extend with GHIDRA_MCP_ALLOWED_HOSTS=host1,host2 "
                "if a legitimate client is rejected — it widens the CORS "
                "origin policy and this one together.",
                _host,
                security.allowed_hosts,
            )
            mcp.settings.transport_security = security
    logger.info(f"Starting MCP bridge ({args.transport})")
    try:
        if args.transport in ("sse", "streamable-http"):
            host = args.mcp_host
            port = args.mcp_port if args.mcp_port else mcp.settings.port
            path = "/sse" if args.transport == "sse" else "/mcp"
            logger.info(f"MCP endpoint: http://{host}:{port}{path}")
            app = _build_http_app(args.transport, host)
            uvicorn.run(app, host=host, port=port, log_level=mcp.settings.log_level.lower())
        else:
            mcp.run(transport=args.transport)
    finally:
        state.shutdown_worker_pool(wait=False)

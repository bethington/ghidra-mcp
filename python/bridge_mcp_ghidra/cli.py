"""Command-line entry point for the GhidraMCP bridge."""

import argparse
import os
import re
import socket

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.cors import CORSMiddleware

from . import state
from .config import logger
from .server import mcp
from .static_tools import _auto_connect, _start_auto_connect_retry


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


def _build_http_app(transport: str, bind_host: str):
    """Return the transport's Starlette app wrapped in CORS middleware.

    Browser-based clients (MCP Inspector) send an OPTIONS preflight before
    every POST and can only read the ``mcp-session-id`` response header if
    it is explicitly exposed. The SDK's stock ``mcp.run()`` apps carry no
    CORS middleware at all, so the preflight got a 405 and the session
    header was invisible to scripts — this wrapper is why the bridge runs
    uvicorn itself instead of delegating to ``mcp.run()``.
    """
    app = mcp.sse_app() if transport == "sse" else mcp.streamable_http_app()
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=_cors_origin_regex(bind_host),
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
        expose_headers=["mcp-session-id", "mcp-protocol-version"],
        max_age=3600,
    )
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
        default=False,
        help="Only load default tool groups on connect (not recommended for Claude Code)",
    )
    parser.add_argument(
        "--no-lazy",
        dest="lazy",
        action="store_false",
        help="Load all tool groups on connect (default)",
    )
    parser.add_argument(
        "--default-groups",
        type=str,
        default=None,
        help="Comma-separated list of default tool groups to load on connect " "(default: listing,function,program)",
    )
    args = parser.parse_args()

    state._lazy_mode = args.lazy
    if args.default_groups is not None:
        state._default_groups = {g.strip() for g in args.default_groups.split(",") if g.strip()}

    if not state._lazy_mode:
        logger.info("Loading all tool groups on startup (clients that don't support tools/list_changed need this)")
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

    _host = args.mcp_host
    if _host not in _LOOPBACK_HOSTS:
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

"""Command-line entry point for the GhidraMCP bridge."""

import argparse
import os
import socket

from mcp.server.transport_security import TransportSecuritySettings

from . import state
from .config import logger
from .server import mcp
from .static_tools import _auto_connect


def _wildcard_allowed_hosts() -> list[str]:
    """Build the allowed-Host list for a 0.0.0.0/:: bind.

    Returns the loopback names plus this machine's hostname, FQDN, and
    every local interface IP, each with a ``:*`` port suffix. This lets
    legitimate remote clients (which use the real hostname/IP in the
    Host header) through while DNS-rebinding attacks (which use an
    attacker-controlled hostname) are rejected.
    """
    hosts: set[str] = {"localhost", "127.0.0.1", "::1"}
    try:
        hn = socket.gethostname()
        if hn:
            hosts.add(hn)
            try:
                hosts.add(socket.getfqdn(hn))
            except OSError:
                pass
            try:
                # All addresses the hostname resolves to (covers multi-NIC).
                for info in socket.getaddrinfo(hn, None):
                    addr = info[4][0]
                    if addr:
                        hosts.add(addr)
            except OSError:
                pass
    except OSError:
        pass
    out: list[str] = []
    for h in sorted(hosts):
        out.append(f"{h}:*")
        # RFC 3986: IPv6 literals are bracketed in Host headers
        # (e.g. "[::1]:8089"); add the bracketed form so they match too.
        if ":" in h and not h.startswith("["):
            out.append(f"[{h}]:*")
    return out


def main():
    parser = argparse.ArgumentParser(
        description="GhidraMCP Bridge -- MCP<->HTTP multiplexer"
    )
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host for HTTP transport (streamable-http or sse)",
    )
    parser.add_argument(
        "--mcp-port", type=int, help="Port for HTTP transport (streamable-http or sse)"
    )
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
        help="Comma-separated list of default tool groups to load on connect "
        "(default: listing,function,program)",
    )
    args = parser.parse_args()

    state._lazy_mode = args.lazy
    if args.default_groups is not None:
        state._default_groups = {
            g.strip() for g in args.default_groups.split(",") if g.strip()
        }

    if not state._lazy_mode:
        logger.info(
            "Loading all tool groups on startup (clients that don't support tools/list_changed need this)"
        )
    _auto_connect()

    mcp.settings.log_level = "INFO"
    mcp.settings.host = args.mcp_host
    if args.mcp_port:
        mcp.settings.port = args.mcp_port

    _host = args.mcp_host
    if _host not in {"127.0.0.1", "localhost", "::1"}:
        if _host in {"0.0.0.0", "::"}:
            # Wildcard bind is the MOST exposed configuration — keep
            # DNS-rebinding protection ON and allow only the machine's
            # actual hostnames/IPs. Previously this branch disabled
            # protection entirely, which is inverted: a malicious page
            # could DNS-rebind to this host and drive every Ghidra tool
            # from the victim's browser.
            #
            # Legitimate remote clients use the real hostname/IP, so
            # they pass the Host-header check. Operators with custom
            # DNS can extend the list via GHIDRA_MCP_ALLOWED_HOSTS
            # (comma-separated), or explicitly opt back into the old
            # unprotected behavior with GHIDRA_MCP_DISABLE_REBIND_PROTECTION=1.
            if os.environ.get("GHIDRA_MCP_DISABLE_REBIND_PROTECTION") == "1":
                logger.warning(
                    "DNS-rebinding protection DISABLED for wildcard bind via "
                    "GHIDRA_MCP_DISABLE_REBIND_PROTECTION=1 — any page in the "
                    "user's browser can drive this server."
                )
                mcp.settings.transport_security = TransportSecuritySettings(
                    enable_dns_rebinding_protection=False
                )
            else:
                allowed = _wildcard_allowed_hosts()
                extra = os.environ.get("GHIDRA_MCP_ALLOWED_HOSTS", "")
                for h in (x.strip() for x in extra.split(",") if x.strip()):
                    allowed.append(f"{h}:*")
                logger.info(
                    "Wildcard bind %s with DNS-rebinding protection ON; "
                    "allowed Host headers: %s. Extend with "
                    "GHIDRA_MCP_ALLOWED_HOSTS=host1,host2 if a remote client "
                    "is rejected.",
                    _host, allowed,
                )
                mcp.settings.transport_security = TransportSecuritySettings(
                    enable_dns_rebinding_protection=True,
                    allowed_hosts=allowed,
                    allowed_origins=[f"http://{h}" for h in allowed],
                )
        else:
            mcp.settings.transport_security = TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=[f"{_host}:*", "localhost:*", "127.0.0.1:*"],
                allowed_origins=[f"http://{_host}:*", "http://localhost:*", "http://127.0.0.1:*"],
            )
    logger.info(f"Starting MCP bridge ({args.transport})")
    if args.transport in ("sse", "streamable-http"):
        host = args.mcp_host
        port = args.mcp_port if args.mcp_port else mcp.settings.port
        path = "/sse" if args.transport == "sse" else "/mcp"
        logger.info(f"MCP endpoint: http://{host}:{port}{path}")
    mcp.run(transport=args.transport)

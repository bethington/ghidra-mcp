"""Command-line entry point for the GhidraMCP bridge."""

import argparse

from mcp.server.transport_security import TransportSecuritySettings

from . import state
from .config import logger
from .server import mcp
from .static_tools import _auto_connect


def main():
    parser = argparse.ArgumentParser(
        description="GhidraMCP Bridge — MCP↔HTTP multiplexer"
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
            mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
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

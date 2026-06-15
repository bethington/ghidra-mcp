"""Startup: auto-connect, CLI parsing, and launching the MCP server."""

import argparse
import os

from . import connection, debugger, registry, tools
from .app import mcp
from .config import DEFAULT_TCP_URL, logger
from .discovery import discover_instances
from .validation import validate_server_url

# Importing the tool modules registers their @mcp.tool handlers on the shared
# `mcp` instance. Referenced here so the side-effecting imports are explicit.
_TOOL_MODULES = (tools, debugger)

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
WILDCARD_HOSTS = {"0.0.0.0", "::"}


def _auto_connect():
    """Try to auto-connect to a single running instance on startup."""
    # Try UDS first
    instances = discover_instances()
    if len(instances) == 1:
        project = instances[0].get("project")
        connection.activate_uds(instances[0]["socket"], project)
        logger.info(f"Auto-connecting via UDS to {project or 'unknown'}")
        try:
            count = registry.fetch_and_register_schema()
            logger.info(f"Auto-registered {count} tools from {project or 'unknown'}")
            return
        except Exception as e:
            logger.warning(f"UDS auto-connect schema fetch failed: {e}")
            connection.reset()
    elif len(instances) > 1:
        logger.info(
            f"Multiple UDS instances found ({len(instances)}). "
            "Use connect_instance() to choose."
        )

    # Try TCP fallback
    tcp_url = os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)
    if not validate_server_url(tcp_url):
        logger.warning(f"Refusing to auto-connect to non-local URL: {tcp_url}")
        return
    try:
        connection.activate_tcp(tcp_url)
        count = registry.fetch_and_register_schema()
        logger.info(f"Auto-connected via TCP to {tcp_url}, registered {count} tools")
    except Exception:
        connection.reset()
        if not instances:
            logger.info(
                "No Ghidra instances found. "
                "Tools will be registered on connect_instance()."
            )


def _build_http_middleware(host: str):
    """Re-express the legacy DNS-rebinding protection for non-local HTTP binds.

    - Local hosts (127.0.0.1/localhost/::1): default fastmcp behavior.
    - Wildcard binds (0.0.0.0/::): no host restriction (matches the old
      "disable DNS rebinding protection" branch).
    - Any other explicit host: restrict the Host header to that host + localhost
      via Starlette's TrustedHostMiddleware.
    """
    if host in LOCAL_HOSTS or host in WILDCARD_HOSTS:
        return None
    from starlette.middleware import Middleware
    from starlette.middleware.trustedhost import TrustedHostMiddleware

    allowed = [host, "localhost", "127.0.0.1"]
    return [Middleware(TrustedHostMiddleware, allowed_hosts=allowed)]


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
        choices=["stdio", "http", "streamable-http", "sse"],
        help="MCP transport: stdio (default, recommended for AI tools), "
        "http/streamable-http (recommended for web/HTTP clients), "
        "sse (deprecated, use http instead)",
    )
    args = parser.parse_args()

    _auto_connect()

    logger.info(f"Starting MCP bridge ({args.transport})")
    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return

    host = args.mcp_host
    port = args.mcp_port
    if host not in LOCAL_HOSTS and host not in WILDCARD_HOSTS:
        logger.info(f"Restricting HTTP Host header to {host} + localhost")
    path = "/sse" if args.transport == "sse" else "/mcp"
    logger.info(f"MCP endpoint: http://{host}:{port or 8000}{path}")
    mcp.run(
        transport=args.transport,
        host=host,
        port=port,
        log_level="INFO",
        middleware=_build_http_middleware(host),
    )


if __name__ == "__main__":
    main()

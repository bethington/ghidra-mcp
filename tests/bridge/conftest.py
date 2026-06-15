"""Shared fixtures for the live integration tests.

These tests talk to a real Ghidra instance over the bridge's TCP transport. They
auto-skip when no instance answers on the configured URL so the suite stays green
on machines (and CI) without Ghidra running.
"""

import os

import pytest
import pytest_asyncio

from ghidra_mcp_bridge import connection, registry
from ghidra_mcp_bridge.app import mcp
from ghidra_mcp_bridge.config import DEFAULT_TCP_URL
from ghidra_mcp_bridge.transport import tcp_request


def server_url() -> str:
    """The Ghidra URL under test. Honors GHIDRA_MCP_URL like the real bridge."""
    return os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)


def _server_up(url: str) -> bool:
    """Return True if a Ghidra instance answers /mcp/instance_info at ``url``."""
    try:
        _, status = tcp_request(url, "GET", "/mcp/instance_info", timeout=3)
    except OSError:
        return False
    return status == 200


@pytest.fixture(scope="session")
def live_bridge() -> int:
    """Point the bridge at the live instance and register its schema once.

    Skips the whole test that depends on it when no instance is reachable.
    Yields the number of dynamic tools registered.
    """
    url = server_url()
    if not _server_up(url):
        pytest.skip(f"No Ghidra instance reachable at {url}")
    connection.activate_tcp(url)
    return registry.fetch_and_register_schema()


@pytest_asyncio.fixture
async def mcp_client(live_bridge: int):
    """An in-memory FastMCP client bound to the singleton bridge app.

    Depends on ``live_bridge`` so the dynamic tools are registered before the
    client connects.
    """
    from fastmcp import Client

    async with Client(mcp) as client:
        yield client

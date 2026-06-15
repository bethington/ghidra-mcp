"""Unit-test fixtures for the ghidra_mcp_bridge package.

The bridge keeps its live-connection state in module-level globals
(``connection._active_socket`` / ``_active_tcp`` / ``_transport_mode``). Salvaged
unit tests mutate that state via ``connection.activate_*``; reset it around every
test so the suite stays order-independent.
"""

import pytest

from ghidra_mcp_bridge import connection


@pytest.fixture(autouse=True)
def _reset_connection_state():
    connection.reset()
    yield
    connection.reset()

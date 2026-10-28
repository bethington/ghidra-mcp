"""Fixtures for the offline tier.

Every server here binds an EPHEMERAL loopback port. Nothing in this tier may
bind 8089 or assume it: a contributor running these while their own Ghidra is
up must not have it touched, and two runs must be able to overlap.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The bridge package lives under python/. tests/conftest.py already puts it on
# sys.path, but this tier is also runnable on its own (pytest tests/offline/).
_PYTHON_DIR = Path(__file__).resolve().parents[2] / "python"
if str(_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(_PYTHON_DIR))

from .fake_ghidra import FakeGhidraServer  # noqa: E402


@pytest.fixture(scope="session")
def fake_ghidra():
    """One strict fake for the whole session, reset between tests."""
    server = FakeGhidraServer().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(autouse=True)
def _reset_fake(request):
    """Clear recorded requests and queued faults before each test."""
    if "fake_ghidra" in request.fixturenames:
        request.getfixturevalue("fake_ghidra").reset()
    yield


@pytest.fixture
def strict_fake():
    """A fake with required-parameter enforcement on, for contract tests."""
    server = FakeGhidraServer(strict_required=True).start()
    try:
        yield server
    finally:
        server.stop()

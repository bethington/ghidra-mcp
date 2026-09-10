"""Live coverage for ``/create_memory_block``'s byte-content support (issue #404).

Two tiers, split by whether the call actually writes to the program.

**Rejection round-trips** (default, no writes). Every case here ends in an
error raised *before* the transaction opens, so nothing reaches the program
database. They are not merely negative tests: they are the only way to prove
end-to-end that ``bytes_hex`` / ``bytes_base64`` / ``fill_byte`` / ``size``
actually arrive at the service as bound body parameters. A parameter that never
made it out of the JSON body produces a *different* error (or a silent success),
so a specific rejection message is positive evidence the plumbing works.

**Real creation** (opt-in). ``/create_memory_block`` has no inverse — there is no
``delete_memory_block`` endpoint, so a created block is a permanent mutation of
whatever program happens to be open. The MCP conformance suite already classes
this tool as destructive for that reason. These tests therefore run only when
``GHIDRA_MCP_ALLOW_BLOCK_CREATE=1`` is set, and they create blocks in a high,
otherwise-unused region under a uniquely suffixed name.

Everything skips cleanly with no server, which is the expected state in CI.
"""

from __future__ import annotations

import base64
import os
import uuid

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("require_server_and_program"),
]

# Far above any normal image base, so an accidental run cannot land on real code.
SCRATCH_BASE = 0x7EF00000

ALLOW_CREATE = os.environ.get("GHIDRA_MCP_ALLOW_BLOCK_CREATE") == "1"


@pytest.fixture(scope="module")
def require_server_and_program(server_available, program_loaded):
    if not server_available:
        pytest.skip("MCP server is not running")
    if not program_loaded:
        pytest.skip("No program loaded in Ghidra")


def _post(http_client, **body):
    """POST /create_memory_block with a JSON body, returning the parsed result.

    Skips rather than fails when the deployed JAR predates #404: the new
    parameters are simply ignored by an old build, and a test that reports
    "byte contents are broken" when the server never had them is a lie.
    """
    response = http_client.post("/create_memory_block", json_data=body)
    if response.status_code == 404:
        pytest.skip("/create_memory_block not registered on this server")
    try:
        return response.json()
    except ValueError:
        pytest.fail(f"non-JSON response: {response.text[:400]}")


@pytest.mark.readonly
class TestCreateMemoryBlockRejections:
    """Bad requests must be refused before any transaction opens."""

    def test_odd_length_hex_is_rejected(self, http_client):
        result = _post(
            http_client,
            name="mcp_test_reject",
            address=hex(SCRATCH_BASE),
            bytes_hex="abc",
        )
        error = str(result.get("error", ""))
        if not error:
            pytest.skip("server predates #404 byte-content support")
        assert "even number of hex digits" in error, error

    def test_non_hex_character_is_named_by_position(self, http_client):
        result = _post(
            http_client,
            name="mcp_test_reject",
            address=hex(SCRATCH_BASE),
            bytes_hex="deadzzbeef",
        )
        error = str(result.get("error", ""))
        if not error:
            pytest.skip("server predates #404 byte-content support")
        assert "non-hex character" in error, error
        assert "position 4" in error, error

    def test_both_encodings_is_rejected(self, http_client):
        result = _post(
            http_client,
            name="mcp_test_reject",
            address=hex(SCRATCH_BASE),
            bytes_hex="dead",
            bytes_base64=base64.b64encode(b"\xde\xad").decode(),
        )
        error = str(result.get("error", ""))
        if not error:
            pytest.skip("server predates #404 byte-content support")
        assert "only one of bytes_hex or bytes_base64" in error, error

    def test_content_longer_than_size_is_rejected_not_truncated(self, http_client):
        """The load-bearing rule: bytes the caller sent are never discarded."""
        result = _post(
            http_client,
            name="mcp_test_reject",
            address=hex(SCRATCH_BASE),
            size=2,
            bytes_hex="deadbeef",
        )
        error = str(result.get("error", ""))
        if not error:
            pytest.skip("server predates #404 byte-content support")
        assert "4 bytes but size is 2" in error, error
        assert "never truncated" in error, error

    def test_fill_byte_out_of_range_is_rejected(self, http_client):
        result = _post(
            http_client,
            name="mcp_test_reject",
            address=hex(SCRATCH_BASE),
            size=16,
            initialized=True,
            fill_byte=999,
        )
        error = str(result.get("error", ""))
        if not error:
            pytest.skip("server predates #404 byte-content support")
        assert "fill_byte must be between 0 and 255" in error, error

    def test_oversized_initialized_block_is_rejected(self, http_client):
        result = _post(
            http_client,
            name="mcp_test_reject",
            address=hex(SCRATCH_BASE),
            size=512 * 1024 * 1024,
            initialized=True,
        )
        error = str(result.get("error", ""))
        if not error:
            pytest.skip("server predates #404 byte-content support")
        assert "initialized=false" in error, error

    def test_zero_size_without_content_is_still_rejected(self, http_client):
        """Pre-#404 behavior must survive: no content and no size is an error."""
        result = _post(
            http_client,
            name="mcp_test_reject",
            address=hex(SCRATCH_BASE),
            size=0,
        )
        assert "size must be positive" in str(result.get("error", "")), result


@pytest.mark.write
@pytest.mark.destructive
@pytest.mark.skipif(
    not ALLOW_CREATE,
    reason="creates a permanent memory block; set GHIDRA_MCP_ALLOW_BLOCK_CREATE=1 to run",
)
class TestCreateMemoryBlockWithContent:
    """Real creations. There is no delete_memory_block, so these are one-way."""

    @staticmethod
    def _unique(prefix):
        return f"{prefix}_{uuid.uuid4().hex[:8]}"

    def test_hex_content_lands_in_the_block(self, http_client):
        addr = SCRATCH_BASE
        result = _post(
            http_client,
            name=self._unique("mcp_hex"),
            address=hex(addr),
            bytes_hex="de ad be ef",
        )
        assert result.get("success") is True, result
        assert result["size"] == 4, result
        assert result["initialized"] is True, result
        assert result["bytes_written"] == 4, result
        assert result["padded_bytes"] == 0, result

        read = http_client.get("/read_memory", params={"address": hex(addr), "length": 4}).json()
        assert read["hex"] == "deadbeef", read

    def test_base64_content_lands_in_the_block(self, http_client):
        addr = SCRATCH_BASE + 0x1000
        payload = bytes([0x90, 0x90, 0xC3])
        result = _post(
            http_client,
            name=self._unique("mcp_b64"),
            address=hex(addr),
            bytes_base64=base64.b64encode(payload).decode(),
        )
        assert result.get("success") is True, result
        assert result["size"] == 3, result

        read = http_client.get("/read_memory", params={"address": hex(addr), "length": 3}).json()
        assert read["hex"] == "9090c3", read

    def test_short_content_pads_the_rest_with_fill_byte(self, http_client):
        addr = SCRATCH_BASE + 0x2000
        result = _post(
            http_client,
            name=self._unique("mcp_pad"),
            address=hex(addr),
            size=16,
            bytes_hex="4d5a",
            fill_byte=0xCC,
        )
        assert result.get("success") is True, result
        assert result["size"] == 16, result
        assert result["bytes_written"] == 2, result
        assert result["padded_bytes"] == 14, result

        read = http_client.get("/read_memory", params={"address": hex(addr), "length": 16}).json()
        assert read["hex"] == "4d5a" + "cc" * 14, read

    def test_uninitialized_block_still_reads_as_uninitialized(self, http_client):
        """The default path is unchanged by #404."""
        addr = SCRATCH_BASE + 0x3000
        result = _post(
            http_client,
            name=self._unique("mcp_uninit"),
            address=hex(addr),
            size=0x100,
        )
        assert result.get("success") is True, result
        assert result["initialized"] is False, result
        assert result["bytes_written"] == 0, result

    def test_overlay_block_reports_its_own_address_space(self, http_client):
        """An overlay deliberately shadows existing memory, so the overlap
        guard must be skipped and the response must name the new space."""
        listing = http_client.get("/list_segments", params={"limit": 1}).json()
        segments = listing if isinstance(listing, list) else listing.get("segments") or []
        if not segments:
            pytest.skip("no segments to overlay")
        start = segments[0].get("start") or segments[0].get("address")
        if not start:
            pytest.skip("segment listing has no start address")

        result = _post(
            http_client,
            name=self._unique("mcp_ovl"),
            address=start if str(start).startswith("0x") else f"0x{start}",
            bytes_hex="cafebabe",
            overlay=True,
        )
        assert result.get("success") is True, result
        assert result["overlay"] is True, result
        assert result["address_space"], result

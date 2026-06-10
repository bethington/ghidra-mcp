"""
Integration tests for /add_memory_reference and /remove_reference.

Covers the user-defined cross-reference tools: catalog/parity, input validation,
a real create -> get_xrefs_to -> remove round-trip, and the empty-match no-op.

The catalog tests run without a server. The live tests auto-skip when the
server/program is unavailable or when the endpoint isn't registered (older JAR).

Run with: pytest tests/integration/test_reference_endpoints.py -v
"""

import json
import re

import pytest


pytestmark = [
    pytest.mark.integration,
    pytest.mark.safe_write,
]


# ---------- catalog / parity (no server needed) ----------


def test_add_memory_reference_in_endpoint_catalog(endpoints):
    """Must be in tests/endpoints.json so EndpointsJsonParityTest passes and
    the bridge registers it dynamically."""
    paths = {e["path"] for e in endpoints}
    assert "/add_memory_reference" in paths, "add_memory_reference missing from endpoints.json"


def test_add_memory_reference_categorized_as_xref(endpoints):
    by_path = {e["path"]: e for e in endpoints}
    entry = by_path.get("/add_memory_reference")
    assert entry is not None
    assert entry.get("category") == "xref"


def test_add_memory_reference_is_post(endpoints):
    by_path = {e["path"]: e for e in endpoints}
    entry = by_path.get("/add_memory_reference")
    assert entry is not None
    assert entry.get("method") == "POST"


def test_add_memory_reference_declares_core_params(endpoints):
    by_path = {e["path"]: e for e in endpoints}
    entry = by_path.get("/add_memory_reference")
    assert entry is not None
    params = set(entry.get("params", []))
    for required in ("from_address", "to_address", "ref_type", "source_type",
                     "operand_index", "program"):
        assert required in params, f"{required} missing from catalog params {params}"


def test_remove_reference_in_endpoint_catalog(endpoints):
    paths = {e["path"] for e in endpoints}
    assert "/remove_reference" in paths, "remove_reference missing from endpoints.json"


def test_remove_reference_categorized_as_xref_post(endpoints):
    by_path = {e["path"]: e for e in endpoints}
    entry = by_path.get("/remove_reference")
    assert entry is not None
    assert entry.get("category") == "xref"
    assert entry.get("method") == "POST"


# ---------- live fixtures ----------


@pytest.fixture(scope="module")
def require_server_and_program(server_available, program_loaded):
    if not server_available:
        pytest.skip("MCP server is not running")
    if not program_loaded:
        pytest.skip("No program loaded in Ghidra")


@pytest.fixture
def endpoint_available(http_client, require_server_and_program):
    """Probe registration with an empty body (no mutation: returns the
    'from_address is required' error if registered, 404 if not)."""
    resp = http_client.post("/add_memory_reference", json_data={})
    if resp.status_code == 404:
        pytest.skip("/add_memory_reference not registered (deploy the updated JAR)")
    return True


@pytest.fixture
def two_addresses(http_client, require_server_and_program):
    """Return two distinct, mapped function-entry addresses from the program."""
    resp = http_client.get("/list_functions", params={"limit": 50})
    if resp.status_code != 200:
        pytest.skip("Cannot list functions")
    addrs = re.findall(r"at\s+(?:0x)?([0-9a-fA-F]+)", resp.text)
    # de-dup preserving order
    seen, uniq = set(), []
    for a in addrs:
        key = a.lower().lstrip("0") or "0"
        if key not in seen:
            seen.add(key)
            uniq.append(a)
    if len(uniq) < 2:
        pytest.skip("Need at least two functions to build a reference")
    return {"from": f"0x{uniq[0]}", "to": f"0x{uniq[1]}"}


def _bare(addr_hex: str) -> str:
    """Normalize '0x00401000' -> '401000' for substring matching."""
    return addr_hex.lower().removeprefix("0x").lstrip("0") or "0"


# ---------- validation (no mutation) ----------


def test_unknown_ref_type_rejected(http_client, endpoint_available):
    resp = http_client.post(
        "/add_memory_reference",
        json_data={"from_address": "0x1000", "to_address": "0x2000",
                   "ref_type": "NOT_A_REAL_TYPE"},
    )
    assert resp.status_code == 200, resp.text
    assert "Unknown ref_type" in resp.text


def test_unknown_source_type_rejected(http_client, endpoint_available):
    resp = http_client.post(
        "/add_memory_reference",
        json_data={"from_address": "0x1000", "to_address": "0x2000",
                   "source_type": "BOGUS"},
    )
    assert resp.status_code == 200, resp.text
    assert "Unknown source_type" in resp.text


def test_missing_to_address_rejected(http_client, endpoint_available):
    resp = http_client.post(
        "/add_memory_reference",
        json_data={"from_address": "0x1000"},
    )
    assert resp.status_code == 200, resp.text
    assert "to_address is required" in resp.text


# ---------- real create -> round-trip ----------


def test_create_then_remove_reference_round_trip(http_client, endpoint_available, two_addresses):
    """Full round-trip: create a USER_DEFINED reference, confirm it shows up in
    get_xrefs_to (bidirectional navigation), then remove it and confirm it's gone.
    The remove step also leaves the test binary clean."""
    src, dst = two_addresses["from"], two_addresses["to"]

    # Create
    resp = http_client.post(
        "/add_memory_reference",
        json_data={
            "from_address": src,
            "to_address": dst,
            "ref_type": "DATA",
            "source_type": "USER_DEFINED",
        },
    )
    assert resp.status_code == 200, resp.text
    body = json.loads(resp.text)
    assert body.get("status") == "success", f"unexpected: {body}"
    assert body.get("ref_type") == "DATA"
    assert body.get("source_type") == "USER_DEFINED"

    try:
        xrefs = http_client.get("/get_xrefs_to", params={"address": dst})
        assert xrefs.status_code == 200, xrefs.text
        assert _bare(src) in xrefs.text.lower(), (
            f"created reference from {src} not found in get_xrefs_to({dst}): {xrefs.text[:300]}"
        )
    finally:
        # Remove (also serves as the dedicated remove_reference assertion + cleanup)
        rm = http_client.post(
            "/remove_reference",
            json_data={"from_address": src, "to_address": dst},
        )
        assert rm.status_code == 200, rm.text
        rm_body = json.loads(rm.text)
        assert rm_body.get("status") == "success", f"unexpected: {rm_body}"
        assert rm_body.get("removed", 0) >= 1, f"expected >=1 removed: {rm_body}"

    # Confirm it's gone
    xrefs_after = http_client.get("/get_xrefs_to", params={"address": dst})
    assert _bare(src) not in xrefs_after.text.lower(), (
        f"reference from {src} still present after remove_reference: {xrefs_after.text[:300]}"
    )


def test_remove_nonexistent_reference_is_clean_no_op(http_client, endpoint_available, two_addresses):
    """Removing a reference that isn't there returns removed=0 without erroring
    (the reversed direction is virtually never a real reference)."""
    resp = http_client.post(
        "/remove_reference",
        json_data={
            "from_address": two_addresses["to"],
            "to_address": two_addresses["from"],
        },
    )
    assert resp.status_code == 200, resp.text
    body = json.loads(resp.text)
    assert body.get("status") == "success", f"unexpected: {body}"
    assert body.get("removed", -1) == 0


def test_remove_reference_missing_from_address_rejected(http_client, endpoint_available):
    resp = http_client.post(
        "/remove_reference",
        json_data={"to_address": "0x1000"},
    )
    assert resp.status_code == 200, resp.text
    assert "from_address is required" in resp.text

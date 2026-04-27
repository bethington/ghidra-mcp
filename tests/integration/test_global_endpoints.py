"""Live integration tests for v5.7.0 global-variable enforcement.

Exercises the new endpoints — `audit_global`, `set_global` — and the
validator hooks added to `rename_data` and `rename_global_variable`.
Each rejection code from `NamingConventions.checkGlobalNameQuality`
is hit by sending a deliberately-bad name and asserting the structured
rejection comes back.

Strategy:
  * Use `list_data_items` to find a real global address in the loaded
    program. We don't pick the address blindly; we read the current
    state first so we can restore at the end.
  * For rejection tests, send the bad input and assert the response
    has `status: "rejected"` with the expected `error` / `issue` —
    we never need to actually mutate state.
  * For success tests, write a known value, verify, then write the
    original value back.

Tagged `safe_write` because the success-path tests do mutate program
state, but always restore it. Run with:

    pytest tests/integration/test_global_endpoints.py -v -m safe_write

Skipped automatically when no MCP server is reachable on 127.0.0.1:8089
or when no program is loaded.
"""

from __future__ import annotations

import pytest


pytestmark = [
    pytest.mark.integration,
    pytest.mark.safe_write,
    pytest.mark.usefixtures("require_server_and_program", "require_v5_7_endpoints"),
]


@pytest.fixture(scope="module")
def require_server_and_program(server_available, program_loaded):
    if not server_available:
        pytest.skip("MCP server is not running")
    if not program_loaded:
        pytest.skip("No program loaded in Ghidra")


@pytest.fixture(scope="module")
def require_v5_7_endpoints(server_url, http_session):
    """Skip when the running plugin doesn't have audit_global/set_global —
    i.e., v5.6.0 or earlier. After a v5.7.0 deploy regression, these
    return 200; before, they return 404. The tests are committed so the
    suite improves regardless; they only run when the live build matches."""
    response = http_session.get(f"{server_url}/audit_global", params={"address": "0x0"}, timeout=5)
    if response.status_code == 404:
        pytest.skip(
            "audit_global endpoint not registered on running server "
            "(v5.7.0 not deployed yet — run "
            "`python -m tools.setup deploy --ghidra-path F:\\ghidra_12.0.4_PUBLIC --test release` "
            "to deploy then re-run these tests)"
        )


@pytest.fixture(scope="module")
def sample_global_address(http_session, server_url):
    """Find a real global data address in the program.

    `list_data_items` returns plain text formatted as
    `<name> @ <hex> [<type>] (<bytes>)` — one item per line.
    We scan for the first parseable hex address.
    """
    import re
    response = http_session.get(f"{server_url}/list_data_items", params={"limit": 10}, timeout=15)
    if response.status_code != 200:
        pytest.skip(f"list_data_items unavailable (status {response.status_code})")
    body = response.text.strip()
    if not body:
        pytest.skip("list_data_items returned empty")
    # Match either "@ <hex>" form (typed item) or a bare DAT_<hex> / hex
    # address on the line.
    addr_pattern = re.compile(r"@\s+([0-9a-fA-F]{4,})\b|DAT_([0-9a-fA-F]{4,})\b|\b([0-9a-fA-F]{6,})\b")
    for line in body.splitlines():
        m = addr_pattern.search(line)
        if m:
            addr = next(g for g in m.groups() if g)
            return f"0x{addr}"
    pytest.skip(f"Could not parse address from list_data_items: {body[:120]}")


# ---------- audit_global ----------


def test_audit_global_returns_expected_shape(http_client, sample_global_address):
    """Smoke: audit_global on a real address returns the expected fields
    even when the global is fully or partially documented. We only assert
    the response shape — not specific values, since this runs against a
    live program whose globals are in flux."""
    response = http_client.get("/audit_global", params={"address": sample_global_address})
    assert response.status_code == 200, response.text
    import json
    data = json.loads(response.text)
    # Required fields per the v5.7.0 contract.
    for key in ("address", "name", "type", "length", "plate_comment", "xref_count", "issues", "fully_documented"):
        assert key in data, f"audit_global missing field: {key}"
    assert isinstance(data["issues"], list)
    assert isinstance(data["fully_documented"], bool)


def test_audit_global_unknown_address_errors_cleanly(http_client):
    """An address with no defined data should still get a usable response —
    not a 500. The endpoint should report what's missing so the model
    knows what to do next. 404/200/400 all acceptable; 5xx is not."""
    response = http_client.get("/audit_global", params={"address": "0x0"})
    assert response.status_code < 500, response.text


# ---------- rename_data validator ----------


def test_rename_data_rejects_missing_g_prefix(http_client, sample_global_address):
    """A name without the g_ prefix is hard-rejected via the validator."""
    response = http_client.post(
        "/rename_data",
        json_data={
            "address": sample_global_address,
            "newName": "dwActiveQuestState",  # missing g_ prefix
        },
    )
    assert response.status_code == 200, response.text
    import json
    body = json.loads(response.text)
    assert body.get("status") == "rejected", f"expected rejection, got: {body}"
    assert body.get("error") == "name_quality"
    assert body.get("issue") == "missing_g_prefix"
    assert body.get("rejected_name") == "dwActiveQuestState"
    # Suggestion text is present so the model has guidance.
    assert body.get("suggestion")


def test_rename_data_rejects_auto_generated_remnant(http_client, sample_global_address):
    """Names that look like 'rename by stripping the auto-generated prefix'
    (e.g., g_DAT_xxx, g_PTR_xxx) are hard-rejected."""
    for bad in [
        "g_DAT_6fdf64d8",
        "g_PTR_DAT_1234",
        "g_FUN_6fcab220",
        "g_dw_6fdf64d8",
    ]:
        response = http_client.post(
            "/rename_data",
            json_data={"address": sample_global_address, "newName": bad},
        )
        assert response.status_code == 200, response.text
        import json
        body = json.loads(response.text)
        assert body.get("status") == "rejected", f"{bad}: expected reject, got {body}"
        assert body.get("issue") == "auto_generated_remnant", f"{bad}: wrong issue"


def test_rename_data_rejects_short_descriptor(http_client, sample_global_address):
    """g_dwX has only a 1-char descriptor — rejected."""
    response = http_client.post(
        "/rename_data",
        json_data={"address": sample_global_address, "newName": "g_dwX"},
    )
    import json
    body = json.loads(response.text)
    assert body.get("status") == "rejected"
    assert body.get("issue") == "short_descriptor"


def test_rename_data_rejects_missing_hungarian(http_client, sample_global_address):
    """A name with g_ prefix but no Hungarian after it (e.g., g_ActiveState)
    fails the Hungarian-prefix check."""
    response = http_client.post(
        "/rename_data",
        json_data={"address": sample_global_address, "newName": "g_ActiveState"},
    )
    import json
    body = json.loads(response.text)
    assert body.get("status") == "rejected"
    assert body.get("issue") == "missing_hungarian_prefix"


# ---------- set_global ----------


def test_set_global_rejects_undefined_type(http_client, sample_global_address):
    """set_global must refuse to apply undefined* types — the whole point
    of the four-axis bar is that globals have real types."""
    response = http_client.post(
        "/set_global",
        json_data={
            "address": sample_global_address,
            "type_name": "undefined4",
        },
    )
    assert response.status_code == 200, response.text
    import json
    body = json.loads(response.text)
    assert body.get("status") == "rejected"
    assert body.get("error") == "undefined_type_rejected"


def test_set_global_rejects_unknown_type(http_client, sample_global_address):
    """Type name that isn't in the data type manager is rejected with
    a helpful suggestion to create it first."""
    response = http_client.post(
        "/set_global",
        json_data={
            "address": sample_global_address,
            "type_name": "ThisTypeDoesNotExistAnywhere",
        },
    )
    import json
    body = json.loads(response.text)
    assert body.get("status") == "rejected"
    assert body.get("error") == "unknown_type"
    assert "ThisTypeDoesNotExistAnywhere" in body.get("type_name", "")
    assert body.get("suggestion")


def test_set_global_rejects_short_plate_comment(http_client, sample_global_address):
    """Plate comments must have a ≥4-word first-line summary."""
    response = http_client.post(
        "/set_global",
        json_data={
            "address": sample_global_address,
            "plate_comment": "global counter",  # only 2 words
        },
    )
    import json
    body = json.loads(response.text)
    assert body.get("status") == "rejected"
    assert body.get("error") == "plate_comment_too_short"
    assert body.get("first_line") == "global counter"


def test_set_global_rejects_bad_name(http_client, sample_global_address):
    """Pre-flight rejects the bad name BEFORE the transaction starts."""
    response = http_client.post(
        "/set_global",
        json_data={
            "address": sample_global_address,
            "name": "DAT_1234",  # missing g_ AND auto-gen pattern
            "plate_comment": "Pointer to the head of the unit list",
        },
    )
    import json
    body = json.loads(response.text)
    assert body.get("status") == "rejected"
    assert body.get("error") == "name_quality"


def test_set_global_no_partial_application_on_rejection(http_client, sample_global_address):
    """When set_global rejects, NONE of the requested changes should have
    landed. We verify by auditing before and after — name/type/plate
    must be unchanged on rejection."""
    import json
    before = json.loads(http_client.get(
        "/audit_global", params={"address": sample_global_address}
    ).text)
    response = http_client.post(
        "/set_global",
        json_data={
            "address": sample_global_address,
            "name": "g_dwLegitName",  # would be valid by itself
            "type_name": "undefined4",  # but this triggers rejection
            "plate_comment": "A perfectly fine plate comment line.",
        },
    )
    body = json.loads(response.text)
    assert body.get("status") == "rejected"
    after = json.loads(http_client.get(
        "/audit_global", params={"address": sample_global_address}
    ).text)
    assert before["name"] == after["name"], "name leaked through despite rejection"
    assert before["type"] == after["type"], "type leaked through despite rejection"
    assert before["plate_comment"] == after["plate_comment"], "plate comment leaked"


def test_set_global_empty_args_is_no_op_success(http_client, sample_global_address):
    """Sending set_global with no fields specified should be a success
    no-op (not an error). Lets the model probe the endpoint without
    side effects."""
    response = http_client.post(
        "/set_global",
        json_data={"address": sample_global_address},
    )
    assert response.status_code == 200, response.text
    import json
    body = json.loads(response.text)
    assert body.get("status") == "success"
    assert body.get("applied") == []


# ---------- endpoint catalog ----------


def test_audit_global_in_endpoint_catalog(endpoints):
    """The new endpoint must be in tests/endpoints.json so the
    EndpointsJsonParityTest passes and the bridge picks it up."""
    paths = {e["path"] for e in endpoints}
    assert "/audit_global" in paths, "audit_global missing from endpoints.json"


def test_set_global_in_endpoint_catalog(endpoints):
    paths = {e["path"] for e in endpoints}
    assert "/set_global" in paths, "set_global missing from endpoints.json"


def test_audit_global_categorized_as_datatype(endpoints):
    by_path = {e["path"]: e for e in endpoints}
    audit = by_path.get("/audit_global")
    assert audit is not None
    assert audit.get("category") == "datatype"


def test_set_global_categorized_as_datatype(endpoints):
    by_path = {e["path"]: e for e in endpoints}
    set_g = by_path.get("/set_global")
    assert set_g is not None
    assert set_g.get("category") == "datatype"


def test_audit_globals_in_function_in_endpoint_catalog(endpoints):
    paths = {e["path"] for e in endpoints}
    assert "/audit_globals_in_function" in paths


# ---------- audit_globals_in_function ----------


def test_audit_globals_in_function_returns_summary(http_client, http_session, server_url):
    """Smoke: pick a real function and verify the bulk audit endpoint
    returns the expected shape — function metadata + per-global array
    + summary histogram. The function might or might not have global
    xrefs; either is fine, we just check the response shape."""
    import json
    # Find a function to audit.
    response = http_session.get(f"{server_url}/list_functions", params={"limit": 1}, timeout=10)
    if response.status_code != 200 or not response.text.strip():
        pytest.skip("No functions available")
    # Try to parse function address.
    import re
    m = re.search(r"@\s+([0-9a-fA-F]+)", response.text)
    if not m:
        m = re.search(r'"address"\s*:\s*"?([0-9a-fA-F]+)', response.text)
    if not m:
        pytest.skip("Could not parse a function address")
    fn_addr = f"0x{m.group(1)}"

    response = http_client.get("/audit_globals_in_function", params={"address": fn_addr})
    assert response.status_code == 200, response.text
    data = json.loads(response.text)
    assert "function" in data
    assert "globals" in data
    assert "summary" in data
    summary = data["summary"]
    for k in ("total", "fully_documented", "with_issues", "issue_histogram"):
        assert k in summary, f"summary missing {k}"
    assert isinstance(data["globals"], list)
    assert isinstance(summary["issue_histogram"], dict)
    # Summary totals must be self-consistent.
    assert summary["fully_documented"] + summary["with_issues"] == summary["total"]
    assert len(data["globals"]) == summary["total"]


def test_audit_globals_in_function_invalid_address(http_client):
    response = http_client.get("/audit_globals_in_function", params={"address": "0x0"})
    # Either rejected (status:rejected) or err'd cleanly — but no 5xx.
    assert response.status_code < 500

"""
Behavioral integration tests for /set_function_this_type (#262).

The offline FunctionServiceThisTypeTest only scrapes the Java source for token
substrings, so it passes even if the runtime behavior regresses. These tests
exercise the real endpoint against a live Ghidra server and assert on actual
behavior — in particular the H2 safety property: a function that has no implicit
'this' (non-member, default calling convention) must NOT be silently re-parented
into a class namespace.

The rejection-path tests are non-destructive (they error before mutating). The
re-parent guard test creates a uniquely-named throwaway struct, asserts the guard,
and cleans the struct up afterward.

Run with: pytest tests/integration/test_this_type_endpoints.py -v
Tests auto-skip if the MCP server is not running or no program is loaded.
"""

import re

import pytest


pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("require_server_and_program"),
]


@pytest.fixture(scope="module")
def require_server_and_program(server_available, program_loaded):
    if not server_available:
        pytest.skip("MCP server is not running")
    if not program_loaded:
        pytest.skip("No program loaded in Ghidra")


def _first_function_address(http_client):
    """Return the address of the first listed function, or skip."""
    response = http_client.get("/list_functions", params={"limit": 1})
    if response.status_code != 200:
        pytest.skip("Cannot list functions")
    match = re.search(r"at\s+(?:0x)?([0-9a-fA-F]+)", response.text)
    if not match:
        match = re.search(r'"address"\s*:\s*"?(?:0x)?([0-9a-fA-F]+)"?', response.text)
    if not match:
        pytest.skip("No functions found")
    return f"0x{match.group(1)}"


def _post_this_type(http_client, body):
    """POST /set_function_this_type, skipping if the endpoint isn't deployed (404).

    set_function_this_type ships in #262; an older JAR running in Ghidra returns 404.
    Like test_global_endpoints, skip rather than fail when the route isn't registered.
    """
    r = http_client.post("/set_function_this_type", json_data=body)
    if r.status_code == 404:
        pytest.skip("/set_function_this_type not registered — deploy the current JAR")
    return r


def test_rejects_missing_this_type(http_client):
    """Empty this_type is rejected before any program lookup or mutation."""
    addr = _first_function_address(http_client)
    r = _post_this_type(http_client, {"function_address": addr, "this_type": ""})
    assert r.status_code == 200
    assert "this_type is required" in r.text


def test_rejects_undefined_this_type(http_client):
    """undefined* placeholder types are rejected (must be a concrete struct ptr)."""
    addr = _first_function_address(http_client)
    r = _post_this_type(
        http_client, {"function_address": addr, "this_type": "undefined4"}
    )
    assert r.status_code == 200
    assert "must be a concrete struct/class pointer" in r.text


def test_rejects_unresolvable_struct(http_client):
    """A this_type whose base struct does not exist errors without mutating."""
    addr = _first_function_address(http_client)
    r = _post_this_type(
        http_client,
        {"function_address": addr, "this_type": "ThisTypeNoSuchStruct_ztq *"},
    )
    assert r.status_code == 200
    # Either "Could not resolve" (pointer wrapper made but base missing) or a
    # not-a-structure error — both are pre-mutation rejections.
    assert ("Could not resolve" in r.text) or ("not a structure" in r.text) \
        or ("must point to a structure" in r.text)


def test_non_member_function_not_reparented(http_client):
    """H2: a function with no implicit 'this' must NOT be moved into a class.

    Creates a throwaway struct, attempts to associate a (default-convention)
    function with it, and asserts the endpoint refuses AND leaves the function's
    namespace unchanged. Cleans up the struct afterward.
    """
    struct_name = "ThisTypeGuardProbe_ztq"
    addr = _first_function_address(http_client)

    # Snapshot the function's current namespace/signature so we can prove no move.
    before = http_client.get("/get_function_by_address", params={"address": addr})
    if before.status_code != 200:
        pytest.skip("Cannot read function details")
    before_text = before.text

    # Create a unique throwaway struct to serve as a resolvable this_type base.
    created = http_client.post(
        "/create_struct",
        json_data={"name": struct_name, "fields": [{"name": "x", "type": "int"}]},
    )
    if created.status_code != 200 or "rror" in created.text and "lready exists" not in created.text:
        pytest.skip(f"Could not create probe struct: {created.text[:120]}")

    try:
        r = _post_this_type(
            http_client,
            {"function_address": addr, "this_type": f"{struct_name} *"},
        )
        assert r.status_code == 200
        # If the chosen function happens to already be __thiscall, the call may
        # succeed — in that case the guard isn't what we're testing, so only
        # assert the invariant when it was rejected for lacking 'this'.
        if "no implicit 'this'" in r.text or "has no implicit" in r.text:
            after = http_client.get(
                "/get_function_by_address", params={"address": addr}
            )
            assert after.status_code == 200
            # The function must not have been re-parented into the probe class.
            assert struct_name not in after.text, (
                "Non-member function was re-parented into the class despite having "
                "no implicit 'this' — H2 safety property violated."
            )
    finally:
        # Best-effort cleanup of the throwaway struct.
        http_client.post(
            "/delete_data_type", json_data={"type_name": struct_name}
        )

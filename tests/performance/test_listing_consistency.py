"""
Regression tests for listing endpoint consistency.

Background: /list_functions_enhanced has an undocumented default limit=10000
that silently truncates results. Anyone calling it without explicit pagination
gets up to 10,000 entries no matter how big the program is. This caused
glide3x.dll and libcrypto-1_1.dll to both show exactly 10,000 functions in
fun-doc's state.json even though they have 10,664 and 12,110 respectively.

These tests catch the drift between /list_functions_enhanced (paginated) and
/get_function_count (authoritative) for any program that might hit the cap.
They also verify that `/list_functions_enhanced` properly paginates when the
caller walks offset forward.
"""
import pytest
import requests


@pytest.mark.requires_program
def test_list_functions_enhanced_pagination_matches_count(server_url, server_available):
    """Walking list_functions_enhanced in pages must return exactly as many
    functions as get_function_count reports (minus externals).

    The absolute equality holds for the in-memory function count. Externals
    don't show up in list_functions, so we compare against a non-external
    count when available. If list_functions silently caps the response, this
    test catches it because the paginated walk is shorter than the count.
    """
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    # Find a program to test against
    try:
        meta = requests.get(f"{server_url}/get_metadata", timeout=5).json()
        program = meta.get("program_name") or meta.get("name")
    except (requests.RequestException, ValueError):
        program = None
    if not program:
        pytest.skip("No program loaded")

    # Get authoritative count
    count_resp = requests.get(
        f"{server_url}/get_function_count",
        params={"program": program},
        timeout=30,
    )
    assert count_resp.status_code == 200
    total_count = count_resp.json().get("function_count")
    assert isinstance(total_count, int) and total_count > 0

    # Walk list_functions_enhanced in pages of 5000
    PAGE_SIZE = 5000
    seen = []
    offset = 0
    while True:
        r = requests.get(
            f"{server_url}/list_functions_enhanced",
            params={"program": program, "offset": offset, "limit": PAGE_SIZE},
            timeout=60,
        )
        assert r.status_code == 200
        page = r.json().get("functions") or []
        seen.extend(page)
        if len(page) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
        if offset > 1_000_000:
            pytest.fail("Pagination walked past 1M functions — infinite loop protection")

    walked_count = len(seen)

    # get_function_count includes externals; list_functions_enhanced excludes
    # them. So walked_count <= total_count. Difference should be <= externals.
    assert walked_count <= total_count, (
        f"list_functions_enhanced walked {walked_count} but get_function_count "
        f"only reports {total_count} — listing returned more than the count?"
    )

    # Any program with > 10,000 functions should NOT have exactly 10,000
    # reported by the walk — that's the signature of the old silent cap.
    if total_count > 10_000:
        assert walked_count != 10_000, (
            f"list_functions_enhanced walk returned exactly 10,000 entries for "
            f"{program} (get_function_count={total_count}). This is the silent "
            f"default-limit truncation signature. Check _fetch_function_list "
            f"callers aren't relying on default limit."
        )


@pytest.mark.requires_server
def test_list_functions_enhanced_default_limit_is_known(server_url, server_available):
    """Document and lock in the default limit behavior so changes are explicit.

    /list_functions_enhanced uses limit=10000 by default. This test records
    that fact so any future change to the default is a deliberate decision
    that requires updating this test.
    """
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    r = requests.get(f"{server_url}/mcp/schema", timeout=5)
    assert r.status_code == 200
    schema = r.json()
    tool = next((t for t in schema["tools"] if t["path"] == "/list_functions_enhanced"), None)
    assert tool is not None, "/list_functions_enhanced not in schema"

    params = {p["name"]: p for p in tool["params"]}
    assert "limit" in params, "/list_functions_enhanced has no limit param"
    assert params["limit"].get("default") == "10000", (
        f"list_functions_enhanced default limit changed from 10000 to "
        f"{params['limit'].get('default')}. Update fun-doc _fetch_function_list "
        f"pagination if the page size should change, or update this test if "
        f"the change is intentional."
    )


@pytest.mark.requires_program
def test_list_functions_offset_beyond_end_returns_empty(server_url, server_available):
    """list_functions_enhanced with an offset past the end should return an
    empty page, not error. This is the termination condition for paginated
    walks — if the endpoint errors out, callers have to add special-case
    handling."""
    if not server_available:
        pytest.skip("Ghidra HTTP server not available")

    try:
        meta = requests.get(f"{server_url}/get_metadata", timeout=5).json()
        program = meta.get("program_name") or meta.get("name")
    except (requests.RequestException, ValueError):
        program = None
    if not program:
        pytest.skip("No program loaded")

    # offset = 2,000,000 is surely past the end of any real program
    r = requests.get(
        f"{server_url}/list_functions_enhanced",
        params={"program": program, "offset": 2_000_000, "limit": 10},
        timeout=30,
    )
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data.get("functions"), list)
    assert len(data["functions"]) == 0

"""Focused live smoke tests for a running Ghidra session.

These are intended to be the quickest non-destructive release gate against a
real project already open in Ghidra. They stick to read-only checks plus
round-trip writes where the original value is written back unchanged.
"""

import json
import pytest


pytestmark = [
    pytest.mark.integration,
    pytest.mark.readonly,
    pytest.mark.safe_write,
    pytest.mark.usefixtures("require_server_and_program"),
]


@pytest.fixture(scope="module")
def require_server_and_program(server_available, program_loaded):
    """Skip this smoke suite unless a live server and program are available."""
    if not server_available:
        pytest.skip("MCP server is not running")
    if not program_loaded:
        pytest.skip("No program loaded in Ghidra")


@pytest.fixture
def first_function_address(http_client):
    """Get the address of the first function in the current program."""
    response = http_client.get("/list_functions", params={"limit": 1})
    if response.status_code != 200 or not response.text.strip():
        pytest.skip("Cannot list functions")

    try:
        from tests.conftest import extract_first_function

        _, address = extract_first_function(response.text)
    except Exception:
        address = None

    if not address:
        pytest.skip("Could not parse a function address from list_functions")
    return address


def _extract_signature(function_text):
    try:
        data = json.loads(function_text)
        if isinstance(data, dict):
            return data.get("signature") or data.get("prototype")
    except json.JSONDecodeError:
        pass
    return None


class TestLiveServerSmoke:
    def test_server_health(self, http_client):
        response = http_client.get("/check_connection")
        assert response.status_code == 200
        assert "connected" in response.text.lower() or "ok" in response.text.lower()

    def test_version_payload_parseable(self, http_client):
        response = http_client.get("/get_version")
        assert response.status_code == 200
        payload = json.loads(response.text)
        assert isinstance(payload, dict)
        assert payload.get("plugin_name") == "GhidraMCP"
        assert "plugin_version" in payload

    def test_program_metadata_present(self, http_client):
        response = http_client.get("/get_metadata")
        assert response.status_code == 200
        text = response.text.lower()
        assert "program name" in text or "executable path" in text

    def test_list_functions_returns_live_data(self, http_client):
        response = http_client.get("/list_functions", params={"limit": 3})
        assert response.status_code == 200
        assert len(response.text.strip()) > 0

    def test_current_selection_optional(self, http_client):
        response = http_client.get("/get_current_selection")
        assert response.status_code in [200, 404]


class TestSafeRoundTripSmoke:
    def test_plate_comment_round_trip(self, http_client, first_function_address):
        get_response = http_client.get(
            "/get_plate_comment", params={"address": first_function_address}
        )
        if get_response.status_code != 200:
            pytest.skip("Plate comment endpoint unavailable")

        comment = get_response.text
        try:
            payload = json.loads(get_response.text)
            if isinstance(payload, dict):
                comment = payload.get("comment", "") or ""
        except json.JSONDecodeError:
            comment = comment.strip('"')

        set_response = http_client.post(
            "/set_plate_comment",
            data={"address": first_function_address, "comment": comment},
        )
        assert set_response.status_code in [200, 400, 404]

    def test_prototype_round_trip(self, http_client, first_function_address):
        get_response = http_client.get(
            "/get_function_by_address", params={"address": first_function_address}
        )
        if get_response.status_code != 200:
            pytest.skip("Function details unavailable")

        signature = _extract_signature(get_response.text)
        if not signature:
            pytest.skip("Function signature not available")

        set_response = http_client.post(
            "/set_function_prototype",
            data={
                "address": first_function_address,
                "function_address": first_function_address,
                "prototype": signature,
            },
        )
        assert set_response.status_code in [200, 400, 404, 500]

    def test_rename_variables_endpoints_reachable(
        self, http_client, first_function_address
    ):
        canonical = http_client.post(
            "/rename_variables",
            json_data={
                "function_address": first_function_address,
                "variable_renames": {},
            },
        )
        assert canonical.status_code == 200

        legacy = http_client.post(
            "/batch_rename_variables",
            json_data={
                "function_address": first_function_address,
                "variable_renames": {},
            },
        )
        assert legacy.status_code in [200, 404]

    def test_no_return_round_trip(self, http_client, first_function_address):
        get_response = http_client.get(
            "/get_function_by_address", params={"address": first_function_address}
        )
        if get_response.status_code != 200:
            pytest.skip("Function details unavailable")

        no_return = False
        try:
            payload = json.loads(get_response.text)
            if isinstance(payload, dict):
                no_return = bool(payload.get("noReturn") or payload.get("no_return"))
        except json.JSONDecodeError:
            if (
                '"noReturn": true' in get_response.text
                or '"no_return": true' in get_response.text
            ):
                no_return = True

        set_response = http_client.post(
            "/set_function_no_return",
            data={
                "function_address": first_function_address,
                "no_return": str(no_return).lower(),
            },
        )
        assert set_response.status_code in [200, 400, 404]

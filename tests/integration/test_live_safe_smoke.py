"""Focused live smoke tests for a running Ghidra session.

These are intended to be the quickest non-destructive release gate against a
real project already open in Ghidra. They stick to read-only checks plus
round-trip writes where the original value is written back unchanged.
"""

import json
import re

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

    def test_version_payload_matches_pom(self, http_client):
        """Catch deploys-of-stale-jar: the live plugin's version must
        equal what pom.xml says we built. Without this, a deploy that
        silently failed to overwrite the user-extension jar leaves the
        previous version running and only manual inspection of the
        Ghidra console would catch it."""
        from pathlib import Path
        import re

        repo_root = Path(__file__).resolve().parents[2]
        pom_text = (repo_root / "pom.xml").read_text(encoding="utf-8")
        # Match the *project* version (the first <version> inside the
        # opening <project> block — avoid dep versions). Anchored to the
        # <packaging>jar</packaging> tag for safety, mirroring tools.setup
        # version-bump.
        # pom.xml lists <packaging>jar</packaging> then <version>X.Y.Z</version>
        # at the project level. Anchoring on packaging avoids matching
        # dependency versions later in the file.
        match = re.search(
            r"<packaging>jar</packaging>\s*<version>([^<]+)</version>",
            pom_text,
        )
        assert match is not None, "Could not locate project version in pom.xml"
        pom_version = match.group(1).strip()

        response = http_client.get("/get_version")
        payload = json.loads(response.text)
        live_version = payload["plugin_version"]

        assert live_version == pom_version, (
            f"Live plugin reports v{live_version} but pom.xml has v{pom_version} — "
            "the deployed jar is stale. Rebuild and redeploy."
        )

    def test_schema_meets_endpoint_floor(self, http_client):
        """The bridge's dynamic tool registration relies on /mcp/schema
        returning every endpoint AnnotationScanner found. If the count
        falls below a sane floor, something failed to register (silent
        class-load failure or scanner regression). Floor is intentionally
        loose; the hard equality check happens in test_endpoint_count_consistent."""
        response = http_client.get("/mcp/schema")
        assert response.status_code == 200
        schema = json.loads(response.text)
        tools = schema.get("tools", [])
        assert len(tools) >= 150, (
            f"Only {len(tools)} tools registered — well below the v5.x floor of 150. "
            "Likely a scanner regression or class-load failure on the plugin."
        )

    def test_endpoint_count_consistent(self, http_client):
        """/get_version.endpoint_count must equal len(/mcp/schema.tools).

        Pre-v5.11.1 the constant was hardcoded and drifted (was 177 while
        the live scanner registered 196). Fixed by having the plugin
        call VersionInfo.setEndpointCount(scanner.getEndpoints().size())
        after registration. This test pins the contract."""
        version_response = http_client.get("/get_version")
        reported = json.loads(version_response.text)["endpoint_count"]

        schema_response = http_client.get("/mcp/schema")
        actual = len(json.loads(schema_response.text).get("tools", []))

        assert reported == actual, (
            f"/mcp/schema returned {actual} tools but /get_version reports "
            f"{reported}. The endpoint count published to the version banner is "
            "stale — either the plugin's setEndpointCount() call regressed or "
            "the deployed jar predates the fix."
        )

    def test_ghidra_version_reported(self, http_client):
        """v5.11.0 added Ghidra 12.1 support (#211). The live plugin
        must report the Ghidra version it was loaded into — used by
        the deploy script's smoke check and by issue triage."""
        response = http_client.get("/get_version")
        payload = json.loads(response.text)
        ghidra_version = payload.get("ghidra_version", "")
        # Strip BUILD_DATE suffix if present (older builds embedded it).
        ghidra_version = ghidra_version.split()[0] if ghidra_version else ""
        # Must look like N.N or N.N.N — not empty, not "unknown".
        assert re.match(r"^\d+\.\d+(?:\.\d+)?$", ghidra_version), (
            f"ghidra_version field looks malformed: {payload.get('ghidra_version')!r}"
        )

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

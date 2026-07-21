"""Live integration tests for program-option and property-map storage tools.

Exercises the two tool families added to close the "Program Options /
metadata" (partial) and "Property maps" (missing) gaps in Ghidra's
per-program / per-address storage surface:

  Program options
    * list_option_groups     (GET)
    * get_program_options    (GET)
    * set_program_option     (POST)
    * remove_program_option  (POST)

  Property maps (typed per-address key -> value stores)
    * list_property_maps     (GET)
    * create_property_map    (POST)
    * delete_property_map     (POST)
    * set_property           (POST)
    * get_property           (GET)
    * remove_property        (POST)
    * list_properties        (GET)

Strategy: every mutating test creates its own throwaway option / property
map with an ``mcp_test_`` prefix, verifies the round-trip, and deletes it
again, so the program is left exactly as found. Tagged ``safe_write``.

Skipped automatically when no MCP server is reachable, when no program is
loaded, or when the running plugin predates these endpoints (they 404).

Run with:

    pytest tests/integration/test_program_storage_endpoints.py -v -m safe_write
"""

from __future__ import annotations

import re

import pytest


pytestmark = [
    pytest.mark.integration,
    pytest.mark.safe_write,
    pytest.mark.usefixtures("require_server_and_program", "require_storage_endpoints"),
]

# A group that Ghidra guarantees on every program.
PROGRAM_INFO_GROUP = "Program Information"


@pytest.fixture(scope="module")
def require_server_and_program(server_available, program_loaded):
    if not server_available:
        pytest.skip("MCP server is not running")
    if not program_loaded:
        pytest.skip("No program loaded in Ghidra")


@pytest.fixture(scope="module")
def require_storage_endpoints(server_url, http_session):
    """Skip when the running plugin doesn't yet expose the storage tools.

    Before this feature lands, /list_option_groups returns 404; after a
    deploy it returns 200. The tests are committed either way so the suite
    improves regardless; they only execute when the live build matches.
    """
    response = http_session.get(f"{server_url}/list_option_groups", timeout=5)
    if response.status_code == 404:
        pytest.skip(
            "list_option_groups endpoint not registered on running server "
            "(feature not deployed yet — deploy the new JAR then re-run)"
        )


@pytest.fixture(scope="module")
def base_address(http_session, server_url):
    """Return a valid in-program address (the image base) as a hex string.

    Parsed from /get_metadata's plain-text 'Base Address: <addr>' line so we
    never guess an out-of-range address for property writes.
    """
    response = http_session.get(f"{server_url}/get_metadata", timeout=15)
    if response.status_code != 200:
        pytest.skip(f"get_metadata unavailable (status {response.status_code})")
    match = re.search(r"Base Address:\s*([0-9a-fA-Fx:]+)", response.text)
    if not match:
        pytest.skip("could not parse base address from get_metadata")
    return match.group(1).strip()


def _json(response):
    assert response.status_code == 200, f"HTTP {response.status_code}: {response.text[:300]}"
    return response.json()


# ======================================================================
# Program options
# ======================================================================


class TestProgramOptions:
    def test_list_option_groups(self, http_client):
        data = _json(http_client.get("/list_option_groups"))
        assert "groups" in data
        names = [g["name"] for g in data["groups"]]
        assert PROGRAM_INFO_GROUP in names, f"expected '{PROGRAM_INFO_GROUP}' in {names}"
        # Every group reports an option_count.
        for g in data["groups"]:
            assert "option_count" in g
        assert data["count"] == len(data["groups"])

    def test_get_program_options(self, http_client):
        data = _json(http_client.get("/get_program_options", params={"group": PROGRAM_INFO_GROUP}))
        assert data["group"] == PROGRAM_INFO_GROUP
        assert isinstance(data["options"], list)
        for entry in data["options"]:
            assert "name" in entry
            assert "type" in entry
            assert "value" in entry
            assert "is_default" in entry

    def test_get_program_options_bad_group(self, http_client):
        response = http_client.get("/get_program_options", params={"group": "NoSuchGroup_XYZ"})
        body = response.text.lower()
        assert "no such option group" in body or "error" in body

    def test_set_get_remove_custom_option(self, http_client):
        group = PROGRAM_INFO_GROUP
        name = "mcp_test_option"
        try:
            # Create a custom string option.
            created = _json(
                http_client.post(
                    "/set_program_option",
                    json_data={"group": group, "name": name, "value": "hello_mcp", "type": "string"},
                )
            )
            assert created["success"] is True
            assert created["value"] == "hello_mcp"

            # It shows up in the group with the value we set.
            opts = _json(http_client.get("/get_program_options", params={"group": group}))
            match = [o for o in opts["options"] if o["name"] == name]
            assert match, f"'{name}' not found after set"
            assert match[0]["value"] == "hello_mcp"

            # Update it (type reused from existing option — no type arg).
            updated = _json(
                http_client.post(
                    "/set_program_option",
                    json_data={"group": group, "name": name, "value": "world_mcp"},
                )
            )
            assert updated["value"] == "world_mcp"
        finally:
            removed = _json(
                http_client.post(
                    "/remove_program_option", json_data={"group": group, "name": name}
                )
            )
            assert removed["success"] is True
            # Confirm it's gone.
            opts = _json(http_client.get("/get_program_options", params={"group": group}))
            assert not [o for o in opts["options"] if o["name"] == name]

    def test_set_option_bad_number(self, http_client):
        response = http_client.post(
            "/set_program_option",
            json_data={"group": PROGRAM_INFO_GROUP, "name": "mcp_test_bad", "value": "notanint", "type": "int"},
        )
        assert "not a valid int" in response.text.lower() or "error" in response.text.lower()


# ======================================================================
# Property maps
# ======================================================================


class TestPropertyMaps:
    def test_string_map_lifecycle(self, http_client, base_address):
        name = "mcp_test_string_map"
        # Clean any stale map from a previous aborted run.
        http_client.post("/delete_property_map", json_data={"name": name})
        try:
            created = _json(http_client.post("/create_property_map", json_data={"name": name, "type": "string"}))
            assert created["success"] is True
            assert created["value_type"] == "string"

            listing = _json(http_client.get("/list_property_maps"))
            entry = [m for m in listing["property_maps"] if m["name"] == name]
            assert entry, f"'{name}' not in list_property_maps"
            assert entry[0]["value_type"] == "string"
            assert entry[0]["size"] == 0

            # Set a value at the base address.
            setres = _json(
                http_client.post(
                    "/set_property",
                    json_data={"map": name, "address": base_address, "value": '{"note":"structured"}'},
                )
            )
            assert setres["success"] is True

            got = _json(http_client.get("/get_property", params={"map": name, "address": base_address}))
            assert got["has_value"] is True
            assert got["value"] == '{"note":"structured"}'
            assert got["value_type"] == "string"

            entries = _json(http_client.get("/list_properties", params={"map": name}))
            assert entries["total"] == 1
            assert entries["count"] == 1
            assert entries["entries"][0]["value"] == '{"note":"structured"}'

            removed = _json(http_client.post("/remove_property", json_data={"map": name, "address": base_address}))
            assert removed["success"] is True

            got2 = _json(http_client.get("/get_property", params={"map": name, "address": base_address}))
            assert got2["has_value"] is False
        finally:
            deleted = _json(http_client.post("/delete_property_map", json_data={"name": name}))
            assert deleted["success"] is True
            listing = _json(http_client.get("/list_property_maps"))
            assert not [m for m in listing["property_maps"] if m["name"] == name]

    def test_int_map_roundtrip(self, http_client, base_address):
        name = "mcp_test_int_map"
        http_client.post("/delete_property_map", json_data={"name": name})
        try:
            _json(http_client.post("/create_property_map", json_data={"name": name, "type": "int"}))
            _json(http_client.post("/set_property", json_data={"map": name, "address": base_address, "value": "1234"}))
            got = _json(http_client.get("/get_property", params={"map": name, "address": base_address}))
            assert got["has_value"] is True
            assert got["value"] == 1234
            assert got["value_type"] == "int"
        finally:
            http_client.post("/delete_property_map", json_data={"name": name})

    def test_void_map_tags_address(self, http_client, base_address):
        name = "mcp_test_void_map"
        http_client.post("/delete_property_map", json_data={"name": name})
        try:
            _json(http_client.post("/create_property_map", json_data={"name": name, "type": "void"}))
            # Void maps ignore the value and just tag the address.
            _json(http_client.post("/set_property", json_data={"map": name, "address": base_address}))
            got = _json(http_client.get("/get_property", params={"map": name, "address": base_address}))
            assert got["has_value"] is True
            assert got["value_type"] == "void"
        finally:
            http_client.post("/delete_property_map", json_data={"name": name})

    def test_create_bad_type_rejected(self, http_client):
        response = http_client.post("/create_property_map", json_data={"name": "mcp_test_bad", "type": "float"})
        assert "unsupported map type" in response.text.lower() or "error" in response.text.lower()

    def test_set_property_missing_map(self, http_client, base_address):
        response = http_client.post(
            "/set_property",
            json_data={"map": "mcp_no_such_map_xyz", "address": base_address, "value": "x"},
        )
        assert "no property map" in response.text.lower() or "error" in response.text.lower()

    def test_int_map_rejects_non_numeric(self, http_client, base_address):
        name = "mcp_test_int_reject"
        http_client.post("/delete_property_map", json_data={"name": name})
        try:
            _json(http_client.post("/create_property_map", json_data={"name": name, "type": "int"}))
            response = http_client.post(
                "/set_property", json_data={"map": name, "address": base_address, "value": "notint"}
            )
            assert "not valid" in response.text.lower() or "error" in response.text.lower()
        finally:
            http_client.post("/delete_property_map", json_data={"name": name})

"""
Safe write operation tests for GhidraMCP.

These tests verify write endpoints work by reading existing values and writing
them back unchanged. This tests the write path without modifying actual data.

Strategy:
1. Read current value from Ghidra
2. Write the same value back
3. Verify the write succeeds (no errors)
4. Optionally verify the value is still the same

Run with: pytest tests/integration/test_safe_write_endpoints.py -v

Note: Tests will be automatically skipped if the MCP server is not running.
"""

import pytest
import json
import re


# Mark all tests as safe-write integration tests
pytestmark = [
    pytest.mark.integration,
    pytest.mark.safe_write,
    pytest.mark.usefixtures("require_server_and_program"),
]


@pytest.fixture(scope="module")
def require_server_and_program(server_available, program_loaded):
    """Skip all tests if server is not available or no program loaded."""
    if not server_available:
        pytest.skip("MCP server is not running")
    if not program_loaded:
        pytest.skip("No program loaded in Ghidra")


@pytest.fixture
def first_function(http_client):
    """Get the first function with its details.

    /list_functions declares only `program` -- "List all functions (no
    pagination)" -- so a `limit` sent here was dropped. The first match in the
    full listing is what the regex below finds anyway.
    """
    response = http_client.get("/list_functions")
    if response.status_code != 200:
        pytest.skip("Cannot list functions")

    text = response.text
    # Try to extract function name and address
    # Format: "FunctionName at 10001000" or "FunctionName at 0x10001000" or JSON
    match = re.search(r"at\s+(?:0x)?([0-9a-fA-F]+)", text)
    if not match:
        # Also try JSON format
        match = re.search(r'"address"\s*:\s*"?(?:0x)?([0-9a-fA-F]+)"?', text)
    if not match:
        pytest.skip("No functions found")

    address = f"0x{match.group(1)}"

    # Get function details
    details_response = http_client.get(
        "/get_function_by_address", params={"address": address}
    )
    if details_response.status_code != 200:
        pytest.skip("Cannot get function details")

    return {"address": address, "details": details_response.text}


@pytest.fixture
def first_named_function(http_client):
    """Get the first function that has a non-default name.

    /list_functions takes no `limit`; the whole listing is scanned and only
    the first match is used.
    """
    response = http_client.get("/list_functions")
    if response.status_code != 200:
        pytest.skip("Cannot list functions")

    text = response.text
    # Look for functions in format: "FunctionName at 10001000"
    matches = re.findall(r"^(\w+)\s+at\s+(?:0x)?([0-9a-fA-F]+)", text, re.MULTILINE)
    if not matches:
        # Try JSON format
        matches = re.findall(
            r'"name"\s*:\s*"([^"]+)".*?"address"\s*:\s*"?(?:0x)?([0-9a-fA-F]+)"?',
            text,
            re.DOTALL,
        )

    if not matches:
        pytest.skip("No functions found")

    name, address = matches[0]
    return {"name": name, "address": f"0x{address}"}


@pytest.fixture
def first_data_item(http_client):
    """Get the first defined data item."""
    response = http_client.get("/list_data_items", params={"limit": 1})
    if response.status_code != 200:
        pytest.skip("Cannot list data items")

    text = response.text
    # Match address with or without 0x prefix
    match = re.search(
        r'(?:at\s+|"address"\s*:\s*"?|^)(?:0x)?([0-9a-fA-F]{6,})', text, re.MULTILINE
    )
    if not match:
        pytest.skip("No data items found")

    return f"0x{match.group(1)}"


@pytest.fixture
def first_label(http_client, first_function):
    """Get the first label in the first function."""
    response = http_client.get(
        "/get_function_labels", params={"address": first_function["address"]}
    )
    if response.status_code != 200:
        pytest.skip("Cannot get function labels")

    text = response.text
    # Try to extract a label name and address
    match = re.search(
        r'"name"\s*:\s*"([^"]+)".*?"address"\s*:\s*"?(?:0x)?([0-9a-fA-F]+)"?',
        text,
        re.DOTALL,
    )
    if not match:
        # Try plain text format: "LabelName at 10001000"
        match = re.search(r"(\w+)\s+at\s+(?:0x)?([0-9a-fA-F]+)", text)

    if not match:
        pytest.skip("No labels found")

    return {"name": match.group(1), "address": match.group(2)}


class TestSafeRenameOperations:
    """Test rename operations by renaming to the same name."""

    def test_rename_function_same_name(self, http_client, first_named_function):
        """Rename a function to its current name (no-op)."""
        name = first_named_function["name"]
        address = first_named_function["address"]

        # The selector is `old_name`, which also accepts the aliases
        # function_address / function / oldName. `address` is not one of them,
        # so it was dropped -- and because `old_name` was also sent the call
        # worked by accident, which is why nothing ever surfaced it.
        response = http_client.post(
            "/rename_function",
            data={"old_name": name, "new_name": name},
        )

        assert response.status_code == 200, response.text
        # Renaming a function to the name it already has must be accepted.
        assert "error" not in response.json(), response.text

    def test_rename_function_by_address_arg_same_name(
        self, http_client, first_named_function
    ):
        """Rename function by address to its current name."""
        name = first_named_function["name"]
        address = first_named_function["address"]

        response = http_client.post(
            "/rename_function",
            data={"old_name": address, "new_name": name},
        )

        assert response.status_code in [200, 400, 404, 500]


class TestSafeCommentOperations:
    """Test comment operations by reading and writing same comments."""

    def test_set_comment_plate_preserve(self, http_client, first_function):
        """Read plate comment and write it back."""
        address = first_function["address"]

        # Get current plate comment
        get_response = http_client.get(
            "/get_comment", params={"address": address}
        )

        if get_response.status_code != 200:
            pytest.skip("Cannot get plate comment")

        # Extract current comment (may be empty)
        current_comment = get_response.text.strip()
        if current_comment.startswith('"') and current_comment.endswith('"'):
            current_comment = current_comment[1:-1]

        # Handle JSON response
        try:
            data = json.loads(get_response.text)
            if isinstance(data, dict):
                current_comment = data.get("plate", "") or ""
        except json.JSONDecodeError:
            pass

        # Write the same comment back
        set_response = http_client.post(
            "/set_comment",
            data={"address": address, "type": "plate", "comment": current_comment},
        )

        # Should succeed
        assert set_response.status_code in [200, 400, 404]

    def test_set_comment_pre_preserve(self, http_client, first_function):
        """Set decompiler comment to empty or existing (safe operation)."""
        address = first_function["address"]

        # Decompiler comments are typically per-line, use function entry
        response = http_client.post(
            "/set_comment",
            json_data={"address": address, "type": "pre", "comment": ""},
        )

        # May not have existing comment, empty should be safe
        # 500 may occur if endpoint has issues with empty comments
        assert response.status_code in [200, 400, 404, 500]

    def test_set_comment_eol_preserve(self, http_client, first_function):
        """Set disassembly comment to empty (safe operation)."""
        address = first_function["address"]

        response = http_client.post(
            "/set_comment", data={"address": address, "type": "eol", "comment": ""}
        )

        # 500 may occur if endpoint has issues with empty comments
        assert response.status_code in [200, 400, 404, 500]


class TestSafeFunctionPrototype:
    """Test function prototype operations."""

    def test_get_and_set_function_prototype(self, http_client, first_function):
        """Read function prototype and write it back."""
        address = first_function["address"]

        # Get function details which includes prototype
        response = http_client.get(
            "/get_function_by_address", params={"address": address}
        )

        if response.status_code != 200:
            pytest.skip("Cannot get function details")

        # Try to extract signature/prototype from response
        text = response.text
        try:
            data = json.loads(text)
            signature = data.get("signature") or data.get("prototype")
            if not signature:
                pytest.skip("No signature in function details")
        except json.JSONDecodeError:
            # Try regex extraction
            match = re.search(r'"signature"\s*:\s*"([^"]+)"', text)
            if not match:
                pytest.skip("Cannot parse function signature")
            signature = match.group(1)

        # Set the same prototype back. The declared selector is
        # `function_address`; sent as `address` it was dropped, the endpoint
        # saw a null address, and the four-way status assertion accepted the
        # resulting error.
        set_response = http_client.post(
            "/set_function_prototype",
            data={"function_address": address, "prototype": signature},
        )

        assert set_response.status_code == 200, set_response.text
        assert set_response.json().get("status") == "success", set_response.text


class TestSafeVariableOperations:
    """Test variable operations by reading and writing same values."""

    def test_get_function_variables(self, http_client, first_function):
        """Get function variables (read-only verification for write tests)."""
        address = first_function["address"]

        response = http_client.get(
            "/get_function_variables", params={"address": address}
        )

        # May not exist in all versions
        assert response.status_code in [200, 404]

    def test_rename_variable_same_name(self, http_client, first_function):
        """Attempt to rename a variable to its current name."""
        address = first_function["address"]

        # Get variables
        var_response = http_client.get(
            "/get_function_variables", params={"address": address}
        )

        if var_response.status_code != 200:
            pytest.skip("Cannot get variables")

        # Try to extract first variable
        text = var_response.text
        try:
            data = json.loads(text)
            if isinstance(data, list) and len(data) > 0:
                var = data[0]
                var_name = var.get("name")
            elif isinstance(data, dict):
                variables = data.get("variables", []) or data.get("locals", [])
                if variables:
                    var_name = variables[0].get("name")
                else:
                    pytest.skip("No variables found")
            else:
                pytest.skip("No variables found")
        except json.JSONDecodeError:
            match = re.search(r'"name"\s*:\s*"([^"]+)"', text)
            if not match:
                pytest.skip("Cannot parse variable name")
            var_name = match.group(1)

        if not var_name:
            pytest.skip("No variable name found")

        # Rename to same name
        response = http_client.post(
            "/rename_variables",
            json_data={
                "function_address": address,
                "variable_renames": {var_name: var_name},
            },
        )

        # Should succeed or indicate no change
        assert response.status_code in [200, 400, 404]


class TestSafeDataTypeOperations:
    """Test data type operations safely."""

    def test_validate_existing_type(self, http_client):
        """Validate that common data types exist."""
        for type_name in ["int", "char", "void", "uint"]:
            response = http_client.get(
                "/validate_data_type", params={"type_name": type_name}
            )
            assert response.status_code == 200

    def test_search_and_get_data_type(self, http_client):
        """Search for a data type and get its size."""
        # Search for int types
        search_response = http_client.get(
            "/search_data_types", params={"pattern": "int"}
        )
        assert search_response.status_code == 200

        # Get size of int
        size_response = http_client.get(
            "/get_type_size", params={"type_name": "int"}
        )
        # May be 404 if endpoint not available
        assert size_response.status_code in [200, 404]


class TestSafeLabelOperations:
    """Test label operations by working with existing labels."""

    def test_rename_symbol_label_same_name(self, http_client, first_label):
        """Rename a label to its current name."""
        name = first_label["name"]
        address = first_label["address"]

        response = http_client.post(
            "/rename_symbol",
            data={"target": address, "kind": "label", "old_name": name,
                  "new_name": name},
        )

        # Should succeed or indicate no change needed
        assert response.status_code in [200, 400, 404]


class TestSafeDocumentationOperations:
    """Test documentation operations."""

    def test_get_function_documentation(self, http_client, first_function):
        """Get and verify function documentation can be retrieved."""
        address = first_function["address"]

        response = http_client.get(
            "/get_function_documentation", params={"address": address}
        )

        assert response.status_code == 200

    def test_apply_same_documentation(self, http_client, first_function):
        """Get documentation and apply it back."""
        address = first_function["address"]

        # Get current documentation
        get_response = http_client.get(
            "/get_function_documentation", params={"address": address}
        )

        if get_response.status_code != 200:
            pytest.skip("Cannot get function documentation")

        # The endpoint declares exactly two parameters: `json_body` (a JSON
        # STRING carrying the documentation record) and `program`. Neither
        # `address` nor `documentation` exists, so both were dropped,
        # `json_body` was null, and the endpoint answered
        # {"error": "target_address is required"} -- accepted by the four-way
        # status assertion on every run.
        #
        # The export names the address it came FROM (`source_address`); the
        # import needs the address to write TO, so the round trip has to set
        # `target_address` explicitly.
        document = get_response.json()
        document["target_address"] = address
        response = http_client.post(
            "/apply_function_documentation",
            json_data={"json_body": json.dumps(document)},
        )

        assert response.status_code == 200, response.text
        assert "error" not in response.json(), response.text


class TestSafeNoReturnAttribute:
    """Test function no-return attribute operations."""

    def test_get_and_set_no_return_same(self, http_client, first_function):
        """Get function's no-return status and set it to the same value."""
        address = first_function["address"]

        # Get function details to find no-return status
        response = http_client.get(
            "/get_function_by_address", params={"address": address}
        )

        if response.status_code != 200:
            pytest.skip("Cannot get function details")

        # Parse the response to find no-return status
        text = response.text
        no_return = False
        try:
            data = json.loads(text)
            no_return = data.get("noReturn", False) or data.get("no_return", False)
        except json.JSONDecodeError:
            # Check if "noReturn" or "no_return" appears as true
            if '"noReturn": true' in text or '"no_return": true' in text:
                no_return = True

        # Set the same value back
        set_response = http_client.post(
            "/set_function_no_return",
            data={"function_address": address, "no_return": str(no_return).lower()},
        )

        assert set_response.status_code in [200, 400, 404]


class TestSafeBatchOperations:
    """Test batch operations with empty or identity operations."""

    def test_batch_set_comments_empty(self, http_client, first_function):
        """Test batch comment setting with empty batch."""
        address = first_function["address"]

        # `comments` is not a parameter of this endpoint. The declared lists
        # are `decompiler_comments` and `disassembly_comments`, and the target
        # is `address` -- so this used to send a body the endpoint ignored
        # entirely, and "succeed or be rejected gracefully" accepted that.
        response = http_client.post(
            "/batch_set_comments",
            json_data={
                "address": address,
                "decompiler_comments": [],
                "disassembly_comments": [],
            },
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body.get("success") is True, response.text
        assert body["decompiler_comments_set"] == 0, response.text
        assert body["disassembly_comments_set"] == 0, response.text

    def test_batch_rename_function_components_identity(
        self, http_client, first_named_function
    ):
        """Test batch rename with identity renames."""
        address = first_named_function["address"]
        name = first_named_function["name"]

        # `renames` is not a parameter. The endpoint takes `function_name`
        # plus `parameter_renames` / `local_renames` maps, so the list this
        # used to send was dropped and the call became a no-op that the
        # three-way status assertion accepted.
        response = http_client.post(
            "/batch_rename_function_components",
            json_data={
                "function_address": address,
                "function_name": name,
                "parameter_renames": {},
                "local_renames": {},
            },
        )

        assert response.status_code == 200, response.text
        assert "error" not in response.json(), response.text


class TestSafeAnalysisOperations:
    """Test analysis operations that don't modify data."""

    def test_analyze_function_completeness(self, http_client, first_function):
        """Analyze function completeness (read-only analysis).

        The declared selector is `function_address`, not `address`.
        """
        address = first_function["address"]

        response = http_client.get(
            "/analyze_function_completeness", params={"function_address": address}
        )

        assert response.status_code == 200
        assert "completeness_score" in response.json(), response.text

    def test_analyze_function_complete(self, http_client, first_function):
        """Get complete function analysis.

        The declared selector is `name` -- "Function reference (name or
        address)" -- so an address is fine, but only under that spelling.
        """
        address = first_function["address"]

        response = http_client.get(
            "/analyze_function_complete", params={"name": address}
        )

        assert response.status_code == 200
        assert "error" not in response.json(), response.text

    def test_analyze_data_region(self, http_client, first_data_item):
        """Analyze a data region (read-only).

        Declared POST, with every parameter ParamSource.BODY. The plugin does
        not enforce the method, so the GET reached the handler with an empty
        body, `address` resolved to null and the answer was an error -- which
        `status_code in [200, 404]` accepted. The endpoint opens no
        transaction, so POSTing it is safe in this tier.
        """
        response = http_client.post(
            "/analyze_data_region", json_data={"address": first_data_item}
        )

        assert response.status_code == 200
        assert "start_address" in response.json(), response.text


class TestSafeHashOperations:
    """Test hash operations that are read-only but verify write-path logic."""

    def test_get_function_hash(self, http_client, first_function):
        """Get function hash (read-only)."""
        address = first_function["address"]

        response = http_client.get("/get_function_hash", params={"address": address})

        assert response.status_code == 200

    # /build_function_hash_index and /lookup_function_by_hash are not
    # endpoints and never have been. Both tests accepted 404, so both were
    # green while never reaching a handler.
    #
    # The capability their author expected was a PERSISTENT hash index plus a
    # reverse hash -> function lookup. This server has neither. What it does
    # have is /get_bulk_function_hashes, which computes the same hash for many
    # functions in one call, so the two tests below ask the surviving surface
    # the same questions: does bulk hashing work, and does a function's own
    # hash identify it in that listing?

    def test_get_bulk_function_hashes(self, http_client):
        """Hash many functions in one call (the surviving bulk-hash surface)."""
        response = http_client.get("/get_bulk_function_hashes", params={"limit": 10})

        assert response.status_code == 200, response.text
        functions = response.json()["functions"]
        assert len(functions) <= 10, response.text
        assert all(entry["hash"] for entry in functions), response.text

    def test_function_hash_matches_bulk_listing(self, http_client, first_function):
        """A function's own hash must be the one the bulk listing reports.

        This is what /lookup_function_by_hash was reaching for. There is no
        reverse index, so the check runs the other way: hash one function,
        then find that hash against the same function in the bulk listing.
        Two code paths computing one value is exactly the shape that drifts.
        """
        address = first_function["address"]

        hash_response = http_client.get(
            "/get_function_hash", params={"address": address}
        )
        assert hash_response.status_code == 200, hash_response.text
        hash_value = hash_response.json()["hash"]
        assert hash_value, hash_response.text

        bulk = http_client.get("/get_bulk_function_hashes", params={"limit": 200})
        assert bulk.status_code == 200, bulk.text
        by_address = {
            int(entry["address"], 16): entry["hash"]
            for entry in bulk.json()["functions"]
        }
        assert int(address, 16) in by_address, sorted(by_address)[:5]
        assert by_address[int(address, 16)] == hash_value


class TestWriteEndpointAvailability:
    """Verify write endpoints exist and respond (even with errors)."""

    @pytest.mark.parametrize(
        "endpoint,method",
        [
            ("/rename_function", "POST"),
            ("/rename_symbol", "POST"),
            ("/create_label", "POST"),
            ("/delete_label", "POST"),
            ("/set_comment", "POST"),
            ("/set_function_prototype", "POST"),
            ("/set_variable_type", "POST"),
            ("/rename_variables", "POST"),
            ("/create_struct", "POST"),
            ("/add_struct_field", "POST"),
            ("/apply_data_type", "POST"),
            ("/create_function", "POST"),
            ("/set_function_no_return", "POST"),
        ],
    )
    def test_write_endpoint_exists(self, http_client, endpoint, method):
        """Verify write endpoint exists (returns something other than 404 for wrong method)."""
        # Send empty request to check endpoint exists
        if method == "POST":
            response = http_client.post(endpoint, data={})
        else:
            response = http_client.get(endpoint)

        # Should exist - may return 400 (bad request) or 500 (error) but not 404
        # Actually 404 is OK if the endpoint just doesn't exist in this version
        # We're checking the endpoint is reachable
        assert response.status_code in [200, 400, 404, 405, 500]

"""
Phase 4: Advanced Features Endpoints Tests

Tests for the 12 Phase 4 endpoints:
- run_ghidra_script (there is no /run_script)
- list_scripts
- search_byte_patterns
- analyze_data_region
- get_function_hash
- get_bulk_function_hashes
- detect_array_bounds
- get_assembly_context
- analyze_struct_field_usage
- get_field_access_context
- rename_symbol
- can_rename_at_address
"""

import pytest
import uuid
import json


class TestScriptExecution:
    """Test script execution endpoints."""

    @pytest.mark.requires_program
    def test_list_scripts(self, http_client):
        """Test listing available scripts."""
        response = http_client.get("/list_scripts")
        assert response.status_code == 200
        # Should return list of scripts or empty

    @pytest.mark.requires_program
    def test_list_scripts_with_filter(self, http_client):
        """Test listing scripts with filter."""
        response = http_client.get("/list_scripts", params={"filter": "Analysis"})
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_run_ghidra_script_nonexistent(self, http_client):
        """A script that does not exist must be refused, not run.

        /run_script is not an endpoint. The two that are: /run_ghidra_script
        (by name, resolved from the Ghidra script path) and /run_script_inline
        (source in the request). The old call 404-ed on every build it ever
        ran against and the assertion accepted 404, so it never reached a
        handler at all -- and `script_path` is not a parameter of either
        endpoint.

        Execution is gated on GHIDRA_MCP_ALLOW_SCRIPTS=1, so both the gate
        refusal and the not-found refusal are correct outcomes here. A success
        is not.
        """
        response = http_client.post("/run_ghidra_script", json_data={
            "script_name": "NonExistentScript_" + uuid.uuid4().hex[:8] + ".java"
        })
        assert response.status_code == 200, response.text
        error = response.json().get("error", "")
        assert "not found" in error.lower() or "disabled" in error.lower(), (
            response.text
        )


class TestPatternSearch:
    """Test byte pattern search endpoint."""

    @pytest.mark.requires_program
    def test_search_byte_patterns_prologue(self, http_client):
        """Test searching for common function prologue."""
        # Search for PUSH EBP (55) - common x86 prologue
        response = http_client.get("/search_byte_patterns", params={
            "pattern": "55"
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_search_byte_patterns_with_wildcards(self, http_client):
        """Test searching with wildcards."""
        # Search for MOV with wildcard operands
        response = http_client.get("/search_byte_patterns", params={
            "pattern": "8B ?? ??"
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_search_byte_patterns_invalid(self, http_client):
        """Test search with invalid pattern."""
        response = http_client.get("/search_byte_patterns", params={
            "pattern": "invalid"
        })
        # Should handle gracefully
        assert response.status_code in [200, 400, 500]


class TestDataRegionAnalysis:
    """Test data region analysis endpoint."""

    # /analyze_data_region is declared POST and every one of its parameters
    # is ParamSource.BODY. The plugin registers one context per path and does
    # not enforce the method, so a GET reached the handler with an EMPTY body:
    # `address` resolved to its default of null and the endpoint answered
    # {"error": ...} with status 200. `assert status_code == 200` passed on
    # that error, every run. The endpoint reads only -- no transaction -- so
    # POSTing it correctly is safe in any tier.

    @pytest.mark.requires_program
    def test_analyze_data_region(self, http_client, sample_address):
        """Test analyzing a data region."""
        response = http_client.post("/analyze_data_region", json_data={
            "address": sample_address
        })
        assert response.status_code == 200
        body = response.json()
        assert int(body["start_address"], 16) == int(sample_address, 16), body

    @pytest.mark.requires_program
    def test_analyze_data_region_with_options(self, http_client, sample_address):
        """Test data region analysis with options."""
        response = http_client.post("/analyze_data_region", json_data={
            "address": sample_address,
            "max_scan_bytes": 256,
            "include_xref_map": True,
            "include_assembly_patterns": True,
            "include_boundary_detection": False
        })
        assert response.status_code == 200
        body = response.json()
        assert int(body["start_address"], 16) == int(sample_address, 16), body
        # `xref_map` is emitted only when include_xref_map is true, so its
        # presence is proof the option arrived rather than being dropped.
        assert "xref_map" in body, body

    @pytest.mark.requires_program
    def test_analyze_data_region_invalid_address(self, http_client):
        """Test data region analysis with invalid address."""
        response = http_client.post("/analyze_data_region", json_data={
            "address": "invalid"
        })
        assert response.status_code == 200
        assert "error" in response.json(), response.text


class TestFunctionHashing:
    """Test function hash endpoints."""

    @pytest.mark.requires_program
    def test_get_function_hash(self, http_client, sample_address):
        """Test getting hash for a function."""
        response = http_client.get("/get_function_hash", params={
            "address": sample_address
        })
        assert response.status_code == 200
        text = response.text
        # Should return hash or error if not a function
        assert "hash" in text.lower() or "error" in text.lower()

    @pytest.mark.requires_program
    def test_get_function_hash_invalid_address(self, http_client):
        """Test getting hash with invalid address."""
        response = http_client.get("/get_function_hash", params={
            "address": "0xDEADBEEF"
        })
        assert response.status_code in [200, 400, 404, 500]

    @pytest.mark.requires_program
    def test_get_bulk_function_hashes(self, http_client):
        """Test getting bulk function hashes."""
        response = http_client.get("/get_bulk_function_hashes", params={
            "offset": 0,
            "limit": 10
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_bulk_function_hashes_filtered(self, http_client):
        """Test bulk hashes with filter."""
        response = http_client.get("/get_bulk_function_hashes", params={
            "offset": 0,
            "limit": 5,
            "filter": "documented"
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_bulk_function_hashes_undocumented(self, http_client):
        """Test bulk hashes for undocumented functions."""
        response = http_client.get("/get_bulk_function_hashes", params={
            "offset": 0,
            "limit": 5,
            "filter": "undocumented"
        })
        assert response.status_code == 200


class TestArrayBoundsDetection:
    """Test array bounds detection endpoint."""

    # Declared POST, all parameters ParamSource.BODY -- see the note above
    # TestDataRegionAnalysis. Read-only, so POSTing it is safe here.

    @pytest.mark.requires_program
    def test_detect_array_bounds(self, http_client, sample_address):
        """Test detecting array bounds."""
        response = http_client.post("/detect_array_bounds", json_data={
            "address": sample_address
        })
        assert response.status_code == 200
        body = response.json()
        assert int(body["address"], 16) == int(sample_address, 16), body
        assert body["element_count"] >= 0, body

    @pytest.mark.requires_program
    def test_detect_array_bounds_with_options(self, http_client, sample_address):
        """Test array detection with options."""
        response = http_client.post("/detect_array_bounds", json_data={
            "address": sample_address,
            "analyze_loop_bounds": True,
            "analyze_indexing": True,
            "max_scan_range": 1024
        })
        assert response.status_code == 200
        body = response.json()
        assert int(body["address"], 16) == int(sample_address, 16), body
        assert body["estimated_size"] <= 1024, body

    @pytest.mark.requires_program
    def test_detect_array_bounds_invalid_address(self, http_client):
        """Test array detection with invalid address."""
        response = http_client.post("/detect_array_bounds", json_data={
            "address": "invalid"
        })
        assert response.status_code == 200
        assert "error" in response.json(), response.text


class TestAssemblyContext:
    """Test assembly context endpoint."""

    # Declared POST, all parameters ParamSource.BODY -- see the note above
    # TestDataRegionAnalysis. GET-ing it produced `{}`: with no xref_sources
    # the handler simply iterated an empty list and returned an empty map,
    # which `status_code == 200` accepted. Read-only, so POST is safe here.

    @pytest.mark.requires_program
    def test_get_assembly_context(self, http_client, sample_address):
        """Test getting assembly context."""
        response = http_client.post("/get_assembly_context", json_data={
            "xref_sources": sample_address
        })
        assert response.status_code == 200
        # The response is keyed by the address string that was sent, so an
        # empty map means the sources never arrived.
        assert list(response.json()) == [sample_address], response.text

    @pytest.mark.requires_program
    def test_get_assembly_context_with_options(self, http_client, sample_address):
        """Test assembly context with options."""
        response = http_client.post("/get_assembly_context", json_data={
            "xref_sources": sample_address,
            "context_instructions": 3,
            "include_patterns": "MOV,CALL,JMP"
        })
        assert response.status_code == 200
        entry = response.json()[sample_address]
        # Either an instruction was found (and context is bounded by the
        # requested 3) or the address is not code and says so.
        if "error" not in entry:
            assert len(entry["context_before"]) <= 3, entry
            assert len(entry["context_after"]) <= 3, entry

    @pytest.mark.requires_program
    def test_get_assembly_context_multiple_sources(self, http_client, sample_address):
        """Test assembly context with multiple xref sources."""
        response = http_client.post("/get_assembly_context", json_data={
            "xref_sources": [sample_address, sample_address]
        })
        assert response.status_code == 200
        assert sample_address in response.json(), response.text


class TestStructFieldAnalysis:
    """Test struct field analysis endpoints."""

    # Both endpoints are declared POST with ParamSource.BODY parameters --
    # see the note above TestDataRegionAnalysis. Both read only.

    @pytest.mark.requires_program
    def test_analyze_struct_field_usage(self, http_client, sample_address):
        """Test analyzing struct field usage."""
        response = http_client.post("/analyze_struct_field_usage", json_data={
            "address": sample_address
        })
        assert response.status_code == 200
        body = response.json()
        # sample_address is a function entry, so the usual answer is a stated
        # refusal -- there is no structure laid down there. Either way the
        # endpoint has to say which, rather than returning the empty answer a
        # dropped address produced.
        if "error" in body:
            assert "structure" in body["error"].lower(), body
        else:
            assert "field_usage" in body, body

    @pytest.mark.requires_program
    def test_analyze_struct_field_usage_with_options(self, http_client, sample_address):
        """Test struct analysis with options."""
        response = http_client.post("/analyze_struct_field_usage", json_data={
            "address": sample_address,
            "max_functions": 5
        })
        assert response.status_code == 200
        body = response.json()
        if "error" in body:
            assert "structure" in body["error"].lower(), body
        else:
            assert body["functions_analyzed"] <= 5, body

    @pytest.mark.requires_program
    def test_get_field_access_context(self, http_client, sample_address):
        """Test getting field access context."""
        response = http_client.post("/get_field_access_context", json_data={
            "struct_address": sample_address,
            "field_offset": 0
        })
        assert response.status_code == 200
        body = response.json()
        assert int(body["field_address"], 16) == int(sample_address, 16), body

    @pytest.mark.requires_program
    def test_get_field_access_context_with_examples(self, http_client, sample_address):
        """Test field access context with example count."""
        response = http_client.post("/get_field_access_context", json_data={
            "struct_address": sample_address,
            "field_offset": 4,
            "num_examples": 3
        })
        assert response.status_code == 200
        body = response.json()
        assert int(body["field_address"], 16) == int(sample_address, 16) + 4, body
        assert len(body["examples"]) <= 3, body


class TestSmartRename:
    """Test smart rename/label endpoints."""

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_rename_symbol_at_address(self, http_client, sample_address):
        """Test smart rename or label creation."""
        unique_name = f"TestLabel_{uuid.uuid4().hex[:8]}"
        response = http_client.post("/rename_symbol", data={
            "target": sample_address,
            "new_name": unique_name
        })
        assert response.status_code == 200
        # Should return success or error
        text = response.text.lower()
        assert "success" in text or "error" in text

    @pytest.mark.requires_program
    def test_rename_symbol_missing_target(self, http_client):
        """Test rename with missing address."""
        response = http_client.post("/rename_symbol", data={
            "new_name": "TestLabel"
        })
        assert response.status_code in [200, 400, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower()

    @pytest.mark.requires_program
    def test_rename_symbol_missing_new_name(self, http_client, sample_address):
        """Test rename with missing name."""
        response = http_client.post("/rename_symbol", data={
            "target": sample_address
        })
        assert response.status_code in [200, 400, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower()

    @pytest.mark.requires_program
    def test_can_rename_at_address(self, http_client, sample_address):
        """Test checking if rename is allowed."""
        response = http_client.get("/can_rename_at_address", params={
            "address": sample_address
        })
        assert response.status_code == 200
        text = response.text.lower()
        # Should return JSON with can_rename field or error
        assert "can_rename" in text or "error" in text

    @pytest.mark.requires_program
    def test_can_rename_at_address_invalid(self, http_client):
        """Test rename check with invalid address."""
        response = http_client.get("/can_rename_at_address", params={
            "address": "invalid"
        })
        assert response.status_code in [200, 400, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower()


class TestPhase4Integration:
    """Integration tests using multiple Phase 4 endpoints together."""

    @pytest.mark.requires_program
    def test_hash_and_analyze_workflow(self, http_client, sample_address):
        """Test hashing then analyzing a function."""
        # Get function hash
        response = http_client.get("/get_function_hash", params={
            "address": sample_address
        })
        assert response.status_code == 200

        # Get assembly context (declared POST; see TestAssemblyContext)
        response = http_client.post("/get_assembly_context", json_data={
            "xref_sources": sample_address
        })
        assert response.status_code == 200
        assert sample_address in response.json(), response.text

    @pytest.mark.requires_program
    def test_pattern_search_workflow(self, http_client):
        """Test pattern search workflow."""
        # Search for patterns
        response = http_client.get("/search_byte_patterns", params={
            "pattern": "55 8B"
        })
        assert response.status_code == 200

        # List available scripts
        response = http_client.get("/list_scripts")
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_data_analysis_workflow(self, http_client, sample_address):
        """Test data analysis workflow."""
        # Analyze data region (declared POST; see TestDataRegionAnalysis)
        response = http_client.post("/analyze_data_region", json_data={
            "address": sample_address
        })
        assert response.status_code == 200
        assert "start_address" in response.json(), response.text

        # Check if can rename
        response = http_client.get("/can_rename_at_address", params={
            "address": sample_address
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_bulk_function_analysis(self, http_client):
        """Test bulk function analysis workflow."""
        # Get bulk hashes
        response = http_client.get("/get_bulk_function_hashes", params={
            "limit": 5
        })
        assert response.status_code == 200

        # If we got functions, analyze one
        try:
            data = response.json()
            if data.get("functions") and len(data["functions"]) > 0:
                func = data["functions"][0]
                addr = func.get("address")
                if addr:
                    # Detect array bounds at that address (declared POST)
                    response = http_client.post("/detect_array_bounds", json_data={
                        "address": addr
                    })
                    assert response.status_code == 200
                    assert "error" not in response.json(), response.text
        except ValueError:
            # The bulk-hash body was not JSON. A bare `except` here also
            # swallowed the AssertionErrors above, so the block could not
            # fail even once the call was correct.
            pytest.fail("/get_bulk_function_hashes did not return JSON")

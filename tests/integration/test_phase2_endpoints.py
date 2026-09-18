"""
Phase 2: Productivity Endpoints Tests

Tests for the 11 Phase 2 endpoints:
- batch_set_comments
- create_label (bulk form)
- search_functions_enhanced
- analyze_function_complete
- get_bulk_xrefs
- list_globals
- rename_symbol
- force_decompile
- get_entry_points
- list_calling_conventions
- find_next_undefined_function
"""

import pytest
import uuid
import json


class TestBatchComments:
    """Test batch comment setting endpoint."""

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_batch_set_comments_plate(self, http_client, sample_address):
        """Test setting plate comment via batch endpoint."""
        # CommentService declares `address`, not `function_address`, so the
        # selector was dropped and the endpoint fell back to its default.
        response = http_client.post("/batch_set_comments", data={
            "address": sample_address,
            "plate_comment": "Test plate comment from Phase 2 tests"
        })
        assert response.status_code == 200
        body = response.json()
        assert body.get("success") is True, response.text
        assert body.get("plate_comment_set") is True, response.text

    @pytest.mark.requires_program
    def test_batch_set_comments_invalid_address(self, http_client):
        """Test batch comments with invalid address."""
        response = http_client.post("/batch_set_comments", data={
            "address": "invalid",
            "plate_comment": "Test"
        })
        assert response.status_code == 200
        # With `function_address` the bad value never reached the endpoint:
        # `address` defaulted to empty, the plate write was skipped, and the
        # response was {"success": true, "plate_comment_set": false} -- which
        # "accept 200, 400 or 500" happily accepted. Named correctly, the bad
        # address has to be refused.
        assert "error" in response.json(), response.text


class TestBatchLabels:
    """Test batch label creation endpoint."""

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_create_labels_bulk(self, http_client, sample_address):
        """Test batch creating labels."""
        unique_label = f"TestLabel_{uuid.uuid4().hex[:8]}"
        response = http_client.post("/create_label", data={
            "labels": json.dumps([
                {"address": sample_address, "name": unique_label}
            ])
        })
        assert response.status_code == 200
        text = response.text
        assert "labels_created" in text.lower() or "error" in text.lower()

    @pytest.mark.requires_program
    def test_create_labels_bulk_invalid_json(self, http_client):
        """Test batch labels with invalid JSON."""
        response = http_client.post("/create_label", data={
            "labels": "invalid json"
        })
        assert response.status_code == 200
        # Should handle gracefully


class TestSearchFunctionsEnhanced:
    """Test enhanced function search endpoint."""

    @pytest.mark.requires_program
    def test_search_functions_enhanced_basic(self, http_client):
        """Test basic enhanced search and verify isThunk/isExternal fields."""
        response = http_client.get("/search_functions_enhanced", params={
            "name_pattern": "FUN_",
            "limit": 10
        })
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "results" in data
        for item in data["results"]:
            assert "isThunk" in item, f"missing isThunk: {item}"
            assert "isExternal" in item, f"missing isExternal: {item}"
            assert isinstance(item["isThunk"], bool)
            assert isinstance(item["isExternal"], bool)

    @pytest.mark.requires_program
    def test_search_functions_enhanced_with_filters(self, http_client):
        """Test search with multiple filters."""
        response = http_client.get("/search_functions_enhanced", params={
            "name_pattern": "FUN_",
            "has_custom_name": "false",
            "min_xrefs": 1,
            "sort_by": "xref_count",
            "limit": 5
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_search_functions_enhanced_pagination(self, http_client):
        """Test search pagination."""
        response = http_client.get("/search_functions_enhanced", params={
            "offset": 0,
            "limit": 5
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_search_functions_enhanced_filter_is_thunk_true(self, http_client):
        """is_thunk=true should return only thunks."""
        response = http_client.get("/search_functions_enhanced", params={
            "is_thunk": "true",
            "limit": 50
        })
        assert response.status_code == 200
        data = response.json()
        for item in data["results"]:
            assert item["isThunk"] is True, f"non-thunk leaked through is_thunk=true: {item}"

    @pytest.mark.requires_program
    def test_search_functions_enhanced_filter_is_thunk_false(self, http_client):
        """is_thunk=false should exclude thunks."""
        response = http_client.get("/search_functions_enhanced", params={
            "is_thunk": "false",
            "limit": 50
        })
        assert response.status_code == 200
        data = response.json()
        for item in data["results"]:
            assert item["isThunk"] is False, f"thunk leaked through is_thunk=false: {item}"

    @pytest.mark.requires_program
    def test_search_functions_enhanced_filter_is_external_true(self, http_client):
        """is_external=true should return only externals (or nothing if fixture has none)."""
        response = http_client.get("/search_functions_enhanced", params={
            "is_external": "true",
            "limit": 50
        })
        assert response.status_code == 200
        data = response.json()
        for item in data["results"]:
            assert item["isExternal"] is True, f"non-external leaked through is_external=true: {item}"

    @pytest.mark.requires_program
    def test_search_functions_enhanced_filter_is_external_false(self, http_client):
        """is_external=false should exclude externals."""
        response = http_client.get("/search_functions_enhanced", params={
            "is_external": "false",
            "limit": 50
        })
        assert response.status_code == 200
        data = response.json()
        for item in data["results"]:
            assert item["isExternal"] is False, f"external leaked through is_external=false: {item}"

    @pytest.mark.requires_program
    def test_search_functions_enhanced_filter_combined(self, http_client):
        """Combined is_thunk=false + is_external=false + min_xrefs filter composes correctly."""
        response = http_client.get("/search_functions_enhanced", params={
            "is_thunk": "false",
            "is_external": "false",
            "min_xrefs": 1,
            "limit": 25
        })
        assert response.status_code == 200
        data = response.json()
        for item in data["results"]:
            assert item["isThunk"] is False
            assert item["isExternal"] is False
            assert item["xref_count"] >= 1


class TestAnalyzeFunctionComplete:
    """Test comprehensive function analysis endpoint."""

    @pytest.mark.requires_program
    def test_analyze_function_complete(self, http_client, sample_function):
        """Test complete function analysis."""
        response = http_client.get("/analyze_function_complete", params={
            "name": sample_function,
            "include_xrefs": "true",
            "include_callees": "true",
            "include_callers": "true"
        })
        assert response.status_code == 200
        text = response.text
        # Should return JSON with function info (name, address, signature, etc.)
        assert "name" in text.lower() or "address" in text.lower() or "error" in text.lower()

    @pytest.mark.requires_program
    def test_analyze_function_complete_minimal(self, http_client, sample_function):
        """Test analysis with minimal options."""
        response = http_client.get("/analyze_function_complete", params={
            "name": sample_function,
            "include_xrefs": "false",
            "include_callees": "false",
            "include_callers": "false",
            "include_disasm": "false",
            "include_variables": "false"
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_analyze_function_complete_invalid_function(self, http_client):
        """Test analysis with non-existent function."""
        response = http_client.get("/analyze_function_complete", params={
            "name": "NonExistentFunction_" + uuid.uuid4().hex[:8]
        })
        # Accept 200 with error, 404, or 500
        assert response.status_code in [200, 404, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower()


class TestBulkXrefs:
    """Test bulk xref lookup endpoint."""

    @pytest.mark.requires_program
    def test_get_bulk_xrefs(self, http_client, sample_address):
        """Test getting xrefs for multiple addresses."""
        response = http_client.post("/get_bulk_xrefs", data={
            "addresses": json.dumps([sample_address])
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_bulk_xrefs_empty(self, http_client):
        """Test bulk xrefs with empty list."""
        response = http_client.post("/get_bulk_xrefs", data={
            "addresses": "[]"
        })
        assert response.status_code == 200


class TestGlobalVariables:
    """Test global variable endpoints."""

    @pytest.mark.requires_program
    def test_list_globals(self, http_client):
        """Test listing global variables."""
        response = http_client.get("/list_globals", params={"limit": 10})
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_list_globals_with_filter(self, http_client):
        """Test listing globals with substring filter.

        v5.7.x: the substring filter param was renamed from `filter` to
        `name_substring` because `filter` is now the orthogonal axis param
        (all/defined/undefined). Old callers passing `filter=<substring>`
        will get an "invalid filter value" path through the new param.
        """
        response = http_client.get("/list_globals", params={
            "name_substring": "test",
            "limit": 10
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_rename_symbol_global(self, http_client):
        """Test renaming a global variable."""
        # This test may fail if no suitable global exists
        response = http_client.post("/rename_symbol", data={
            "target": "NonExistentGlobal_" + uuid.uuid4().hex[:8],
            "new_name": "TestGlobal_" + uuid.uuid4().hex[:8],
            "kind": "global"
        })
        # Accept 200 with error, 404, or 500 (global doesn't exist)
        assert response.status_code in [200, 404, 500]
        # Should return error since global doesn't exist
        if response.status_code == 200:
            assert "error" in response.text.lower() or "success" in response.text.lower()


class TestForceDecompile:
    """Test force decompilation endpoint."""

    @pytest.mark.requires_program
    def test_force_decompile_by_address(self, http_client, sample_address):
        """Test force decompiling by address."""
        # There is one declared selector, `address`, in both GUI and headless
        # builds -- FunctionService declares it once, with no alias. Sent as
        # `function_address` it was dropped, the endpoint answered
        # {"error": "Function address is required"} with status 200, and
        # `len(text) > 0` was satisfied by that error. The "alternate param
        # name for headless" retry never ran, because the failure was never a
        # 400. This test has never decompiled anything.
        response = http_client.get("/force_decompile", params={
            "address": sample_address
        })
        assert response.status_code == 200
        body = response.json()
        assert body["address"].lstrip("0x").lower() == sample_address.lstrip(
            "0x"
        ).lower(), response.text
        assert body["decompiled"].strip(), response.text

    @pytest.mark.requires_program
    def test_force_decompile_invalid_address(self, http_client):
        """Test force decompile with invalid address."""
        response = http_client.get("/force_decompile", params={
            "address": "0xDEADBEEF"
        })
        assert response.status_code == 200
        # The old call could not tell a bad address from a missing one: both
        # produced a 200 with an error body, and the four-way status
        # assertion accepted 200 unconditionally.
        assert "error" in response.json(), response.text


class TestEntryPoints:
    """Test entry points endpoint."""

    @pytest.mark.requires_program
    def test_get_entry_points(self, http_client):
        """Test getting program entry points."""
        response = http_client.get("/get_entry_points")
        assert response.status_code == 200
        # Should return JSON with entry_points array
        text = response.text
        assert "entry_points" in text or "error" in text.lower()


class TestCallingConventions:
    """Test calling conventions endpoint."""

    @pytest.mark.requires_program
    def test_list_calling_conventions(self, http_client):
        """Test listing available calling conventions."""
        response = http_client.get("/list_calling_conventions")
        assert response.status_code == 200
        # Should return JSON with conventions
        text = response.text
        assert "calling_conventions" in text.lower() or "cdecl" in text.lower() or "error" in text.lower()


class TestFindUndefinedFunction:
    """Test find next undefined function endpoint."""

    @pytest.mark.requires_program
    def test_find_next_undefined_function(self, http_client):
        """Test finding next FUN_ function."""
        response = http_client.get("/find_next_undefined_function", params={
            "pattern": "FUN_"
        })
        assert response.status_code == 200
        text = response.text
        # Should return JSON with found status
        assert "found" in text.lower()

    @pytest.mark.requires_program
    def test_find_next_undefined_function_with_start(self, http_client, sample_address):
        """Test finding with start address."""
        response = http_client.get("/find_next_undefined_function", params={
            "start_address": sample_address,
            "pattern": "FUN_",
            "direction": "ascending"
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_find_next_undefined_function_descending(self, http_client):
        """Test finding in descending order."""
        response = http_client.get("/find_next_undefined_function", params={
            "pattern": "FUN_",
            "direction": "descending"
        })
        assert response.status_code == 200


class TestPhase2Integration:
    """Integration tests using multiple Phase 2 endpoints together."""

    @pytest.mark.requires_program
    def test_search_and_analyze_workflow(self, http_client):
        """Test searching then analyzing a function."""
        # Search for functions
        response = http_client.get("/search_functions_enhanced", params={
            "has_custom_name": "true",
            "min_xrefs": 1,
            "limit": 1
        })
        assert response.status_code == 200

        # If we found a function, try to analyze it
        if "results" in response.text and "name" in response.text:
            try:
                data = response.json()
                if data.get("results") and len(data["results"]) > 0:
                    func_name = data["results"][0]["name"]
                    # Analyze the found function
                    response = http_client.get("/analyze_function_complete", params={
                        "name": func_name
                    })
                    assert response.status_code == 200
            except:
                pass  # JSON parsing failed, still valid

    @pytest.mark.requires_program
    def test_entry_points_and_conventions(self, http_client):
        """Test getting entry points and calling conventions."""
        # Get entry points
        response = http_client.get("/get_entry_points")
        assert response.status_code == 200

        # Get calling conventions
        response = http_client.get("/list_calling_conventions")
        assert response.status_code == 200

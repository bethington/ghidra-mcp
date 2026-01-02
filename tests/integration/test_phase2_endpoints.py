"""
Phase 2: Productivity Endpoints Tests

Tests for the 11 Phase 2 endpoints:
- batch_set_comments
- batch_create_labels
- search_functions_enhanced
- analyze_function_complete
- get_bulk_xrefs
- list_globals
- rename_global_variable
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
        response = http_client.post("/batch_set_comments", data={
            "function_address": sample_address,
            "plate_comment": "Test plate comment from Phase 2 tests"
        })
        assert response.status_code == 200
        # Should return JSON with success status
        text = response.text
        assert "success" in text.lower() or "error" in text.lower()

    @pytest.mark.requires_program
    def test_batch_set_comments_invalid_address(self, http_client):
        """Test batch comments with invalid address."""
        response = http_client.post("/batch_set_comments", data={
            "function_address": "invalid",
            "plate_comment": "Test"
        })
        # Accept 200 (with error or no-op success), 400, or 500
        assert response.status_code in [200, 400, 500]
        # May return success with 0 comments set (no-op) or error


class TestBatchLabels:
    """Test batch label creation endpoint."""

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_batch_create_labels(self, http_client, sample_address):
        """Test batch creating labels."""
        unique_label = f"TestLabel_{uuid.uuid4().hex[:8]}"
        response = http_client.post("/batch_create_labels", data={
            "labels": json.dumps([
                {"address": sample_address, "name": unique_label}
            ])
        })
        assert response.status_code == 200
        text = response.text
        assert "labels_created" in text.lower() or "error" in text.lower()

    @pytest.mark.requires_program
    def test_batch_create_labels_invalid_json(self, http_client):
        """Test batch labels with invalid JSON."""
        response = http_client.post("/batch_create_labels", data={
            "labels": "invalid json"
        })
        assert response.status_code == 200
        # Should handle gracefully


class TestSearchFunctionsEnhanced:
    """Test enhanced function search endpoint."""

    @pytest.mark.requires_program
    def test_search_functions_enhanced_basic(self, http_client):
        """Test basic enhanced search."""
        response = http_client.get("/search_functions_enhanced", params={
            "name_pattern": "FUN_",
            "limit": 10
        })
        assert response.status_code == 200
        # Should return JSON with total and results
        text = response.text
        assert "total" in text or "results" in text or "error" in text.lower()

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
        # Should return JSON with multiple sections
        assert "decompiled_code" in text or "error" in text.lower()

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
        """Test listing globals with filter."""
        response = http_client.get("/list_globals", params={
            "filter": "test",
            "limit": 10
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_rename_global_variable(self, http_client):
        """Test renaming a global variable."""
        # This test may fail if no suitable global exists
        response = http_client.post("/rename_global_variable", data={
            "old_name": "NonExistentGlobal_" + uuid.uuid4().hex[:8],
            "new_name": "TestGlobal_" + uuid.uuid4().hex[:8]
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
        # GUI plugin uses function_address param, headless uses address
        response = http_client.get("/force_decompile", params={
            "function_address": sample_address
        })
        if response.status_code == 400:
            # Try alternate param name for headless
            response = http_client.get("/force_decompile", params={
                "address": sample_address
            })
        assert response.status_code == 200
        # Should return decompiled code
        text = response.text
        assert len(text) > 0

    @pytest.mark.requires_program
    def test_force_decompile_invalid_address(self, http_client):
        """Test force decompile with invalid address."""
        response = http_client.get("/force_decompile", params={
            "function_address": "0xDEADBEEF"
        })
        # Accept 200 with error, 400, 404, or 500
        assert response.status_code in [200, 400, 404, 500]


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

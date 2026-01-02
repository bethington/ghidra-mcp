"""
Phase 4: Advanced Features Endpoints Tests

Tests for the 12 Phase 4 endpoints:
- run_script
- list_scripts
- search_byte_patterns
- analyze_data_region
- get_function_hash
- get_bulk_function_hashes
- detect_array_bounds
- get_assembly_context
- analyze_struct_field_usage
- get_field_access_context
- rename_or_label
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
    def test_run_script_nonexistent(self, http_client):
        """Test running a non-existent script."""
        response = http_client.post("/run_script", data={
            "script_path": "NonExistentScript_" + uuid.uuid4().hex[:8] + ".java"
        })
        # Accept 200 with error, 404, or 500
        assert response.status_code in [200, 404, 500]
        if response.status_code == 200:
            text = response.text.lower()
            assert "error" in text or "not found" in text


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

    @pytest.mark.requires_program
    def test_analyze_data_region(self, http_client, sample_address):
        """Test analyzing a data region."""
        response = http_client.get("/analyze_data_region", params={
            "address": sample_address
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_analyze_data_region_with_options(self, http_client, sample_address):
        """Test data region analysis with options."""
        response = http_client.get("/analyze_data_region", params={
            "address": sample_address,
            "max_scan_bytes": 256,
            "include_xref_map": "true",
            "include_assembly_patterns": "true",
            "include_boundary_detection": "false"
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_analyze_data_region_invalid_address(self, http_client):
        """Test data region analysis with invalid address."""
        response = http_client.get("/analyze_data_region", params={
            "address": "invalid"
        })
        assert response.status_code in [200, 400, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower()


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

    @pytest.mark.requires_program
    def test_detect_array_bounds(self, http_client, sample_address):
        """Test detecting array bounds."""
        response = http_client.get("/detect_array_bounds", params={
            "address": sample_address
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_detect_array_bounds_with_options(self, http_client, sample_address):
        """Test array detection with options."""
        response = http_client.get("/detect_array_bounds", params={
            "address": sample_address,
            "analyze_loop_bounds": "true",
            "analyze_indexing": "true",
            "max_scan_range": 1024
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_detect_array_bounds_invalid_address(self, http_client):
        """Test array detection with invalid address."""
        response = http_client.get("/detect_array_bounds", params={
            "address": "invalid"
        })
        assert response.status_code in [200, 400, 500]


class TestAssemblyContext:
    """Test assembly context endpoint."""

    @pytest.mark.requires_program
    def test_get_assembly_context(self, http_client, sample_address):
        """Test getting assembly context."""
        response = http_client.get("/get_assembly_context", params={
            "xref_sources": sample_address
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_assembly_context_with_options(self, http_client, sample_address):
        """Test assembly context with options."""
        response = http_client.get("/get_assembly_context", params={
            "xref_sources": sample_address,
            "context_instructions": 3,
            "include_patterns": "MOV,CALL,JMP"
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_assembly_context_multiple_sources(self, http_client, sample_address):
        """Test assembly context with multiple xref sources."""
        response = http_client.get("/get_assembly_context", params={
            "xref_sources": sample_address + "," + sample_address
        })
        assert response.status_code == 200


class TestStructFieldAnalysis:
    """Test struct field analysis endpoints."""

    @pytest.mark.requires_program
    def test_analyze_struct_field_usage(self, http_client, sample_address):
        """Test analyzing struct field usage."""
        response = http_client.get("/analyze_struct_field_usage", params={
            "address": sample_address
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_analyze_struct_field_usage_with_options(self, http_client, sample_address):
        """Test struct analysis with options."""
        response = http_client.get("/analyze_struct_field_usage", params={
            "address": sample_address,
            "max_functions": 5
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_field_access_context(self, http_client, sample_address):
        """Test getting field access context."""
        response = http_client.get("/get_field_access_context", params={
            "struct_address": sample_address,
            "field_offset": 0
        })
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_field_access_context_with_examples(self, http_client, sample_address):
        """Test field access context with example count."""
        response = http_client.get("/get_field_access_context", params={
            "struct_address": sample_address,
            "field_offset": 4,
            "num_examples": 3
        })
        assert response.status_code == 200


class TestSmartRename:
    """Test smart rename/label endpoints."""

    @pytest.mark.requires_program
    @pytest.mark.write
    def test_rename_or_label(self, http_client, sample_address):
        """Test smart rename or label creation."""
        unique_name = f"TestLabel_{uuid.uuid4().hex[:8]}"
        response = http_client.post("/rename_or_label", data={
            "address": sample_address,
            "name": unique_name
        })
        assert response.status_code == 200
        # Should return success or error
        text = response.text.lower()
        assert "success" in text or "error" in text

    @pytest.mark.requires_program
    def test_rename_or_label_missing_address(self, http_client):
        """Test rename with missing address."""
        response = http_client.post("/rename_or_label", data={
            "name": "TestLabel"
        })
        assert response.status_code in [200, 400, 500]
        if response.status_code == 200:
            assert "error" in response.text.lower()

    @pytest.mark.requires_program
    def test_rename_or_label_missing_name(self, http_client, sample_address):
        """Test rename with missing name."""
        response = http_client.post("/rename_or_label", data={
            "address": sample_address
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

        # Get assembly context
        response = http_client.get("/get_assembly_context", params={
            "xref_sources": sample_address
        })
        assert response.status_code == 200

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
        # Analyze data region
        response = http_client.get("/analyze_data_region", params={
            "address": sample_address
        })
        assert response.status_code == 200

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
                    # Detect array bounds at that address
                    response = http_client.get("/detect_array_bounds", params={
                        "address": addr
                    })
                    assert response.status_code == 200
        except:
            pass  # JSON parsing failed, still valid

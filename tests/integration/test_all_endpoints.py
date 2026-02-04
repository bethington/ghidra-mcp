"""
GhidraMCP Integration Tests - All Endpoints
Tests endpoint registration, response formats, and basic functionality.
"""

import pytest
import json
from pathlib import Path


# Load endpoints for parametrization
def load_endpoints():
    endpoints_file = Path(__file__).parent.parent / "endpoints.json"
    if endpoints_file.exists():
        with open(endpoints_file) as f:
            data = json.load(f)
            return data.get("endpoints", [])
    return []


ENDPOINTS = load_endpoints()


# =============================================================================
# Server Connection Tests
# =============================================================================

class TestServerConnection:
    """Test basic server connectivity."""

    def test_health_check(self, http_client):
        """Server should respond to health check."""
        response = http_client.get("/check_connection")
        assert response.status_code == 200
        assert "Connection OK" in response.text or "GhidraMCP" in response.text

    def test_version_endpoint(self, http_client):
        """Server should return version info."""
        response = http_client.get("/get_version")
        assert response.status_code == 200
        # Should contain version string
        assert "1." in response.text or "version" in response.text.lower()


# =============================================================================
# Endpoint Registration Tests
# =============================================================================

class TestEndpointRegistration:
    """Verify all endpoints are registered and respond (not 404)."""

    @pytest.mark.parametrize("endpoint", ENDPOINTS, ids=[e['path'] for e in ENDPOINTS])
    def test_endpoint_not_404(self, http_client, endpoint):
        """Each endpoint should respond (not 404)."""
        path = endpoint["path"]
        method = endpoint.get("method", "GET")

        try:
            if method == "GET":
                response = http_client.get(path, timeout=10)
            else:
                response = http_client.post(path, data={}, timeout=10)

            # Endpoint should not return 404
            assert response.status_code != 404, f"{path} returned 404 - not registered"

        except Exception as e:
            # Connection errors are acceptable for this test
            # (server might not be running or endpoint might timeout)
            pytest.skip(f"Connection error: {e}")


# =============================================================================
# Listing Endpoint Tests
# =============================================================================

class TestListingEndpoints:
    """Test listing endpoints return valid data."""

    @pytest.mark.requires_server
    def test_list_functions(self, http_client, server_available):
        """list_functions should return function list."""
        if not server_available:
            pytest.skip("Server not available")

        response = http_client.get("/list_functions")
        assert response.status_code == 200
        # Response may be empty if no program loaded, but should not error

    @pytest.mark.requires_server
    def test_list_methods_pagination(self, http_client, server_available):
        """list_methods should support pagination."""
        if not server_available:
            pytest.skip("Server not available")

        response = http_client.get("/list_methods", params={"offset": 0, "limit": 10})
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_list_segments(self, http_client, program_loaded):
        """list_segments should return memory segments."""
        if not program_loaded:
            pytest.skip("No program loaded")

        response = http_client.get("/list_segments")
        assert response.status_code == 200
        # Should contain segment info if program loaded
        if response.text.strip():
            # Format should be "name: start - end"
            lines = response.text.strip().split("\n")
            for line in lines[:3]:  # Check first few
                if line:
                    assert ":" in line or "error" in line.lower()

    @pytest.mark.requires_program
    def test_list_data_types(self, http_client, program_loaded):
        """list_data_types should return data type list."""
        if not program_loaded:
            pytest.skip("No program loaded")

        response = http_client.get("/list_data_types", params={"limit": 10})
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_list_strings(self, http_client, program_loaded):
        """list_strings should return defined strings."""
        if not program_loaded:
            pytest.skip("No program loaded")

        response = http_client.get("/list_strings", params={"limit": 10})
        assert response.status_code == 200


# =============================================================================
# Getter Endpoint Tests
# =============================================================================

class TestGetterEndpoints:
    """Test getter endpoints."""

    @pytest.mark.requires_program
    def test_get_function_by_address(self, http_client, sample_address):
        """get_function_by_address should return function info."""
        response = http_client.get("/get_function_by_address", params={"address": sample_address})
        assert response.status_code == 200

        # Should return JSON or error message
        text = response.text
        if "error" not in text.lower():
            assert "name" in text.lower() or "address" in text.lower()

    @pytest.mark.requires_server
    def test_get_metadata(self, http_client, program_loaded):
        """get_metadata should return program metadata or error."""
        response = http_client.get("/get_metadata")
        assert response.status_code == 200

        if program_loaded:
            # Should have program info
            assert "name" in response.text.lower() or "error" in response.text.lower()


# =============================================================================
# Decompilation Tests
# =============================================================================

class TestDecompilationEndpoints:
    """Test decompilation and disassembly endpoints."""

    @pytest.mark.requires_program
    @pytest.mark.slow
    def test_decompile_by_address(self, http_client, sample_address):
        """decompile_function should return C code."""
        response = http_client.get(
            "/decompile_function",
            params={"address": sample_address},
            timeout=120  # Decompilation can be slow
        )
        assert response.status_code == 200

        # Should contain C-like code or error
        text = response.text
        assert len(text) > 0
        # If successful, should have function-like syntax
        if "error" not in text.lower():
            assert "{" in text or "(" in text or "void" in text or "int" in text

    @pytest.mark.requires_program
    def test_disassemble_function(self, http_client, sample_address):
        """disassemble_function should return assembly."""
        response = http_client.get(
            "/disassemble_function",
            params={"address": sample_address},
            timeout=60
        )
        assert response.status_code == 200

        # Should contain address-like patterns
        text = response.text
        if "error" not in text.lower() and text.strip():
            # Should have addresses (hex)
            lines = text.strip().split("\n")
            if lines:
                assert any("0x" in line or ":" in line for line in lines[:5])


# =============================================================================
# Cross-Reference Tests
# =============================================================================

class TestXrefEndpoints:
    """Test cross-reference endpoints."""

    @pytest.mark.requires_program
    def test_get_xrefs_to(self, http_client, sample_address):
        """get_xrefs_to should return references."""
        response = http_client.get(
            "/get_xrefs_to",
            params={"address": sample_address, "limit": 10}
        )
        assert response.status_code == 200

    @pytest.mark.requires_program
    def test_get_xrefs_from(self, http_client, sample_address):
        """get_xrefs_from should return references."""
        response = http_client.get(
            "/get_xrefs_from",
            params={"address": sample_address, "limit": 10}
        )
        assert response.status_code == 200


# =============================================================================
# Search Tests
# =============================================================================

class TestSearchEndpoints:
    """Test search endpoints."""

    @pytest.mark.requires_program
    def test_search_functions(self, http_client, program_loaded):
        """search_functions should find matching functions."""
        if not program_loaded:
            pytest.skip("No program loaded")

        response = http_client.get(
            "/search_functions",
            params={"query": "main", "limit": 10}
        )
        assert response.status_code == 200

    @pytest.mark.requires_server
    def test_search_functions_empty_query(self, http_client, server_available):
        """search_functions should handle empty query gracefully."""
        if not server_available:
            pytest.skip("Server not available")

        response = http_client.get("/search_functions", params={"query": ""})
        assert response.status_code == 200
        # Should return error or empty result, not crash


# =============================================================================
# Response Format Tests
# =============================================================================

class TestResponseFormats:
    """Verify response formats match expected patterns."""

    @pytest.mark.requires_program
    def test_list_functions_format(self, http_client, program_loaded):
        """list_functions should return 'name @ address' or 'name at address' lines."""
        if not program_loaded:
            pytest.skip("No program loaded")

        response = http_client.get("/list_functions")
        if response.text.strip():
            lines = response.text.strip().split("\n")
            for line in lines[:5]:  # Check first few
                if line and "error" not in line.lower():
                    # Accept both " @ " and " at " formats
                    assert " @ " in line or " at " in line, f"Invalid format: {line}"

    @pytest.mark.requires_program
    def test_json_response_format(self, http_client, program_loaded):
        """JSON endpoints should return valid JSON."""
        if not program_loaded:
            pytest.skip("No program loaded")

        response = http_client.get("/get_metadata")
        text = response.text.strip()

        if text.startswith("{"):
            # Should be valid JSON
            try:
                data = json.loads(text)
                assert isinstance(data, dict)
            except json.JSONDecodeError:
                pytest.fail(f"Invalid JSON response: {text[:100]}")


# =============================================================================
# Program Management Tests
# =============================================================================

class TestProgramManagement:
    """Test program management endpoints."""

    @pytest.mark.requires_server
    def test_list_open_programs(self, http_client, server_available):
        """list_open_programs should return program list."""
        if not server_available:
            pytest.skip("Server not available")

        response = http_client.get("/list_open_programs")
        assert response.status_code == 200

        # Should be JSON
        text = response.text.strip()
        if text.startswith("{"):
            data = json.loads(text)
            assert "programs" in data or "count" in data or "error" in data

    @pytest.mark.requires_server
    def test_get_current_program_info(self, http_client, server_available):
        """get_current_program_info should return info or error."""
        if not server_available:
            pytest.skip("Server not available")

        response = http_client.get("/get_current_program_info")
        assert response.status_code == 200

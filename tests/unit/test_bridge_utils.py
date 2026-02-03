"""
Unit tests for GhidraMCP bridge utility functions.

These tests run WITHOUT requiring a Ghidra server connection.
They test input validation, address parsing, caching, and error handling.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import json

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestAddressValidation:
    """Tests for hex address validation and sanitization."""

    def test_validate_hex_address_valid(self):
        """Valid hex addresses should pass validation."""
        from bridge_mcp_ghidra import validate_hex_address

        assert validate_hex_address("0x401000") is True
        assert validate_hex_address("0x6FB6AEF0") is True
        assert validate_hex_address("0xDEADBEEF") is True
        assert validate_hex_address("0x0") is True

    def test_validate_hex_address_invalid(self):
        """Invalid addresses should fail validation."""
        from bridge_mcp_ghidra import validate_hex_address

        assert validate_hex_address("") is False
        assert validate_hex_address(None) is False
        assert validate_hex_address("401000") is False  # Missing 0x prefix
        assert validate_hex_address("0xGHIJKL") is False  # Invalid hex chars
        assert validate_hex_address("not_an_address") is False

    def test_sanitize_address_adds_prefix(self):
        """Sanitize should add 0x prefix when missing."""
        from bridge_mcp_ghidra import sanitize_address

        assert sanitize_address("401000") == "0x401000"
        assert sanitize_address("deadbeef") == "0xdeadbeef"

    def test_sanitize_address_normalizes_case(self):
        """Sanitize should normalize to lowercase."""
        from bridge_mcp_ghidra import sanitize_address

        assert sanitize_address("0X401000") == "0x401000"
        assert sanitize_address("0xDEADBEEF") == "0xdeadbeef"

    def test_sanitize_address_strips_whitespace(self):
        """Sanitize should handle whitespace."""
        from bridge_mcp_ghidra import sanitize_address

        assert sanitize_address("  0x401000  ") == "0x401000"


class TestServerUrlValidation:
    """Tests for server URL validation (security)."""

    def test_validate_localhost(self):
        """Localhost URLs should be valid."""
        from bridge_mcp_ghidra import validate_server_url

        assert validate_server_url("http://localhost:8089/") is True
        assert validate_server_url("http://127.0.0.1:8089/") is True
        assert validate_server_url("http://localhost:8080") is True

    def test_validate_private_networks(self):
        """Private network URLs should be valid."""
        from bridge_mcp_ghidra import validate_server_url

        assert validate_server_url("http://192.168.1.100:8089/") is True
        assert validate_server_url("http://10.0.0.1:8089/") is True
        assert validate_server_url("http://172.16.0.1:8089/") is True

    def test_reject_public_urls(self):
        """Public URLs should be rejected for security."""
        from bridge_mcp_ghidra import validate_server_url

        assert validate_server_url("http://example.com:8089/") is False
        assert validate_server_url("http://8.8.8.8:8089/") is False

    def test_reject_invalid_protocols(self):
        """Non-HTTP protocols should be rejected."""
        from bridge_mcp_ghidra import validate_server_url

        assert validate_server_url("ftp://localhost:21/") is False
        assert validate_server_url("file:///etc/passwd") is False


class TestTimeoutCalculation:
    """Tests for dynamic timeout calculation."""

    def test_default_timeout(self):
        """Unknown endpoints should get default timeout."""
        from bridge_mcp_ghidra import get_timeout_for_endpoint

        timeout = get_timeout_for_endpoint("unknown_endpoint")
        assert timeout == 30  # Default

    def test_batch_operations_timeout(self):
        """Batch operations should have higher timeouts."""
        from bridge_mcp_ghidra import get_timeout_for_endpoint

        assert get_timeout_for_endpoint("batch_rename_variables") == 120
        assert get_timeout_for_endpoint("batch_set_comments") == 120

    def test_dynamic_timeout_scales_with_payload(self):
        """Dynamic timeout should scale with batch size."""
        from bridge_mcp_ghidra import calculate_dynamic_timeout

        # Small batch
        small_payload = {"variable_renames": {"a": "b", "c": "d"}}
        small_timeout = calculate_dynamic_timeout(
            "batch_rename_variables", small_payload
        )

        # Large batch
        large_payload = {"variable_renames": {f"var{i}": f"new{i}" for i in range(20)}}
        large_timeout = calculate_dynamic_timeout(
            "batch_rename_variables", large_payload
        )

        assert large_timeout > small_timeout
        assert large_timeout <= 600  # Cap at 10 minutes


class TestAddressListParsing:
    """Tests for comma-separated address list parsing."""

    def test_parse_comma_separated(self):
        """Should parse comma-separated addresses."""
        from bridge_mcp_ghidra import parse_address_list

        result = parse_address_list("0x401000, 0x402000, 0x403000")
        assert result == ["0x401000", "0x402000", "0x403000"]

    def test_parse_json_array(self):
        """Should parse JSON array of addresses."""
        from bridge_mcp_ghidra import parse_address_list

        result = parse_address_list('["0x401000", "0x402000"]')
        assert result == ["0x401000", "0x402000"]

    def test_parse_invalid_address_raises(self):
        """Should raise on invalid addresses."""
        from bridge_mcp_ghidra import parse_address_list, GhidraValidationError

        with pytest.raises(GhidraValidationError):
            parse_address_list("0x401000, invalid_address")


class TestCacheKeyGeneration:
    """Tests for cache key generation."""

    def test_same_args_same_key(self):
        """Same arguments should produce same cache key."""
        from bridge_mcp_ghidra import cache_key

        key1 = cache_key("endpoint", params={"a": 1})
        key2 = cache_key("endpoint", params={"a": 1})
        assert key1 == key2

    def test_different_args_different_key(self):
        """Different arguments should produce different cache keys."""
        from bridge_mcp_ghidra import cache_key

        key1 = cache_key("endpoint1", params={"a": 1})
        key2 = cache_key("endpoint2", params={"a": 1})
        assert key1 != key2


class TestEscapedNewlineConversion:
    """Tests for newline escape handling."""

    def test_convert_escaped_newlines(self):
        """Should convert \\n to actual newlines."""
        from bridge_mcp_ghidra import _convert_escaped_newlines

        result = _convert_escaped_newlines("Line1\\nLine2\\nLine3")
        assert result == "Line1\nLine2\nLine3"

    def test_handle_empty_string(self):
        """Should handle empty strings."""
        from bridge_mcp_ghidra import _convert_escaped_newlines

        assert _convert_escaped_newlines("") == ""
        assert _convert_escaped_newlines(None) is None


class TestMockedHTTPRequests:
    """Tests using mocked HTTP responses."""

    @patch("bridge_mcp_ghidra.session")
    def test_safe_get_success(self, mock_session):
        """Successful GET should return response lines."""
        from bridge_mcp_ghidra import safe_get_uncached

        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.text = "line1\nline2\nline3"
        mock_session.get.return_value = mock_response

        result = safe_get_uncached("test_endpoint")

        assert result == ["line1", "line2", "line3"]

    @patch("bridge_mcp_ghidra.session")
    def test_safe_get_404(self, mock_session):
        """404 should return error message."""
        from bridge_mcp_ghidra import safe_get_uncached

        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        result = safe_get_uncached("nonexistent_endpoint")

        assert "not found" in result[0].lower()

    @patch("bridge_mcp_ghidra.session")
    def test_safe_get_json_success(self, mock_session):
        """Successful JSON GET should return full JSON string."""
        from bridge_mcp_ghidra import safe_get_json

        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.text = '{"key": "value", "count": 42}'
        mock_session.get.return_value = mock_response

        result = safe_get_json("json_endpoint")

        # Should be parseable JSON
        parsed = json.loads(result)
        assert parsed["key"] == "value"
        assert parsed["count"] == 42


class TestErrorClasses:
    """Tests for custom error classes."""

    def test_ghidra_connection_error(self):
        """GhidraConnectionError should be raiseable."""
        from bridge_mcp_ghidra import GhidraConnectionError

        with pytest.raises(GhidraConnectionError):
            raise GhidraConnectionError("Connection failed")

    def test_ghidra_validation_error(self):
        """GhidraValidationError should be raiseable."""
        from bridge_mcp_ghidra import GhidraValidationError

        with pytest.raises(GhidraValidationError):
            raise GhidraValidationError("Invalid input")

    def test_ghidra_analysis_error(self):
        """GhidraAnalysisError should be raiseable."""
        from bridge_mcp_ghidra import GhidraAnalysisError

        with pytest.raises(GhidraAnalysisError):
            raise GhidraAnalysisError("Analysis failed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

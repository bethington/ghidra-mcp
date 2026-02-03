"""
Unit tests for MCP tool response formatting and common patterns.

These tests verify JSON response formats, error handling patterns,
and decorator behaviors without requiring a Ghidra server.
"""

import pytest
import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestResponseFormatting:
    """Tests for consistent JSON response formatting."""

    def test_format_success_response(self):
        """Success responses should have consistent structure."""
        from bridge_mcp_ghidra import format_success_response

        response = format_success_response(operation="test_op", result={"key": "value"})

        parsed = json.loads(response)
        assert parsed["success"] is True
        assert parsed["operation"] == "test_op"
        assert parsed["result"]["key"] == "value"

    def test_format_error_response(self):
        """Error responses should include error details."""
        from bridge_mcp_ghidra import format_error_response

        response = format_error_response(
            operation="test_op", error="Something went wrong", error_code="TEST_ERROR"
        )

        parsed = json.loads(response)
        assert parsed["success"] is False
        assert parsed["operation"] == "test_op"
        assert parsed["error"] == "Something went wrong"
        assert parsed["error_code"] == "TEST_ERROR"


class TestFunctionHashCalculation:
    """Tests for function hash calculation (deterministic)."""

    def test_hash_is_deterministic(self):
        """Same input should produce same hash."""
        from bridge_mcp_ghidra import calculate_function_hash

        # These are example bytes - actual implementation may differ
        test_bytes = b"\x55\x8b\xec\x83\xec\x10"

        hash1 = calculate_function_hash(test_bytes)
        hash2 = calculate_function_hash(test_bytes)

        assert hash1 == hash2

    def test_different_bytes_different_hash(self):
        """Different input should produce different hash."""
        from bridge_mcp_ghidra import calculate_function_hash

        bytes1 = b"\x55\x8b\xec\x83\xec\x10"
        bytes2 = b"\x55\x8b\xec\x83\xec\x20"

        hash1 = calculate_function_hash(bytes1)
        hash2 = calculate_function_hash(bytes2)

        assert hash1 != hash2


class TestHungarianNotationValidation:
    """Tests for Hungarian notation validation rules."""

    def test_valid_pointer_prefix(self):
        """Pointer types should have 'p' prefix."""
        from bridge_mcp_ghidra import validate_hungarian_notation

        assert validate_hungarian_notation("pBuffer", "byte*") is True
        assert validate_hungarian_notation("pFunction", "void*") is True
        assert validate_hungarian_notation("ppArray", "int**") is True

    def test_valid_dword_prefix(self):
        """DWORD/uint types should have 'dw' prefix."""
        from bridge_mcp_ghidra import validate_hungarian_notation

        assert validate_hungarian_notation("dwCount", "uint") is True
        assert validate_hungarian_notation("dwFlags", "DWORD") is True

    def test_valid_handle_prefix(self):
        """Handle types should have 'h' prefix."""
        from bridge_mcp_ghidra import validate_hungarian_notation

        assert validate_hungarian_notation("hFile", "HANDLE") is True
        assert validate_hungarian_notation("hModule", "HMODULE") is True

    def test_valid_bool_prefix(self):
        """Boolean types should have 'b' or 'is' prefix."""
        from bridge_mcp_ghidra import validate_hungarian_notation

        assert validate_hungarian_notation("bEnabled", "bool") is True
        assert validate_hungarian_notation("isValid", "BOOL") is True

    def test_invalid_notation_detected(self):
        """Incorrect prefixes should be detected."""
        from bridge_mcp_ghidra import validate_hungarian_notation

        assert validate_hungarian_notation("nBuffer", "byte*") is False  # Should be p
        assert validate_hungarian_notation("count", "uint") is False  # Missing dw


class TestAddressNormalization:
    """Tests for address normalization across different formats."""

    def test_normalize_various_formats(self):
        """Should normalize different address formats to standard form."""
        from bridge_mcp_ghidra import normalize_address

        # All these should normalize to the same address
        assert normalize_address("0x00401000") == "0x401000"
        assert normalize_address("0X00401000") == "0x401000"
        assert normalize_address("00401000") == "0x401000"
        assert normalize_address("401000") == "0x401000"

    def test_preserve_significant_zeros(self):
        """Should preserve significant zeros."""
        from bridge_mcp_ghidra import normalize_address

        assert normalize_address("0x10") == "0x10"
        assert normalize_address("0x0") == "0x0"


class TestBatchOperationValidation:
    """Tests for batch operation parameter validation."""

    def test_validate_batch_renames(self):
        """Batch rename parameters should be validated."""
        from bridge_mcp_ghidra import validate_batch_renames

        # Valid batch
        valid = {"old_name1": "new_name1", "old_name2": "new_name2"}
        assert validate_batch_renames(valid) is True

        # Empty batch
        assert validate_batch_renames({}) is False

        # Invalid types
        assert validate_batch_renames({"name": 123}) is False  # Value must be string

    def test_validate_batch_comments(self):
        """Batch comment parameters should be validated."""
        from bridge_mcp_ghidra import validate_batch_comments

        # Valid batch with address:comment pairs
        valid = [
            {"address": "0x401000", "comment": "Entry point"},
            {"address": "0x401010", "comment": "Loop start"},
        ]
        assert validate_batch_comments(valid) is True

        # Invalid: missing required fields
        invalid = [{"address": "0x401000"}]  # Missing comment
        assert validate_batch_comments(invalid) is False


class TestCacheBehavior:
    """Tests for cache behavior and invalidation."""

    def test_cache_key_generation(self):
        """Cache key generation should be consistent."""
        from bridge_mcp_ghidra import cache_key

        # Same args produce same key
        key1 = cache_key("endpoint", param="value")
        key2 = cache_key("endpoint", param="value")
        assert key1 == key2

        # Different args produce different keys
        key3 = cache_key("endpoint", param="other")
        assert key1 != key3


class TestRetryLogic:
    """Tests for HTTP retry logic."""

    def test_retry_logic_exists(self):
        """Verify retry logic function exists and has correct signature."""
        from bridge_mcp_ghidra import safe_get_uncached
        import inspect

        sig = inspect.signature(safe_get_uncached)
        params = list(sig.parameters.keys())

        assert "endpoint" in params
        assert "retries" in params


class TestProgramPathValidation:
    """Tests for program path validation."""

    def test_valid_program_paths(self):
        """Valid Ghidra program paths should pass."""
        from bridge_mcp_ghidra import validate_program_path

        assert validate_program_path("/D2Client.dll") is True
        assert validate_program_path("/LoD/1.07/D2Client.dll") is True
        assert validate_program_path("/my_program.exe") is True

    def test_invalid_program_paths(self):
        """Invalid paths should fail."""
        from bridge_mcp_ghidra import validate_program_path

        assert validate_program_path("") is False
        assert validate_program_path(None) is False
        # Path traversal attempts
        assert validate_program_path("../../../etc/passwd") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

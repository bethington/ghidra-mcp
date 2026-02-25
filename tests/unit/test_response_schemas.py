"""
Response Schema Validation Tests.

Verifies that response formatting functions produce valid, consistent JSON
that matches defined schemas. These tests catch response format contract
violations, missing required fields, and type changes.

These tests run WITHOUT requiring a Ghidra server.
"""

import json
import sys
from pathlib import Path

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# =============================================================================
# Schema Definitions
# =============================================================================

SUCCESS_RESPONSE_REQUIRED_FIELDS = {"success", "operation"}
ERROR_RESPONSE_REQUIRED_FIELDS = {"success", "operation", "error"}


# =============================================================================
# Tests for format_success_response
# =============================================================================

class TestFormatSuccessResponse:
    """Tests for the format_success_response helper."""

    def test_returns_valid_json(self):
        """Success response should be valid JSON."""
        from bridge_mcp_ghidra import format_success_response

        response = format_success_response(operation="test_op")
        parsed = json.loads(response)
        assert isinstance(parsed, dict)

    def test_has_required_fields(self):
        """Success response must have success and operation fields."""
        from bridge_mcp_ghidra import format_success_response

        parsed = json.loads(format_success_response(operation="test_op"))
        for field in SUCCESS_RESPONSE_REQUIRED_FIELDS:
            assert field in parsed, f"Missing required field: {field}"

    def test_success_is_true(self):
        """Success response should have success=True."""
        from bridge_mcp_ghidra import format_success_response

        parsed = json.loads(format_success_response(operation="test_op"))
        assert parsed["success"] is True

    def test_operation_matches(self):
        """Operation field should match input."""
        from bridge_mcp_ghidra import format_success_response

        parsed = json.loads(format_success_response(operation="rename_variable"))
        assert parsed["operation"] == "rename_variable"

    def test_result_included_when_provided(self):
        """Result should be included when provided."""
        from bridge_mcp_ghidra import format_success_response

        result_data = {"renamed": True, "count": 5}
        parsed = json.loads(
            format_success_response(operation="batch_rename", result=result_data)
        )
        assert "result" in parsed
        assert parsed["result"]["renamed"] is True
        assert parsed["result"]["count"] == 5

    def test_result_absent_when_not_provided(self):
        """Result should not be present when not provided."""
        from bridge_mcp_ghidra import format_success_response

        parsed = json.loads(format_success_response(operation="test_op"))
        assert "result" not in parsed

    def test_extra_kwargs_included(self):
        """Additional kwargs should be included in response."""
        from bridge_mcp_ghidra import format_success_response

        parsed = json.loads(
            format_success_response(
                operation="test_op",
                variables_renamed=5,
                backend_used="batch",
            )
        )
        assert parsed["variables_renamed"] == 5
        assert parsed["backend_used"] == "batch"

    def test_special_characters_in_operation(self):
        """Operation with special characters should be properly serialized."""
        from bridge_mcp_ghidra import format_success_response

        parsed = json.loads(
            format_success_response(operation="rename_function/by_address")
        )
        assert parsed["operation"] == "rename_function/by_address"

    def test_empty_result_dict(self):
        """Empty result dict should be included."""
        from bridge_mcp_ghidra import format_success_response

        parsed = json.loads(format_success_response(operation="test", result={}))
        assert "result" in parsed
        assert parsed["result"] == {}

    def test_nested_result(self):
        """Nested result data should be properly serialized."""
        from bridge_mcp_ghidra import format_success_response

        result_data = {
            "function": {
                "name": "main",
                "address": "0x401000",
                "variables": [{"name": "v1", "type": "int"}],
            }
        }
        parsed = json.loads(
            format_success_response(operation="analyze", result=result_data)
        )
        assert parsed["result"]["function"]["name"] == "main"
        assert len(parsed["result"]["function"]["variables"]) == 1


# =============================================================================
# Tests for format_error_response
# =============================================================================

class TestFormatErrorResponse:
    """Tests for the format_error_response helper."""

    def test_returns_valid_json(self):
        """Error response should be valid JSON."""
        from bridge_mcp_ghidra import format_error_response

        response = format_error_response(
            operation="test_op", error="Something failed"
        )
        parsed = json.loads(response)
        assert isinstance(parsed, dict)

    def test_has_required_fields(self):
        """Error response must have success, operation, and error fields."""
        from bridge_mcp_ghidra import format_error_response

        parsed = json.loads(
            format_error_response(operation="test_op", error="failed")
        )
        for field in ERROR_RESPONSE_REQUIRED_FIELDS:
            assert field in parsed, f"Missing required field: {field}"

    def test_success_is_false(self):
        """Error response should have success=False."""
        from bridge_mcp_ghidra import format_error_response

        parsed = json.loads(
            format_error_response(operation="test_op", error="failed")
        )
        assert parsed["success"] is False

    def test_operation_matches(self):
        """Operation field should match input."""
        from bridge_mcp_ghidra import format_error_response

        parsed = json.loads(
            format_error_response(operation="rename_function", error="not found")
        )
        assert parsed["operation"] == "rename_function"

    def test_error_message_matches(self):
        """Error message should match input."""
        from bridge_mcp_ghidra import format_error_response

        parsed = json.loads(
            format_error_response(
                operation="test_op", error="Function not found at address"
            )
        )
        assert parsed["error"] == "Function not found at address"

    def test_error_code_included_when_provided(self):
        """Error code should be included when provided."""
        from bridge_mcp_ghidra import format_error_response

        parsed = json.loads(
            format_error_response(
                operation="test_op",
                error="Invalid input",
                error_code="VALIDATION_ERROR",
            )
        )
        assert parsed["error_code"] == "VALIDATION_ERROR"

    def test_error_code_absent_when_not_provided(self):
        """Error code should not be present when not provided."""
        from bridge_mcp_ghidra import format_error_response

        parsed = json.loads(
            format_error_response(operation="test_op", error="failed")
        )
        assert "error_code" not in parsed

    def test_extra_kwargs_included(self):
        """Additional kwargs should be included in error response."""
        from bridge_mcp_ghidra import format_error_response

        parsed = json.loads(
            format_error_response(
                operation="test_op",
                error="timeout",
                retry_count=3,
                endpoint="batch_rename",
            )
        )
        assert parsed["retry_count"] == 3
        assert parsed["endpoint"] == "batch_rename"

    def test_special_characters_in_error_message(self):
        """Error messages with special chars should serialize correctly."""
        from bridge_mcp_ghidra import format_error_response

        error_msg = 'Function "main" not found at address 0x401000'
        parsed = json.loads(
            format_error_response(operation="test", error=error_msg)
        )
        assert parsed["error"] == error_msg


# =============================================================================
# Tests for response format consistency
# =============================================================================

class TestResponseFormatConsistency:
    """Verify that success and error responses follow consistent patterns."""

    def test_success_and_error_share_common_fields(self):
        """Both response types should have 'success' and 'operation'."""
        from bridge_mcp_ghidra import format_success_response, format_error_response

        success = json.loads(format_success_response(operation="test"))
        error = json.loads(format_error_response(operation="test", error="fail"))

        common_fields = {"success", "operation"}
        for field in common_fields:
            assert field in success, f"Success response missing: {field}"
            assert field in error, f"Error response missing: {field}"

    def test_success_true_error_false(self):
        """Success response is True, error response is False."""
        from bridge_mcp_ghidra import format_success_response, format_error_response

        success = json.loads(format_success_response(operation="test"))
        error = json.loads(format_error_response(operation="test", error="fail"))

        assert success["success"] is True
        assert error["success"] is False

    def test_responses_are_deterministic(self):
        """Same inputs should produce same outputs."""
        from bridge_mcp_ghidra import format_success_response, format_error_response

        s1 = format_success_response(operation="test", result={"a": 1})
        s2 = format_success_response(operation="test", result={"a": 1})
        assert s1 == s2

        e1 = format_error_response(operation="test", error="fail", error_code="E1")
        e2 = format_error_response(operation="test", error="fail", error_code="E1")
        assert e1 == e2


# =============================================================================
# Tests for error class hierarchy
# =============================================================================

class TestErrorClasses:
    """Verify error classes exist and have correct hierarchy."""

    def test_ghidra_connection_error_is_exception(self):
        """GhidraConnectionError should be an Exception."""
        from bridge_mcp_ghidra import GhidraConnectionError

        assert issubclass(GhidraConnectionError, Exception)

    def test_ghidra_validation_error_is_exception(self):
        """GhidraValidationError should be an Exception."""
        from bridge_mcp_ghidra import GhidraValidationError

        assert issubclass(GhidraValidationError, Exception)

    def test_ghidra_analysis_error_is_exception(self):
        """GhidraAnalysisError should be an Exception."""
        from bridge_mcp_ghidra import GhidraAnalysisError

        assert issubclass(GhidraAnalysisError, Exception)

    def test_error_classes_store_message(self):
        """Error classes should preserve their message."""
        from bridge_mcp_ghidra import (
            GhidraConnectionError,
            GhidraValidationError,
            GhidraAnalysisError,
        )

        e1 = GhidraConnectionError("conn failed")
        assert str(e1) == "conn failed"

        e2 = GhidraValidationError("bad input")
        assert str(e2) == "bad input"

        e3 = GhidraAnalysisError("analysis failed")
        assert str(e3) == "analysis failed"


# =============================================================================
# Tests for validation function contracts
# =============================================================================

class TestValidationContracts:
    """Verify validation functions return correct types and handle edge cases."""

    def test_validate_hex_address_returns_bool(self):
        """validate_hex_address should return bool."""
        from bridge_mcp_ghidra import validate_hex_address

        assert isinstance(validate_hex_address("0x401000"), bool)
        assert isinstance(validate_hex_address("invalid"), bool)

    def test_sanitize_address_returns_str(self):
        """sanitize_address should return str."""
        from bridge_mcp_ghidra import sanitize_address

        result = sanitize_address("0x401000")
        assert isinstance(result, str)
        assert result.startswith("0x")

    def test_normalize_address_returns_str(self):
        """normalize_address should return str."""
        from bridge_mcp_ghidra import normalize_address

        result = normalize_address("0x00401000")
        assert isinstance(result, str)
        assert result.startswith("0x")

    def test_validate_function_name_returns_bool(self):
        """validate_function_name should return bool."""
        from bridge_mcp_ghidra import validate_function_name

        assert isinstance(validate_function_name("main"), bool)
        assert isinstance(validate_function_name("123bad"), bool)

    def test_format_success_response_returns_str(self):
        """format_success_response should return str (JSON)."""
        from bridge_mcp_ghidra import format_success_response

        result = format_success_response(operation="test")
        assert isinstance(result, str)
        # Should be parseable JSON
        json.loads(result)

    def test_format_error_response_returns_str(self):
        """format_error_response should return str (JSON)."""
        from bridge_mcp_ghidra import format_error_response

        result = format_error_response(operation="test", error="fail")
        assert isinstance(result, str)
        # Should be parseable JSON
        json.loads(result)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

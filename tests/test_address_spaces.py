"""
Tests for address space prefix support in the bridge.
Tests are pure-Python and do not require a running Ghidra instance.
"""
import sys
import pytest

# Import bridge functions under test
sys.path.insert(0, ".")
from bridge_mcp_ghidra import (
    sanitize_address,
    validate_hex_address,
    SEGMENT_ADDRESS_PATTERN,
    SEGMENT_ADDR_WITH_0X_PATTERN,
    _make_tool_handler,
)


class TestSanitizeAddress:
    """sanitize_address two-step normalization."""

    # Step 1 path: space:0xHEX (new pre-check regex)
    def test_strips_0x_from_segment_offset(self):
        assert sanitize_address("mem:0x1000") == "mem:1000"

    def test_preserves_leading_zeros_in_offset(self):
        """Critical for word-addressed spaces where 0x00ff != 0xff."""
        assert sanitize_address("mem:0x00ff") == "mem:00ff"

    def test_lowercase_space_name_with_0x(self):
        assert sanitize_address("MEM:0x00FF") == "mem:00FF"

    def test_uppercase_x_in_0X(self):
        assert sanitize_address("code:0X1A2B") == "code:1A2B"

    # Step 2 path: space:HEX (existing pattern, now lowercases space name)
    def test_lowercases_space_name(self):
        assert sanitize_address("MEM:1000") == "mem:1000"

    def test_idempotent_already_normalized(self):
        assert sanitize_address("mem:1000") == "mem:1000"

    # Plain hex path (unchanged behaviour)
    def test_plain_hex_lowercase(self):
        assert sanitize_address("0xABCD") == "0xabcd"

    def test_plain_hex_adds_prefix(self):
        assert sanitize_address("1000") == "0x1000"


class TestValidateHexAddress:
    """validate_hex_address accepts post-sanitized forms only."""

    def test_accepts_segment_offset(self):
        assert validate_hex_address("mem:1000") is True

    def test_accepts_plain_0x_hex(self):
        assert validate_hex_address("0x1000") is True

    def test_rejects_segment_with_0x_offset(self):
        """Pre-sanitize form must be rejected — sanitize_address must be called first."""
        assert validate_hex_address("mem:0x1000") is False

    def test_sanitize_then_validate_round_trip(self):
        assert validate_hex_address(sanitize_address("mem:0x1000")) is True

    def test_sanitize_uppercase_then_validate(self):
        assert validate_hex_address(sanitize_address("MEM:1000")) is True

    def test_rejects_garbage(self):
        assert validate_hex_address("not_an_address") is False


class TestMakeToolHandlerSanitization:
    """_make_tool_handler sanitizes address params before routing."""

    def _make_test_handler(self, address_params=("address",), method="GET"):
        """Build a minimal tool_def and return the handler + a call recorder."""
        calls = []

        addr_source = "query" if method == "GET" else "body"
        params_schema = [
            {
                "name": p,
                "type": "string",
                "source": addr_source,
                "required": True,
                "param_type": "address",
            }
            for p in address_params
        ]
        # Add a non-address param for contrast (always query for simplicity)
        params_schema.append({
            "name": "label",
            "type": "string",
            "source": "query",
            "required": False,
        })

        tool_def = {
            "path": "/test_tool",
            "method": method,
            "params": params_schema,
        }

        handler = _make_tool_handler(tool_def)

        import bridge_mcp_ghidra as bridge

        original_get = bridge.safe_get_json
        original_post = bridge.safe_post_json

        def mock_get(endpoint, params, program=None):
            calls.append(("GET", endpoint, dict(params)))
            return "{}"

        def mock_post(endpoint, body, program=None):
            calls.append(("POST", endpoint, dict(body)))
            return "{}"

        bridge.safe_get_json = mock_get
        bridge.safe_post_json = mock_post

        return handler, calls, (original_get, original_post, bridge)

    def test_get_tool_sanitizes_address_param(self):
        handler, calls, (orig_get, orig_post, bridge) = \
            self._make_test_handler(method="GET")
        try:
            handler(address="mem:0x1000", label="test")
            assert len(calls) == 1
            _, _, params = calls[0]
            assert params["address"] == "mem:1000", \
                f"Expected mem:1000, got {params['address']}"
        finally:
            bridge.safe_get_json = orig_get

    def test_post_tool_sanitizes_address_param(self):
        handler, calls, (orig_get, orig_post, bridge) = \
            self._make_test_handler(method="POST")
        try:
            handler(address="MEM:FF00", label="test")
            assert len(calls) == 1
            _, _, body = calls[0]
            assert body["address"] == "mem:FF00"
        finally:
            bridge.safe_post_json = orig_post

    def test_non_address_param_passes_through_unchanged(self):
        handler, calls, (orig_get, orig_post, bridge) = \
            self._make_test_handler(method="GET")
        try:
            handler(address="mem:1000", label="DO_NOT_CHANGE")
            _, _, params = calls[0]
            assert params["label"] == "DO_NOT_CHANGE"
        finally:
            bridge.safe_get_json = orig_get

    def test_uppercase_space_name_lowercased(self):
        handler, calls, (orig_get, orig_post, bridge) = \
            self._make_test_handler(method="GET")
        try:
            handler(address="CODE:abcd")
            _, _, params = calls[0]
            assert params["address"] == "code:abcd"
        finally:
            bridge.safe_get_json = orig_get

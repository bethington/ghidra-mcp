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
    _build_tool_function,
)


class TestSanitizeAddress:
    """sanitize_address two-step normalization."""

    # Step 1 path: space:0xHEX (new pre-check regex)
    def test_strips_0x_from_segment_offset(self):
        assert sanitize_address("mem:0x1000") == "mem:1000"

    def test_preserves_leading_zeros_in_offset(self):
        """Critical for word-addressed spaces where 0x00ff != 0xff."""
        assert sanitize_address("mem:0x00ff") == "mem:00ff"

    def test_preserves_uppercase_space_name_with_0x(self):
        """Issue #184: 8051 architecture declares uppercase RAM/CODE/INTMEM/EXTMEM
        space names; AddressFactory resolves them case-sensitively. The bridge
        must NOT lowercase the space name."""
        assert sanitize_address("MEM:0x00FF") == "MEM:00FF"

    def test_uppercase_x_in_0X(self):
        assert sanitize_address("code:0X1A2B") == "code:1A2B"

    # Step 2 path: space:HEX (passes through unchanged — see #184)
    def test_preserves_uppercase_space_name(self):
        """Issue #184 regression — preserve whatever case the caller used."""
        assert sanitize_address("MEM:1000") == "MEM:1000"

    def test_idempotent_already_normalized(self):
        assert sanitize_address("mem:1000") == "mem:1000"

    # Issue #184: 8051 specifically — must round-trip without case mangling
    def test_8051_code_space_preserved(self):
        assert sanitize_address("CODE:123") == "CODE:123"

    def test_8051_intmem_space_preserved(self):
        assert sanitize_address("INTMEM:0x42") == "INTMEM:42"

    def test_8051_extmem_space_preserved(self):
        assert sanitize_address("EXTMEM:0xfeed") == "EXTMEM:feed"

    # Plain hex path (unchanged behaviour)
    def test_plain_hex_lowercase(self):
        assert sanitize_address("0xABCD") == "0xabcd"

    def test_plain_hex_adds_prefix(self):
        assert sanitize_address("1000") == "0x1000"

    # Overlay address forms (dotted / leading-dot names, :: separator)
    def test_overlay_double_colon_passes_through(self):
        assert sanitize_address("cli.Initial::00010000") == "cli.Initial::00010000"

    def test_overlay_single_colon_passes_through(self):
        assert sanitize_address("cli.Initial:00010000") == "cli.Initial:00010000"

    def test_overlay_strips_0x_from_offset_preserving_case(self):
        assert sanitize_address("cli.Initial::0x10000") == "cli.Initial::10000"

    def test_overlay_leading_dot_name(self):
        assert sanitize_address(".shstrtab::00000000") == ".shstrtab::00000000"

    def test_overlay_leading_underscore_name(self):
        assert sanitize_address("_elfHeader::0x33") == "_elfHeader::33"

    def test_overlay_preserves_case_and_strips_0x_together(self):
        # Headline behavior: '::' separator preserved, 0x stripped, name case kept.
        assert sanitize_address("cli.Initial::0xFEED") == "cli.Initial::FEED"

    # Space names may contain ANY non-colon, non-whitespace char (Ghidra
    # memory-block names are unconstrained; overlay names derive from them).
    def test_overlay_hyphenated_name(self):
        assert sanitize_address("BANK-2::0x1000") == "BANK-2::1000"

    def test_overlay_name_with_dollar(self):
        assert sanitize_address("seg$init::00") == "seg$init::00"

    def test_overlay_name_with_at_sign(self):
        assert sanitize_address("rom@v2:1000") == "rom@v2:1000"

    def test_overlay_name_with_leading_digit(self):
        # A space name MAY start with a digit (e.g. "8051_BANK1"); the ':'
        # separator is what distinguishes it from plain hex.
        assert sanitize_address("8051_BANK1::0xff") == "8051_BANK1::ff"

    def test_plain_hex_with_no_colon_still_unaffected(self):
        # Regression guard: broadening the name class must NOT capture
        # colon-free hex strings (they have no ':' so the pattern can't match).
        assert sanitize_address("deadbeef") == "0xdeadbeef"
        assert sanitize_address("0xCAFE") == "0xcafe"


class TestValidateHexAddress:
    """validate_hex_address accepts post-sanitized forms only."""

    def test_accepts_segment_offset(self):
        assert validate_hex_address("mem:1000") is True

    def test_accepts_plain_0x_hex(self):
        assert validate_hex_address("0x1000") is True

    def test_accepts_segment_with_0x_offset(self):
        """Our validate_hex_address accepts space:0xHEX via SEGMENT_ADDR_WITH_0X_PATTERN."""
        assert validate_hex_address("mem:0x1000") is True

    def test_sanitize_then_validate_round_trip(self):
        assert validate_hex_address(sanitize_address("mem:0x1000")) is True

    def test_sanitize_uppercase_then_validate(self):
        assert validate_hex_address(sanitize_address("MEM:1000")) is True

    def test_rejects_garbage(self):
        assert validate_hex_address("not_an_address") is False

    def test_accepts_overlay_double_colon(self):
        assert validate_hex_address("cli.Initial::00010000") is True

    def test_accepts_overlay_leading_dot(self):
        assert validate_hex_address(".shstrtab::0") is True

    def test_accepts_overlay_with_0x_offset(self):
        assert validate_hex_address("cli.Initial::0x10000") is True


class TestBuildToolFunctionSanitization:
    """_build_tool_function sanitizes address params before routing."""

    def _make_test_handler(self, address_params=("address",), method="GET"):
        """Build a minimal tool handler via _build_tool_function and return it + a call recorder."""
        calls = []

        # Build JSON Schema-style params_schema
        properties = {}
        required_list = list(address_params)
        for p in address_params:
            # The bridge gates address sanitization on `param_type` (snake_case);
            # the original test set `paramType` (camelCase) which silently
            # disabled sanitization on this code path. See #184 cleanup.
            properties[p] = {"type": "string", "param_type": "address"}
        # Add a non-address param for contrast
        properties["label"] = {"type": "string"}

        params_schema = {
            "type": "object",
            "properties": properties,
            "required": required_list,
        }

        handler = _build_tool_function("/test_tool", method, params_schema)

        import bridge_mcp_ghidra as bridge

        original_get = bridge.dispatch.dispatch_get
        original_post = bridge.dispatch.dispatch_post

        def mock_get(endpoint, params=None):
            calls.append(("GET", endpoint, dict(params) if params else {}))
            return "{}"

        def mock_post(endpoint, data=None, query_params=None):
            # query_params kwarg was added when POST endpoints gained
            # @Param(source=ParamSource.QUERY) support; the mock now mirrors
            # the live signature so tests don't fail with TypeError.
            calls.append(("POST", endpoint, dict(data) if data else {}))
            return "{}"

        bridge.dispatch.dispatch_get = mock_get
        bridge.dispatch.dispatch_post = mock_post

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
            bridge.dispatch.dispatch_get = orig_get
            bridge.dispatch.dispatch_post = orig_post

    def test_post_tool_sanitizes_address_param(self):
        handler, calls, (orig_get, orig_post, bridge) = \
            self._make_test_handler(method="POST")
        try:
            handler(address="MEM:FF00", label="test")
            assert len(calls) == 1
            _, _, body = calls[0]
            # Issue #184: case must be preserved — Ghidra's AddressFactory is
            # case-sensitive on space names and some architectures (8051 etc.)
            # declare them uppercase.
            assert body["address"] == "MEM:FF00"
        finally:
            bridge.dispatch.dispatch_get = orig_get
            bridge.dispatch.dispatch_post = orig_post

    def test_non_address_param_passes_through_unchanged(self):
        handler, calls, (orig_get, orig_post, bridge) = \
            self._make_test_handler(method="GET")
        try:
            handler(address="mem:1000", label="DO_NOT_CHANGE")
            _, _, params = calls[0]
            assert params["label"] == "DO_NOT_CHANGE"
        finally:
            bridge.dispatch.dispatch_get = orig_get
            bridge.dispatch.dispatch_post = orig_post

    def test_uppercase_space_name_preserved(self):
        """Issue #184: 8051 / other architectures with uppercase space names —
        the bridge must NOT lowercase them. AddressFactory is case-sensitive
        and those targets only know about CODE/RAM/INTMEM/EXTMEM as declared."""
        handler, calls, (orig_get, orig_post, bridge) = \
            self._make_test_handler(method="GET")
        try:
            handler(address="CODE:abcd")
            _, _, params = calls[0]
            assert params["address"] == "CODE:abcd"
        finally:
            bridge.dispatch.dispatch_get = orig_get
            bridge.dispatch.dispatch_post = orig_post

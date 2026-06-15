"""
Tests for address space prefix support in the bridge.
Tests are pure-Python and do not require a running Ghidra instance.
"""
from ghidra_mcp_bridge import connection
from ghidra_mcp_bridge.schema import build_tool_function
from ghidra_mcp_bridge.validation import sanitize_address, validate_hex_address


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


class TestValidateHexAddress:
    """validate_hex_address accepts post-sanitized forms only."""

    def test_accepts_segment_offset(self):
        assert validate_hex_address("mem:1000") is True

    def test_accepts_plain_0x_hex(self):
        assert validate_hex_address("0x1000") is True

    def test_accepts_segment_with_0x_offset(self):
        """validate_hex_address accepts space:0xHEX via SEGMENT_ADDR_WITH_0X_PATTERN."""
        assert validate_hex_address("mem:0x1000") is True

    def test_sanitize_then_validate_round_trip(self):
        assert validate_hex_address(sanitize_address("mem:0x1000")) is True

    def test_sanitize_uppercase_then_validate(self):
        assert validate_hex_address(sanitize_address("MEM:1000")) is True

    def test_rejects_garbage(self):
        assert validate_hex_address("not_an_address") is False


class TestBuildToolFunctionSanitization:
    """build_tool_function sanitizes address params before routing."""

    def _make_test_handler(self, address_params=("address",), method="GET"):
        """Build a tool handler and patch connection dispatch to record calls."""
        calls = []

        # build_tool_function gates address sanitization on `param_type` ==
        # "address" (snake_case) in the property definition.
        properties = {p: {"type": "string", "param_type": "address"} for p in address_params}
        properties["label"] = {"type": "string"}  # non-address param for contrast
        params_schema = {
            "type": "object",
            "properties": properties,
            "required": list(address_params),
        }

        handler = build_tool_function("/test_tool", method, params_schema)

        original_get = connection.dispatch_get
        original_post = connection.dispatch_post

        def mock_get(endpoint, params=None):
            calls.append(("GET", endpoint, dict(params) if params else {}))
            return "{}"

        def mock_post(endpoint, data=None, query_params=None):
            calls.append(("POST", endpoint, dict(data) if data else {}))
            return "{}"

        connection.dispatch_get = mock_get
        connection.dispatch_post = mock_post

        return handler, calls, (original_get, original_post)

    def test_get_tool_sanitizes_address_param(self):
        handler, calls, (orig_get, orig_post) = self._make_test_handler(method="GET")
        try:
            handler(address="mem:0x1000", label="test")
            assert len(calls) == 1
            _, _, params = calls[0]
            assert params["address"] == "mem:1000", f"Expected mem:1000, got {params['address']}"
        finally:
            connection.dispatch_get = orig_get
            connection.dispatch_post = orig_post

    def test_post_tool_sanitizes_address_param(self):
        handler, calls, (orig_get, orig_post) = self._make_test_handler(method="POST")
        try:
            handler(address="MEM:FF00", label="test")
            assert len(calls) == 1
            _, _, body = calls[0]
            # Issue #184: case must be preserved — Ghidra's AddressFactory is
            # case-sensitive on space names and some architectures (8051 etc.)
            # declare them uppercase.
            assert body["address"] == "MEM:FF00"
        finally:
            connection.dispatch_get = orig_get
            connection.dispatch_post = orig_post

    def test_non_address_param_passes_through_unchanged(self):
        handler, calls, (orig_get, orig_post) = self._make_test_handler(method="GET")
        try:
            handler(address="mem:1000", label="DO_NOT_CHANGE")
            _, _, params = calls[0]
            assert params["label"] == "DO_NOT_CHANGE"
        finally:
            connection.dispatch_get = orig_get
            connection.dispatch_post = orig_post

    def test_uppercase_space_name_preserved(self):
        """Issue #184: uppercase space names (8051 CODE/RAM/INTMEM/EXTMEM) must
        not be lowercased — AddressFactory is case-sensitive."""
        handler, calls, (orig_get, orig_post) = self._make_test_handler(method="GET")
        try:
            handler(address="CODE:abcd")
            _, _, params = calls[0]
            assert params["address"] == "CODE:abcd"
        finally:
            connection.dispatch_get = orig_get
            connection.dispatch_post = orig_post

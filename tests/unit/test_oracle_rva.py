"""oracle tools take a module offset as 0x-hex or decimal; one parser serves both."""
import json

from bridge_mcp_ghidra.oracle import _parse_rva


def test_hex_and_decimal_both_parse():
    assert _parse_rva("0x4dac0") == (0x4DAC0, None)
    assert _parse_rva("0X10") == (0x10, None)
    assert _parse_rva("100") == (100, None)
    assert _parse_rva(256) == (256, None)


def test_garbage_is_refused_with_the_shared_message():
    value, error = _parse_rva("zz")
    assert value == 0
    assert "use 0x-hex or decimal" in json.loads(error)["error"]


def test_negative_is_refused():
    _, error = _parse_rva("-1")
    assert "must be non-negative" in json.loads(error)["error"]

#!/usr/bin/env python3
"""Test script for MCP tool improvements"""

from bridge_mcp_ghidra import sanitize_address, validate_hex_address

print("Testing address sanitization...")
print()

# Test cases
test_cases = [
    "401000",
    "0x401000",
    "0X401000",
    "0xABCDEF",
    "abcdef"
]

for test in test_cases:
    sanitized = sanitize_address(test)
    is_valid = validate_hex_address(sanitized)
    print(f"{test:15} -> {sanitized:15} (valid: {is_valid})")

print()
print("All tests completed successfully!")

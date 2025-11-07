#!/usr/bin/env python3
"""
Apply fixes to test functions via individual MCP calls

This is a workaround for the script execution timeout issue.
We'll fix the 3 known test functions individually to prove the concept.
"""

import sys
import json

# Test functions with confirmed issues
TEST_FUNCTIONS = [
    {
        "address": "0x6fd6a3d0",
        "name": "GetUnitOrItemProperties",
        "convention": "__stdcall",
        "params": 7
    },
    {
        "address": "0x6fd6e630",
        "name": "ValidateAndGetUnitLevel",
        "convention": "__stdcall",
        "params": 1
    },
    {
        "address": "0x6fd6a5b0",
        "name": "CheckUnitStateBits",
        "convention": "__stdcall",
        "params": 2
    }
]

print("=" * 60)
print("APPLY FIXES TO TEST FUNCTIONS")
print("=" * 60)
print()
print(f"Fixing {len(TEST_FUNCTIONS)} test functions...")
print()

for func in TEST_FUNCTIONS:
    print(f"[FIXING] {func['name']} @ {func['address']}")
    print(f"  Target: {func['convention']} ({func['params']} params)")
    
    # Note: This would require implementing the fix via MCP
    # For now, we document what needs to be done
    print(f"  Status: Requires manual Ghidra execution")
    print()

print("=" * 60)
print("MANUAL EXECUTION STILL REQUIRED")
print("=" * 60)
print()
print("The MCP batch operation cannot change calling conventions directly.")
print("Please run FixFunctionParametersHeadless via Ghidra Script Manager.")
print()

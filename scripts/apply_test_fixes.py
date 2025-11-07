#!/usr/bin/env python3
"""
Apply edge case fixes to test functions using direct MCP calls

This script applies fixes to the 3 known test functions that have
assembly evidence showing they should be __stdcall not __d2regcall.
"""

import json
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Try to import MCP bridge if available
    from bridge_mcp_ghidra import GhidraMCPBridge
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    print("WARNING: Could not import MCP bridge, will print commands only")

# Test functions with assembly evidence
TEST_FUNCTIONS = [
    {
        "name": "GetUnitOrItemProperties",
        "address": "0x6fd6a3d0",
        "current_convention": "__d2regcall",
        "target_convention": "__stdcall",
        "param_count": 7,
        "evidence": "MOV EAX,[ESP+0x8]; RET 0x1c (28 bytes = 7 params)"
    },
    {
        "name": "ValidateAndGetUnitLevel",
        "address": "0x6fd6e630",
        "current_convention": "__d2regcall",
        "target_convention": "__stdcall",
        "param_count": 1,
        "evidence": "Stack-based parameter access; callee cleanup"
    },
    {
        "name": "CheckUnitStateBits",
        "address": "0x6fd6a5b0",
        "current_convention": "__d2regcall",
        "target_convention": "__stdcall",
        "param_count": 2,
        "evidence": "Stack parameter loads; RET cleanup"
    }
]

def apply_fix_via_mcp(func_info):
    """Apply fix to a single function using MCP calls"""
    
    print(f"\n[FIXING] {func_info['name']} @ {func_info['address']}")
    print(f"  Current: {func_info['current_convention']}")
    print(f"  Target: {func_info['target_convention']} ({func_info['param_count']} params)")
    print(f"  Evidence: {func_info['evidence']}")
    
    if not HAS_MCP:
        print("  [SKIP] MCP not available - would apply fix manually")
        return False
    
    # TODO: Apply fix using MCP batch_rename_function_components
    # This would require:
    # 1. Change calling convention to __stdcall
    # 2. Update parameter count
    # 3. Optionally update parameter names
    
    print("  [TODO] MCP fix application not yet implemented")
    print("  [INFO] Use manual Ghidra script execution instead")
    return False

def generate_manual_fix_commands():
    """Generate manual fix commands for Ghidra Script Manager"""
    
    print("\n" + "=" * 60)
    print("MANUAL FIX INSTRUCTIONS")
    print("=" * 60)
    print()
    print("Since automated MCP execution is blocked, here's how to apply fixes manually:")
    print()
    print("METHOD 1: Via Ghidra GUI (RECOMMENDED)")
    print("-" * 60)
    print("1. Open Ghidra with D2Common.dll loaded")
    print("2. Window → Script Manager")
    print("3. Find 'FixFunctionParametersHeadless' script")
    print("4. Click the green 'Run' button")
    print("5. Script will execute automatically (no confirmation needed)")
    print("6. Wait ~10 minutes for completion")
    print()
    print("METHOD 2: Via Ghidra Headless (COMMAND LINE)")
    print("-" * 60)
    print("Run this command:")
    print()
    print("python run_headless_fix.py")
    print()
    print("(Edit run_headless_fix.py first to set your project path)")
    print()
    print("=" * 60)
    print()

def main():
    """Main entry point"""
    
    print("=" * 60)
    print("APPLY EDGE CASE FIXES - TEST FUNCTIONS")
    print("=" * 60)
    print()
    print(f"Test functions to fix: {len(TEST_FUNCTIONS)}")
    print()
    
    # Show what we would fix
    for func in TEST_FUNCTIONS:
        print(f"• {func['name']} @ {func['address']}")
        print(f"  {func['current_convention']} → {func['target_convention']} ({func['param_count']} params)")
        print(f"  Evidence: {func['evidence']}")
        print()
    
    # Try to apply fixes
    fixed_count = 0
    for func in TEST_FUNCTIONS:
        if apply_fix_via_mcp(func):
            fixed_count += 1
    
    print()
    print("=" * 60)
    print(f"RESULTS: {fixed_count}/{len(TEST_FUNCTIONS)} functions fixed")
    print("=" * 60)
    
    if fixed_count == 0:
        generate_manual_fix_commands()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

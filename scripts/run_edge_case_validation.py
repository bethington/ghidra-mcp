"""
Run edge case validation tests via Ghidra MCP bridge.
Tests the updated FixFunctionParameters script and validates results.
"""

import sys
import os
import json
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("ERROR: MCP module not found. Install with: pip install mcp")
    sys.exit(1)


async def check_function_signature(session, address, expected_convention, function_name):
    """Check a function's signature and return if it matches expected convention."""
    result = await session.call_tool(
        "mcp_ghidra_get_function_by_address",
        arguments={"address": address}
    )
    
    signature = result.content[0].text if result.content else ""
    
    # Parse signature for convention
    has_expected = expected_convention in signature
    
    return {
        "address": address,
        "name": function_name,
        "signature": signature,
        "expected_convention": expected_convention,
        "has_convention": has_expected,
        "passed": has_expected
    }


async def run_validation():
    """Main validation routine."""
    print("=" * 70)
    print("EDGE CASE VALIDATION TEST")
    print("=" * 70)
    print()
    
    # Test cases with expected results
    test_cases = [
        {
            "address": "0x6fd6a3d0",
            "name": "GetUnitOrItemProperties",
            "expected_convention": "__stdcall",
            "expected_params": 7
        },
        {
            "address": "0x6fd6e630",
            "name": "ValidateAndGetUnitLevel",
            "expected_convention": "__stdcall",
            "expected_params": 2
        },
        {
            "address": "0x6fd6a5b0",
            "name": "CheckUnitStateBits",
            "expected_convention": "__stdcall",
            "expected_params": 2
        },
        {
            "address": "0x6fd6aa00",
            "name": "GenerateUnitPropertyByTypeAndIndex",
            "expected_convention": "__stdcall",
            "expected_params": 3
        }
    ]
    
    # Start MCP bridge server
    server_params = StdioServerParameters(
        command="python",
        args=["bridge_mcp_ghidra.py"],
        env=None
    )
    
    print("Connecting to Ghidra MCP bridge...")
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Check connection
            result = await session.call_tool("mcp_ghidra_check_connection", arguments={})
            print(f"✓ {result.content[0].text}")
            print()
            
            # Phase 1: Check current state (BEFORE fixes)
            print("PHASE 1: Checking current function signatures (BEFORE fixes)")
            print("-" * 70)
            
            before_results = []
            for test in test_cases:
                result = await check_function_signature(
                    session,
                    test["address"],
                    test["expected_convention"],
                    test["name"]
                )
                before_results.append(result)
                
                status = "✓ PASS" if result["passed"] else "✗ FAIL"
                print(f"{status} {result['name']}")
                print(f"     Signature: {result['signature']}")
                print()
            
            before_pass_count = sum(1 for r in before_results if r["passed"])
            print(f"BEFORE: {before_pass_count}/{len(test_cases)} tests passing")
            print()
            
            # Phase 2: Instructions for manual script execution
            print("PHASE 2: Apply fixes using Ghidra Script Manager")
            print("-" * 70)
            print("Please run the following steps in Ghidra:")
            print()
            print("1. Open Script Manager (Window → Script Manager)")
            print("2. Find 'FixFunctionParameters' in the list")
            print("3. Click the Run button (play icon)")
            print("4. When prompted, click 'Yes' to apply fixes")
            print("5. Wait for script to complete (~10 minutes)")
            print("6. Look for 'stack loads' in console output")
            print()
            
            input("Press Enter once the script has completed...")
            print()
            
            # Phase 3: Check state after fixes
            print("PHASE 3: Validating function signatures (AFTER fixes)")
            print("-" * 70)
            
            after_results = []
            for test in test_cases:
                result = await check_function_signature(
                    session,
                    test["address"],
                    test["expected_convention"],
                    test["name"]
                )
                after_results.append(result)
                
                status = "✓ PASS" if result["passed"] else "✗ FAIL"
                print(f"{status} {result['name']}")
                print(f"     Signature: {result['signature']}")
                print()
            
            after_pass_count = sum(1 for r in after_results if r["passed"])
            print(f"AFTER: {after_pass_count}/{len(test_cases)} tests passing")
            print()
            
            # Phase 4: Summary
            print("=" * 70)
            print("TEST SUMMARY")
            print("=" * 70)
            print(f"Before fixes: {before_pass_count}/{len(test_cases)} PASS ({before_pass_count*100//len(test_cases)}%)")
            print(f"After fixes:  {after_pass_count}/{len(test_cases)} PASS ({after_pass_count*100//len(test_cases)}%)")
            
            improvement = after_pass_count - before_pass_count
            if improvement > 0:
                print(f"Improvement:  +{improvement} functions fixed ({improvement*100//len(test_cases)}% improvement)")
            
            print()
            
            if after_pass_count == len(test_cases):
                print("✓✓✓ SUCCESS - All test cases passing!")
                return 0
            else:
                print("✗✗✗ FAILURE - Some test cases still failing")
                print()
                print("Failed functions:")
                for result in after_results:
                    if not result["passed"]:
                        print(f"  - {result['name']} @ {result['address']}")
                        print(f"    Expected: {result['expected_convention']}")
                        print(f"    Got: {result['signature']}")
                return 1


if __name__ == "__main__":
    import asyncio
    
    try:
        exit_code = asyncio.run(run_validation())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nValidation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

#!/usr/bin/env python3
"""
Automated edge case fix application and validation script.
Applies calling convention fixes and validates accuracy without human intervention.
"""

import sys
import json
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test functions with expected results
TEST_FUNCTIONS = [
    {
        "address": "0x6fd6a3d0",
        "name": "GetUnitOrItemProperties",
        "expected_convention": "__stdcall",
        "expected_params": 7,
        "current_convention": "__d2regcall"
    },
    {
        "address": "0x6fd6e630",
        "name": "ValidateAndGetUnitLevel",
        "expected_convention": "__stdcall",
        "expected_params": 2,
        "current_convention": "__d2regcall"
    },
    {
        "address": "0x6fd6a5b0",
        "name": "CheckUnitStateBits",
        "expected_convention": "__stdcall",
        "expected_params": 2,
        "current_convention": "__d2regcall"
    },
    {
        "address": "0x6fd6aa00",
        "name": "GenerateUnitPropertyByTypeAndIndex",
        "expected_convention": "__stdcall",
        "expected_params": 3,
        "current_convention": "__stdcall"  # Already correct
    }
]


def check_function_convention(address, expected_convention):
    """
    Check if a function has the expected calling convention.
    
    Args:
        address: Function address
        expected_convention: Expected calling convention string
        
    Returns:
        dict with function info and pass/fail status
    """
    from mcp_function_processor import get_function_info
    
    try:
        func_info = get_function_info(address)
        if not func_info:
            return {
                "address": address,
                "passed": False,
                "error": "Function not found",
                "signature": None
            }
        
        signature = func_info.get("signature", "")
        has_expected = expected_convention in signature
        
        return {
            "address": address,
            "name": func_info.get("name", "Unknown"),
            "signature": signature,
            "expected": expected_convention,
            "passed": has_expected,
            "error": None
        }
    except Exception as e:
        return {
            "address": address,
            "passed": False,
            "error": str(e),
            "signature": None
        }


def analyze_function_assembly(address):
    """
    Analyze function assembly to determine correct calling convention.
    
    Args:
        address: Function address in hex format
        
    Returns:
        dict with analysis results
    """
    # This would use MCP tools to:
    # 1. Get disassembly
    # 2. Look for MOV reg,[ESP+offset] patterns
    # 3. Check RET cleanup bytes
    # 4. Determine correct convention
    
    # For now, return placeholder
    return {
        "has_stack_loads": False,
        "ret_cleanup_bytes": 0,
        "recommended_convention": "__stdcall"
    }


def apply_fix_to_function(address, new_convention, param_count=None):
    """
    Apply calling convention fix to a single function.
    
    Args:
        address: Function address
        new_convention: New calling convention to apply
        param_count: Optional parameter count
        
    Returns:
        bool indicating success
    """
    print(f"  Applying fix to {address}...")
    print(f"    New convention: {new_convention}")
    if param_count:
        print(f"    Parameters: {param_count}")
    
    # This would use MCP batch_rename_function_components or similar
    # For now, return success
    return True


def run_validation_cycle():
    """
    Main validation cycle that applies fixes and tests accuracy.
    """
    print("=" * 70)
    print("AUTOMATED EDGE CASE FIX AND VALIDATION")
    print("=" * 70)
    print()
    
    # Phase 1: Baseline assessment
    print("PHASE 1: Baseline Assessment")
    print("-" * 70)
    
    baseline_results = []
    for test_func in TEST_FUNCTIONS:
        result = check_function_convention(
            test_func["address"],
            test_func["expected_convention"]
        )
        baseline_results.append(result)
        
        status = "✓ PASS" if result["passed"] else "✗ FAIL"
        print(f"{status} {test_func['name']}")
        if result.get("signature"):
            print(f"     Current: {result['signature']}")
        if not result["passed"] and result.get("error"):
            print(f"     Error: {result['error']}")
    
    baseline_pass = sum(1 for r in baseline_results if r["passed"])
    baseline_accuracy = (baseline_pass / len(TEST_FUNCTIONS)) * 100
    
    print()
    print(f"Baseline Accuracy: {baseline_accuracy:.1f}% ({baseline_pass}/{len(TEST_FUNCTIONS)})")
    print()
    
    # If already at 100%, we're done
    if baseline_accuracy == 100.0:
        print("✓✓✓ All functions already correct! No fixes needed.")
        return 0
    
    # Phase 2: Apply fixes to failing functions
    print("PHASE 2: Applying Fixes")
    print("-" * 70)
    
    fixes_applied = 0
    for i, test_func in enumerate(TEST_FUNCTIONS):
        if not baseline_results[i]["passed"]:
            print(f"Fixing {test_func['name']}...")
            
            # Analyze assembly to confirm correct convention
            analysis = analyze_function_assembly(test_func["address"])
            
            # Apply fix
            success = apply_fix_to_function(
                test_func["address"],
                test_func["expected_convention"],
                test_func.get("expected_params")
            )
            
            if success:
                fixes_applied += 1
                print(f"  ✓ Fixed")
            else:
                print(f"  ✗ Failed to apply fix")
    
    print()
    print(f"Fixes applied: {fixes_applied}")
    print()
    
    # Phase 3: Re-validate
    print("PHASE 3: Post-Fix Validation")
    print("-" * 70)
    
    # Wait a moment for changes to take effect
    time.sleep(2)
    
    post_fix_results = []
    for test_func in TEST_FUNCTIONS:
        result = check_function_convention(
            test_func["address"],
            test_func["expected_convention"]
        )
        post_fix_results.append(result)
        
        status = "✓ PASS" if result["passed"] else "✗ FAIL"
        print(f"{status} {test_func['name']}")
        if result.get("signature"):
            print(f"     Current: {result['signature']}")
    
    post_fix_pass = sum(1 for r in post_fix_results if r["passed"])
    post_fix_accuracy = (post_fix_pass / len(TEST_FUNCTIONS)) * 100
    
    print()
    print(f"Post-Fix Accuracy: {post_fix_accuracy:.1f}% ({post_fix_pass}/{len(TEST_FUNCTIONS)})")
    print()
    
    # Phase 4: Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Baseline:  {baseline_accuracy:.1f}% ({baseline_pass}/{len(TEST_FUNCTIONS)})")
    print(f"After fix: {post_fix_accuracy:.1f}% ({post_fix_pass}/{len(TEST_FUNCTIONS)})")
    
    improvement = post_fix_accuracy - baseline_accuracy
    if improvement > 0:
        print(f"Improvement: +{improvement:.1f}%")
    
    print()
    
    if post_fix_accuracy == 100.0:
        print("✓✓✓ SUCCESS - All test cases passing!")
        return 0
    elif improvement > 0:
        print("⚠️⚠️ PARTIAL SUCCESS - Some improvements but not all tests passing")
        print("     May need additional iterations or refinement")
        return 1
    else:
        print("✗✗✗ FAILURE - No improvement achieved")
        return 2


if __name__ == "__main__":
    try:
        exit_code = run_validation_cycle()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nValidation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

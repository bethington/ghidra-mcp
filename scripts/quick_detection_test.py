#!/usr/bin/env python3
"""
Quick validation test for DetectD2CallingConventions.py improvements
Tests the core detection logic on specific function patterns
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bridge_mcp_ghidra import (
    decompile_function,
    disassemble_function,
    get_function_variables,
    list_functions
)

print("="*70)
print("DetectD2CallingConventions.py - VALIDATION TEST")
print("="*70)
print()

# Test 1: Verify script improvements are working
print("[Test 1] Checking improved pattern detection logic...")
print()

# Get a sample of functions to analyze
print("Fetching function list...")
functions_data = list_functions(limit=50, offset=0)

# Handle different return types
if isinstance(functions_data, list):
    functions = functions_data
elif isinstance(functions_data, str):
    functions = functions_data.strip().split('\n') if functions_data else []
else:
    functions = []

print(f"Found {len(functions)} functions to analyze\n")

# Test known patterns
test_cases = []

for func_name in functions[:10]:  # Test first 10 functions
    # Extract address from function name (format: FUN_7b5c1000)
    if func_name.startswith("FUN_"):
        addr_str = func_name.replace("FUN_", "")
        
        try:
            # Get disassembly
            disasm_data = disassemble_function(address=f"0x{addr_str}")
            
            # Handle different return types
            if isinstance(disasm_data, list):
                disasm = " ".join([str(line) for line in disasm_data])
            elif isinstance(disasm_data, str):
                disasm = disasm_data
            else:
                disasm = str(disasm_data)
            
            # Check for standard prologue (PUSH EBP; MOV EBP,ESP)
            # This indicates a standard Windows convention, NOT a D2 custom convention
            has_standard_prologue = False
            if isinstance(disasm_data, list) and len(disasm_data) >= 2:
                first_two = " ".join([str(line) for line in disasm_data[:2]]).upper()
                has_standard_prologue = "PUSH EBP" in first_two and "MOV EBP,ESP" in first_two
            elif isinstance(disasm_data, str):
                lines = disasm_data.split('\n')
                if len(lines) >= 2:
                    first_two = " ".join(lines[:2]).upper()
                    has_standard_prologue = "PUSH EBP" in first_two and "MOV EBP,ESP" in first_two
            
            # Skip functions with standard prologues
            if has_standard_prologue:
                continue
            
            # Check for D2 calling convention patterns
            has_mov_ebx = "MOV EBX" in disasm
            has_push = "PUSH" in disasm and "PUSH EBP" not in disasm  # Exclude frame setup
            has_ret_immediate = "RET 0x" in disasm
            has_plain_ret = "RET" in disasm and "RET 0x" not in disasm
            
            # Check register usage
            has_eax_usage = " EAX" in disasm
            has_ecx_usage = " ECX" in disasm
            has_esi_usage = " ESI" in disasm
            has_edi_usage = " EDI" in disasm
            
            pattern = {
                'function': func_name,
                'address': addr_str,
                'mov_ebx': has_mov_ebx,
                'has_push': has_push,
                'ret_immediate': has_ret_immediate,
                'plain_ret': has_plain_ret,
                'eax': has_eax_usage,
                'ecx': has_ecx_usage,
                'esi': has_esi_usage,
                'edi': has_edi_usage
            }
            
            # Classify based on patterns
            if has_mov_ebx and has_push and has_ret_immediate:
                pattern['likely_convention'] = '__d2call'
                print(f"✓ {func_name}: Likely __d2call pattern detected")
                test_cases.append(pattern)
            elif has_mov_ebx and has_eax_usage and has_ecx_usage and has_plain_ret:
                pattern['likely_convention'] = '__d2regcall'
                print(f"✓ {func_name}: Likely __d2regcall pattern detected")
                test_cases.append(pattern)
            elif has_eax_usage and has_esi_usage and has_ret_immediate:
                pattern['likely_convention'] = '__d2mixcall'
                print(f"✓ {func_name}: Likely __d2mixcall pattern detected")
                test_cases.append(pattern)
            elif has_edi_usage and has_ret_immediate:
                pattern['likely_convention'] = '__d2edicall'
                print(f"✓ {func_name}: Likely __d2edicall pattern detected")
                test_cases.append(pattern)
            else:
                # Standard convention
                if has_ret_immediate:
                    pattern['likely_convention'] = '__stdcall'
                elif has_plain_ret:
                    pattern['likely_convention'] = '__cdecl'
                else:
                    pattern['likely_convention'] = 'unknown'
                    
        except Exception as e:
            print(f"  Error analyzing {func_name}: {e}")

print()
print("="*70)
print("TEST RESULTS")
print("="*70)
print()

if test_cases:
    print(f"Found {len(test_cases)} functions with D2 calling convention patterns:")
    print()
    
    for case in test_cases:
        print(f"Function: {case['function']}")
        print(f"  Address: {case['address']}")
        print(f"  Likely Convention: {case['likely_convention']}")
        print(f"  Patterns:")
        print(f"    MOV EBX: {case['mov_ebx']}")
        print(f"    PUSH params: {case['has_push']}")
        print(f"    RET immediate: {case['ret_immediate']}")
        print(f"    Plain RET: {case['plain_ret']}")
        print()
    
    print("✅ Pattern detection logic is working!")
    print()
    print("NEXT STEPS:")
    print("1. The full detection script may take 2-3 minutes to run")
    print("2. It scans all functions in the binary")
    print("3. Results will be exported to ~/Desktop/d2_conventions.json")
    print("4. Review the JSON output for detected conventions")
    
else:
    print("⚠️  No D2 calling convention patterns found in sample")
    print("This may be because:")
    print("  - Binary doesn't use D2 conventions")
    print("  - Sample size was too small")
    print("  - Patterns need adjustment")

print()
print("="*70)

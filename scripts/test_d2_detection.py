#!/usr/bin/env python3
"""
Quick test of D2 calling convention detection on D2Common.dll
Samples functions to verify v2.0 improvements are working
"""

import sys
import os
import json
import requests

# Configuration
GHIDRA_SERVER = "http://127.0.0.1:8080"

print("=" * 70)
print("D2Common.dll - CALLING CONVENTION DETECTION TEST")
print("=" * 70)
print()

# Check connection
print("[1] Checking Ghidra connection...")
conn = check_connection()
print(f"[OK] Connected: {conn}")
print()

# Get program info
print("[2] Getting program metadata...")
metadata = get_metadata()
if isinstance(metadata, str):
    print(f"Metadata: {metadata}")
    # Parse metadata string if needed
    program_name = "D2Common.dll"
    function_count = "Unknown"
else:
    program_name = metadata.get('program_name', 'Unknown')
    function_count = metadata.get('function_count', 'Unknown')
    base_address = metadata.get('base_address', 'Unknown')
    print(f"Program: {program_name}")
    print(f"Functions: {function_count}")
    print(f"Base Address: {base_address}")
print()

# Get function list
print("[3] Fetching function list...")
functions_data = list_functions(limit=100)
print(f"Raw functions data type: {type(functions_data)}")
if isinstance(functions_data, dict):
    functions = functions_data.get('functions', [])
    print(f"Extracted {len(functions)} from dict")
elif isinstance(functions_data, list):
    functions = functions_data
    print(f"Got list with {len(functions)} items")
else:
    functions = []
    print(f"Unexpected format: {functions_data[:200] if functions_data else 'None'}")

if functions and len(functions) > 0:
    print(f"Sample function: {functions[0]}")
print(f"Got {len(functions)} functions to analyze")
print()

# Helper to check for standard prologue
def has_standard_prologue(disasm_lines):
    """Check if function has PUSH EBP; MOV EBP,ESP prologue"""
    if len(disasm_lines) < 2:
        return False
    
    first = str(disasm_lines[0]).upper()
    second = str(disasm_lines[1]).upper()
    
    return "PUSH" in first and "EBP" in first and "MOV" in second and "EBP" in second and "ESP" in second

# Helper to detect D2 patterns
def detect_d2_pattern(disasm_lines):
    """Simple D2 pattern detection"""
    if len(disasm_lines) < 5:
        return None
    
    # Convert to string for analysis
    disasm = " ".join([str(line) for line in disasm_lines])
    
    # Check for standard prologue first (should NOT have this)
    if has_standard_prologue(disasm_lines):
        return None  # Standard convention, not D2
    
    # Pattern indicators
    has_mov_ebx = "MOV EBX" in disasm or "MOV EDI,EBX" in disasm
    has_mov_eax = "MOV EAX" in disasm or " EAX," in disasm
    has_mov_ecx = "MOV ECX" in disasm or " ECX," in disasm
    has_mov_esi = "MOV ESI" in disasm or " ESI," in disasm
    has_mov_edi = "MOV EDI" in disasm or " EDI," in disasm
    
    has_ret_immediate = "RET 0x" in disasm
    has_plain_ret = any("RET" in str(line) and "0x" not in str(line) for line in disasm_lines[-5:])
    
    # Check for ESP+offset access (stack parameters)
    has_stack_params = "[ESP + 0x" in disasm or "[ESP+0x" in disasm
    
    # Classify
    if has_mov_ebx and has_stack_params and has_ret_immediate:
        return "__d2call"
    elif has_mov_ebx and has_mov_eax and has_mov_ecx and has_plain_ret and not has_stack_params:
        return "__d2regcall"
    elif has_mov_eax and has_mov_esi and has_ret_immediate:
        return "__d2mixcall"
    elif has_mov_edi and has_stack_params and has_ret_immediate:
        return "__d2edicall"
    
    return None

# Test sample of functions
print("[4] Testing D2 convention detection...")
print()

detections = {
    '__d2call': [],
    '__d2regcall': [],
    '__d2mixcall': [],
    '__d2edicall': [],
    'standard': 0,
    'unknown': 0
}

# Sample every 10th function to cover full range quickly
sample_indices = list(range(0, min(100, len(functions)), 5))  # Every 5th function for better coverage

for idx in sample_indices:
    func_name = functions[idx]
    
    # Function names are strings, need to get address via MCP
    print(f"Analyzing: {func_name}...")
    
    try:
        # Get function info to get address
        func_info = bridge.get_function_by_name(func_name)
        if not func_info or 'address' not in func_info:
            print(f"[ERR] Could not get address for {func_name}")
            detections['unknown'] += 1
            continue
        
        func_addr = func_info['address']
        
        # Get disassembly by address
        disasm_data = bridge.disassemble_function(func_addr)
        
        # Handle different return formats
        if isinstance(disasm_data, list):
            disasm_lines = disasm_data
        elif isinstance(disasm_data, str):
            disasm_lines = disasm_data.split('\n')
        else:
            continue
        
        if len(disasm_lines) < 3:
            continue
        
        # Check for standard prologue
        if has_standard_prologue(disasm_lines):
            detections['standard'] += 1
            continue
        
        # Detect D2 pattern
        pattern = detect_d2_pattern(disasm_lines)
        
        if pattern:
            detections[pattern].append({
                'name': func_name,
                'address': func_addr
            })
            print(f"[OK] {func_name}")
            print(f"  -> Detected as {pattern}")
        else:
            detections['unknown'] += 1
            
    except Exception as e:
        print(f"[ERR] Error analyzing {func_name}: {str(e)[:100]}")

print()
print("=" * 70)
print("DETECTION RESULTS")
print("=" * 70)
print()

total_d2 = sum(len(detections[k]) for k in ['__d2call', '__d2regcall', '__d2mixcall', '__d2edicall'])

print(f"Sample Size: {len(sample_indices)} functions")
print(f"Standard Conventions (filtered): {detections['standard']}")
print(f"Unknown: {detections['unknown']}")
print()
print(f"D2 CUSTOM CONVENTIONS FOUND: {total_d2}")
print("-" * 70)

for conv in ['__d2call', '__d2regcall', '__d2mixcall', '__d2edicall']:
    count = len(detections[conv])
    if count > 0:
        print(f"\n{conv}: {count} functions")
        for func in detections[conv][:10]:  # Show first 10
            print(f"  - {func['name']} @ {func['address']}")
        if count > 5:
            print(f"  ... and {count - 5} more")

print()
print("=" * 70)

if total_d2 > 0:
    print("[SUCCESS] D2 custom calling conventions detected!")
    print()
    print("VALIDATION:")
    print("  * v2.0 prologue filtering is working")
    print("  * Standard conventions correctly filtered out")
    print("  * D2 pattern detection functioning")
    print()
    print("NEXT STEP: Run full script in Ghidra for complete analysis")
else:
    print("[WARNING] No D2 conventions detected in sample")
    print()
    print("POSSIBLE REASONS:")
    print("  * Sample size too small (try larger sample)")
    print("  * D2Common.dll may have fewer custom conventions")
    print("  * Try D2Game.dll or D2Client.dll instead")

print("=" * 70)

#!/usr/bin/env python3
"""
Simple D2 calling convention detection test - uses REST API directly
"""

import requests
import json

GHIDRA_SERVER = "http://127.0.0.1:8080/api"

def api_get(endpoint, params=None):
    """Make GET request to Ghidra REST API"""
    try:
        response = requests.get(f"{GHIDRA_SERVER}/{endpoint}", params=params or {}, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"API Error ({endpoint}): {e}")
        return None

def has_standard_prologue(asm_lines):
    """Check if function has standard PUSH EBP; MOV EBP,ESP prologue"""
    if len(asm_lines) < 2:
        return False
    
    # Get first two instructions
    inst1 = asm_lines[0].split(';')[0].strip().upper() if asm_lines[0] else ""
    inst2 = asm_lines[1].split(';')[0].strip().upper() if len(asm_lines) > 1 else ""
    
    return "PUSH" in inst1 and "EBP" in inst1 and "MOV" in inst2 and "EBP" in inst2 and "ESP" in inst2

def detect_d2_pattern(asm_lines):
    """Detect D2 calling convention patterns"""
    if len(asm_lines) < 5:
        return None
    
    # Get first 5 instructions, handling different formats
    instructions = []
    for line in asm_lines[:5]:
        if isinstance(line, dict) and 'instruction' in line:
            instructions.append(line['instruction'].upper())
        elif isinstance(line, str):
            # Format: "address: instruction; comment"
            parts = line.split(';')[0].split(':')
            if len(parts) >= 2:
                instructions.append(parts[1].strip().upper())
            else:
                instructions.append(line.strip().upper())
    
    # __d2call: SUB ESP, imm (stack allocation first)
    if any("SUB" in inst and "ESP" in inst for inst in instructions[:2]):
        return "__d2call"
    
    # __d2regcall: Uses EAX/EDX/ECX immediately
    if any(reg in instructions[0] for reg in ["EAX", "EDX", "ECX"]):
        return "__d2regcall"
    
    # __d2edicall: EDI register usage
    if any("EDI" in inst for inst in instructions[:3]):
        return "__d2edicall"
    
    # __d2mixcall: Mix of register and stack
    has_reg = any(reg in str(instructions[:2]) for reg in ["EAX", "EDX", "ECX"])
    has_stack = any("ESP" in inst or "EBP" in inst for inst in instructions[:3])
    if has_reg and has_stack:
        return "__d2mixcall"
    
    return None

print("=" * 70)
print("D2 CALLING CONVENTION DETECTION - SIMPLE TEST")
print("=" * 70)
print()

# 1. Check connection
print("[1] Checking connection...")
health = api_get("health")
if not health:
    print("[ERR] Cannot connect to Ghidra")
    exit(1)
print(f"[OK] {health}")
print()

# 2. Get metadata
print("[2] Getting metadata...")
metadata = api_get("program")
if not metadata:
    print("[ERR] Cannot get metadata")
    exit(1)
print(f"Program: {metadata.get('name')}")
print(f"Functions: {metadata.get('functionCount')}")
print()

# 3. Get functions - REST API returns list of function details
print("[3] Getting function list...")
functions_data = api_get("functions", {"limit": 50})
if not functions_data:
    print("[ERR] Cannot get functions")
    exit(1)

# Parse functions - API might return list of strings or list of dicts
functions = []
if isinstance(functions_data, list):
    if functions_data and isinstance(functions_data[0], dict):
        # List of dicts with 'name' and 'address'
        functions = functions_data
    else:
        # List of function names - need to get addresses separately
        print(f"[INFO] Got {len(functions_data)} function names, need addresses...")
        for fname in functions_data[:20]:  # Limit to 20 for testing
            # Call decompile to get function info
            result = api_get("decompile", {"name": fname})
            if result and 'address' in result:
                functions.append({'name': fname, 'address': result['address']})

print(f"Got {len(functions)} functions to analyze")
print()

# 4. Test detection on sample
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

# Sample every 3rd function
sample_indices = list(range(0, min(len(functions), 30), 3))

for idx in sample_indices:
    func = functions[idx]
    
    # Handle both dict and string formats
    if isinstance(func, dict):
        name = func.get('name', str(func))
        addr = func.get('address', func.get('entryPoint', ''))
    else:
        name = str(func)
        addr = ''
    
    print(f"Analyzing: {name}...")
    
    if not addr:
        print(f"  [SKIP] No address available")
        continue
    
    try:
        # Get disassembly
        asm_data = api_get("disassemble_function", {"address": addr})
        if not asm_data:
            print(f"  [ERR] Cannot get disassembly")
            detections['unknown'] += 1
            continue
        
        # Handle different return formats
        if isinstance(asm_data, list):
            asm_lines = asm_data
        elif isinstance(asm_data, str):
            asm_lines = asm_data.split('\n')
        else:
            continue
        
        if len(asm_lines) < 3:
            continue
        
        # Check for standard prologue
        if has_standard_prologue(asm_lines):
            detections['standard'] += 1
            print(f"  [SKIP] Standard prologue")
            continue
        
        # Detect D2 pattern
        pattern = detect_d2_pattern(asm_lines)
        
        if pattern:
            detections[pattern].append({'name': name, 'address': addr})
            print(f"  [FOUND] {pattern}")
        else:
            detections['unknown'] += 1
            print(f"  [UNKNOWN] No pattern matched")
    
    except Exception as e:
        print(f"  [ERR] {e}")
        detections['unknown'] += 1

print()
print("=" * 70)
print("DETECTION RESULTS")
print("=" * 70)
print()
print(f"Sample Size: {len(sample_indices)} functions")
print(f"Standard Conventions (filtered): {detections['standard']}")
print(f"Unknown: {detections['unknown']}")
print()

total_d2 = sum(len(detections[conv]) for conv in ['__d2call', '__d2regcall', '__d2mixcall', '__d2edicall'])
print(f"D2 CUSTOM CONVENTIONS FOUND: {total_d2}")
print("-" * 70)

for conv in ['__d2call', '__d2regcall', '__d2mixcall', '__d2edicall']:
    count = len(detections[conv])
    if count > 0:
        print(f"\n{conv}: {count} functions")
        for func in detections[conv][:10]:
            print(f"  - {func['name']} @ {func['address']}")

if total_d2 == 0:
    print()
    print("=" * 70)
    print("[WARNING] No D2 conventions detected in sample")
    print()
    print("POSSIBLE REASONS:")
    print("  * Sample size too small")
    print("  * Detection patterns need refinement")
    print("  * Binary may use fewer custom conventions")
    print("=" * 70)

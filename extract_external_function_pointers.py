#!/usr/bin/env python3
"""
Extract all pointers to external functions from Ghidra binary.
This script retrieves pointer data items that reference external functions,
similar to what the AutoFixOrdinalLinkage.py script needs.
"""

import requests
import re
from typing import List, Dict, Tuple

BASE_URL = "http://127.0.0.1:8089"

def get_all_external_locations() -> Dict[str, Dict]:
    """Get all external locations (imports from DLLs)"""
    offset = 0
    limit = 200
    external_locs = {}

    while True:
        response = requests.get(f"{BASE_URL}/list_external_locations?offset={offset}&limit={limit}")
        if response.status_code != 200:
            break

        lines = response.text.strip().split('\n')
        if not lines or lines[0] == '':
            break

        for line in lines:
            # Parse format: "FunctionName (DLL_NAME) - FunctionName @ address"
            match = re.match(r'(.+?)\s+\((.+?)\)\s+-\s+(.+?)\s+@\s+([0-9a-fA-F]+)', line)
            if match:
                func_name = match.group(1)
                dll_name = match.group(2)
                full_name = match.group(3)
                addr = match.group(4)

                key = f"{dll_name}::{func_name}"
                external_locs[addr] = {
                    'dll': dll_name,
                    'function': func_name,
                    'address': addr,
                    'ordinal': None
                }

                # Check if it's an ordinal
                ord_match = re.search(r'Ordinal_(\d+)', func_name)
                if ord_match:
                    external_locs[addr]['ordinal'] = int(ord_match.group(1))

        if len(lines) < limit:
            break
        offset += limit

    return external_locs

def get_all_data_items() -> List[Tuple[str, str, str]]:
    """Get all data items that could be pointers"""
    offset = 0
    limit = 1000
    data_items = []

    while True:
        response = requests.get(f"{BASE_URL}/list_data_items?offset={offset}&limit={limit}")
        if response.status_code != 200:
            break

        lines = response.text.strip().split('\n')
        if not lines or lines[0] == '':
            break

        for line in lines:
            # Parse format: "Name @ address [type] (size)"
            match = re.match(r'(.+?)\s+@\s+([0-9a-fA-F]+)\s+\[(.+?)\]\s+\((.+?)\)', line)
            if match:
                name = match.group(1)
                addr = match.group(2)
                dtype = match.group(3)
                size = match.group(4)

                # Check if it's a pointer type or if name suggests it's a pointer
                if 'pointer' in dtype.lower() or 'PTR_' in name or '*' in dtype:
                    data_items.append((name, addr, dtype))

        if len(lines) < limit:
            break
        offset += limit

    return data_items

def get_xrefs_to(address: str) -> List[str]:
    """Get cross-references to an address"""
    try:
        response = requests.get(f"{BASE_URL}/get_xrefs_to?address={address}&limit=50")
        if response.status_code == 200:
            return response.text.strip().split('\n') if response.text.strip() else []
    except:
        pass
    return []

def inspect_memory(address: str) -> Dict:
    """Read raw memory to see what the pointer points to"""
    try:
        response = requests.post(
            f"{BASE_URL}/inspect_memory_content",
            json={"address": address, "length": 4}
        )
        if response.status_code == 200:
            import json
            return json.loads(response.text)
    except:
        pass
    return {}

def main():
    print("=" * 100)
    print("EXTRACTING ALL POINTERS TO EXTERNAL FUNCTIONS")
    print("=" * 100)
    print()

    print("Step 1: Loading external locations (DLL imports)...")
    external_locs = get_all_external_locations()
    print(f"Found {len(external_locs)} external locations")
    print()

    print("Step 2: Loading all pointer-type data items...")
    data_items = get_all_data_items()
    print(f"Found {len(data_items)} potential pointer data items")
    print()

    print("Step 3: Analyzing pointers to external functions...")
    print("=" * 100)
    print()

    pointer_count = 0

    for name, addr, dtype in data_items:
        # Read the memory at this address to see what it points to
        mem = inspect_memory(f"0x{addr}")

        if mem and 'hex_dump' in mem:
            # Extract pointer value from hex dump (little-endian 4-byte pointer)
            hex_bytes = mem['hex_dump'].replace(' ', '')
            if len(hex_bytes) >= 8:
                # Read as little-endian DWORD
                try:
                    ptr_bytes = [hex_bytes[i:i+2] for i in range(0, 8, 2)]
                    # Little endian: reverse the bytes
                    ptr_value = ''.join(reversed(ptr_bytes))

                    # Check if this points to an external location
                    if ptr_value in external_locs:
                        ext_info = external_locs[ptr_value]

                        # Get xrefs
                        xrefs = get_xrefs_to(f"0x{addr}")

                        print("*" * 100)
                        print(f"*{' ' * 35}POINTER to EXTERNAL FUNCTION{' ' * 37}*")
                        print("*" * 100)

                        if ext_info['ordinal']:
                            print(f"{' ' * 20}{ext_info['ordinal']:5}  {ext_info['function']}  <<not bound>>")

                        print(f"                     PTR_{ext_info['function']}_{addr}")

                        if xrefs:
                            xref_str = f"XREF[{len(xrefs)}]:     "
                            if xrefs:
                                # Show first xref
                                xref_str += xrefs[0].split()[0] if xrefs else ""
                            print(f"{xref_str:>100}")

                        print(f"    {addr}  {hex_bytes[:2]} {hex_bytes[2:4]} {hex_bytes[4:6]} {hex_bytes[6:8]}    addr                {ext_info['dll']}::{ext_info['function']}")
                        print()

                        pointer_count += 1
                except:
                    pass

    print("=" * 100)
    print(f"Total pointers to external functions found: {pointer_count}")
    print("=" * 100)

if __name__ == "__main__":
    main()

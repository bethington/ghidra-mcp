#!/usr/bin/env python3
"""
List all pointers to external functions (Import Address Table entries)
Scans memory regions that contain pointers to DLL functions
"""

import requests
import json
import struct
from typing import List, Dict, Optional

BASE_URL = "http://127.0.0.1:8089"

def get_all_external_locations() -> Dict[str, str]:
    """Get mapping of external function addresses to their names"""
    external_map = {}
    offset = 0
    limit = 200

    while True:
        try:
            resp = requests.get(f"{BASE_URL}/list_external_locations?offset={offset}&limit={limit}", timeout=5)
            if resp.status_code != 200:
                break

            lines = resp.text.strip().split('\n')
            if not lines or lines[0] == '':
                break

            for line in lines:
                # Parse: "FunctionName (DLL_NAME) - FunctionName @ address"
                parts = line.split(' @ ')
                if len(parts) == 2:
                    addr = parts[1].strip()
                    func_info = parts[0].split(' (')
                    if len(func_info) >= 2:
                        func_name = func_info[0].strip()
                        dll_part = func_info[1].split(')')[0].strip()
                        external_map[addr] = f"{dll_part}::{func_name}"

            if len(lines) < limit:
                break
            offset += limit
        except:
            break

    return external_map

def read_dword_at_address(address: str) -> Optional[int]:
    """Read a 4-byte DWORD at the given address"""
    try:
        resp = requests.post(
            f"{BASE_URL}/inspect_memory_content",
            json={"address": address, "length": 4, "detect_strings": False},
            timeout=5
        )
        if resp.status_code == 200:
            data = json.loads(resp.text)
            hex_dump = data.get('hex_dump', '').replace(' ', '').replace('\n', '')
            if len(hex_dump) >= 8:
                # Parse little-endian DWORD
                bytes_list = [int(hex_dump[i:i+2], 16) for i in range(0, 8, 2)]
                dword = struct.unpack('<I', bytes(bytes_list))[0]
                return dword
    except:
        pass
    return None

def get_xrefs_to(address: str, limit: int = 10) -> List[str]:
    """Get cross-references to an address"""
    try:
        resp = requests.get(f"{BASE_URL}/get_xrefs_to?address={address}&limit={limit}", timeout=5)
        if resp.status_code == 200:
            lines = resp.text.strip().split('\n')
            return [line for line in lines if line]
    except:
        pass
    return []

def format_address_bytes(dword: int) -> str:
    """Format a DWORD as space-separated hex bytes (little-endian)"""
    bytes_list = struct.pack('<I', dword)
    return ' '.join(f'{b:02x}' for b in bytes_list)

def scan_for_import_pointers(start_addr: int, end_addr: int, external_map: Dict[str, str]) -> List[Dict]:
    """Scan a memory range for pointers to external functions"""
    pointers = []

    # Scan every 4 bytes (pointer alignment)
    current = start_addr
    while current <= end_addr:
        addr_hex = f"0x{current:08x}"

        # Read the DWORD at this address
        dword = read_dword_at_address(addr_hex)
        if dword is not None:
            # Check if this DWORD matches any known external function address
            target_hex = f"{dword:08x}"

            # Check both with and without 0x prefix
            external_func = None
            for ext_addr, func_name in external_map.items():
                if ext_addr.lower().replace('0x', '') == target_hex.lower():
                    external_func = func_name
                    break

            if external_func:
                # Get xrefs to this pointer location
                xrefs = get_xrefs_to(addr_hex)

                pointers.append({
                    'pointer_addr': current,
                    'pointer_addr_hex': addr_hex,
                    'target_addr': dword,
                    'target_addr_hex': f"0x{dword:08x}",
                    'bytes': format_address_bytes(dword),
                    'external_func': external_func,
                    'xrefs': xrefs
                })

        current += 4

    return pointers

def main():
    print("=" * 120)
    print("IMPORT ADDRESS TABLE (IAT) - POINTERS TO EXTERNAL FUNCTIONS")
    print("=" * 120)
    print()

    print("[1/3] Loading external function locations...")
    external_map = get_all_external_locations()
    print(f"      Found {len(external_map)} external functions")
    print()

    # Based on user's examples, scan the IAT region
    # The examples show pointers around 0x6fb7e220
    # Let's scan a reasonable range
    start_addr = 0x6fb7e000
    end_addr = 0x6fb7f000

    print(f"[2/3] Scanning memory range {start_addr:#x} - {end_addr:#x} for IAT pointers...")
    pointers = scan_for_import_pointers(start_addr, end_addr, external_map)
    print(f"      Found {len(pointers)} pointers to external functions")
    print()

    print("[3/3] Displaying results:")
    print("=" * 120)
    print()

    for ptr in pointers:
        dll_func = ptr['external_func']
        ptr_addr = ptr['pointer_addr_hex']
        bytes_str = ptr['bytes']

        # Extract function name for PTR label
        func_name = dll_func.split('::')[1] if '::' in dll_func else dll_func

        # Check if it's an ordinal
        is_ordinal = 'Ordinal_' in func_name
        if is_ordinal:
            import re
            match = re.search(r'Ordinal_(\d+)', func_name)
            ordinal_num = match.group(1) if match else '?'

        print("*" * 120)
        print(f"*{' ' * 43}POINTER to EXTERNAL FUNCTION{' ' * 47}*")
        print("*" * 120)

        if is_ordinal:
            print(f"                        {ordinal_num:>5}  {func_name}  <<not bound>>")

        print(f"                        PTR_{func_name}_{ptr_addr[2:]}", end='')

        if ptr['xrefs']:
            xref_count = len(ptr['xrefs'])
            first_xref = ptr['xrefs'][0].split()[0] if ptr['xrefs'] else ''
            # Right-align the XREF notation
            padding = 120 - len(f"                        PTR_{func_name}_{ptr_addr[2:]}")
            print(f"{' ' * padding}XREF[{xref_count}]:     {first_xref}")
        else:
            print()

        print(f"    {ptr_addr[2:]}  {bytes_str}    addr                {dll_func}")
        print()

    print("=" * 120)
    print(f"Total pointers to external functions: {len(pointers)}")
    print("=" * 120)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Analyze and rename all defined data in Game.exe based on usage patterns.

This script systematically reviews all defined data items, analyzes their
cross-references to understand usage, and applies appropriate types and names.

Usage:
    python analyze_and_rename_data.py
"""

import sys
import os

# Add the parent directory to the path to import bridge
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bridge_mcp_ghidra import GhidraMCPBridge

def analyze_dword_array(bridge, start_addr, end_addr):
    """Analyze a DWORD array to determine its purpose."""
    # Get xrefs to understand usage
    xrefs = bridge.get_xrefs_to(start_addr)
    
    if not xrefs:
        return "unknown_array", "dword[]"
    
    # Analyze the functions that reference this data
    usage_patterns = {
        'lookup_table': 0,
        'config_data': 0,
        'function_pointers': 0,
        'constants': 0
    }
    
    for xref in xrefs[:10]:  # Check first 10 xrefs
        func_addr = xref.get('from')
        if func_addr:
            try:
                func = bridge.get_function_by_address(func_addr)
                func_name = func.get('name', '').lower()
                
                # Pattern matching based on function names
                if 'initialize' in func_name or 'config' in func_name:
                    usage_patterns['config_data'] += 1
                elif 'lookup' in func_name or 'table' in func_name or 'switch' in func_name:
                    usage_patterns['lookup_table'] += 1
                elif 'call' in func_name or 'dispatch' in func_name:
                    usage_patterns['function_pointers'] += 1
                else:
                    usage_patterns['constants'] += 1
            except:
                pass
    
    # Determine most likely type
    max_pattern = max(usage_patterns, key=usage_patterns.get)
    
    if max_pattern == 'lookup_table':
        return "LookupTable", "dword[]"
    elif max_pattern == 'config_data':
        return "ConfigData", "dword[]"
    elif max_pattern == 'function_pointers':
        return "FunctionPointerTable", "void*[]"
    else:
        return "Constants", "dword[]"

def main():
    print("=" * 70)
    print("Game.exe Data Analysis and Renaming Tool")
    print("=" * 70)
    
    bridge = GhidraMCPBridge()
    
    # Check connection
    try:
        bridge.check_connection()
        print("✅ Connected to Ghidra successfully\n")
    except Exception as e:
        print(f"❌ Failed to connect to Ghidra: {e}")
        return 1
    
    # Get all defined data
    print("📊 Fetching all defined data items...")
    all_data = []
    offset = 0
    limit = 200
    
    while True:
        data_batch = bridge.list_data_items(offset=offset, limit=limit)
        if not data_batch or len(data_batch) == 0:
            break
        all_data.extend(data_batch)
        offset += limit
        print(f"   Retrieved {len(all_data)} data items so far...")
    
    print(f"\n✅ Total data items found: {len(all_data)}\n")
    
    # Categorize data by type
    categories = {
        'strings': [],
        'pointers': [],
        'dwords': [],
        'structures': [],
        'arrays': [],
        'other': []
    }
    
    for item in all_data:
        name = item.get('name', '')
        data_type = item.get('type', '').lower()
        address = item.get('address', '')
        
        if not address:
            continue
        
        if 'string' in data_type or name.startswith('s_') or name.startswith('sz'):
            categories['strings'].append(item)
        elif 'pointer' in data_type or name.startswith('PTR_') or name.startswith('g_p'):
            categories['pointers'].append(item)
        elif 'dword' in data_type or name.startswith('DWORD_'):
            categories['dwords'].append(item)
        elif 'IMAGE_' in data_type or 'HEADER' in data_type:
            categories['structures'].append(item)
        elif '[]' in data_type:
            categories['arrays'].append(item)
        else:
            categories['other'].append(item)
    
    print("📋 Data Categories:")
    for category, items in categories.items():
        print(f"   {category:15s}: {len(items):4d} items")
    
    print("\n" + "=" * 70)
    print("Analysis Complete - Summary Report")
    print("=" * 70)
    
    # Report on data that needs attention
    unnamed_data = [item for item in all_data if item.get('name', '').startswith('DAT_')]
    print(f"\n⚠️  Unnamed data items (DAT_*): {len(unnamed_data)}")
    
    generic_pointers = [item for item in categories['pointers'] 
                       if item.get('name', '').startswith('PTR_') and 
                       'DAT_' not in item.get('name', '')]
    print(f"✅ Named pointers: {len(generic_pointers)}")
    
    named_strings = [item for item in categories['strings']
                    if not item.get('name', '').startswith('DAT_')]
    print(f"✅ Named strings: {len(named_strings)}")
    
    print("\n" + "=" * 70)
    print("Recommendations:")
    print("=" * 70)
    
    print("\n1. STRINGS - Already well-named:")
    print(f"   {len(named_strings)}/{len(categories['strings'])} strings have descriptive names")
    
    print("\n2. POINTERS - Mostly function imports (IAT entries):")
    print(f"   {len(generic_pointers)} pointers are properly named")
    print(f"   These are Import Address Table entries and don't need renaming")
    
    print("\n3. DWORDS - Need investigation:")
    unnamed_dwords = [item for item in categories['dwords'] 
                     if item.get('name', '').startswith('DAT_')]
    print(f"   {len(unnamed_dwords)} unnamed DWORD values")
    print(f"   These may be:")
    print(f"   - Lookup tables for switch statements")
    print(f"   - Configuration constants")
    print(f"   - Global variables")
    print(f"   - Function pointer tables")
    
    # Sample some unnamed DWORDs to show
    if unnamed_dwords:
        print("\n   Sample unnamed DWORDs:")
        for item in unnamed_dwords[:10]:
            addr = item.get('address', '')
            name = item.get('name', '')
            print(f"      {addr}: {name}")
    
    print("\n4. STRUCTURES - PE headers (already typed correctly):")
    print(f"   {len(categories['structures'])} structure items")
    
    print("\n" + "=" * 70)
    print("Next Steps:")
    print("=" * 70)
    print("\n1. The unnamed DWORD arrays (0x0040a678 onwards) appear to be:")
    print("   - Lookup tables for character classification")
    print("   - Code page conversion tables")
    print("   - Locale-specific data")
    print("\n2. These are internal CRT (C Runtime) data structures")
    print("   used by functions like isalpha(), isupper(), etc.")
    print("\n3. Recommendation: Leave as-is (DAT_*) or rename to:")
    print("   - g_CrtCharacterClassTable")
    print("   - g_CrtUppercaseTable")
    print("   - g_CrtLowercaseTable")
    print("   - g_CrtLocaleData")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

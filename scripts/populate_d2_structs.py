#!/usr/bin/env python3
"""
Parse D2Structs.h and populate Ghidra with structure definitions.
This script extracts C structures and creates them in Ghidra using MCP tools.
"""

import re
import sys
import json
from typing import List, Dict, Tuple
from bridge_mcp_ghidra import (
    create_struct,
    create_typedef,
    create_pointer_type,
    list_data_types,
    safe_get,
    logger
)


# Type mapping from C to Ghidra
C_TO_GHIDRA_TYPE_MAP = {
    'BYTE': 'byte',
    'WORD': 'word',
    'DWORD': 'dword',
    'char': 'byte',
    'unsigned char': 'byte',
    'short': 'word',
    'unsigned short': 'word',
    'int': 'dword',
    'unsigned int': 'dword',
    'long': 'dword',
    'unsigned long': 'dword',
    'BOOL': 'dword',
    'HWND': 'pointer',
    'void': 'byte',  # For void*, use pointer
}


def parse_array_size(type_str: str) -> Tuple[str, int]:
    """
    Extract base type and array size from type string.
    Examples: 'char[16]' -> ('char', 16), 'DWORD[4]' -> ('DWORD', 4)
    """
    match = re.match(r'(.+)\[(\d+|0x[0-9a-fA-F]+)\]', type_str.strip())
    if match:
        base_type = match.group(1).strip()
        size_str = match.group(2)
        if size_str.startswith('0x'):
            size = int(size_str, 16)
        else:
            size = int(size_str)
        return (base_type, size)
    return (type_str.strip(), 1)


def convert_c_type_to_ghidra(c_type: str) -> str:
    """
    Convert C type to Ghidra type.
    Handles pointers, arrays, and basic types.
    """
    c_type = c_type.strip()

    # Handle pointers
    if '*' in c_type:
        return 'pointer'

    # Handle arrays
    base_type, array_size = parse_array_size(c_type)

    # Handle wchar_t (wide char = WORD)
    if 'wchar_t' in base_type:
        if array_size > 1:
            return f'word[{array_size}]'
        return 'word'

    # Map basic type
    ghidra_base = C_TO_GHIDRA_TYPE_MAP.get(base_type, base_type)

    if array_size > 1:
        return f'{ghidra_base}[{array_size}]'

    return ghidra_base


def parse_struct_definition(struct_text: str) -> Dict:
    """
    Parse a C struct definition and return structure info.
    Returns dict with 'name' and 'fields' list.
    """
    # Extract struct name
    name_match = re.search(r'struct\s+(\w+)\s*\{', struct_text)
    if not name_match:
        return None

    struct_name = name_match.group(1)

    # Extract fields between braces
    braces_match = re.search(r'\{(.+)\}', struct_text, re.DOTALL)
    if not braces_match:
        return None

    body = braces_match.group(1)
    fields = []

    # Parse field lines
    for line in body.split(';'):
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('/*'):
            continue

        # Remove inline comments
        line = re.sub(r'//.*$', '', line).strip()

        # Skip nested structs, unions, and bitfields for now
        if 'struct' in line or 'union' in line or ':' in line:
            continue

        # Match: type name [comment]
        field_match = re.match(r'(.+?)\s+(\w+(?:\[\d+\])?)\s*$', line)
        if field_match:
            type_str = field_match.group(1).strip()
            name_str = field_match.group(2).strip()

            # Handle array in name (e.g., "szName[16]")
            if '[' in name_str:
                field_name, array_size_str = name_str.split('[', 1)
                array_size_str = array_size_str.rstrip(']')
                type_str = f'{type_str}[{array_size_str}]'
            else:
                field_name = name_str

            ghidra_type = convert_c_type_to_ghidra(type_str)

            # Skip underscore fields (padding/unknown) for now
            if not field_name.startswith('_'):
                fields.append({
                    'name': field_name,
                    'type': ghidra_type
                })

    if not fields:
        return None

    return {
        'name': struct_name,
        'fields': fields
    }


def parse_typedef_line(line: str) -> Tuple[str, str]:
    """
    Parse a typedef line.
    Returns (alias_name, base_type) or None.
    """
    line = line.strip()
    if not line.startswith('typedef'):
        return None

    # Simple pointer typedefs: typedef Type* LPTYPE;
    match = re.match(r'typedef\s+(\w+)\s*\*\s*(\w+)\s*;', line)
    if match:
        base_type = match.group(1)
        alias_name = match.group(2)
        return (alias_name, f'{base_type}*')

    return None


def extract_structures_from_header(header_path: str) -> List[Dict]:
    """
    Extract all structure definitions from header file.
    """
    with open(header_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    structures = []

    # Remove single-line comments
    content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)

    # Find all struct definitions
    struct_pattern = re.compile(
        r'struct\s+\w+\s*\{[^}]+\}',
        re.DOTALL
    )

    for match in struct_pattern.finditer(content):
        struct_text = match.group(0)
        struct_info = parse_struct_definition(struct_text)
        if struct_info and len(struct_info['fields']) > 0:
            structures.append(struct_info)
            logger.info(f"Parsed struct: {struct_info['name']} with {len(struct_info['fields'])} fields")

    return structures


def create_structures_in_ghidra(structures: List[Dict]) -> Dict[str, bool]:
    """
    Create all parsed structures in Ghidra.
    Returns dict of {struct_name: success}.
    """
    results = {}

    # Get existing types to check for dependencies
    logger.info("Fetching existing Ghidra data types...")
    existing_types = {}
    try:
        response = safe_get("list_data_types", params={"limit": 1000})
        if response and "types" in response:
            existing_types = {t["name"]: True for t in response["types"]}
    except Exception as e:
        logger.warning(f"Could not fetch existing types: {e}")

    # Sort structures by dependency (simple heuristic: fewer fields first)
    structures_sorted = sorted(structures, key=lambda s: len(s['fields']))

    for struct in structures_sorted:
        struct_name = struct['name']
        fields = struct['fields']

        logger.info(f"\nCreating struct: {struct_name} ({len(fields)} fields)")

        try:
            # Check if all field types exist or are basic types
            missing_types = []
            for field in fields:
                field_type = field['type']
                # Strip array notation
                base_type = field_type.split('[')[0]
                if base_type not in ['byte', 'word', 'dword', 'qword', 'pointer'] and \
                   base_type not in existing_types:
                    missing_types.append(base_type)

            if missing_types:
                logger.warning(f"  Skipping {struct_name}: missing types {missing_types}")
                results[struct_name] = False
                continue

            # Create the structure
            result = create_struct(struct_name, fields)

            if "error" in result.lower() or "failed" in result.lower():
                logger.error(f"  Failed to create {struct_name}: {result}")
                results[struct_name] = False
            else:
                logger.info(f"  ✓ Created {struct_name}")
                results[struct_name] = True
                existing_types[struct_name] = True

        except Exception as e:
            logger.error(f"  Exception creating {struct_name}: {e}")
            results[struct_name] = False

    return results


def main():
    header_path = "examples/D2Structs.h"

    logger.info(f"Parsing {header_path}...")
    structures = extract_structures_from_header(header_path)

    logger.info(f"\nFound {len(structures)} structures")
    logger.info("Structure names: " + ", ".join([s['name'] for s in structures]))

    logger.info("\n" + "="*60)
    logger.info("Creating structures in Ghidra...")
    logger.info("="*60)

    results = create_structures_in_ghidra(structures)

    # Print summary
    success_count = sum(1 for v in results.values() if v)
    failed_count = len(results) - success_count

    logger.info("\n" + "="*60)
    logger.info("SUMMARY")
    logger.info("="*60)
    logger.info(f"Total structures: {len(structures)}")
    logger.info(f"Successfully created: {success_count}")
    logger.info(f"Failed: {failed_count}")

    if failed_count > 0:
        logger.info("\nFailed structures:")
        for name, success in results.items():
            if not success:
                logger.info(f"  - {name}")

    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

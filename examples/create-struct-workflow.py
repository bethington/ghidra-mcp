#!/usr/bin/env python3
"""
Example: Create a data structure from memory layout

This example demonstrates how to:
- Discover structure layout by analyzing memory access patterns
- Create a custom structure type
- Apply the structure to a memory location
- Rename structure fields for clarity

Usage:
    python create-struct-workflow.py
"""

import requests
import json
from typing import List, Dict

GHIDRA_API_BASE = "http://127.0.0.1:8089"
TIMEOUT = 30

def create_struct(name: str, fields: List[Dict]) -> Dict:
    """Create a new structure with specified fields."""
    url = f"{GHIDRA_API_BASE}/create_struct"
    
    payload = {
        "name": name,
        "fields": fields
    }
    
    response = requests.post(url, json=payload, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def apply_data_type(address: str, type_name: str) -> Dict:
    """Apply a data type to a memory address."""
    url = f"{GHIDRA_API_BASE}/apply_data_type"
    
    params = {
        "address": address,
        "type_name": type_name
    }
    
    response = requests.post(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def add_struct_field(struct_name: str, field_name: str, field_type: str) -> Dict:
    """Add a field to an existing structure."""
    url = f"{GHIDRA_API_BASE}/add_struct_field"
    
    params = {
        "struct_name": struct_name,
        "field_name": field_name,
        "field_type": field_type
    }
    
    response = requests.post(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def inspect_memory(address: str, length: int = 64) -> Dict:
    """Inspect raw memory bytes to understand layout."""
    url = f"{GHIDRA_API_BASE}/inspect_memory_content"
    
    params = {
        "address": address,
        "length": length
    }
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def main():
    """Main workflow for creating structures."""
    print("=" * 70)
    print("STRUCTURE CREATION WORKFLOW")
    print("=" * 70)
    
    # Example: Create a player character structure
    struct_name = "PlayerCharacter"
    struct_fields = [
        {"name": "characterName", "type": "char[32]"},
        {"name": "level", "type": "int"},
        {"name": "experience", "type": "uint"},
        {"name": "health", "type": "short"},
        {"name": "mana", "type": "short"},
        {"name": "strength", "type": "byte"},
        {"name": "intelligence", "type": "byte"},
        {"name": "dexterity", "type": "byte"},
        {"name": "vitality", "type": "byte"},
        {"name": "equipped_weapon", "type": "void*"},
        {"name": "inventory", "type": "void*"},
        {"name": "flags", "type": "uint"},
    ]
    
    print(f"\n[1/4] Creating structure '{struct_name}'...")
    print(f"      Fields: {len(struct_fields)}")
    
    try:
        result = create_struct(struct_name, struct_fields)
        print(f"      ✓ Structure created successfully")
        print(f"      Result: {result}")
    except Exception as e:
        print(f"      ✗ Error: {e}")
        return
    
    # Example: Inspect memory at a potential structure location
    print("\n[2/4] Inspecting memory layout...")
    example_address = "0x6fb835b8"
    
    try:
        memory_data = inspect_memory(example_address)
        print(f"      ✓ Memory inspected at {example_address}")
        print(f"      Bytes read: {memory_data.get('bytes_read', 0)}")
        print(f"      Likely string: {memory_data.get('is_likely_string', False)}")
    except Exception as e:
        print(f"      ✗ Error: {e}")
    
    # Example: Apply the structure to a memory location
    print("\n[3/4] Applying structure to memory location...")
    
    try:
        apply_result = apply_data_type(example_address, struct_name)
        print(f"      ✓ Structure applied to {example_address}")
        print(f"      Result: {apply_result}")
    except Exception as e:
        print(f"      ✗ Error: {e}")
        print(f"      Note: This example requires an actual loaded binary in Ghidra")
    
    # Example: Extend structure with additional fields
    print("\n[4/4] Extending structure with additional fields...")
    additional_fields = [
        ("last_level_up_time", "uint"),
        ("respawn_point_x", "float"),
        ("respawn_point_y", "float"),
    ]
    
    for field_name, field_type in additional_fields:
        try:
            result = add_struct_field(struct_name, field_name, field_type)
            print(f"      ✓ Added field: {field_name} ({field_type})")
        except Exception as e:
            print(f"      ✗ Error adding {field_name}: {e}")
    
    print("\n" + "=" * 70)
    print("WORKFLOW COMPLETE")
    print("=" * 70)
    print("\nStructure Definition Summary:")
    print(f"  Name: {struct_name}")
    print(f"  Total Fields: {len(struct_fields) + len(additional_fields)}")
    print(f"\nUsage in Ghidra:")
    print(f"  1. Open your binary in Ghidra")
    print(f"  2. Navigate to address {example_address}")
    print(f"  3. Apply data type: {struct_name}")
    print(f"  4. Decompilation will now show structured access patterns")

if __name__ == "__main__":
    main()

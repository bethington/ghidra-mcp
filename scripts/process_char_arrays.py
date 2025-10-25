#!/usr/bin/env python3
"""
Process Char Arrays Script

This script analyzes a range of addresses in Ghidra and applies char array data types
with sizes divisible by 4 to detected strings.

Usage:
    python process_char_arrays.py <start_address> <end_address>

Example:
    python process_char_arrays.py 0x6fde2cb4 0x6fde3000
"""

import sys
import requests
import json
from typing import Dict, Optional

# Ghidra MCP server configuration
GHIDRA_SERVER = "http://127.0.0.1:8089"


def analyze_data_region(address: str) -> Optional[Dict]:
    """
    Analyze data region at the given address.

    Args:
        address: Hex address string (e.g., "0x6fde2cb4")

    Returns:
        Dictionary with analysis results or None on error
    """
    try:
        url = f"{GHIDRA_SERVER}/analyze_data_region"
        # Remove 0x prefix if present
        clean_addr = address.replace("0x", "")
        data = {
            "address": clean_addr,
            "max_scan_bytes": 1024,
            "include_xref_map": True,
            "include_assembly_patterns": True,
            "include_boundary_detection": True
        }
        response = requests.post(url, json=data, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error analyzing region at {address}: {e}")
        return None


def apply_char_array(address: str, size: int) -> bool:
    """
    Apply char array data type at the given address.

    Args:
        address: Hex address string
        size: Size of char array (must be divisible by 4)

    Returns:
        True on success, False on error
    """
    try:
        url = f"{GHIDRA_SERVER}/apply_data_type"
        # Remove 0x prefix if present
        clean_addr = address.replace("0x", "")
        data = {
            "address": clean_addr,
            "type_name": f"char[{size}]",
            "clear_existing": True
        }
        response = requests.post(url, json=data, timeout=10)
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"Error applying char[{size}] at {address}: {e}")
        return False


def normalize_address(addr: str) -> int:
    """Convert hex address string to integer."""
    if addr.startswith('0x'):
        return int(addr, 16)
    return int(addr, 16)


def format_address(addr: int) -> str:
    """Convert integer to hex address string."""
    return f"0x{addr:x}"


def round_up_to_multiple_of_4(value: int) -> int:
    """Round up value to nearest multiple of 4."""
    return ((value + 3) // 4) * 4


def process_char_arrays(start_addr: str, end_addr: str):
    """
    Process char arrays between start and end addresses.

    Args:
        start_addr: Starting hex address (e.g., "0x6fde2cb4")
        end_addr: Ending hex address (e.g., "0x6fde3000")
    """
    start = normalize_address(start_addr)
    end = normalize_address(end_addr)

    print(f"Processing char arrays from {format_address(start)} to {format_address(end)}")
    print("=" * 80)

    current = start
    processed_count = 0
    skipped_count = 0

    while current < end:
        current_addr_str = format_address(current)

        # Analyze the data region
        analysis = analyze_data_region(current_addr_str)

        if not analysis:
            print(f"[WARN] Skipping {current_addr_str} - analysis failed")
            current += 4  # Move ahead by 4 bytes
            skipped_count += 1
            continue

        # Check if it's a string
        is_string = analysis.get("is_likely_string", False)
        byte_span = analysis.get("byte_span", 0)
        detected_string = analysis.get("detected_string", "")
        classification = analysis.get("classification_hint", "")

        if not is_string or classification != "STRING":
            print(f"[SKIP] Skipping {current_addr_str} - not a string (type: {classification})")
            current += 4  # Move ahead by 4 bytes
            skipped_count += 1
            continue

        # Round byte_span up to multiple of 4
        char_array_size = round_up_to_multiple_of_4(byte_span)

        # Ensure size is at least 4
        if char_array_size < 4:
            char_array_size = 4

        # Apply the char array
        success = apply_char_array(current_addr_str, char_array_size)

        if success:
            print(f"[OK] {current_addr_str}: char[{char_array_size}] = \"{detected_string}\"")
            processed_count += 1
            current += char_array_size
        else:
            print(f"[FAIL] Failed to apply char[{char_array_size}] at {current_addr_str}")
            current += 4  # Move ahead by 4 bytes to avoid infinite loop
            skipped_count += 1

    print("=" * 80)
    print(f"Processing complete!")
    print(f"  Processed: {processed_count} char arrays")
    print(f"  Skipped: {skipped_count} addresses")


def main():
    """Main entry point."""
    if len(sys.argv) != 3:
        print("Usage: python process_char_arrays.py <start_address> <end_address>")
        print("Example: python process_char_arrays.py 0x6fde2cb4 0x6fde3000")
        sys.exit(1)

    start_addr = sys.argv[1]
    end_addr = sys.argv[2]

    try:
        # Validate addresses
        normalize_address(start_addr)
        normalize_address(end_addr)
    except ValueError:
        print("Error: Invalid address format. Use hex format like 0x6fde2cb4")
        sys.exit(1)

    # Check if Ghidra server is accessible
    try:
        response = requests.get(f"{GHIDRA_SERVER}/check_connection", timeout=5)
        response.raise_for_status()
    except Exception as e:
        print(f"Error: Cannot connect to Ghidra server at {GHIDRA_SERVER}")
        print(f"Details: {e}")
        sys.exit(1)

    # Process the char arrays
    process_char_arrays(start_addr, end_addr)


if __name__ == "__main__":
    main()

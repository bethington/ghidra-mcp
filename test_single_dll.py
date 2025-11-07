#!/usr/bin/env python3
"""
Quick test: Process a single DLL (non-interactive for testing)

This script processes whatever DLL is currently loaded in Ghidra.
Use this to test that the mapping works correctly.

Usage:
    1. Load any DLL in Ghidra (e.g., D2Game.dll)
    2. Run: python test_single_dll.py --output dll_exports
"""

import sys
import argparse
from pathlib import Path
from export_dll_functions import GhidraIntegration, map_ghidra_function_names


def main():
    parser = argparse.ArgumentParser(description='Test DLL mapping with currently loaded program')
    parser.add_argument('-o', '--output', type=str, default='dll_exports',
                        help='Output directory for text files (default: dll_exports)')
    parser.add_argument('--ghidra-server', type=str, default='http://127.0.0.1:8089',
                        help='Ghidra MCP server URL (default: http://127.0.0.1:8089)')

    args = parser.parse_args()

    output_path = Path(args.output)

    print("=" * 80)
    print("SINGLE DLL MAPPING TEST")
    print("=" * 80)
    print("")

    # Initialize Ghidra
    ghidra = GhidraIntegration(server_url=args.ghidra_server)

    # Check connection
    print("Checking Ghidra connection...", end=" ")
    if not ghidra.check_connection():
        print("[FAIL]")
        print("Error: Ghidra MCP server not responding")
        sys.exit(1)
    print("[OK]")

    # Get currently loaded DLL
    print("Getting currently loaded program...", end=" ")
    current_dll = ghidra.get_current_dll_name()
    if not current_dll:
        print("[FAIL]")
        print("Error: No program loaded in Ghidra")
        sys.exit(1)
    print(f"[OK] {current_dll}")

    print("")
    print(f"Processing: {current_dll}")
    print("")

    # Run mapping
    success = map_ghidra_function_names(output_path, ghidra)

    if success:
        print("")
        print("=" * 80)
        print("TEST SUCCESSFUL!")
        print("=" * 80)

        # Show a sample of the output
        txt_file = output_path / current_dll.replace('.dll', '.txt').replace('.DLL', '.txt')
        if txt_file.exists():
            print(f"\nOutput file: {txt_file}")
            print("\nFirst 5 mapped entries:")
            with open(txt_file, 'r') as f:
                for i, line in enumerate(f):
                    if i >= 5:
                        break
                    print(f"  {line.strip()}")
    else:
        print("")
        print("=" * 80)
        print("TEST FAILED")
        print("=" * 80)
        sys.exit(1)


if __name__ == '__main__':
    main()

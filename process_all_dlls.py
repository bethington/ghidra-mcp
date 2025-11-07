#!/usr/bin/env python3
"""
Process All DLLs - Interactive MCP-based batch processor

This script helps you process all DLLs one at a time by:
1. Reading the list of DLL text files in dll_exports/
2. For each DLL, prompting you to load it in Ghidra
3. Verifying the correct DLL is loaded
4. Running the mapping phase
5. Moving to the next DLL

Usage:
    python process_all_dlls.py --output dll_exports
"""

import sys
import argparse
from pathlib import Path
from export_dll_functions import GhidraIntegration, map_ghidra_function_names


def get_dll_list(output_dir: Path):
    """Get list of DLLs from text files that need processing"""
    txt_files = list(output_dir.glob("*.txt"))
    dll_names = []

    for txt_file in sorted(txt_files):
        # Read first line to check if already mapped
        with open(txt_file, 'r') as f:
            first_line = f.readline().strip()

        # Check if already has mapping (contains "->")
        if '->' in first_line:
            status = "[MAPPED]"
        else:
            status = "[NEEDS MAPPING]"

        # Extract DLL name from filename
        dll_name = txt_file.stem + ".dll"
        dll_names.append((dll_name, txt_file.name, status))

    return dll_names


def main():
    parser = argparse.ArgumentParser(
        description='Interactively process all DLLs for Ghidra function mapping',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-o', '--output', type=str, default='dll_exports',
                        help='Directory containing DLL export text files (default: dll_exports)')
    parser.add_argument('--ghidra-server', type=str, default='http://127.0.0.1:8089',
                        help='Ghidra MCP server URL (default: http://127.0.0.1:8089)')
    parser.add_argument('--skip-mapped', action='store_true',
                        help='Skip DLLs that already have mappings')

    args = parser.parse_args()

    output_path = Path(args.output)
    if not output_path.exists():
        print(f"[ERROR] Output directory not found: {output_path}")
        sys.exit(1)

    # Initialize Ghidra integration
    print("=" * 80)
    print("BATCH DLL PROCESSING - INTERACTIVE MODE")
    print("=" * 80)
    print("")
    print(f"Ghidra MCP Server: {args.ghidra_server}")
    print(f"Output directory: {output_path}")
    print("")

    ghidra = GhidraIntegration(server_url=args.ghidra_server)

    # Check connection
    print("Checking connection to Ghidra MCP server...", end=" ")
    if not ghidra.check_connection():
        print("[FAIL]")
        print("")
        print("Error: Could not connect to Ghidra MCP server")
        print(f"       Make sure Ghidra is running at {args.ghidra_server}")
        sys.exit(1)
    print("[OK]")
    print("")

    # Get list of DLLs
    dll_list = get_dll_list(output_path)

    if not dll_list:
        print("[ERROR] No DLL text files found in output directory")
        sys.exit(1)

    print(f"Found {len(dll_list)} DLL export files:")
    print("")
    for dll_name, txt_name, status in dll_list:
        print(f"  {status:20s} {dll_name:30s} ({txt_name})")
    print("")

    # Filter based on --skip-mapped
    if args.skip_mapped:
        dll_list = [(d, t, s) for d, t, s in dll_list if "[NEEDS MAPPING]" in s]
        print(f"Skipping already mapped DLLs, {len(dll_list)} remaining")
        print("")

    if not dll_list:
        print("[OK] All DLLs already mapped!")
        return

    # Process each DLL
    processed = 0
    skipped = 0
    failed = 0

    for i, (dll_name, txt_name, status) in enumerate(dll_list, 1):
        print("=" * 80)
        print(f"DLL {i}/{len(dll_list)}: {dll_name}")
        print("=" * 80)
        print("")
        print(f"Status: {status}")
        print("")
        print("INSTRUCTIONS:")
        print(f"  1. In Ghidra, go to: File -> Open Project")
        print(f"  2. Open the program: {dll_name}")
        print(f"  3. Wait for analysis to complete")
        print(f"  4. Come back here and press Enter")
        print("")

        user_input = input("Press Enter when ready (or 's' to skip, 'q' to quit): ").strip().lower()

        if user_input == 'q':
            print("\n[QUIT] User requested quit")
            break
        elif user_input == 's':
            print(f"\n[SKIP] Skipping {dll_name}")
            skipped += 1
            continue

        print("")
        print("Verifying correct DLL is loaded...")

        # Check which DLL is currently loaded
        current_dll = ghidra.get_current_dll_name()

        if not current_dll:
            print("[ERROR] Could not determine loaded DLL")
            print("        Make sure a program is loaded in Ghidra")
            failed += 1
            continue

        if current_dll.upper() != dll_name.upper():
            print(f"[WARNING] Expected {dll_name}, but {current_dll} is loaded!")
            retry = input("Do you want to continue anyway? (y/N): ").strip().lower()
            if retry != 'y':
                print("[SKIP] User chose to skip")
                skipped += 1
                continue
        else:
            print(f"[OK] Verified: {current_dll} is loaded")

        print("")
        print(f"Processing {dll_name}...")
        print("")

        # Run the mapping
        try:
            success = map_ghidra_function_names(output_path, ghidra)
            if success:
                processed += 1
                print(f"\n[SUCCESS] {dll_name} processed successfully!")
            else:
                failed += 1
                print(f"\n[FAILED] {dll_name} processing failed")
        except Exception as e:
            failed += 1
            print(f"\n[ERROR] Exception processing {dll_name}: {e}")

        print("")

    # Final summary
    print("")
    print("=" * 80)
    print("BATCH PROCESSING COMPLETE")
    print("=" * 80)
    print(f"Total DLLs: {len(dll_list)}")
    print(f"Processed: {processed}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {failed}")
    print("")


if __name__ == '__main__':
    main()

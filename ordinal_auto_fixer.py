#!/usr/bin/env python3
"""
Ordinal Auto Fixer - Automatically restore ordinal linkages

This tool:
1. Takes an original DLL file and scans for ordinals
2. Compares with the current binary's ordinals
3. Finds what each ordinal maps to in the new DLL
4. Automatically updates Ghidra with correct names and addresses

Usage:
    python ordinal_auto_fixer.py original_dll.dll updated_dll.dll
    python ordinal_auto_fixer.py original_dll.dll updated_dll.dll --apply
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Tuple, Optional
import requests

try:
    import pefile
except ImportError:
    print("Error: pefile module required. Install with: pip install pefile")
    sys.exit(1)


class DLLOrdinalExtractor:
    """Extract ordinal mappings from PE DLL files"""

    def __init__(self, dll_path: str):
        self.dll_path = Path(dll_path)
        self.pe = None
        self.ordinals: Dict[int, str] = {}

        if not self.dll_path.exists():
            raise FileNotFoundError(f"DLL not found: {dll_path}")

        self._load_dll()

    def _load_dll(self):
        """Load and parse the DLL"""
        try:
            self.pe = pefile.PE(str(self.dll_path))
        except Exception as e:
            raise RuntimeError(f"Failed to load DLL: {e}")

    def extract_ordinals(self) -> Dict[int, str]:
        """Extract all ordinal -> function_name mappings"""
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"Warning: No export table in {self.dll_path}")
            return {}

        ordinals = {}
        try:
            for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if symbol.name:
                    name = symbol.name.decode() if isinstance(symbol.name, bytes) else symbol.name
                    ordinals[symbol.ordinal] = name
        except Exception as e:
            print(f"Error extracting ordinals: {e}")

        self.ordinals = ordinals
        return ordinals

    def get_ordinal_name(self, ordinal_num: int) -> Optional[str]:
        """Get the function name for a specific ordinal"""
        return self.ordinals.get(ordinal_num)

    def get_all_ordinals(self) -> Dict[int, str]:
        """Get all ordinal mappings"""
        return self.ordinals.copy()


class OrdinalAutoFixer:
    """Automatically fix broken ordinal linkages"""

    def __init__(self, ghidra_url: str = "http://127.0.0.1:8089"):
        self.ghidra_url = ghidra_url
        self.original_dll: Optional[DLLOrdinalExtractor] = None
        self.updated_dll: Optional[DLLOrdinalExtractor] = None
        self.mapping: Dict[int, Tuple[str, str]] = {}  # ordinal -> (old_name, new_name)

    def load_dlls(self, original_path: str, updated_path: str):
        """Load both the original and updated DLL files"""
        print("Loading original DLL...")
        self.original_dll = DLLOrdinalExtractor(original_path)
        self.original_dll.extract_ordinals()
        print(f"  Found {len(self.original_dll.ordinals)} ordinals in original")

        print("Loading updated DLL...")
        self.updated_dll = DLLOrdinalExtractor(updated_path)
        self.updated_dll.extract_ordinals()
        print(f"  Found {len(self.updated_dll.ordinals)} ordinals in updated")

    def build_mapping(self) -> Dict[int, Tuple[str, str]]:
        """Build mapping of what each ordinal changed from/to"""
        print("\nBuilding ordinal mapping...")
        mapping = {}

        for ordinal, old_name in self.original_dll.ordinals.items():
            new_name = self.updated_dll.get_ordinal_name(ordinal)

            if new_name:
                if old_name != new_name:
                    mapping[ordinal] = (old_name, new_name)
                    print(f"  Ordinal {ordinal}: {old_name} -> {new_name}")
                else:
                    print(f"  Ordinal {ordinal}: {old_name} (unchanged)")
            else:
                print(f"  WARNING: Ordinal {ordinal} ({old_name}) not found in updated DLL!")

        self.mapping = mapping
        return mapping

    def get_ghidra_imports(self) -> Dict[str, Dict]:
        """Query Ghidra for current external imports"""
        try:
            response = requests.get(f"{self.ghidra_url}/list_imports", timeout=10)
            response.raise_for_status()

            imports = {}
            for line in response.text.strip().split('\n'):
                if " -> " not in line:
                    continue

                parts = line.split(" -> ")
                if len(parts) == 2:
                    func_name = parts[0].strip()
                    address = parts[1].strip()
                    imports[func_name] = address

            return imports
        except requests.exceptions.RequestException as e:
            print(f"Error querying Ghidra: {e}")
            return {}

    def find_broken_imports(self, imports: Dict[str, Dict]) -> Dict[str, str]:
        """Find which imports in Ghidra are using old names"""
        broken = {}

        for ordinal, (old_name, new_name) in self.mapping.items():
            # Check if the old name exists in Ghidra
            if old_name in imports:
                address = imports[old_name]
                broken[old_name] = new_name
                print(f"Found broken import: {old_name} @ {address}")

        return broken

    def generate_repair_script(self, output_file: str = "repair_ordinals.py"):
        """Generate a Ghidra script to repair all broken ordinals"""
        script_content = '''# Auto-generated ordinal repair script
# This script updates broken ordinal-based imports with correct names

from ghidra.util.exception import CancelledException

def repair_ordinals():
    """Repair broken ordinal linkages"""
    refManager = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    repairs = {
'''
        # Add mapping data
        for ordinal, (old_name, new_name) in self.mapping.items():
            script_content += f"        {ordinal}: ('{old_name}', '{new_name}'),\n"

        script_content += '''    }

    print("=" * 80)
    print("ORDINAL REPAIR SCRIPT")
    print("=" * 80)
    print("")

    # Get all external functions
    externalFunctions = currentProgram.getFunctionManager().getExternalFunctions()
    repaired_count = 0

    for func in externalFunctions:
        location = func.getExternalLocation()
        if not location:
            continue

        funcName = location.getLabel()

        # Check if this is one we need to repair
        for ordinal, (old_name, new_name) in repairs.items():
            if funcName == old_name or funcName.startswith("Ordinal_"):
                print("Found broken ordinal: {} -> {}".format(funcName, new_name))
                try:
                    # Update the external function's name
                    func.setName(new_name)
                    repaired_count += 1
                    print("  ✓ Repaired: {} @ {}".format(new_name, func.getEntryPoint()))
                except Exception as e:
                    print("  ✗ Failed to repair: {}".format(str(e)))

    print("")
    print("=" * 80)
    print("REPAIR COMPLETE")
    print("=" * 80)
    print("Repaired {} ordinal linkages".format(repaired_count))
    print("")

try:
    repair_ordinals()
except CancelledException:
    print("Repair cancelled")
'''

        with open(output_file, 'w') as f:
            f.write(script_content)

        print(f"\nGenerated repair script: {output_file}")
        return output_file

    def generate_json_mapping(self, output_file: str = "ordinal_mapping.json"):
        """Generate JSON mapping file"""
        mapping_json = {}
        for ordinal, (old_name, new_name) in self.mapping.items():
            mapping_json[str(ordinal)] = {
                "old_name": old_name,
                "new_name": new_name
            }

        with open(output_file, 'w') as f:
            json.dump(mapping_json, f, indent=2)

        print(f"Generated mapping file: {output_file}")
        return output_file

    def print_summary(self):
        """Print summary of changes"""
        print("\n" + "=" * 80)
        print("ORDINAL MAPPING SUMMARY")
        print("=" * 80)

        if not self.mapping:
            print("No ordinal name changes detected")
            return

        print(f"\nTotal ordinals that changed: {len(self.mapping)}")
        print("\nDetailed changes:")
        print("-" * 80)

        for ordinal in sorted(self.mapping.keys()):
            old_name, new_name = self.mapping[ordinal]
            print(f"Ordinal {ordinal:3d}: {old_name:40s} -> {new_name}")

        print("-" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Automatically fix broken ordinal linkages',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Analyze differences between DLLs
  python ordinal_auto_fixer.py original.dll updated.dll

  # Generate repair script
  python ordinal_auto_fixer.py original.dll updated.dll --script

  # Generate JSON mapping
  python ordinal_auto_fixer.py original.dll updated.dll --json

  # Full workflow (analyze + generate script + JSON)
  python ordinal_auto_fixer.py original.dll updated.dll --script --json
        '''
    )

    parser.add_argument('original_dll', help='Original DLL file path')
    parser.add_argument('updated_dll', help='Updated DLL file path')
    parser.add_argument('--script', action='store_true',
                        help='Generate Ghidra repair script')
    parser.add_argument('--json', action='store_true',
                        help='Generate JSON mapping file')
    parser.add_argument('--ghidra-url', default='http://127.0.0.1:8089',
                        help='Ghidra server URL')

    args = parser.parse_args()

    try:
        fixer = OrdinalAutoFixer(args.ghidra_url)

        # Load both DLLs
        fixer.load_dlls(args.original_dll, args.updated_dll)

        # Build mapping
        fixer.build_mapping()

        # Print summary
        fixer.print_summary()

        # Query Ghidra for current state
        print("\n" + "=" * 80)
        print("GHIDRA INTEGRATION")
        print("=" * 80)
        print("Querying Ghidra for current imports...")

        imports = fixer.get_ghidra_imports()
        if imports:
            print(f"Found {len(imports)} imports in Ghidra")

            # Find broken imports
            broken = fixer.find_broken_imports(imports)
            if broken:
                print(f"\nFound {len(broken)} broken ordinal references:")
                for old_name, new_name in broken.items():
                    print(f"  {old_name} -> {new_name}")
            else:
                print("No broken ordinal references detected")
        else:
            print("Could not query Ghidra (not running?)")

        # Generate output files if requested
        if args.script:
            fixer.generate_repair_script()

        if args.json:
            fixer.generate_json_mapping()

        if not args.script and not args.json:
            print("\nTip: Use --script to generate Ghidra repair script")
            print("Tip: Use --json to generate JSON mapping file")

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

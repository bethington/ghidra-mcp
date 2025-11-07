#!/usr/bin/env python3
r"""
Export DLL Functions and Addresses with Ghidra Mapping

This script performs two phases:

PHASE 1 (Default): Export DLL functions
- Scans a directory for all DLL files
- Exports all exported functions with their addresses
- Creates text files (one per DLL) with format: DLLNAME::FunctionName@address

PHASE 2 (--map-ghidra): Map Ghidra function names
- For the DLL currently loaded in Ghidra
- Reads the text file created in Phase 1
- Queries Ghidra MCP server for function name at each address
- Appends Ghidra function name: DLLNAME::FunctionName@address->GhidraFunctionName

Usage:
    # Phase 1: Export DLL functions
    python export_dll_functions.py F:\PD2_RE --output exports_folder

    # Phase 2: Map Ghidra function names (requires Ghidra MCP server running)
    python export_dll_functions.py --map-ghidra --output exports_folder

Requirements:
    - pip install pefile requests
    - Phase 2 requires Ghidra with GhidraMCP plugin running on port 8089
"""

import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
import os
import json

try:
    import pefile
except ImportError:
    print("Error: pefile module required. Install with: pip install pefile")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Error: requests module required. Install with: pip install requests")
    sys.exit(1)


class DLLExportExtractor:
    """Extract all exports from a single DLL"""

    def __init__(self, dll_path: str):
        self.dll_path = Path(dll_path)
        self.pe = None
        self.exports: Dict[str, Any] = {}

        if not self.dll_path.exists():
            raise FileNotFoundError(f"DLL not found: {dll_path}")

        self._load_dll()

    def _load_dll(self):
        """Load and parse the DLL"""
        try:
            self.pe = pefile.PE(str(self.dll_path))
        except Exception as e:
            raise RuntimeError(f"Failed to load DLL {self.dll_path}: {e}")

    def extract_exports(self) -> Dict[int, Dict[str, Any]]:
        """Extract all exports with their details"""
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return {}

        exports = {}

        try:
            export_table = self.pe.DIRECTORY_ENTRY_EXPORT

            # Get image base
            image_base = self.pe.OPTIONAL_HEADER.ImageBase

            # Get export table RVA
            export_table_rva = self.pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions

            for symbol in export_table.symbols:
                # Get ordinal (always present)
                ordinal = symbol.ordinal
                
                # Get name if available, otherwise use Ordinal_XXX
                if symbol.name:
                    name = symbol.name.decode() if isinstance(symbol.name, bytes) else symbol.name
                else:
                    name = f"Ordinal_{ordinal}"

                # Get RVA (Relative Virtual Address)
                rva = symbol.address

                # Calculate absolute address (what it would be in memory)
                absolute_address = image_base + rva

                # Entry point (actual function address in memory)
                entry_point = absolute_address

                exports[ordinal] = {
                    'name': name,
                    'ordinal': ordinal,
                    'rva': f"0x{rva:x}",  # Relative Virtual Address
                    'absolute_address': f"0x{absolute_address:x}",  # In memory
                    'entry_point': f"0x{entry_point:x}",  # Function entry
                    'offset': rva  # Raw offset for calculations
                }

        except Exception as e:
            print(f"Warning: Error extracting exports from {self.dll_path}: {e}")

        self.exports = exports
        return exports

    def get_dll_info(self) -> Dict[str, Any]:
        """Get metadata about the DLL"""
        try:
            machine_type = self.pe.FILE_HEADER.Machine
            characteristics = self.pe.FILE_HEADER.Characteristics
            is_64bit = machine_type == 0x8664  # Machine.AMD64
            is_32bit = machine_type == 0x014c  # Machine.I386

            return {
                'path': str(self.dll_path),
                'filename': self.dll_path.name,
                'size': self.dll_path.stat().st_size,
                'machine': 'x64' if is_64bit else ('x86' if is_32bit else 'unknown'),
                'image_base': f"0x{self.pe.OPTIONAL_HEADER.ImageBase:x}",
                'entry_point': f"0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}",
                'subsystem': self.pe.OPTIONAL_HEADER.Subsystem,
                'number_of_sections': self.pe.FILE_HEADER.NumberOfSections
            }
        except Exception as e:
            return {'path': str(self.dll_path), 'error': str(e)}

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        return {
            'total_exports': len(self.exports),
            'ordinal_range': [min(self.exports.keys()), max(self.exports.keys())] if self.exports else [0, 0],
            'by_name': sum(1 for e in self.exports.values() if e.get('name')),
            'by_ordinal': len(self.exports)
        }


class DLLExportCollector:
    """Collect exports from multiple DLLs"""

    def __init__(self, directory: str):
        self.directory = Path(directory)
        self.dlls: Dict[str, Dict[str, Any]] = {}

        if not self.directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        if not self.directory.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")

    def scan_directory(self, recursive: bool = True) -> List[Path]:
        """Find all DLL files in directory"""
        pattern = "**/*.dll" if recursive else "*.dll"
        dll_files = list(self.directory.glob(pattern))
        return sorted(dll_files)

    def extract_all(self, recursive: bool = True) -> Dict[str, Dict[str, Any]]:
        """Extract exports from all DLLs"""
        dll_files = self.scan_directory(recursive=recursive)

        print(f"Found {len(dll_files)} DLL files in {self.directory}")
        print("")

        for i, dll_path in enumerate(dll_files, 1):
            dll_name = dll_path.name
            print(f"[{i}/{len(dll_files)}] Processing: {dll_name}...", end=" ")

            try:
                extractor = DLLExportExtractor(str(dll_path))
                exports = extractor.extract_exports()

                if exports:
                    self.dlls[dll_name] = {
                        'info': extractor.get_dll_info(),
                        'exports': exports,
                        'summary': extractor.get_summary()
                    }
                    print(f"[OK] ({len(exports)} exports)")
                else:
                    print("[WARN] (no exports)")

            except Exception as e:
                print(f"[FAIL] Error: {e}")

        return self.dlls


class GhidraIntegration:
    """Integration with Ghidra MCP server for function name mapping"""

    def __init__(self, server_url: str = "http://127.0.0.1:8089"):
        self.server_url = server_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})

    def check_connection(self) -> bool:
        """Check if Ghidra MCP server is running"""
        try:
            response = self.session.get(f"{self.server_url}/check_connection", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    def get_metadata(self) -> Optional[Dict[str, Any]]:
        """Get metadata about the currently loaded program in Ghidra"""
        try:
            response = self.session.get(f"{self.server_url}/get_metadata", timeout=5)
            if response.status_code == 200:
                # Parse text response format (not JSON)
                text = response.text.strip()
                metadata = {}
                for line in text.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        metadata[key.strip().lower().replace(' ', '_')] = value.strip()
                return metadata
            return None
        except Exception as e:
            print(f"Error getting Ghidra metadata: {e}")
            return None

    def get_function_by_address(self, address: str) -> Optional[str]:
        """Get function name at a specific address in Ghidra"""
        try:
            # Ensure address has 0x prefix
            if not address.startswith('0x'):
                address = f"0x{address}"

            url = f"{self.server_url}/get_function_by_address"
            params = {'address': address}
            response = self.session.get(url, params=params, timeout=5)

            if response.status_code == 200:
                # Parse text response format: "Function: FuncName at address"
                text = response.text.strip()
                if text.startswith('Function: '):
                    # Extract function name (between "Function: " and " at ")
                    func_part = text.split('Function: ')[1]
                    func_name = func_part.split(' at ')[0]
                    return func_name
            return None
        except Exception:
            return None

    def get_current_dll_name(self) -> Optional[str]:
        """Get the name of the currently loaded DLL in Ghidra"""
        metadata = self.get_metadata()
        if metadata:
            # Extract the program name (e.g., "D2Common.dll" from path)
            program_name = metadata.get('program_name', '')
            if program_name:
                # Get just the filename
                return Path(program_name).name
        return None


def export_text_list(collector: DLLExportCollector, output_dir: Path):
    """Export each DLL's exports to separate text files in format: DLLNAME::ExportedName@address"""
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    total_lines = 0
    files_created = []
    
    for dll_name, dll_data in sorted(collector.dlls.items()):
        dll_upper = dll_name.upper()
        lines = []
        
        for ordinal, export_data in sorted(dll_data['exports'].items()):
            # Use the actual exported function name from the DLL export table
            exported_name = export_data['name']
            address = export_data['absolute_address'].replace('0x', '')
            line = f"{dll_upper}::{exported_name}@{address}"
            lines.append(line)
        
        if lines:
            # Create filename from DLL name (e.g., D2Common.dll -> D2Common.txt)
            output_file = output_dir / f"{dll_name.replace('.dll', '.txt').replace('.DLL', '.txt')}"
            
            with open(output_file, 'w') as f:
                f.write('\n'.join(lines))
            
            total_lines += len(lines)
            files_created.append(output_file.name)
    
    return total_lines, files_created


def map_ghidra_function_names(output_dir: Path, ghidra: GhidraIntegration) -> bool:
    """
    Add Ghidra function name mappings to text files.

    For the DLL currently loaded in Ghidra, reads its text file and appends
    the Ghidra function name after each line: DLLNAME::ExportName@address->GhidraFuncName

    Args:
        output_dir: Directory containing the text export files
        ghidra: GhidraIntegration instance for querying Ghidra

    Returns:
        True if successful, False otherwise
    """
    # Step 1: Get the currently loaded DLL name from Ghidra
    print("")
    print("=" * 80)
    print("MAPPING GHIDRA FUNCTION NAMES")
    print("=" * 80)
    print("")

    dll_name = ghidra.get_current_dll_name()
    if not dll_name:
        print("[ERROR] Could not determine currently loaded DLL in Ghidra")
        print("        Make sure a program is loaded in Ghidra's CodeBrowser")
        return False

    print(f"[OK] Currently loaded DLL in Ghidra: {dll_name}")

    # Step 2: Find the corresponding text file
    text_file = output_dir / f"{dll_name.replace('.dll', '.txt').replace('.DLL', '.txt')}"

    if not text_file.exists():
        print(f"[ERROR] Text file not found: {text_file}")
        print(f"        Run the export phase first without --map-ghidra")
        return False

    print(f"[OK] Found export file: {text_file.name}")
    print("")

    # Step 3: Read the file and process each line
    print("Processing lines and querying Ghidra...")
    print("")

    with open(text_file, 'r') as f:
        lines = f.readlines()

    mapped_lines = []
    success_count = 0
    fail_count = 0

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        # Parse line format: DLLNAME::ExportName@address
        try:
            # Extract address (after '@')
            if '@' not in line:
                print(f"[WARN] Line {i}: Invalid format (no '@'): {line}")
                mapped_lines.append(line)
                fail_count += 1
                continue

            address_part = line.split('@')[1]

            # Query Ghidra for function name at this address
            ghidra_func_name = ghidra.get_function_by_address(address_part)

            if ghidra_func_name:
                # Append Ghidra function name
                mapped_line = f"{line}->{ghidra_func_name}"
                mapped_lines.append(mapped_line)
                success_count += 1

                # Progress indicator every 10 lines
                if i % 10 == 0:
                    print(f"  [{i}/{len(lines)}] Processed {success_count} successful, {fail_count} failed")
            else:
                # No function at this address in Ghidra
                mapped_lines.append(line)
                fail_count += 1

        except Exception as e:
            print(f"[WARN] Line {i}: Error processing: {e}")
            mapped_lines.append(line)
            fail_count += 1

    # Step 4: Write the mapped lines back to the file
    with open(text_file, 'w') as f:
        f.write('\n'.join(mapped_lines))

    print("")
    print(f"[OK] Mapping complete!")
    print(f"  Total lines: {len(lines)}")
    print(f"  Successful mappings: {success_count}")
    print(f"  Failed/unmapped: {fail_count}")
    print(f"  Output file: {text_file}")
    print("")

    return True


def main():
    parser = argparse.ArgumentParser(
        description='Extract and export DLL function names and addresses to text files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Export all DLLs from default directory
  python export_dll_functions.py

  # Export from specific directory
  python export_dll_functions.py F:\\OtherFolder

  # Save to specific output directory
  python export_dll_functions.py --output my_exports

  # Non-recursive (top level only)
  python export_dll_functions.py --no-recursive

  # Map Ghidra function names to existing export file
  python export_dll_functions.py --map-ghidra --output dll_exports

  # Map with custom Ghidra server URL
  python export_dll_functions.py --map-ghidra --ghidra-server http://localhost:8089
        '''
    )

    parser.add_argument('directory', nargs='?', default='F:\\PD2_RE',
                        help='Directory to scan for DLL files (default: F:\\PD2_RE)')
    parser.add_argument('-o', '--output', type=str, default='dll_exports',
                        help='Output directory for text files (default: dll_exports)')
    parser.add_argument('--no-recursive', action='store_true',
                        help='Only scan top-level directory (not recursive)')
    parser.add_argument('--map-ghidra', action='store_true',
                        help='Add Ghidra function name mappings to text file (requires Ghidra MCP server)')
    parser.add_argument('--ghidra-server', type=str, default='http://127.0.0.1:8089',
                        help='Ghidra MCP server URL (default: http://127.0.0.1:8089)')

    args = parser.parse_args()

    try:
        # Check if we're doing the mapping phase only
        if args.map_ghidra:
            # Phase 2: Map Ghidra function names to existing export files
            print("=" * 80)
            print("GHIDRA FUNCTION NAME MAPPING")
            print("=" * 80)
            print("")
            print(f"Ghidra MCP Server: {args.ghidra_server}")
            print("")

            # Initialize Ghidra integration
            ghidra = GhidraIntegration(server_url=args.ghidra_server)

            # Check connection
            print("Checking connection to Ghidra MCP server...", end=" ")
            if not ghidra.check_connection():
                print("[FAIL]")
                print("")
                print("Error: Could not connect to Ghidra MCP server")
                print(f"       Make sure Ghidra is running with the GhidraMCP plugin at {args.ghidra_server}")
                sys.exit(1)
            print("[OK]")

            # Perform mapping
            output_path = Path(args.output)
            success = map_ghidra_function_names(output_path, ghidra)

            if success:
                print("=" * 80)
                print("MAPPING COMPLETE")
                print("=" * 80)
                print(f"Format: DLLNAME::FunctionName@address->GhidraFunctionName")
                print("")
            else:
                print("=" * 80)
                print("MAPPING FAILED")
                print("=" * 80)
                sys.exit(1)

        else:
            # Phase 1: Extract DLL exports (normal mode)
            print("=" * 80)
            print("DLL EXPORT EXTRACTOR")
            print("=" * 80)
            print("")

            # Create collector
            collector = DLLExportCollector(args.directory)

            # Extract all exports
            recursive = not args.no_recursive
            collector.extract_all(recursive=recursive)

            print("")
            print("=" * 80)
            print("GENERATING OUTPUT")
            print("=" * 80)
            print("")

            # Write text list (primary output) - separate file per DLL
            output_path = Path(args.output)
            line_count, files_created = export_text_list(collector, output_path)
            print(f"[OK] Exported text files to: {output_path}/")
            print(f"  Files created: {len(files_created)}")
            print(f"  Total lines: {line_count:,}")

            # Print summary
            print("")
            print("=" * 80)
            print("SUMMARY")
            print("=" * 80)
            print(f"DLLs processed: {len(collector.dlls)}")
            print(f"Total exports: {sum(d['summary']['total_exports'] for d in collector.dlls.values())}")
            print("")

            for dll_name, dll_data in sorted(collector.dlls.items()):
                summary = dll_data['summary']
                print(f"{dll_name}:")
                print(f"  Exports: {summary['total_exports']}")
                print(f"  Ordinal range: {summary['ordinal_range'][0]}-{summary['ordinal_range'][1]}")
                print(f"  By name: {summary['by_name']}")
                print("")

            print("=" * 80)
            print("EXPORT COMPLETE")
            print("=" * 80)
            print("")
            print(f"Output directory: {output_path}/")
            print(f"Format: DLLNAME::FunctionName@address")
            print("")
            print("Next step: Run with --map-ghidra to add Ghidra function name mappings")
            print("")

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

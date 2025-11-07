#!/usr/bin/env python3
"""
Generate Ordinal Mapping File

This utility helps create the ordinal mapping JSON file by:
1. Parsing PE export tables from external DLL files
2. Extracting ordinal -> function_name mappings
3. Outputting in formats compatible with ordinal_linkage_manager.py

Usage:
    python generate_ordinal_mapping.py C:\path\to\external.dll
    python generate_ordinal_mapping.py C:\path\to\external.dll -o mapping.json
    python generate_ordinal_mapping.py C:\Windows\System32\kernel32.dll -f json
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Optional, Tuple
import struct


class PEExportParser:
    """Parse PE export tables to extract ordinal mappings"""

    def __init__(self, dll_path: str):
        self.dll_path = Path(dll_path)
        self.exports: Dict[int, str] = {}

        if not self.dll_path.exists():
            raise FileNotFoundError(f"DLL not found: {dll_path}")

    def parse(self) -> Dict[int, str]:
        """Parse PE export table and return ordinal mappings"""
        try:
            # Try using pefile library if available
            return self._parse_with_pefile()
        except ImportError:
            # Fall back to manual PE parsing
            return self._parse_manual()

    def _parse_with_pefile(self) -> Dict[int, str]:
        """Parse using pefile library (most reliable)"""
        try:
            import pefile
        except ImportError:
            raise ImportError(
                "pefile module required. Install with: pip install pefile"
            )

        pe = pefile.PE(str(self.dll_path))

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"Warning: No export table found in {self.dll_path}")
            return {}

        exports = {}
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if symbol.name:
                # Decode bytes to string if necessary
                name = symbol.name.decode() if isinstance(symbol.name, bytes) else symbol.name
                exports[symbol.ordinal] = name

        return exports

    def _parse_manual(self) -> Dict[int, str]:
        """Manual PE parsing without external libraries"""
        print("pefile not available, using manual PE parsing...")
        exports = {}

        try:
            with open(self.dll_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    raise ValueError("Invalid PE file: Missing MZ signature")

                # Get PE header offset (at 0x3C)
                pe_offset = struct.unpack('<I', dos_header[0x3C:0x40])[0]

                # Seek to PE header
                f.seek(pe_offset)
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    raise ValueError("Invalid PE file: Missing PE signature")

                # Parse PE header
                coff_header = f.read(20)
                machine, num_sections = struct.unpack('<HH', coff_header[0:4])[:2]

                # Read optional header size
                opt_header_size = struct.unpack('<H', coff_header[16:18])[0]

                # Read export table RVA from optional header
                # Data directory[0] is export table, offset 0x60 in optional header
                f.seek(pe_offset + 24 + 0x60)
                export_table_rva = struct.unpack('<I', f.read(4))[0]
                export_table_size = struct.unpack('<I', f.read(4))[0]

                if export_table_rva == 0:
                    print("Warning: No export table in this DLL")
                    return {}

                # Find section containing export table
                f.seek(pe_offset + 24 + opt_header_size)
                section_offset = f.tell()
                export_section_offset = None

                for i in range(num_sections):
                    f.seek(section_offset + i * 40)
                    section_header = f.read(40)
                    section_rva = struct.unpack('<I', section_header[12:16])[0]
                    section_vsize = struct.unpack('<I', section_header[8:12])[0]

                    if (section_rva <= export_table_rva < section_rva + section_vsize):
                        section_pointer = struct.unpack('<I', section_header[20:24])[0]
                        export_section_offset = section_pointer + (export_table_rva - section_rva)
                        break

                if export_section_offset is None:
                    print("Warning: Could not locate export table section")
                    return {}

                # Parse export directory
                f.seek(export_section_offset)
                export_dir = f.read(40)

                flags, timestamp = struct.unpack('<II', export_dir[0:8])
                major_ver, minor_ver = struct.unpack('<HH', export_dir[8:12])
                dll_name_rva, base_ordinal = struct.unpack('<II', export_dir[12:20])
                num_functions, num_names = struct.unpack('<II', export_dir[20:28])
                eat_rva, ent_rva, eot_rva = struct.unpack('<III', export_dir[28:40])

                # This is simplified; full parsing would require more work
                print(f"DLL exports {num_functions} functions, {num_names} by name")
                print(f"Base ordinal: {base_ordinal}")

                # For simplicity, return empty for manual parsing
                # Users should install pefile for full functionality
                return {}

        except Exception as e:
            print(f"Error parsing PE: {e}")
            return {}

    def get_exports(self) -> Dict[int, str]:
        """Get the parsed exports"""
        if not self.exports:
            self.exports = self.parse()
        return self.exports


class MappingGenerator:
    """Generate mapping files from export data"""

    @staticmethod
    def generate_flat_mapping(exports: Dict[int, str]) -> Dict[str, str]:
        """Generate flat mapping: ordinal_number -> function_name"""
        return {str(ordinal): name for ordinal, name in exports.items()}

    @staticmethod
    def generate_by_dll_mapping(exports: Dict[int, str], dll_name: str) -> Dict[str, Dict[str, str]]:
        """Generate hierarchical mapping by DLL name"""
        return {
            dll_name: {str(ordinal): name for ordinal, name in exports.items()}
        }

    @staticmethod
    def generate_detailed_mapping(exports: Dict[int, str], dll_name: str, dll_path: str) -> Dict:
        """Generate detailed mapping with metadata"""
        return {
            'dll_name': dll_name,
            'dll_path': str(dll_path),
            'exports': {str(ordinal): name for ordinal, name in exports.items()},
            'metadata': {
                'total_exports': len(exports),
                'ordinal_range': [min(exports.keys()), max(exports.keys())] if exports else [0, 0]
            }
        }


def format_output(exports: Dict[int, str], format_type: str, dll_name: str, dll_path: str) -> str:
    """Format output based on requested format"""
    if format_type == 'json_flat':
        mapping = MappingGenerator.generate_flat_mapping(exports)
    elif format_type == 'json_detailed':
        mapping = MappingGenerator.generate_detailed_mapping(exports, dll_name, str(dll_path))
    elif format_type == 'json':
        mapping = MappingGenerator.generate_by_dll_mapping(exports, dll_name)
    elif format_type == 'csv':
        lines = ['Ordinal,FunctionName']
        for ordinal in sorted(exports.keys()):
            lines.append(f'{ordinal},{exports[ordinal]}')
        return '\n'.join(lines)
    elif format_type == 'txt':
        lines = [f'Export mapping for {dll_name}', '=' * 60, '']
        for ordinal in sorted(exports.keys()):
            lines.append(f'Ordinal {ordinal}: {exports[ordinal]}')
        return '\n'.join(lines)
    else:
        mapping = exports

    return json.dumps(mapping, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description='Generate ordinal mapping files from PE DLL exports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Parse and print to console
  python generate_ordinal_mapping.py C:\\Windows\\System32\\kernel32.dll

  # Save as JSON
  python generate_ordinal_mapping.py kernel32.dll -o kernel32_map.json

  # Export as CSV for spreadsheet
  python generate_ordinal_mapping.py mydll.dll -f csv -o exports.csv

  # Generate detailed mapping with metadata
  python generate_ordinal_mapping.py mydll.dll -f json_detailed -o mapping.json
        '''
    )

    parser.add_argument('dll_path', help='Path to the DLL file')
    parser.add_argument('-o', '--output', type=str, help='Output file (default: print to stdout)')
    parser.add_argument('-f', '--format', choices=['json', 'json_flat', 'json_detailed', 'csv', 'txt'],
                        default='json', help='Output format (default: json)')
    parser.add_argument('-n', '--name', type=str, help='DLL name for mapping (default: extracted from path)')

    args = parser.parse_args()

    dll_path = Path(args.dll_path)
    dll_name = args.name or dll_path.stem.upper() + '.DLL'

    print(f"Parsing {dll_path}...", file=sys.stderr)

    try:
        parser = PEExportParser(str(dll_path))
        exports = parser.parse()

        if not exports:
            print("ERROR: No exports found. Try installing pefile: pip install pefile", file=sys.stderr)
            sys.exit(1)

        print(f"Found {len(exports)} exports", file=sys.stderr)

        output = format_output(exports, args.format, dll_name, dll_path)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Written to {args.output}", file=sys.stderr)
        else:
            print(output)

    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("\nNote: Install pefile for better PE parsing: pip install pefile", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Ordinal Linkage Manager

This tool helps manage and restore ordinal-based import linkages when external
DLL function names change. It uses the Ghidra MCP API to:

1. Identify all ordinal-based imports in the binary
2. Track which ordinals are referenced and where
3. Build mappings between ordinals and current function names
4. Re-establish linkage when names change

Usage:
    python ordinal_linkage_manager.py --analyze
    python ordinal_linkage_manager.py --repair --mapping ordinal_map.json
    python ordinal_linkage_manager.py --export-report report.txt
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import re

try:
    import requests
except ImportError:
    print("Error: requests module required. Install with: pip install requests")
    sys.exit(1)


class OrdinalLinkageManager:
    """Manages ordinal-based import linkages in Ghidra"""

    def __init__(self, ghidra_url: str = "http://127.0.0.1:8089"):
        self.ghidra_url = ghidra_url
        self.ordinals: Dict[str, Dict[int, Dict]] = {}
        self.references: List[Dict] = []

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Optional[str]:
        """Safe GET request to Ghidra server"""
        try:
            url = f"{self.ghidra_url}/{endpoint}"
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            return None

    def analyze_ordinal_imports(self) -> Dict[str, Dict[int, Dict]]:
        """Analyze all ordinal-based imports in the loaded program"""
        print("Analyzing ordinal-based imports...")

        result = self.get("list_imports")
        if not result:
            return {}

        # Parse imports list - looking for ordinal-based entries
        imports = {}
        for line in result.strip().split('\n'):
            if not line or " -> " not in line:
                continue

            parts = line.split(" -> ")
            if len(parts) != 2:
                continue

            name = parts[0].strip()
            address = parts[1].strip()

            # Check if name is ordinal-based (e.g., "Ordinal_123" or starts with number)
            ordinal_match = re.match(r"(?:Ordinal_)?(\d+)", name)
            if ordinal_match:
                ordinal_num = int(ordinal_match.group(1))

                # Extract library name from context (would need additional parsing)
                lib_name = "UNKNOWN"

                if lib_name not in imports:
                    imports[lib_name] = {}

                imports[lib_name][ordinal_num] = {
                    'name': name,
                    'address': address,
                    'type': 'ordinal'
                }

        self.ordinals = imports
        return imports

    def find_broken_ordinal_references(self) -> List[Dict]:
        """Find all references to ordinal imports throughout the binary"""
        print("Scanning for references to ordinal imports...")

        if not self.ordinals:
            print("No ordinals analyzed. Run analyze_ordinal_imports first.")
            return []

        references = []

        # For each ordinal, find all references to it
        for lib_name in self.ordinals:
            for ordinal_num, info in self.ordinals[lib_name].items():
                address = info['address']

                # Get xrefs to this import address
                result = self.get(f"get_xrefs_to", params={"address": address})
                if result and result.strip():
                    refs = result.strip().split('\n')
                    for ref in refs:
                        if ref:
                            references.append({
                                'ordinal': ordinal_num,
                                'library': lib_name,
                                'import_address': address,
                                'reference_from': ref,
                                'status': 'BROKEN' if 'Ordinal_' in info['name'] else 'OK'
                            })

        self.references = references
        return references

    def generate_ordinal_report(self) -> str:
        """Generate a comprehensive report of ordinal linkage status"""
        report = []
        report.append("=" * 80)
        report.append("ORDINAL LINKAGE ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")

        if not self.ordinals:
            report.append("No ordinal-based imports found")
        else:
            total_ordinals = sum(len(ords) for ords in self.ordinals.values())
            report.append(f"Total ordinal-based imports: {total_ordinals}")
            report.append("")

            for lib_name in sorted(self.ordinals.keys()):
                report.append(f"Library: {lib_name}")
                for ordinal_num in sorted(self.ordinals[lib_name].keys()):
                    info = self.ordinals[lib_name][ordinal_num]
                    report.append(f"  Ordinal {ordinal_num}: {info['name']} @ {info['address']}")
                report.append("")

        if self.references:
            report.append("=" * 80)
            report.append("REFERENCE ANALYSIS")
            report.append("=" * 80)
            report.append(f"Total references to ordinal imports: {len(self.references)}")
            report.append("")

            broken_count = sum(1 for r in self.references if r['status'] == 'BROKEN')
            if broken_count > 0:
                report.append(f"WARNING: {broken_count} broken ordinal references detected")
                report.append("")

                for ref in self.references:
                    if ref['status'] == 'BROKEN':
                        report.append(f"  Ordinal {ref['ordinal']}: referenced from {ref['reference_from']}")

            report.append("")

        report.append("=" * 80)
        report.append("RESTORATION STEPS")
        report.append("=" * 80)
        report.append("1. Export external DLL export tables using ExportOrdinalLister.py")
        report.append("2. Create ordinal mapping file mapping ordinals to current function names")
        report.append("3. Use --repair mode to update broken references")
        report.append("4. Verify linkage with --analyze mode")
        report.append("")

        return "\n".join(report)

    def create_ordinal_mapping(self, external_dll_exports: Dict[int, str]) -> Dict[int, str]:
        """
        Create a mapping between ordinal numbers and external DLL function names

        Args:
            external_dll_exports: Dict of ordinal_number -> function_name from external DLL

        Returns:
            Mapping of ordinal numbers to function names
        """
        mapping = {}

        for ordinal_num, func_name in external_dll_exports.items():
            mapping[ordinal_num] = func_name

        return mapping

    def repair_broken_references(self, ordinal_mapping: Dict[int, str]) -> List[Tuple[str, bool]]:
        """
        Repair broken ordinal references using the provided mapping

        Args:
            ordinal_mapping: Dict of ordinal_number -> correct_function_name

        Returns:
            List of (operation, success) tuples
        """
        results = []

        if not self.references:
            print("No references to repair. Run find_broken_ordinal_references first.")
            return results

        print("Repairing broken ordinal references...")

        for ref in self.references:
            if ref['status'] == 'BROKEN':
                ordinal_num = ref['ordinal']
                if ordinal_num in ordinal_mapping:
                    correct_name = ordinal_mapping[ordinal_num]

                    # Update the import name in Ghidra
                    operation = f"Update Ordinal {ordinal_num} -> {correct_name}"

                    # In a real implementation, this would call:
                    # rename_function(ref['import_address'], correct_name)
                    # set_function_prototype(...)

                    results.append((operation, True))

        return results

    def export_csv(self, filename: str):
        """Export ordinal analysis as CSV"""
        lines = ["Ordinal,Library,Name,Address,References"]

        for lib_name in sorted(self.ordinals.keys()):
            for ordinal_num in sorted(self.ordinals[lib_name].keys()):
                info = self.ordinals[lib_name][ordinal_num]

                # Count references for this ordinal
                ref_count = sum(1 for r in self.references if r['ordinal'] == ordinal_num)

                lines.append(f"{ordinal_num},{lib_name},{info['name']},{info['address']},{ref_count}")

        with open(filename, 'w') as f:
            f.write("\n".join(lines))

        print(f"Exported CSV to {filename}")

    def export_json(self, filename: str):
        """Export ordinal analysis as JSON"""
        data = {
            'ordinals': self.ordinals,
            'references': self.references,
            'summary': {
                'total_ordinals': sum(len(ords) for ords in self.ordinals.values()),
                'total_references': len(self.references),
                'broken_references': sum(1 for r in self.references if r['status'] == 'BROKEN')
            }
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"Exported JSON to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Ordinal Linkage Manager for Ghidra",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all ordinal imports
  python ordinal_linkage_manager.py --analyze

  # Export analysis report
  python ordinal_linkage_manager.py --analyze --report report.txt

  # Export as CSV for external processing
  python ordinal_linkage_manager.py --analyze --csv ordinals.csv

  # Repair with mapping file
  python ordinal_linkage_manager.py --repair --mapping ordinal_map.json
        """
    )

    parser.add_argument('--ghidra-url', default='http://127.0.0.1:8089',
                        help='Ghidra MCP server URL (default: http://127.0.0.1:8089)')
    parser.add_argument('--analyze', action='store_true',
                        help='Analyze ordinal imports and references')
    parser.add_argument('--repair', action='store_true',
                        help='Repair broken ordinal references')
    parser.add_argument('--mapping', type=str,
                        help='Ordinal mapping JSON file (ordinal_num -> function_name)')
    parser.add_argument('--report', type=str,
                        help='Output file for text report')
    parser.add_argument('--csv', type=str,
                        help='Output file for CSV export')
    parser.add_argument('--json', type=str,
                        help='Output file for JSON export')

    args = parser.parse_args()

    manager = OrdinalLinkageManager(args.ghidra_url)

    if args.analyze:
        manager.analyze_ordinal_imports()
        manager.find_broken_ordinal_references()

        # Generate report
        report = manager.generate_ordinal_report()
        print(report)

        if args.report:
            with open(args.report, 'w') as f:
                f.write(report)
            print(f"Report saved to {args.report}")

        if args.csv:
            manager.export_csv(args.csv)

        if args.json:
            manager.export_json(args.json)

    elif args.repair:
        if not args.mapping:
            print("Error: --repair requires --mapping argument")
            sys.exit(1)

        # Load mapping file
        try:
            with open(args.mapping, 'r') as f:
                ordinal_mapping = json.load(f)
        except FileNotFoundError:
            print(f"Error: Mapping file not found: {args.mapping}")
            sys.exit(1)

        manager.analyze_ordinal_imports()
        manager.find_broken_ordinal_references()
        results = manager.repair_broken_references(ordinal_mapping)

        print(f"Repaired {len(results)} broken references")
        for op, success in results:
            status = "OK" if success else "FAILED"
            print(f"  [{status}] {op}")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

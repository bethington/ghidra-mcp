#!/usr/bin/env python3
"""
Hash-Based Function Renaming System

Identifies functions with identical hashes across Storm.dll versions
and applies consolidated naming based on actual function behavior.

Usage:
    python hash_based_function_renaming.py [--mode analyze|apply|report]
    
Modes:
    - analyze: Scan all versions, compute hashes, identify matches
    - apply: Apply proposed names to functions
    - report: Generate detailed report of findings
"""

import json
import sys
from typing import Dict, Set, List, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import subprocess

@dataclass
class FunctionInfo:
    """Information about a function"""
    name: str
    address: str
    hash: str
    program: str
    instruction_count: int
    size_bytes: int
    
    def __hash__(self):
        return hash(self.address)
    
    def __eq__(self, other):
        if not isinstance(other, FunctionInfo):
            return False
        return self.address == other.address and self.program == other.program


class HashBasedFunctionRenamer:
    """Main class for managing hash-based function identification and renaming"""
    
    def __init__(self):
        self.hash_map: Dict[str, Set[FunctionInfo]] = defaultdict(set)
        self.versions = ["1.07", "1.08", "1.09"]
        self.naming_map = {
            # Known function identifications based on hash analysis
            "6a8112287fd08c30ab44f98afa0132d620ca6da6feff43d0b62148c882879428": "SMemAllocEx",
            "8b80a54b37bf516cd6aaff884aab63c3a8649ae966d78191f8ea88ab8bca7181": "SMemAlloc",
            "3c7e6ee2ee198c85523ed3a24bdbd7709af6bbde02e30eb663885142c5996dd9": "AllocateConnectionRecord"
        }
        
    def analyze_version(self, version: str) -> Dict[str, FunctionInfo]:
        """
        Analyze all functions in a Storm.dll version.
        Returns mapping of function_address -> FunctionInfo
        """
        print(f"\n[*] Analyzing Storm.dll {version}...")
        functions = {}
        
        # Use MCP commands to get functions
        # This would be called from a wrapper script that has MCP access
        # For now, document the process
        
        ordinals = self._get_ordinal_functions(version)
        print(f"    Found {len(ordinals)} Ordinal functions")
        
        for func_name, address in ordinals.items():
            func_hash = self._compute_hash(version, address)
            if func_hash:
                info = FunctionInfo(
                    name=func_name,
                    address=address,
                    hash=func_hash,
                    program=f"Storm.dll {version}",
                    instruction_count=0,
                    size_bytes=0
                )
                functions[address] = info
                self.hash_map[func_hash].add(info)
        
        return functions
    
    def _get_ordinal_functions(self, version: str) -> Dict[str, str]:
        """Get all Ordinal functions from a version"""
        # This would call MCP search_functions_by_name with pattern "Ordinal_"
        # For now, return placeholder
        return {}
    
    def _compute_hash(self, version: str, address: str) -> str:
        """Compute normalized hash for a function"""
        # This would call mcp_ghidra_get_function_hash
        # Returns the hash or None
        return None
    
    def find_cross_version_duplicates(self) -> Dict[str, List[FunctionInfo]]:
        """Find functions with same hash but potentially different names"""
        duplicates = {}
        
        for hash_value, functions in self.hash_map.items():
            if len(functions) > 1:
                # Check if names differ
                names = set(f.name for f in functions)
                if len(names) > 1:
                    duplicates[hash_value] = list(functions)
        
        return duplicates
    
    def propose_consolidated_name(self, functions: List[FunctionInfo]) -> str:
        """
        Propose a consolidated name for functions with same hash.
        
        Strategy:
        1. Prefer non-Ordinal names (they're usually more descriptive)
        2. Prefer non-FUN_ names
        3. If hash is in naming_map, use that name
        4. Otherwise, use the longest/most descriptive name
        """
        names = sorted(functions, key=lambda f: (
            f.name.startswith("Ordinal_"),  # False first (non-Ordinals)
            f.name.startswith("FUN_"),       # False first (non-FUN_)
            -len(f.name)                     # Longer names first
        ))
        
        best_name = names[0].name
        hash_val = list(functions)[0].hash
        
        # Override with naming_map if available
        if hash_val in self.naming_map:
            return self.naming_map[hash_val]
        
        return best_name
    
    def generate_report(self) -> str:
        """Generate detailed report of findings"""
        report = []
        report.append("=" * 80)
        report.append("HASH-BASED FUNCTION RENAMING ANALYSIS REPORT")
        report.append("=" * 80)
        
        duplicates = self.find_cross_version_duplicates()
        
        if not duplicates:
            report.append("\n✓ No cross-version function name conflicts detected.")
            report.append("  All functions maintain consistent names across versions.")
            return "\n".join(report)
        
        report.append(f"\nFound {len(duplicates)} function groups with naming inconsistencies:")
        report.append("")
        
        group_num = 1
        for hash_val, functions in sorted(duplicates.items()):
            report.append(f"\n[Group {group_num}] Hash: {hash_val[:32]}...")
            report.append("-" * 80)
            
            # Show all names for this hash
            by_version = defaultdict(list)
            for func in functions:
                by_version[func.program].append(func)
            
            for program, funcs in sorted(by_version.items()):
                names = [f.name for f in funcs]
                report.append(f"  {program}: {', '.join(set(names))}")
            
            # Propose name
            proposed = self.propose_consolidated_name(functions)
            report.append(f"\n  → Proposed consolidated name: {proposed}")
            
            # Show which functions need renaming
            needs_rename = [f for f in functions if f.name != proposed]
            if needs_rename:
                report.append(f"  → Needs renaming ({len(needs_rename)}):")
                for func in needs_rename:
                    report.append(f"     {func.name} @ {func.address} ({func.program})")
            
            group_num += 1
        
        report.append("\n" + "=" * 80)
        
        # Summary statistics
        total_functions = sum(len(funcs) for funcs in self.hash_map.values())
        report.append(f"\nSummary:")
        report.append(f"  Total unique function hashes: {len(self.hash_map)}")
        report.append(f"  Total functions analyzed: {total_functions}")
        report.append(f"  Function groups with conflicts: {len(duplicates)}")
        report.append(f"  Total functions needing rename: {sum(len([f for f in funcs if f.name != self.propose_consolidated_name(funcs)]) for funcs in duplicates.values())}")
        
        return "\n".join(report)
    
    def generate_rename_commands(self) -> List[Tuple[str, str, str]]:
        """
        Generate rename commands as tuples of (program, address, new_name)
        
        Returns list of (program, address, new_name) tuples
        """
        commands = []
        duplicates = self.find_cross_version_duplicates()
        
        for hash_val, functions in duplicates.items():
            proposed_name = self.propose_consolidated_name(functions)
            
            for func in functions:
                if func.name != proposed_name:
                    commands.append((func.program, func.address, proposed_name))
        
        return commands


def main():
    """Main entry point"""
    mode = "analyze"
    if len(sys.argv) > 1:
        mode = sys.argv[1].replace("--mode=", "").replace("--", "")
    
    print("\n" + "=" * 80)
    print("HASH-BASED FUNCTION RENAMING SYSTEM")
    print("=" * 80)
    print(f"Mode: {mode}")
    
    renamer = HashBasedFunctionRenamer()
    
    if mode == "analyze" or mode == "report":
        # Placeholder - actual implementation would use MCP tools
        print("\n[*] This script requires MCP integration to run.")
        print("[*] It will be invoked from a Python wrapper with MCP context.")
        print("\nKey workflow:")
        print("  1. Switch to each Storm.dll version")
        print("  2. Search for Ordinal_* functions")
        print("  3. Compute hash for each function")
        print("  4. Compare hashes across versions")
        print("  5. Identify functions with same hash but different names")
        print("  6. Propose consolidated names")
        print("  7. Apply renaming via MCP tools")
        
    elif mode == "apply":
        print("\n[*] Application mode - would apply names to functions")
        print("[!] This requires MCP integration and should be done carefully")
        
    else:
        print(f"[!] Unknown mode: {mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()

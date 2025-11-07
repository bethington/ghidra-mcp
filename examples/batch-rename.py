#!/usr/bin/env python3
"""
Example: Batch rename functions and variables

This example demonstrates how to:
- Find functions matching a pattern
- Extract meaningful names based on analysis
- Rename functions and their variables atomically
- Track rename statistics

Usage:
    python batch-rename.py
"""

import requests
import json
import re
from typing import List, Dict, Tuple

GHIDRA_API_BASE = "http://127.0.0.1:8089"
TIMEOUT = 30

def search_functions_enhanced(pattern: str, min_xrefs: int = 0) -> List[Dict]:
    """Search for functions matching criteria."""
    url = f"{GHIDRA_API_BASE}/search_functions_enhanced"
    
    params = {
        "name_pattern": pattern,
        "min_xrefs": min_xrefs,
        "sort_by": "xref_count"
    }
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    data = response.json()
    return data.get("results", [])

def decompile_function(name: str) -> str:
    """Get decompiled code to help generate meaningful names."""
    url = f"{GHIDRA_API_BASE}/decompile_function"
    params = {"name": name}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.text

def rename_function(old_name: str, new_name: str) -> Dict:
    """Rename a function."""
    url = f"{GHIDRA_API_BASE}/rename_function"
    
    params = {
        "old_name": old_name,
        "new_name": new_name
    }
    
    response = requests.post(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def get_function_variables(function_name: str) -> List[Dict]:
    """Get all variables in a function."""
    url = f"{GHIDRA_API_BASE}/get_function_variables"
    params = {"function_name": function_name}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def rename_variable(function_name: str, old_name: str, new_name: str) -> Dict:
    """Rename a local variable in a function."""
    url = f"{GHIDRA_API_BASE}/rename_variable"
    
    params = {
        "function_name": function_name,
        "old_name": old_name,
        "new_name": new_name
    }
    
    response = requests.post(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def generate_function_name(decompiled_code: str, default_name: str) -> str:
    """
    Generate a meaningful function name based on decompiled code patterns.
    This is a simple heuristic; real implementation would be more sophisticated.
    """
    code_lower = decompiled_code.lower()
    
    # Pattern matching for common function types
    patterns = {
        "initialize": r"(initialize|init|setup|configure|allocate)",
        "cleanup": r"(cleanup|destroy|finalize|free|release|exit)",
        "validate": r"(validate|verify|check|test|assert)",
        "process": r"(process|handle|execute|run|perform)",
        "parse": r"(parse|decode|deserialize|unpack)",
        "serialize": r"(serialize|encode|pack|format)",
        "calculate": r"(calculate|compute|eval|sum|count)",
        "search": r"(search|find|lookup|query)",
    }
    
    for name_prefix, pattern in patterns.items():
        if re.search(pattern, code_lower):
            return name_prefix
    
    return default_name

def suggest_variable_renames(decompiled_code: str) -> Dict[str, str]:
    """Suggest meaningful variable names based on code patterns."""
    suggestions = {}
    
    # Simple heuristics for common variable patterns
    if re.search(r"unaff_", decompiled_code):
        suggestions["unaff_EBP"] = "local_storage"
        suggestions["unaff_EBX"] = "loop_counter"
    
    if re.search(r"param_1.*\*", decompiled_code):
        suggestions["param_1"] = "ptr_data"
    
    if re.search(r"iVar\d+.*size|length", decompiled_code):
        suggestions["iVar1"] = "size"
        suggestions["iVar2"] = "count"
    
    return suggestions

def main():
    """Main batch rename workflow."""
    print("=" * 70)
    print("BATCH FUNCTION RENAME WORKFLOW")
    print("=" * 70)
    
    # Find candidate functions (auto-named functions with multiple cross-references)
    print("\n[1/3] Finding candidate functions...")
    print("      Searching for FUN_* with 2+ cross-references...")
    
    try:
        functions = search_functions_enhanced(pattern="FUN_", min_xrefs=2)
        print(f"      ✓ Found {len(functions)} candidates")
        
        # Show first 5 candidates
        if functions:
            print("\n      Top candidates by xref count:")
            for func in functions[:5]:
                print(f"        - {func.get('name', 'unknown')}: "
                      f"{func.get('xref_count', 0)} xrefs @ {func.get('address', 'unknown')}")
    except Exception as e:
        print(f"      ✗ Error: {e}")
        print("      Note: This example requires Ghidra to be running")
        print("      To test locally, see the mock data below:")
        functions = [
            {"name": "FUN_401000", "address": "0x401000", "xref_count": 5},
            {"name": "FUN_401050", "address": "0x401050", "xref_count": 3},
            {"name": "FUN_401100", "address": "0x401100", "xref_count": 8},
        ]
    
    # Analyze functions and suggest renames
    print("\n[2/3] Analyzing functions and suggesting renames...")
    renames = {}
    
    for func in functions[:3]:  # Limit to first 3 for demo
        old_name = func.get("name", "unknown")
        address = func.get("address", "unknown")
        xref_count = func.get("xref_count", 0)
        
        print(f"\n      Function: {old_name} @ {address} ({xref_count} xrefs)")
        
        try:
            decompiled = decompile_function(old_name)
            suggested_prefix = generate_function_name(decompiled, "Process")
            new_name = f"{suggested_prefix}_{old_name.split('_')[1][:8]}"
            
            print(f"        Suggested: {new_name}")
            renames[old_name] = new_name
        except Exception as e:
            print(f"        Error analyzing: {e}")
            suggested_prefix = "Process"
            new_name = f"{suggested_prefix}_{old_name.split('_')[1][:8]}"
            renames[old_name] = new_name
    
    # Apply renames
    print("\n[3/3] Applying renames...")
    stats = {
        "functions_renamed": 0,
        "variables_renamed": 0,
        "errors": []
    }
    
    for old_name, new_name in renames.items():
        try:
            result = rename_function(old_name, new_name)
            print(f"      ✓ Renamed: {old_name} → {new_name}")
            stats["functions_renamed"] += 1
            
            # Try to get and rename variables too
            try:
                variables = get_function_variables(new_name)  # Use new name after rename
                var_suggestions = suggest_variable_renames("")
                
                for var in variables:
                    var_name = var.get("name", "")
                    if var_name in var_suggestions:
                        new_var_name = var_suggestions[var_name]
                        try:
                            rename_variable(new_name, var_name, new_var_name)
                            print(f"        ✓ Variable: {var_name} → {new_var_name}")
                            stats["variables_renamed"] += 1
                        except Exception as e:
                            stats["errors"].append(f"Variable rename error: {e}")
            except Exception as e:
                pass  # Variable analysis is optional
                
        except Exception as e:
            print(f"      ✗ Error renaming {old_name}: {e}")
            stats["errors"].append(str(e))
    
    # Report
    print("\n" + "=" * 70)
    print("RENAME SUMMARY")
    print("=" * 70)
    print(f"Functions Renamed: {stats['functions_renamed']}")
    print(f"Variables Renamed: {stats['variables_renamed']}")
    
    if stats["errors"]:
        print(f"\nErrors ({len(stats['errors'])}): ")
        for error in stats["errors"]:
            print(f"  - {error}")
    
    # Save report
    report = {
        "renames": renames,
        "statistics": stats,
        "timestamp": "2025-11-05"
    }
    
    with open("batch_rename_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved to: batch_rename_report.json")
    print("\nNext steps:")
    print("  1. Review the renamed functions in Ghidra")
    print("  2. If satisfied, commit the changes")
    print("  3. Run again on other auto-named functions")

if __name__ == "__main__":
    main()

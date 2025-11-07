#!/usr/bin/env python3
"""
Example: Analyze all functions in a binary

This example demonstrates how to:
- List all functions in the currently open program
- Decompile each function
- Get cross-references (callers) for each function
- Generate a report of function analysis

Usage:
    python analyze-functions.py
"""

import requests
import json
from typing import Dict, List

# Configuration
GHIDRA_API_BASE = "http://127.0.0.1:8089"
TIMEOUT = 30

def get_all_functions(limit: int = 100, offset: int = 0) -> List[Dict]:
    """List all functions in the current program."""
    url = f"{GHIDRA_API_BASE}/list_functions"
    params = {"limit": limit, "offset": offset}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def decompile_function(name: str) -> str:
    """Get decompiled pseudocode for a function."""
    url = f"{GHIDRA_API_BASE}/decompile_function"
    params = {"name": name}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.text

def get_function_xrefs(name: str, limit: int = 50) -> List[Dict]:
    """Get all cross-references (callers) for a function."""
    url = f"{GHIDRA_API_BASE}/get_function_xrefs"
    params = {"name": name, "limit": limit}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def get_function_callees(name: str, limit: int = 50) -> List[Dict]:
    """Get all functions called by the specified function."""
    url = f"{GHIDRA_API_BASE}/get_function_callees"
    params = {"name": name, "limit": limit}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def analyze_function(func_name: str) -> Dict:
    """Comprehensive analysis of a single function."""
    print(f"  Analyzing {func_name}...", end="", flush=True)
    
    analysis = {
        "name": func_name,
        "callers": [],
        "callees": [],
        "decompiled_lines": 0,
        "xref_count": 0
    }
    
    try:
        # Get callers (functions that call this function)
        callers = get_function_xrefs(func_name, limit=20)
        analysis["callers"] = [c.get("from", "unknown") for c in callers if "from" in c]
        analysis["xref_count"] = len(analysis["callers"])
        
        # Get callees (functions this one calls)
        callees = get_function_callees(func_name, limit=20)
        analysis["callees"] = [c.get("name", "unknown") for c in callees if "name" in c]
        
        # Get decompilation
        decompiled = decompile_function(func_name)
        analysis["decompiled_lines"] = len(decompiled.split("\n"))
        
        print(" ✓")
    except Exception as e:
        print(f" ✗ ({str(e)})")
        analysis["error"] = str(e)
    
    return analysis

def main():
    """Main analysis workflow."""
    print("=" * 70)
    print("FUNCTION ANALYSIS REPORT")
    print("=" * 70)
    
    # Get all functions
    print("\n[1/3] Retrieving all functions...")
    try:
        functions = get_all_functions(limit=50)  # Limit to first 50 for demo
        print(f"  Found {len(functions)} functions\n")
    except Exception as e:
        print(f"  ERROR: {e}")
        return
    
    # Analyze each function
    print("[2/3] Analyzing functions...")
    analyses = []
    for func in functions:
        func_name = func.get("name", "unknown")
        if not func_name.startswith("FUN_"):  # Skip auto-generated names in demo
            analysis = analyze_function(func_name)
            analyses.append(analysis)
            if len(analyses) >= 10:  # Limit analysis to first 10 named functions
                break
    
    # Generate report
    print("\n[3/3] Generating report...\n")
    print("=" * 70)
    print("ANALYSIS RESULTS")
    print("=" * 70)
    
    for analysis in analyses:
        print(f"\nFunction: {analysis['name']}")
        print(f"  Decompiled Lines: {analysis['decompiled_lines']}")
        print(f"  Callers: {analysis['xref_count']}")
        print(f"  Callees: {len(analysis['callees'])}")
        
        if analysis['callers']:
            print(f"  Called By: {', '.join(analysis['callers'][:3])}", end="")
            if len(analysis['callers']) > 3:
                print(f" (+{len(analysis['callers']) - 3} more)")
            else:
                print()
        
        if analysis['callees']:
            print(f"  Calls: {', '.join(analysis['callees'][:3])}", end="")
            if len(analysis['callees']) > 3:
                print(f" (+{len(analysis['callees']) - 3} more)")
            else:
                print()
        
        if "error" in analysis:
            print(f"  ⚠️ Error: {analysis['error']}")
    
    # Summary statistics
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Functions Analyzed: {len(analyses)}")
    print(f"Total Callers: {sum(a['xref_count'] for a in analyses)}")
    print(f"Total Callees: {sum(len(a['callees']) for a in analyses)}")
    print(f"Avg Decompiled Lines: {sum(a['decompiled_lines'] for a in analyses) // len(analyses)}")
    
    # Save report to JSON
    report_file = "function_analysis_report.json"
    with open(report_file, "w") as f:
        json.dump(analyses, f, indent=2)
    print(f"\nReport saved to: {report_file}")

if __name__ == "__main__":
    main()

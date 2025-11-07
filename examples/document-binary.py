#!/usr/bin/env python3
"""
Example: Comprehensive binary documentation workflow

This example demonstrates how to:
- Analyze all important functions in a binary
- Generate documentation for each function
- Create a structured binary analysis report
- Export findings in multiple formats

Usage:
    python document-binary.py
"""

import requests
import json
from datetime import datetime
from typing import List, Dict

GHIDRA_API_BASE = "http://127.0.0.1:8089"
TIMEOUT = 30

def get_metadata() -> Dict:
    """Get program metadata."""
    url = f"{GHIDRA_API_BASE}/get_metadata"
    
    response = requests.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def list_functions(limit: int = 100) -> List[Dict]:
    """List functions in the program."""
    url = f"{GHIDRA_API_BASE}/list_functions"
    params = {"limit": limit}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def decompile_function(name: str) -> str:
    """Get decompiled code for a function."""
    url = f"{GHIDRA_API_BASE}/decompile_function"
    params = {"name": name}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.text

def get_function_xrefs(name: str) -> List[Dict]:
    """Get cross-references for a function."""
    url = f"{GHIDRA_API_BASE}/get_function_xrefs"
    params = {"name": name, "limit": 20}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def get_function_callees(name: str) -> List[Dict]:
    """Get functions called by the specified function."""
    url = f"{GHIDRA_API_BASE}/get_function_callees"
    params = {"name": name, "limit": 20}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def document_function(name: str) -> Dict:
    """Gather comprehensive documentation for a function."""
    doc = {
        "name": name,
        "xrefs": [],
        "callees": [],
        "decompiled_lines": 0
    }
    
    try:
        # Get callers
        xrefs = get_function_xrefs(name)
        doc["xrefs"] = [x.get("from") for x in xrefs if "from" in x]
    except:
        pass
    
    try:
        # Get callees
        callees = get_function_callees(name)
        doc["callees"] = [c.get("name") for c in callees if "name" in c]
    except:
        pass
    
    try:
        # Get decompilation
        decompiled = decompile_function(name)
        doc["decompiled_lines"] = len(decompiled.split("\n"))
        doc["decompiled_preview"] = "\n".join(decompiled.split("\n")[:10])
    except:
        pass
    
    return doc

def generate_markdown_report(metadata: Dict, functions: List[Dict]) -> str:
    """Generate a markdown report."""
    report = []
    
    report.append("# Binary Analysis Report\n")
    
    # Header
    report.append("## Program Information\n")
    report.append(f"- **Name**: {metadata.get('name', 'Unknown')}\n")
    report.append(f"- **Architecture**: {metadata.get('architecture', 'Unknown')}\n")
    report.append(f"- **Base Address**: {metadata.get('base_address', 'Unknown')}\n")
    report.append(f"- **Analysis Date**: {datetime.now().isoformat()}\n\n")
    
    # Summary
    report.append("## Analysis Summary\n")
    report.append(f"- **Functions Analyzed**: {len(functions)}\n")
    report.append(f"- **Total Cross-references**: {sum(len(f.get('xrefs', [])) for f in functions)}\n")
    report.append(f"- **Total Callees**: {sum(len(f.get('callees', [])) for f in functions)}\n")
    report.append(f"- **Average Lines per Function**: {sum(f.get('decompiled_lines', 0) for f in functions) // max(1, len(functions))}\n\n")
    
    # Top functions by cross-references
    report.append("## Important Functions (by cross-references)\n")
    sorted_functions = sorted(functions, 
                             key=lambda x: len(x.get('xrefs', [])), 
                             reverse=True)
    
    for func in sorted_functions[:20]:
        name = func.get('name', 'Unknown')
        xref_count = len(func.get('xrefs', []))
        callee_count = len(func.get('callees', []))
        lines = func.get('decompiled_lines', 0)
        
        report.append(f"### {name}\n")
        report.append(f"- **Cross-references**: {xref_count}\n")
        report.append(f"- **Called Functions**: {callee_count}\n")
        report.append(f"- **Decompiled Lines**: {lines}\n\n")
    
    return "".join(report)

def generate_json_report(metadata: Dict, functions: List[Dict]) -> Dict:
    """Generate a structured JSON report."""
    return {
        "metadata": metadata,
        "analysis": {
            "timestamp": datetime.now().isoformat(),
            "functions_analyzed": len(functions),
            "total_xrefs": sum(len(f.get('xrefs', [])) for f in functions),
            "total_callees": sum(len(f.get('callees', [])) for f in functions),
        },
        "functions": functions,
        "statistics": {
            "most_called": sorted(
                functions,
                key=lambda x: len(x.get('xrefs', [])),
                reverse=True
            )[:10],
            "largest_functions": sorted(
                functions,
                key=lambda x: x.get('decompiled_lines', 0),
                reverse=True
            )[:10],
        }
    }

def main():
    """Main documentation workflow."""
    print("=" * 70)
    print("BINARY DOCUMENTATION WORKFLOW")
    print("=" * 70)
    
    # Get program metadata
    print("\n[1/4] Retrieving program metadata...")
    try:
        metadata = get_metadata()
        print(f"      ✓ Program: {metadata.get('name', 'Unknown')}")
        print(f"      ✓ Architecture: {metadata.get('architecture', 'Unknown')}")
    except Exception as e:
        print(f"      ✗ Error: {e}")
        print("      Note: This example requires Ghidra to be running")
        metadata = {
            "name": "sample.exe",
            "architecture": "x86-32",
            "base_address": "0x400000"
        }
    
    # List functions
    print("\n[2/4] Listing functions...")
    try:
        functions = list_functions(limit=50)
        print(f"      ✓ Found {len(functions)} functions")
    except Exception as e:
        print(f"      ✗ Error: {e}")
        functions = []
    
    # Document each function
    print("\n[3/4] Documenting functions...")
    documented = []
    for i, func in enumerate(functions[:25]):  # Limit to first 25
        func_name = func.get("name", "unknown")
        print(f"      [{i+1}/{min(25, len(functions))}] {func_name}...", end="", flush=True)
        
        try:
            doc = document_function(func_name)
            documented.append(doc)
            print(" ✓")
        except Exception as e:
            print(f" ✗")
    
    # Generate reports
    print("\n[4/4] Generating reports...")
    
    # Markdown report
    md_report = generate_markdown_report(metadata, documented)
    with open("binary_analysis_report.md", "w") as f:
        f.write(md_report)
    print("      ✓ Markdown report: binary_analysis_report.md")
    
    # JSON report
    json_report = generate_json_report(metadata, documented)
    with open("binary_analysis_report.json", "w") as f:
        json.dump(json_report, f, indent=2)
    print("      ✓ JSON report: binary_analysis_report.json")
    
    # Summary
    print("\n" + "=" * 70)
    print("DOCUMENTATION COMPLETE")
    print("=" * 70)
    print(f"\nReport Summary:")
    print(f"  Functions Documented: {len(documented)}")
    print(f"  Total Cross-references: {sum(len(f.get('xrefs', [])) for f in documented)}")
    print(f"  Total Callees: {sum(len(f.get('callees', [])) for f in documented)}")
    print(f"\nOutput Files:")
    print(f"  - binary_analysis_report.md (for humans)")
    print(f"  - binary_analysis_report.json (for automation)")
    print(f"\nNext steps:")
    print(f"  1. Review the markdown report in your text editor")
    print(f"  2. Use JSON report for further processing")
    print(f"  3. Run on full binary with higher limits for comprehensive analysis")

if __name__ == "__main__":
    main()

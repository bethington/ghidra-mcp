#!/usr/bin/env python3
"""
Example: Extract and analyze strings from binary

This example demonstrates how to:
- List all strings found in the binary
- Filter strings by type and content
- Extract IOCs (IP addresses, URLs, file paths)
- Generate string statistics

Usage:
    python extract-strings.py
"""

import requests
import re
import json
from typing import List, Dict
from collections import Counter

GHIDRA_API_BASE = "http://127.0.0.1:8089"
TIMEOUT = 30

def list_strings(limit: int = 100, offset: int = 0) -> List[Dict]:
    """List all strings in the binary."""
    url = f"{GHIDRA_API_BASE}/list_strings"
    params = {"limit": limit, "offset": offset}
    
    response = requests.get(url, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def extract_iocs() -> Dict:
    """Extract indicators of compromise (IOCs) from strings."""
    url = f"{GHIDRA_API_BASE}/extract_iocs"
    
    response = requests.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()

def classify_string(s: str) -> str:
    """Classify a string based on its content."""
    if re.match(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", s):
        return "IP_ADDRESS"
    elif re.match(r"^https?://", s):
        return "URL"
    elif re.match(r"^[a-zA-Z]:\\", s):
        return "FILE_PATH"
    elif re.match(r"^HKEY_", s):
        return "REGISTRY_KEY"
    elif re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", s):
        return "IDENTIFIER"
    elif len(s) < 4:
        return "SHORT"
    elif re.match(r"^[a-zA-Z0-9+/]{20,}={0,2}$", s):
        return "BASE64"
    elif s.startswith("Error") or s.startswith("Warning") or s.startswith("Debug"):
        return "DEBUG_MESSAGE"
    else:
        return "TEXT"

def main():
    """Main string analysis workflow."""
    print("=" * 70)
    print("STRING EXTRACTION AND ANALYSIS")
    print("=" * 70)
    
    # Extract IOCs first (faster, targeted)
    print("\n[1/3] Extracting Indicators of Compromise (IOCs)...")
    
    try:
        iocs = extract_iocs()
        print("      ✓ IOC extraction complete")
        
        print(f"\n      IP Addresses ({len(iocs.get('ips', []))}): ")
        for ip in iocs.get('ips', [])[:5]:
            print(f"        - {ip}")
        if len(iocs.get('ips', [])) > 5:
            print(f"        ... and {len(iocs.get('ips', [])) - 5} more")
        
        print(f"\n      URLs ({len(iocs.get('urls', []))}): ")
        for url in iocs.get('urls', [])[:5]:
            print(f"        - {url}")
        if len(iocs.get('urls', [])) > 5:
            print(f"        ... and {len(iocs.get('urls', [])) - 5} more")
        
        print(f"\n      File Paths ({len(iocs.get('file_paths', []))}): ")
        for path in iocs.get('file_paths', [])[:5]:
            print(f"        - {path}")
        if len(iocs.get('file_paths', [])) > 5:
            print(f"        ... and {len(iocs.get('file_paths', [])) - 5} more")
        
        print(f"\n      Registry Keys ({len(iocs.get('registry_keys', []))}): ")
        for key in iocs.get('registry_keys', [])[:5]:
            print(f"        - {key}")
        if len(iocs.get('registry_keys', [])) > 5:
            print(f"        ... and {len(iocs.get('registry_keys', [])) - 5} more")
    except Exception as e:
        print(f"      ✗ Error: {e}")
    
    # List all strings for comprehensive analysis
    print("\n[2/3] Listing all strings in binary...")
    
    try:
        strings = list_strings(limit=200)
        print(f"      ✓ Found {len(strings)} strings")
        
        # Classify strings
        classifications = Counter()
        string_data = []
        
        for s in strings:
            string_value = s.get("value", "")
            address = s.get("address", "unknown")
            classification = classify_string(string_value)
            classifications[classification] += 1
            string_data.append({
                "address": address,
                "value": string_value,
                "type": classification,
                "length": len(string_value)
            })
        
    except Exception as e:
        print(f"      ✗ Error: {e}")
        string_data = []
    
    # Generate report
    print("\n[3/3] Generating analysis report...\n")
    print("=" * 70)
    print("STRING CLASSIFICATION SUMMARY")
    print("=" * 70)
    
    if string_data:
        for classification in sorted(classifications.keys()):
            count = classifications[classification]
            percentage = (count / len(string_data)) * 100
            print(f"{classification:20} {count:4}  ({percentage:5.1f}%)")
        
        # Show examples of each type
        print("\n" + "=" * 70)
        print("STRING EXAMPLES BY TYPE")
        print("=" * 70)
        
        by_type = {}
        for data in string_data:
            s_type = data["type"]
            if s_type not in by_type:
                by_type[s_type] = []
            by_type[s_type].append(data["value"])
        
        for s_type in sorted(by_type.keys()):
            examples = by_type[s_type][:5]
            print(f"\n{s_type}:")
            for example in examples:
                preview = example if len(example) <= 60 else example[:57] + "..."
                print(f"  - {preview}")
        
        # Statistics
        print("\n" + "=" * 70)
        print("STATISTICS")
        print("=" * 70)
        lengths = [data["length"] for data in string_data]
        print(f"Total Strings: {len(string_data)}")
        print(f"Average Length: {sum(lengths) // len(lengths)} chars")
        print(f"Longest String: {max(lengths)} chars")
        print(f"Shortest String: {min(lengths)} chars")
        
        # Find interesting patterns
        interesting = [s for s in string_data 
                      if s["type"] in ["FILE_PATH", "URL", "IP_ADDRESS", "REGISTRY_KEY"]]
        print(f"Suspicious Strings: {len(interesting)}")
        
        # Save detailed report
        report = {
            "total_strings": len(string_data),
            "classifications": dict(classifications),
            "iocs_found": len(interesting),
            "strings": string_data[:100],  # Save first 100 for review
            "ioc_examples": interesting[:20]
        }
        
        with open("string_analysis_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\nDetailed report saved to: string_analysis_report.json")
    
    print("\nNext steps:")
    print("  1. Review suspicious strings (URLs, file paths, registry keys)")
    print("  2. Cross-reference with function analysis")
    print("  3. Investigate any unexpected external connections")

if __name__ == "__main__":
    main()

#!/usr/bin/env python
"""
Comprehensive search for pUnit struct references and unit-related functions in Ghidra
"""

import requests
import json
import re
import time
from typing import Dict, List, Optional, Set
from collections import defaultdict

# Configuration
GHIDRA_SERVER = "http://127.0.0.1:8089/"
REQUEST_TIMEOUT = 120

# Pattern definitions for searching
PATTERNS = {
    'pUnit': r'\bpUnit\b',
    'UnitAny': r'\bUnitAny\b',
    'pData': r'\bpData\b',
    'dwUnitId': r'\bdwUnitId\b',
    'dwUnitType': r'\bdwUnitType\b',
    'dwMode': r'\bdwMode\b',
    'pAct': r'\bpAct\b',
    'pPath': r'\bpPath\b',
    'pInventory': r'\bpInventory\b',
    'pStats': r'\bpStats\b',
    'dwOwnerType': r'\bdwOwnerType\b',
    'dwOwnerId': r'\bdwOwnerId\b',
}

FUNCTION_PATTERNS = [
    r'.*[Uu]nit.*',
    r'.*[Pp]layer.*',
    r'.*[Mm]onster.*',
    r'.*[Ee]ntity.*',
]

def safe_get(endpoint: str, params: dict = None) -> Optional[str]:
    """Safely make HTTP GET request to Ghidra server"""
    try:
        full_url = GHIDRA_SERVER.rstrip('/') + '/' + endpoint.lstrip('/')
        response = requests.get(full_url, params=params, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            return response.text
        return None
    except Exception as e:
        print("  ERROR: {} - {}".format(endpoint, str(e)))
        return None

def get_all_functions() -> List[str]:
    """Get list of all functions"""
    print("[*] Fetching all functions...")
    functions = []
    offset = 0
    limit = 100
    
    while True:
        result = safe_get("/list_methods", {"offset": offset, "limit": limit})
        if not result:
            break
        
        lines = result.strip().split('\n')
        if not lines or lines[0] == "No program loaded":
            break
        
        functions.extend([line.strip() for line in lines if line.strip()])
        
        if len(lines) < limit:
            break
        offset += limit
        time.sleep(0.1)
    
    print("[+] Found {} functions".format(len(functions)))
    return functions

def decompile_function(address: str) -> Optional[str]:
    """Decompile a single function"""
    try:
        result = safe_get("/decompile_function", {"address": address})
        return result
    except Exception as e:
        return None

def search_pattern_in_decompilation(pattern: str, decompilation: str) -> int:
    """Count pattern matches in decompilation"""
    try:
        regex = re.compile(pattern, re.IGNORECASE)
        return len(regex.findall(decompilation))
    except:
        return 0

def find_functions_by_pattern(pattern: str) -> List[str]:
    """Find functions matching name pattern"""
    all_functions = get_all_functions()
    regex = re.compile(pattern, re.IGNORECASE)
    return [f for f in all_functions if regex.search(f)]

def analyze_function(address: str, function_name: str) -> Dict:
    """Analyze a function for unit-related patterns"""
    result = {
        'address': address,
        'name': function_name,
        'patterns_found': {},
        'total_matches': 0,
    }
    
    decomp = decompile_function(address)
    if decomp and "Error" not in decomp and "failed" not in decomp.lower():
        for pattern_name, pattern_regex in PATTERNS.items():
            count = search_pattern_in_decompilation(pattern_regex, decomp)
            if count > 0:
                result['patterns_found'][pattern_name] = count
                result['total_matches'] += count
    
    return result

def main():
    """Main analysis routine"""
    print("\n" + "="*80)
    print("SEARCHING FOR pUNIT STRUCT REFERENCES IN GHIDRA")
    print("="*80 + "\n")
    
    results = []
    
    # Find functions matching unit patterns
    print("[STEP 1] Finding unit-related functions...")
    all_unit_functions = set()
    
    for pattern in FUNCTION_PATTERNS:
        matches = find_functions_by_pattern(pattern)
        all_unit_functions.update(matches)
        print("  Pattern '{}': {} matches".format(pattern, len(matches)))
        time.sleep(0.2)
    
    print("\n[+] Total unit-related functions: {}".format(len(all_unit_functions)))
    
    # Analyze functions
    print("\n[STEP 2] Analyzing functions for unit patterns...")
    for i, func_name in enumerate(sorted(all_unit_functions), 1):
        if i % 10 == 0:
            print("  Progress: {}/{}".format(i, len(all_unit_functions)))
        
        if ' @ ' in func_name:
            address = func_name.split(' @ ')[-1].strip()
            clean_name = func_name.split(' @ ')[0].strip()
        else:
            address = func_name
            clean_name = func_name
        
        analysis = analyze_function(address, clean_name)
        if analysis['total_matches'] > 0:
            results.append(analysis)
        
        time.sleep(0.05)
    
    # Sort by match count
    results = sorted(results, key=lambda x: x['total_matches'], reverse=True)
    
    # Print results
    print("\n" + "="*80)
    print("FUNCTIONS WITH UNIT-RELATED PATTERNS (top 50)")
    print("="*80 + "\n")
    
    for i, func in enumerate(results[:50], 1):
        print("{}. {} @ {}".format(i, func['name'], func['address']))
        print("   Total matches: {}".format(func['total_matches']))
        for pattern_name, count in sorted(func['patterns_found'].items(), key=lambda x: x[1], reverse=True):
            print("   - {}: {} occurrences".format(pattern_name, count))
        print()
    
    print("\nTotal functions with unit patterns: {}".format(len(results)))

if __name__ == "__main__":
    main()

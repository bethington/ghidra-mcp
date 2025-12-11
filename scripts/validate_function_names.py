#!/usr/bin/env python3
"""
Validates function names against naming standards and identifies violations.

This script retrieves all functions from Ghidra via the MCP server and filters
out valid patterns, leaving only functions that may need review or renaming.

Valid patterns (auto-filtered):
- FUN_* (unprocessed Ghidra default names)
- Ordinal_* (DLL ordinal exports)
- thunk_* (thunk/trampoline functions)
- switch_* (switch table handlers)
- entry (program entry point)
- _* __* ___* (library/CRT functions)
- PascalCase with valid verb prefixes

Usage:
    python validate_function_names.py
    python validate_function_names.py --output-file naming-violations.txt
    python validate_function_names.py --show-valid
    python validate_function_names.py --ghidra-server http://127.0.0.1:8080
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime

import requests


# Valid patterns that should be skipped (compiled regex patterns)
VALID_PATTERNS = [
    # Unprocessed/default names - skip entirely
    re.compile(r'^FUN_[0-9a-fA-F]+$'),           # Ghidra default: FUN_6fc80a40
    re.compile(r'^Ordinal_\d+$'),                 # DLL ordinals: Ordinal_10025
    re.compile(r'^thunk_'),                       # Thunk functions
    re.compile(r'^switch_'),                      # Switch handlers
    re.compile(r'^entry$'),                       # Entry point
    re.compile(r'^_entry$'),                      # Alt entry point
    
    # Library/runtime functions - valid as-is
    re.compile(r'^_{1,3}[a-z]'),                  # _malloc, __aullrem, ___add_12
    re.compile(r'^_[A-Z][a-z]'),                  # _CxxThrowException, _Alloca
    
    # Compiler-generated
    re.compile(r'^\?\?'),                         # C++ mangled names ??0ClassName@@
    re.compile(r'^@'),                            # Fastcall decorated @funcname@8
    
    # Valid PascalCase with action verbs
    re.compile(r'^(Get|Set|Init|Initialize|Process|Update|Validate|Create|Alloc|Free|'
               r'Destroy|Handle|Is|Has|Can|Find|Search|Load|Save|Draw|Render|Parse|Build|'
               r'Calculate|Compute|Check|Execute|Run|Start|Stop|Enable|Disable|Add|Remove|'
               r'Insert|Delete|Clear|Reset|Open|Close|Read|Write|Send|Receive|Connect|'
               r'Disconnect|Register|Unregister|Lock|Unlock|Acquire|Release|Push|Pop|'
               r'Enqueue|Dequeue|Allocate|Deallocate|Attach|Detach|Bind|Unbind|Show|Hide|'
               r'Activate|Deactivate|Begin|End|Enter|Exit|Format|Convert|Transform|Apply|'
               r'Revoke|Grant|Deny|Accept|Reject|Dispatch|Notify|Signal|Wait|Sleep|Wake|'
               r'Resume|Suspend|Cancel|Abort|Retry|Skip|Ignore|Verify|Confirm|Authenticate|'
               r'Authorize|Encrypt|Decrypt|Compress|Decompress|Encode|Decode|Serialize|'
               r'Deserialize|Marshal|Unmarshal|Pack|Unpack|Wrap|Unwrap|Map|Unmap|Mount|'
               r'Unmount|Install|Uninstall|Configure|Reconfigure|Prepare|Cleanup|Finalize|'
               r'Terminate|Kill|Spawn|Fork|Join|Merge|Split|Copy|Move|Swap|Sort|Filter|'
               r'Reduce|Aggregate|Collect|Gather|Scatter|Broadcast|Multicast|Publish|'
               r'Subscribe|Emit|Consume|Produce|Generate|Fabricate|Synthesize|Analyze|'
               r'Evaluate|Measure|Sample|Poll|Query|Fetch|Retrieve|Lookup|Resolve|Translate|'
               r'Interpolate|Extrapolate|Approximate|Estimate|Predict|Infer|Deduce|Derive|'
               r'Extract|Inject|Embed)[A-Z][a-zA-Z0-9]*$'),
]

# Known invalid patterns that definitely need fixing
INVALID_PATTERNS = [
    (re.compile(r'^[A-Z]+_[A-Z]'), 'Snake_case prefix (MODULE_Function)'),
    (re.compile(r'^[a-z][a-zA-Z]+$'), 'camelCase (should be PascalCase)'),
    (re.compile(r'^[A-Z]+$'), 'ALL_CAPS (should be PascalCase)'),
    (re.compile(r'^[A-Z][a-z]+\d+$'), 'Generic numbered name (Handler1, Process2)'),
    (re.compile(r'^(Handler|Process|Function|Method|Routine|Procedure|Sub|Func)$'), 'Generic single-word name'),
]


class Colors:
    """ANSI color codes for terminal output."""
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def colorize(text: str, color: str) -> str:
    """Wrap text in ANSI color codes."""
    return f"{color}{text}{Colors.RESET}"


def is_valid_function_name(name: str) -> bool:
    """Check if a function name matches valid patterns."""
    for pattern in VALID_PATTERNS:
        if pattern.search(name):
            return True
    return False


def get_invalid_reason(name: str) -> str:
    """Determine why a function name is invalid."""
    for pattern, issue in INVALID_PATTERNS:
        if pattern.search(name):
            return issue
    
    # Additional checks
    if re.match(r'^[a-z]', name):
        return 'Starts with lowercase'
    if '_' in name and not name.startswith('_'):
        return 'Contains underscore (not library function)'
    if len(name) < 4:
        return 'Name too short'
    
    return 'Does not match PascalCase verb-first pattern'


def fetch_functions(server_url: str, timeout: int = 30) -> list:
    """Fetch all functions from Ghidra server."""
    url = f"{server_url.rstrip('/')}/list_functions?offset=0&limit=10000"
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    return data.get('functions', [])


def validate_functions(functions: list) -> tuple:
    """
    Categorize functions into valid, invalid, and unprocessed.
    
    Returns:
        Tuple of (valid_list, invalid_list, unprocessed_list)
    """
    valid = []
    invalid = []
    unprocessed = []
    
    for func in functions:
        name = func.get('name', '')
        address = func.get('address', '')
        
        # Check if it's an unprocessed name (FUN_, Ordinal_)
        if re.match(r'^FUN_[0-9a-fA-F]+$', name) or re.match(r'^Ordinal_\d+$', name):
            unprocessed.append({'name': name, 'address': address})
            continue
        
        # Check if it's a valid name pattern
        if is_valid_function_name(name):
            valid.append({'name': name, 'address': address})
        else:
            reason = get_invalid_reason(name)
            invalid.append({'name': name, 'address': address, 'reason': reason})
    
    return valid, invalid, unprocessed


def print_results(functions: list, valid: list, invalid: list, unprocessed: list, show_valid: bool = False):
    """Print validation results to console."""
    print(colorize("========================================", Colors.CYAN))
    print(colorize("RESULTS SUMMARY", Colors.CYAN))
    print(colorize("========================================", Colors.CYAN))
    print()
    print(f"{colorize('Total functions:', Colors.WHITE)}     {len(functions)}")
    print(f"{colorize('Unprocessed (FUN_):', Colors.GRAY)}  {len(unprocessed)}")
    print(f"{colorize('Valid names:', Colors.GREEN)}         {len(valid)}")
    
    invalid_color = Colors.YELLOW if invalid else Colors.GREEN
    print(f"{colorize('Need review:', invalid_color)}         {len(invalid)}")
    print()
    
    if show_valid and valid:
        print(colorize("VALID FUNCTIONS:", Colors.GREEN))
        print(colorize("----------------", Colors.GREEN))
        for v in sorted(valid, key=lambda x: x['name']):
            print(colorize(f"  {v['name']}", Colors.GRAY))
        print()
    
    if invalid:
        print(colorize("FUNCTIONS NEEDING REVIEW:", Colors.YELLOW))
        print(colorize("-------------------------", Colors.YELLOW))
        
        # Group by reason
        grouped = defaultdict(list)
        for item in invalid:
            grouped[item['reason']].append(item)
        
        # Sort groups by count (descending)
        for reason in sorted(grouped.keys(), key=lambda r: len(grouped[r]), reverse=True):
            items = grouped[reason]
            print()
            print(colorize(f"[{len(items)}] {reason}:", Colors.YELLOW))
            for item in sorted(items, key=lambda x: x['name']):
                print(colorize(f"  0x{item['address']}: {item['name']}", Colors.WHITE))


def write_output_file(output_file: str, server_url: str, functions: list, 
                      valid: list, invalid: list, unprocessed: list):
    """Write results to output file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("Function Name Validation Report\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write(f"Server: {server_url}\n")
        f.write("\n")
        f.write("Summary:\n")
        f.write(f"  Total: {len(functions)}\n")
        f.write(f"  Unprocessed: {len(unprocessed)}\n")
        f.write(f"  Valid: {len(valid)}\n")
        f.write(f"  Need Review: {len(invalid)}\n")
        f.write("\n")
        
        if invalid:
            f.write("Functions Needing Review:\n")
            f.write("-------------------------\n")
            for item in sorted(invalid, key=lambda x: (x['reason'], x['name'])):
                f.write(f"0x{item['address']}\t{item['name']}\t{item['reason']}\n")
    
    print()
    print(colorize(f"Results written to: {output_file}", Colors.CYAN))


def main():
    parser = argparse.ArgumentParser(
        description='Validate function names against naming standards',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        '--ghidra-server', '-s',
        default='http://127.0.0.1:8089',
        help='URL of the Ghidra MCP server (default: http://127.0.0.1:8089)'
    )
    parser.add_argument(
        '--output-file', '-o',
        default='',
        help='Optional file to write results to'
    )
    parser.add_argument(
        '--show-valid', '-v',
        action='store_true',
        help='Also show valid functions (for debugging)'
    )
    parser.add_argument(
        '--fix-automatically', '-f',
        action='store_true',
        help='Attempt to rename obvious violations automatically (not yet implemented)'
    )
    
    args = parser.parse_args()
    
    print(colorize("========================================", Colors.CYAN))
    print(colorize("Function Name Validation Tool", Colors.CYAN))
    print(colorize("========================================", Colors.CYAN))
    print()
    
    # Fetch functions from Ghidra
    print(colorize(f"Fetching functions from {args.ghidra_server}...", Colors.YELLOW))
    try:
        functions = fetch_functions(args.ghidra_server)
        print(colorize(f"Retrieved {len(functions)} functions", Colors.GREEN))
    except requests.exceptions.RequestException as e:
        print(colorize(f"ERROR: Could not connect to Ghidra server at {args.ghidra_server}", Colors.RED))
        print(colorize(str(e), Colors.RED))
        sys.exit(1)
    
    # Categorize functions
    valid, invalid, unprocessed = validate_functions(functions)
    
    # Print results
    print_results(functions, valid, invalid, unprocessed, args.show_valid)
    
    # Write to file if requested
    if args.output_file:
        write_output_file(args.output_file, args.ghidra_server, functions,
                         valid, invalid, unprocessed)
    
    print()
    print(colorize("========================================", Colors.CYAN))
    
    # Return count of invalid for scripting
    sys.exit(len(invalid))


if __name__ == '__main__':
    main()

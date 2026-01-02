#!/usr/bin/env python3
"""
Cross-Version Function Matcher for Ghidra MCP

Matches and synchronizes function names across different versions of binaries.
Uses multiple strategies: hash matching, string references, call graphs, and ordinal signatures.

Usage:
    python cross_version_matcher.py --source "1.07/D2Client.dll" --target "1.11/D2Client.dll"
"""

import json
import requests
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import argparse

GHIDRA_MCP_URL = "http://127.0.0.1:8089"

# Program name format: Use the full Ghidra project path like "/LoD/1.07/D2Client.dll"
# Or just the DLL name if it's currently open


@dataclass
class FunctionMatch:
    """Represents a matched function across versions."""
    source_addr: str
    source_name: str
    target_addr: str
    target_name: str
    match_method: str
    confidence: str  # high, medium, low
    match_evidence: str


@dataclass
class MatchResult:
    """Results of cross-version matching."""
    hash_matches: List[FunctionMatch] = field(default_factory=list)
    string_matches: List[FunctionMatch] = field(default_factory=list)
    call_graph_matches: List[FunctionMatch] = field(default_factory=list)
    ordinal_matches: List[FunctionMatch] = field(default_factory=list)


def call_ghidra_json(endpoint: str, params: dict = None) -> dict:
    """Call Ghidra MCP endpoint that returns JSON."""
    url = f"{GHIDRA_MCP_URL}/{endpoint}"
    try:
        response = requests.get(url, params=params, timeout=60)
        return response.json() if response.ok else {"error": response.text}
    except Exception as e:
        return {"error": str(e)}


def call_ghidra_text(endpoint: str, params: dict = None) -> str:
    """Call Ghidra MCP endpoint that returns text."""
    url = f"{GHIDRA_MCP_URL}/{endpoint}"
    try:
        response = requests.get(url, params=params, timeout=60)
        return response.text if response.ok else ""
    except Exception as e:
        return ""


def get_documented_functions(program: str) -> List[dict]:
    """Get all documented (custom-named) functions from a program."""
    text = call_ghidra_text("list_functions", {"program": program, "limit": 10000})
    if not text:
        return []

    functions = []
    for line in text.split("\n"):
        if " @ " in line and not line.startswith("FUN_"):
            parts = line.split(" @ ")
            if len(parts) == 2:
                functions.append({
                    "name": parts[0].strip(),
                    "address": parts[1].strip()
                })
    return functions


def get_function_hashes(program: str, limit: int = 1000) -> Dict[str, dict]:
    """Get function hashes for a program."""
    result = call_ghidra_json("get_bulk_function_hashes", {
        "program": program,
        "filter": "documented",
        "limit": limit
    })

    if "error" in result:
        return {}

    try:
        # REST API returns JSON directly
        return {f["hash"]: f for f in result.get("functions", [])}
    except:
        return {}


def find_hash_matches(source_prog: str, target_prog: str) -> List[FunctionMatch]:
    """Find functions with identical hashes across versions."""
    print("  Finding hash matches...")

    source_hashes = get_function_hashes(source_prog)
    target_hashes = get_function_hashes(target_prog)

    matches = []
    for hash_val, src_func in source_hashes.items():
        if hash_val in target_hashes:
            tgt_func = target_hashes[hash_val]
            matches.append(FunctionMatch(
                source_addr=src_func["address"],
                source_name=src_func["name"],
                target_addr=tgt_func["address"],
                target_name=tgt_func["name"],
                match_method="hash",
                confidence="high",
                match_evidence=f"Identical hash: {hash_val[:16]}..."
            ))

    return matches


def get_strings(program: str, filter_text: str = None) -> List[dict]:
    """Get strings from a program, optionally filtered."""
    params = {"program": program, "limit": 1000}
    if filter_text:
        params["filter"] = filter_text

    text = call_ghidra_text("list_strings", params)
    if not text:
        return []

    strings = []
    for line in text.strip().split("\n"):
        if ": " in line:
            parts = line.split(": ", 1)
            strings.append({
                "address": parts[0].strip(),
                "value": parts[1].strip().strip('"')
            })
    return strings


def get_xrefs_to(address: str, program: str) -> List[dict]:
    """Get cross-references to an address."""
    text = call_ghidra_text("get_xrefs_to", {"address": address, "program": program, "limit": 50})
    if not text:
        return []

    xrefs = []
    for line in text.strip().split("\n"):
        if " in " in line:
            # Parse: "From 6fb382d4 in CleanupUIElementsAndSlots [DATA]"
            parts = line.split(" in ")
            if len(parts) >= 2:
                addr = parts[0].replace("From ", "").strip()
                func_part = parts[1].split(" [")[0].strip()
                xrefs.append({
                    "from_addr": addr,
                    "function": func_part
                })
    return xrefs


def find_string_matches(source_prog: str, target_prog: str,
                        string_filters: List[str] = None) -> List[FunctionMatch]:
    """Find functions that reference the same unique strings."""
    print("  Finding string-based matches...")

    if string_filters is None:
        # Default filters for D2 binaries
        string_filters = [
            "Diablo II",
            "Mini Panel",
            ".txt",
            "Resolution",
            "\\Source\\",
        ]

    matches = []

    for filter_text in string_filters:
        source_strings = get_strings(source_prog, filter_text)
        target_strings = get_strings(target_prog, filter_text)

        # Match strings by value
        source_by_value = {s["value"]: s for s in source_strings}
        target_by_value = {s["value"]: s for s in target_strings}

        common_values = set(source_by_value.keys()) & set(target_by_value.keys())

        for value in common_values:
            src_str = source_by_value[value]
            tgt_str = target_by_value[value]

            # Get functions referencing these strings
            src_xrefs = get_xrefs_to(src_str["address"], source_prog)
            tgt_xrefs = get_xrefs_to(tgt_str["address"], target_prog)

            # Create potential matches
            for src_xref in src_xrefs:
                for tgt_xref in tgt_xrefs:
                    # Only match if source is documented but target isn't
                    if (not src_xref["function"].startswith("FUN_") and
                        tgt_xref["function"].startswith("FUN_")):
                        matches.append(FunctionMatch(
                            source_addr=src_xref["from_addr"],
                            source_name=src_xref["function"],
                            target_addr=tgt_xref["from_addr"],
                            target_name=tgt_xref["function"],
                            match_method="string_reference",
                            confidence="medium",
                            match_evidence=f'Both reference: "{value}"'
                        ))

    return matches


def get_function_callees(func_name: str, program: str) -> Set[str]:
    """Get names of functions called by a function."""
    text = call_ghidra_text("get_function_callees", {"name": func_name, "program": program})
    if not text:
        return set()

    callees = set()
    for line in text.strip().split("\n"):
        if " @ " in line:
            callees.add(line.split(" @ ")[0].strip())
    return callees


def get_function_callers(func_name: str, program: str) -> Set[str]:
    """Get names of functions that call a function."""
    text = call_ghidra_text("get_function_callers", {"name": func_name, "program": program})
    if not text:
        return set()

    callers = set()
    for line in text.strip().split("\n"):
        if " @ " in line:
            callers.add(line.split(" @ ")[0].strip())
    return callers


def find_call_graph_matches(source_prog: str, target_prog: str,
                           seed_matches: List[FunctionMatch]) -> List[FunctionMatch]:
    """Find matches by following call graph from seed matches."""
    print("  Finding call graph matches...")

    matches = []

    for seed in seed_matches:
        # Get callers of source and target
        src_callers = get_function_callers(seed.source_name, source_prog)
        tgt_callers = get_function_callers(seed.target_name, target_prog)

        # Find documented source callers with undocumented target callers
        for src_caller in src_callers:
            if src_caller.startswith("FUN_"):
                continue
            for tgt_caller in tgt_callers:
                if tgt_caller.startswith("FUN_"):
                    matches.append(FunctionMatch(
                        source_addr="",  # Would need lookup
                        source_name=src_caller,
                        target_addr="",  # Would need lookup
                        target_name=tgt_caller,
                        match_method="call_graph",
                        confidence="medium",
                        match_evidence=f"Both call {seed.source_name}/{seed.target_name}"
                    ))

    return matches


def print_matches(matches: List[FunctionMatch], title: str):
    """Print match results in a formatted table."""
    if not matches:
        print(f"\n{title}: No matches found")
        return

    print(f"\n{title} ({len(matches)} matches):")
    print("-" * 100)

    for m in matches[:20]:  # Limit output
        sync_needed = "SYNC" if m.source_name != m.target_name else "OK"
        print(f"  [{m.confidence:6}] {sync_needed:4} | {m.source_name[:35]:35} -> {m.target_name[:25]:25}")
        print(f"           Evidence: {m.match_evidence}")


def deduplicate_matches(matches: List[FunctionMatch]) -> List[FunctionMatch]:
    """Remove duplicate matches, keeping the one with highest confidence."""
    seen = {}  # (source_name, target_name) -> best match
    confidence_order = {"high": 3, "medium": 2, "low": 1}

    for m in matches:
        key = (m.source_name, m.target_name)
        if key not in seen:
            seen[key] = m
        else:
            # Keep higher confidence match
            if confidence_order.get(m.confidence, 0) > confidence_order.get(seen[key].confidence, 0):
                seen[key] = m

    return list(seen.values())


def run_matching(source_prog: str, target_prog: str) -> MatchResult:
    """Run all matching strategies."""
    print(f"\nCross-Version Function Matching")
    print(f"  Source: {source_prog}")
    print(f"  Target: {target_prog}")
    print("=" * 60)

    result = MatchResult()

    # Phase 1: Hash matching
    result.hash_matches = find_hash_matches(source_prog, target_prog)

    # Phase 2: String-based matching
    result.string_matches = find_string_matches(source_prog, target_prog)
    result.string_matches = deduplicate_matches(result.string_matches)

    # Phase 3: Call graph matching (using hash matches as seeds)
    all_seeds = result.hash_matches + result.string_matches
    result.call_graph_matches = find_call_graph_matches(source_prog, target_prog, all_seeds)
    result.call_graph_matches = deduplicate_matches(result.call_graph_matches)

    return result


def main():
    parser = argparse.ArgumentParser(description="Cross-version function matcher")
    parser.add_argument("--source", required=True, help="Source program path")
    parser.add_argument("--target", required=True, help="Target program path")
    parser.add_argument("--output", help="Output JSON file for matches")
    args = parser.parse_args()

    result = run_matching(args.source, args.target)

    # Print results
    print_matches(result.hash_matches, "Hash Matches (Identical Functions)")
    print_matches(result.string_matches, "String Reference Matches")
    print_matches(result.call_graph_matches, "Call Graph Matches")

    # Summary
    total = (len(result.hash_matches) + len(result.string_matches) +
             len(result.call_graph_matches))
    print(f"\n{'=' * 60}")
    print(f"Total matches found: {total}")
    print(f"  Hash matches: {len(result.hash_matches)}")
    print(f"  String matches: {len(result.string_matches)}")
    print(f"  Call graph matches: {len(result.call_graph_matches)}")

    # Export to JSON if requested
    if args.output:
        output_data = {
            "source": args.source,
            "target": args.target,
            "matches": {
                "hash": [vars(m) for m in result.hash_matches],
                "string": [vars(m) for m in result.string_matches],
                "call_graph": [vars(m) for m in result.call_graph_matches]
            }
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()

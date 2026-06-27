#!/usr/bin/env python3
"""
Measure context window usage for ghidra-mcp's 251 MCP tools.
Provides token estimates using tiktoken (Claude models).
"""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

try:
    import tiktoken
    HAS_TIKTOKEN = True
except ImportError:
    HAS_TIKTOKEN = False
    print("⚠️  tiktoken not installed. Install with: pip install tiktoken")
    print("   Falling back to character-based estimates.\n")


def load_endpoints():
    """Load endpoints.json catalog."""
    # Find endpoints.json relative to project root
    script_dir = Path(__file__).parent.resolve()
    project_root = script_dir.parent.parent
    endpoints_file = project_root / "tests" / "endpoints.json"
    
    with open(endpoints_file, "r") as f:
        return json.load(f)


def measure_json_size(data):
    """Measure size of JSON object."""
    content = json.dumps(data)
    return len(content), content


def estimate_tokens_claude(text):
    """Estimate Claude tokens (cl100k_base encoding)."""
    if not HAS_TIKTOKEN:
        # Rough estimate: 1 token ≈ 4 characters for English
        return len(text) // 4
    
    encoding = tiktoken.get_encoding("cl100k_base")
    return len(encoding.encode(text))


def analyze_endpoints():
    """Analyze context usage by endpoints."""
    data = load_endpoints()
    endpoints = data["endpoints"]
    
    file_size, raw_json = measure_json_size(data)
    tokens = estimate_tokens_claude(raw_json)
    
    print("=" * 80)
    print("GHIDRA-MCP CONTEXT WINDOW ANALYSIS")
    print("=" * 80)
    print()
    print(f"Total Endpoints: {data['total_endpoints']}")
    print()
    print("FILE SIZE:")
    print(f"  Endpoints.json:        {file_size:>10,} bytes")
    print(f"  Character count:       {len(raw_json):>10,} chars")
    print()
    
    if HAS_TIKTOKEN:
        print("TOKEN ESTIMATES (Claude cl100k_base encoding):")
        print(f"  Full endpoints.json:   {tokens:>10,} tokens")
        print(f"  Avg per endpoint:      {tokens // data['total_endpoints']:>10} tokens")
    else:
        print("TOKEN ESTIMATES (character-based, ÷4 approximation):")
        print(f"  Full endpoints.json:   ~{tokens:>9,} tokens (rough)")
        print(f"  Avg per endpoint:      ~{tokens // data['total_endpoints']:>9} tokens (rough)")
    print()
    
    # Breakdown by category
    category_stats = defaultdict(lambda: {"count": 0, "chars": 0, "tokens": 0})
    
    for endpoint in endpoints:
        category = endpoint.get("category", "uncategorized")
        endpoint_json = json.dumps(endpoint)
        category_stats[category]["count"] += 1
        category_stats[category]["chars"] += len(endpoint_json)
        category_stats[category]["tokens"] += estimate_tokens_claude(endpoint_json)
    
    print("CONTEXT USAGE BY CATEGORY:")
    print()
    
    sorted_categories = sorted(
        category_stats.items(),
        key=lambda x: x[1]["tokens"],
        reverse=True
    )
    
    for category, stats in sorted_categories:
        pct_tokens = (stats["tokens"] / tokens) * 100 if tokens > 0 else 0
        print(f"  {category:<20}  {stats['count']:>3} endpoints  "
              f"{stats['tokens']:>7,} tokens  ({pct_tokens:>5.1f}%)")
    
    print()
    print("=" * 80)
    print("CONTEXT WINDOW IMPACT ANALYSIS")
    print("=" * 80)
    print()
    
    # Typical context windows
    windows = {
        "Claude 3.5 Haiku":     200_000,
        "Claude 3.5 Sonnet":    200_000,
        "Claude 3 Opus":        200_000,
        "GPT-4o":               128_000,
        "GPT-4 Turbo":          128_000,
    }
    
    print("Endpoints.json as % of context window:")
    print()
    for model, window in windows.items():
        pct = (tokens / window) * 100
        print(f"  {model:<25}  {pct:>6.2f}% ({tokens:,} / {window:,} tokens)")
    
    print()
    print("RECOMMENDATIONS:")
    print()
    print("1. Full Tool List Trade-off:")
    print(f"   - All 251 endpoints use ~{tokens:,} tokens (~0.5% of typical context)")
    print("   - Small cost compared to query/response overhead")
    print("   - RAG-MCP study shows tool-search retrieval dramatically improves")
    print("     accuracy (43.1% vs 13.6% on unfiltered sets)")
    print()
    print("2. Mitigation strategies (already implemented):")
    print("   - Tool groups (GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS)")
    print("   - Dynamic filtering by endpoint category")
    print("   - Parameter aliases reduce prompt ambiguity (Issue #210)")
    print()
    print("3. Further optimization:")
    print("   - Implement tool search/retrieval (e.g., via /list_tool_groups)")
    print("   - Consider endpoint descriptions - currently concise")
    print("   - Monitor actual MCP tool invocation patterns from live logs")
    print()


if __name__ == "__main__":
    analyze_endpoints()

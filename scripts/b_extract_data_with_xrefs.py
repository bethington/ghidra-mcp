#!/usr/bin/env python3
"""
Extract all defined data items from Ghidra with their cross-reference counts.

This script queries the Ghidra MCP server to get all defined data items,
then uses batch operations to efficiently retrieve xref counts for each item.

Usage:
    python extract_data_with_xrefs.py [--output OUTPUT_FILE] [--format FORMAT]

Arguments:
    --output    Output file path (default: data_xrefs.csv)
    --format    Output format: csv, json, or tsv (default: csv)
    --limit     Maximum number of data items to process (default: all)
    --min-xrefs Minimum xrefs to include in output (default: 0)
"""

import argparse
import csv
import json
import sys
from typing import List, Dict, Any
import requests
from collections import defaultdict

# Ghidra MCP server configuration
GHIDRA_SERVER = "http://127.0.0.1:8089"
BATCH_SIZE = 50  # Number of addresses to query at once


def parse_data_item_line(line: str) -> Dict[str, Any]:
    """Parse a data item line from Ghidra format: 'name @ address [type] (size)'"""
    import re

    # Pattern: name @ address [type] (size)
    pattern = r'^(.+?)\s+@\s+([0-9a-fA-F]+)\s+\[(.+?)\]\s+\((.+?)\)$'
    match = re.match(pattern, line.strip())

    if not match:
        return None

    name, address, data_type, size_info = match.groups()

    return {
        "name": name.strip(),
        "address": "0x" + address.strip(),
        "type": data_type.strip(),
        "size_info": size_info.strip()
    }


def get_all_data_items(limit: int = None) -> List[Dict[str, Any]]:
    """Fetch all defined data items from Ghidra."""
    all_items = []
    offset = 0
    batch_size = 1000

    print(f"Fetching defined data items...", file=sys.stderr)

    while True:
        url = f"{GHIDRA_SERVER}/list_data_items"
        params = {"offset": offset, "limit": batch_size}

        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()

            # Response is plain text, not JSON
            text = response.text.strip()

            if not text or "No program loaded" in text:
                break

            # Parse each line
            lines = text.split('\n')
            for line in lines:
                if not line.strip():
                    continue

                item = parse_data_item_line(line)
                if item:
                    all_items.append(item)

            print(f"  Fetched {len(all_items)} items...", file=sys.stderr)

            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                break

            # If we got fewer lines than requested, we're done
            if len(lines) < batch_size:
                break

            offset += batch_size

        except requests.exceptions.RequestException as e:
            print(f"Error fetching data items: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"Total data items fetched: {len(all_items)}", file=sys.stderr)
    return all_items


def get_bulk_xrefs(addresses: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Get cross-references for multiple addresses in a single batch request."""
    url = f"{GHIDRA_SERVER}/get_bulk_xrefs"
    payload = {"addresses": addresses}

    try:
        response = requests.post(url, json=payload, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching bulk xrefs: {e}", file=sys.stderr)
        return {}


def process_xrefs_in_batches(data_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Process xref counts for all data items using batch requests."""
    results = []
    addresses = [item["address"] for item in data_items]

    print(f"Processing xrefs in batches of {BATCH_SIZE}...", file=sys.stderr)

    for i in range(0, len(addresses), BATCH_SIZE):
        batch_addresses = addresses[i:i + BATCH_SIZE]
        batch_items = data_items[i:i + BATCH_SIZE]

        print(f"  Processing batch {i//BATCH_SIZE + 1}/{(len(addresses) + BATCH_SIZE - 1)//BATCH_SIZE}...", file=sys.stderr)

        xref_map = get_bulk_xrefs(batch_addresses)

        for item in batch_items:
            address = item["address"]
            xrefs = xref_map.get(address, [])
            xref_count = len(xrefs)

            results.append({
                "address": address,
                "name": item.get("name", ""),
                "type": item.get("type", ""),
                "size_info": item.get("size_info", ""),
                "xref_count": xref_count,
                "xrefs": xrefs
            })

    return results


def save_as_csv(results: List[Dict[str, Any]], output_file: str, min_xrefs: int = 0):
    """Save results to CSV format."""
    filtered = [r for r in results if r["xref_count"] >= min_xrefs]

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Address", "Name", "Type", "Size", "Xref Count"])

        for item in filtered:
            writer.writerow([
                item["address"],
                item["name"],
                item["type"],
                item["size_info"],
                item["xref_count"]
            ])

    print(f"Results saved to {output_file} ({len(filtered)} items)", file=sys.stderr)


def save_as_tsv(results: List[Dict[str, Any]], output_file: str, min_xrefs: int = 0):
    """Save results to TSV format."""
    filtered = [r for r in results if r["xref_count"] >= min_xrefs]

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter='\t')
        writer.writerow(["Address", "Name", "Type", "Size", "Xref Count"])

        for item in filtered:
            writer.writerow([
                item["address"],
                item["name"],
                item["type"],
                item["size_info"],
                item["xref_count"]
            ])

    print(f"Results saved to {output_file} ({len(filtered)} items)", file=sys.stderr)


def save_as_json(results: List[Dict[str, Any]], output_file: str, min_xrefs: int = 0, include_xrefs: bool = False):
    """Save results to JSON format."""
    filtered = [r for r in results if r["xref_count"] >= min_xrefs]

    # Remove xref details if not requested
    if not include_xrefs:
        for item in filtered:
            item.pop("xrefs", None)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(filtered, f, indent=2)

    print(f"Results saved to {output_file} ({len(filtered)} items)", file=sys.stderr)


def print_summary(results: List[Dict[str, Any]]):
    """Print summary statistics."""
    total = len(results)
    with_xrefs = sum(1 for r in results if r["xref_count"] > 0)
    no_xrefs = total - with_xrefs
    max_xrefs = max((r["xref_count"] for r in results), default=0)

    print("\n" + "="*60, file=sys.stderr)
    print("SUMMARY", file=sys.stderr)
    print("="*60, file=sys.stderr)
    print(f"Total data items:        {total}", file=sys.stderr)
    print(f"Items with xrefs:        {with_xrefs} ({with_xrefs*100//total if total > 0 else 0}%)", file=sys.stderr)
    print(f"Items without xrefs:     {no_xrefs} ({no_xrefs*100//total if total > 0 else 0}%)", file=sys.stderr)
    print(f"Maximum xref count:      {max_xrefs}", file=sys.stderr)

    # Top 10 most referenced items
    sorted_results = sorted(results, key=lambda x: x["xref_count"], reverse=True)
    print("\nTop 10 most referenced data items:", file=sys.stderr)
    print("-"*60, file=sys.stderr)
    for i, item in enumerate(sorted_results[:10], 1):
        print(f"{i:2d}. {item['address']} ({item['name']:<30s}) - {item['xref_count']} xrefs", file=sys.stderr)
    print("="*60 + "\n", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Extract defined data items with cross-reference counts from Ghidra"
    )
    parser.add_argument(
        "--output", "-o",
        default="data_xrefs.csv",
        help="Output file path (default: data_xrefs.csv)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["csv", "json", "tsv"],
        default="csv",
        help="Output format (default: csv)"
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        help="Maximum number of data items to process (default: all)"
    )
    parser.add_argument(
        "--min-xrefs", "-m",
        type=int,
        default=0,
        help="Minimum xrefs to include in output (default: 0)"
    )
    parser.add_argument(
        "--include-xref-details",
        action="store_true",
        help="Include detailed xref information in JSON output"
    )

    args = parser.parse_args()

    # Fetch all data items
    data_items = get_all_data_items(limit=args.limit)

    if not data_items:
        print("No data items found!", file=sys.stderr)
        sys.exit(1)

    # Process xrefs in batches
    results = process_xrefs_in_batches(data_items)

    # Save results
    if args.format == "csv":
        save_as_csv(results, args.output, args.min_xrefs)
    elif args.format == "tsv":
        save_as_tsv(results, args.output, args.min_xrefs)
    elif args.format == "json":
        save_as_json(results, args.output, args.min_xrefs, args.include_xref_details)

    # Print summary
    print_summary(results)


if __name__ == "__main__":
    main()

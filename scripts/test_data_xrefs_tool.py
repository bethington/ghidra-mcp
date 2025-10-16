#!/usr/bin/env python3
"""
Test script for the new list_data_items_by_xrefs MCP tool.

This script tests both text and JSON output formats.
"""

import requests
import json

GHIDRA_SERVER = "http://127.0.0.1:8089"


def test_endpoint_text():
    """Test the REST endpoint with text format."""
    print("=" * 70)
    print("TEST 1: REST Endpoint - Text Format")
    print("=" * 70)

    url = f"{GHIDRA_SERVER}/list_data_items_by_xrefs"
    params = {"offset": 0, "limit": 10, "format": "text"}

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        print(response.text)
        print("\n✓ Text format test PASSED\n")
        return True
    except Exception as e:
        print(f"\n✗ Text format test FAILED: {e}\n")
        return False


def test_endpoint_json():
    """Test the REST endpoint with JSON format."""
    print("=" * 70)
    print("TEST 2: REST Endpoint - JSON Format")
    print("=" * 70)

    url = f"{GHIDRA_SERVER}/list_data_items_by_xrefs"
    params = {"offset": 0, "limit": 10, "format": "json"}

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        # Parse and pretty-print JSON
        data = json.loads(response.text)
        print(json.dumps(data, indent=2))

        # Verify structure
        if not isinstance(data, list):
            raise ValueError("Expected a list")

        if len(data) > 0:
            first_item = data[0]
            required_fields = ["address", "name", "type", "size", "xref_count"]
            for field in required_fields:
                if field not in first_item:
                    raise ValueError(f"Missing required field: {field}")

        print("\n✓ JSON format test PASSED\n")
        return True
    except Exception as e:
        print(f"\n✗ JSON format test FAILED: {e}\n")
        return False


def test_sorting():
    """Test that results are actually sorted by xref count."""
    print("=" * 70)
    print("TEST 3: Verify Sorting by Xref Count")
    print("=" * 70)

    url = f"{GHIDRA_SERVER}/list_data_items_by_xrefs"
    params = {"offset": 0, "limit": 50, "format": "json"}

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        data = json.loads(response.text)

        # Check that xref counts are in descending order
        xref_counts = [item["xref_count"] for item in data]

        print(f"Top 10 xref counts: {xref_counts[:10]}")

        # Verify descending order
        for i in range(len(xref_counts) - 1):
            if xref_counts[i] < xref_counts[i + 1]:
                raise ValueError(
                    f"Items not sorted! xref_count[{i}]={xref_counts[i]} < "
                    f"xref_count[{i+1}]={xref_counts[i+1]}"
                )

        print("\n✓ Sorting test PASSED - Items are correctly sorted in descending order\n")
        return True
    except Exception as e:
        print(f"\n✗ Sorting test FAILED: {e}\n")
        return False


def show_top_items():
    """Display the top 20 most referenced data items."""
    print("=" * 70)
    print("TOP 20 MOST REFERENCED DATA ITEMS")
    print("=" * 70)

    url = f"{GHIDRA_SERVER}/list_data_items_by_xrefs"
    params = {"offset": 0, "limit": 20, "format": "json"}

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        data = json.loads(response.text)

        print(f"\n{'Rank':<6} {'Address':<12} {'Xrefs':<8} {'Name':<30} {'Type':<15}")
        print("-" * 70)

        for i, item in enumerate(data, 1):
            print(
                f"{i:<6} {item['address']:<12} {item['xref_count']:<8} "
                f"{item['name']:<30} {item['type']:<15}"
            )

        print("\n✓ Successfully displayed top 20 items\n")
        return True
    except Exception as e:
        print(f"\n✗ Failed to display top items: {e}\n")
        return False


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("GHIDRA MCP - list_data_items_by_xrefs Tool Test Suite")
    print("=" * 70 + "\n")

    # Check connection
    try:
        response = requests.get(f"{GHIDRA_SERVER}/check_connection", timeout=5)
        print(f"✓ Connected to Ghidra: {response.text.strip()}\n")
    except Exception as e:
        print(f"✗ Cannot connect to Ghidra server: {e}")
        print("Please ensure:")
        print("  1. Ghidra is running")
        print("  2. A program is loaded in CodeBrowser")
        print("  3. GhidraMCP plugin is active on port 8089")
        return

    # Run tests
    results = []
    results.append(("Text Format", test_endpoint_text()))
    results.append(("JSON Format", test_endpoint_json()))
    results.append(("Sorting", test_sorting()))
    results.append(("Top Items Display", show_top_items()))

    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{name:<25} {status}")

    print("-" * 70)
    print(f"Tests Passed: {passed}/{total}")
    print("=" * 70 + "\n")

    if passed == total:
        print("✓ All tests passed! The new tool is working correctly.\n")
    else:
        print(f"✗ {total - passed} test(s) failed. Please check the errors above.\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
GhidraMCP Test Runner

Usage:
    python run_tests.py --unit           # Run unit tests only
    python run_tests.py --integration    # Run integration tests
    python run_tests.py --docker         # Run Docker tests
    python run_tests.py --all            # Run all tests
    python run_tests.py --server URL     # Specify server URL

Examples:
    # Run integration tests against local server
    python run_tests.py --integration --server http://localhost:8089

    # Run all tests in verbose mode
    python run_tests.py --all -v

    # Run specific test file
    python run_tests.py tests/integration/test_all_endpoints.py
"""

import argparse
import os
import sys
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="GhidraMCP Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # Test selection
    parser.add_argument("--unit", action="store_true",
                        help="Run unit tests only (no server required)")
    parser.add_argument("--integration", action="store_true",
                        help="Run integration tests (requires running server)")
    parser.add_argument("--docker", action="store_true",
                        help="Run Docker tests (requires Docker)")
    parser.add_argument("--all", action="store_true",
                        help="Run all tests")

    # Configuration
    parser.add_argument("--server", default="http://localhost:8089",
                        help="Server URL (default: http://localhost:8089)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Request timeout in seconds (default: 30)")

    # Pytest options
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("-x", "--exitfirst", action="store_true",
                        help="Exit on first failure")
    parser.add_argument("-k", metavar="EXPRESSION",
                        help="Run tests matching expression")
    parser.add_argument("--collect-only", action="store_true",
                        help="Only collect tests, don't run")
    parser.add_argument("--html", metavar="FILE",
                        help="Generate HTML report")

    # Extra arguments
    parser.add_argument("extra_args", nargs="*",
                        help="Additional pytest arguments")

    args = parser.parse_args()

    # Set environment variables
    os.environ["GHIDRA_MCP_URL"] = args.server
    os.environ["GHIDRA_MCP_TIMEOUT"] = str(args.timeout)

    # Build pytest arguments
    pytest_args = []

    # Verbosity
    if args.verbose:
        pytest_args.append("-v")
    else:
        pytest_args.append("--tb=short")

    # Exit on first failure
    if args.exitfirst:
        pytest_args.append("-x")

    # Filter expression
    if args.k:
        pytest_args.extend(["-k", args.k])

    # Collect only
    if args.collect_only:
        pytest_args.append("--collect-only")

    # HTML report
    if args.html:
        pytest_args.extend(["--html", args.html, "--self-contained-html"])

    # Test directories
    tests_dir = Path(__file__).parent

    if args.all:
        pytest_args.append(str(tests_dir))
    else:
        if args.unit:
            pytest_args.append(str(tests_dir / "unit"))
        if args.integration:
            pytest_args.append(str(tests_dir / "integration"))
        if args.docker:
            pytest_args.append(str(tests_dir / "docker"))

    # If no test type specified, run all
    if not (args.unit or args.integration or args.docker or args.all):
        if args.extra_args:
            # Run specified files
            pytest_args.extend(args.extra_args)
        else:
            # Default to integration tests
            pytest_args.append(str(tests_dir / "integration"))

    # Add extra arguments
    if args.extra_args and not (args.unit or args.integration or args.docker or args.all):
        pass  # Already added above
    elif args.extra_args:
        pytest_args.extend(args.extra_args)

    # Print configuration
    print("=" * 60)
    print("GhidraMCP Test Runner")
    print("=" * 60)
    print(f"Server URL: {args.server}")
    print(f"Timeout: {args.timeout}s")
    print(f"pytest args: {' '.join(pytest_args)}")
    print("=" * 60)
    print()

    # Check server availability
    if args.integration or args.all:
        try:
            import requests
            response = requests.get(f"{args.server}/check_connection", timeout=5)
            if response.status_code == 200:
                print(f"[OK] Server is running at {args.server}")
            else:
                print(f"[WARN] Server returned status {response.status_code}")
        except Exception as e:
            print(f"[WARN] Cannot connect to server: {e}")
            print("       Integration tests may fail")
        print()

    # Run pytest
    try:
        import pytest
        return pytest.main(pytest_args)
    except ImportError:
        print("ERROR: pytest not installed")
        print("Install with: pip install pytest pytest-html requests")
        return 1


def generate_endpoint_report():
    """Generate a report of tested endpoints."""
    endpoints_file = Path(__file__).parent / "endpoints.json"
    if not endpoints_file.exists():
        print("endpoints.json not found")
        return

    with open(endpoints_file) as f:
        data = json.load(f)

    endpoints = data.get("endpoints", [])
    categories = {}

    for endpoint in endpoints:
        cat = endpoint.get("category", "unknown")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(endpoint)

    print("\nEndpoint Coverage Report")
    print("=" * 60)
    print(f"Total endpoints: {len(endpoints)}")
    print()

    for cat, eps in sorted(categories.items()):
        print(f"{cat.upper()}: {len(eps)} endpoints")
        for ep in eps[:5]:
            print(f"  {ep['method']:6} {ep['path']}")
        if len(eps) > 5:
            print(f"  ... and {len(eps) - 5} more")
        print()


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
GhidraMCP Test Runner

A comprehensive test runner for the GhidraMCP project that supports
different test types, configurations, and reporting options.

Usage:
    python run_tests.py                    # Run all tests
    python run_tests.py --unit             # Run only unit tests
    python run_tests.py --integration      # Run only integration tests  
    python run_tests.py --functional       # Run only functional tests
    python run_tests.py --slow             # Include slow tests
    python run_tests.py --coverage         # Generate coverage report
    python run_tests.py --html             # Generate HTML report
    python run_tests.py --server-url URL   # Use custom server URL
"""

import argparse
import sys
import os
import subprocess
from pathlib import Path
from typing import List, Optional


class TestRunner:
    """Main test runner for GhidraMCP."""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.tests_dir = project_root / "tests"
        
    def build_pytest_command(self, args: argparse.Namespace) -> List[str]:
        """Build the pytest command based on arguments."""
        cmd = ["python", "-m", "pytest"]
        
        # Test selection
        if args.unit:
            cmd.extend([str(self.tests_dir / "unit")])
        elif args.integration:
            cmd.extend([str(self.tests_dir / "integration")])
        elif args.functional:
            cmd.extend([str(self.tests_dir / "functional")])
        else:
            cmd.extend([str(self.tests_dir)])
        
        # Markers and filters
        markers = []
        if not args.slow:
            markers.append("not slow")
        if args.unit:
            markers.append("unit")
        elif args.integration:
            markers.append("integration") 
        elif args.functional:
            markers.append("functional")
            
        if markers:
            cmd.extend(["-m", " and ".join(markers)])
        
        # Output options
        if args.verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")
            
        # Coverage
        if args.coverage:
            cmd.extend([
                "--cov=src",
                "--cov-report=term-missing",
                "--cov-report=html:tests/coverage"
            ])
            
        # HTML report
        if args.html:
            cmd.extend([
                "--html=tests/report.html",
                "--self-contained-html"
            ])
            
        # Parallel execution
        if args.parallel and args.parallel > 1:
            cmd.extend(["-n", str(args.parallel)])
            
        # JUnit XML for CI
        if args.junit:
            cmd.extend(["--junit-xml=tests/junit.xml"])
            
        # Server URL
        if args.server_url:
            os.environ['GHIDRA_MCP_SERVER_URL'] = args.server_url
            
        # Timeout
        if args.timeout:
            cmd.extend(["--timeout", str(args.timeout)])
            
        # Additional pytest args
        if args.pytest_args:
            cmd.extend(args.pytest_args.split())
            
        return cmd
    
    def check_requirements(self) -> bool:
        """Check if test requirements are installed."""
        try:
            import pytest
            import requests
            print(f"✓ Testing environment ready (pytest {pytest.__version__})")
            return True
        except ImportError as e:
            print(f"✗ Missing test requirements: {e}")
            print("Install with: pip install -r requirements-test.txt")
            return False
    
    def run_tests(self, args: argparse.Namespace) -> int:
        """Run the tests and return exit code."""
        if not self.check_requirements():
            return 1
            
        cmd = self.build_pytest_command(args)
        
        print(f"Running command: {' '.join(cmd)}")
        print(f"Working directory: {self.project_root}")
        print("-" * 80)
        
        try:
            result = subprocess.run(cmd, cwd=self.project_root)
            return result.returncode
        except KeyboardInterrupt:
            print("\n\nTest run interrupted by user")
            return 130
        except Exception as e:
            print(f"Error running tests: {e}")
            return 1


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="GhidraMCP Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Run all tests
  %(prog)s --unit --coverage      # Run unit tests with coverage
  %(prog)s --integration -v       # Run integration tests verbosely
  %(prog)s --functional --slow    # Run functional tests including slow ones
  %(prog)s --parallel 4           # Run tests in parallel with 4 workers
  %(prog)s --server-url http://localhost:8080/  # Use custom server
        """
    )
    
    # Test type selection (mutually exclusive)
    test_group = parser.add_mutually_exclusive_group()
    test_group.add_argument(
        "--unit", 
        action="store_true",
        help="Run only unit tests"
    )
    test_group.add_argument(
        "--integration", 
        action="store_true",
        help="Run only integration tests"
    )
    test_group.add_argument(
        "--functional", 
        action="store_true",
        help="Run only functional tests"
    )
    
    # Test options
    parser.add_argument(
        "--slow", 
        action="store_true",
        help="Include slow tests (default: skip slow tests)"
    )
    parser.add_argument(
        "--coverage", 
        action="store_true",
        help="Generate coverage report"
    )
    parser.add_argument(
        "--html", 
        action="store_true",
        help="Generate HTML test report"
    )
    parser.add_argument(
        "--junit", 
        action="store_true",
        help="Generate JUnit XML report for CI"
    )
    
    # Output options
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Verbose output"
    )
    
    # Performance options
    parser.add_argument(
        "--parallel", 
        type=int,
        help="Run tests in parallel with N workers"
    )
    parser.add_argument(
        "--timeout", 
        type=int, 
        default=300,
        help="Test timeout in seconds (default: 300)"
    )
    
    # Server configuration
    parser.add_argument(
        "--server-url", 
        default="http://127.0.0.1:8089",
        help="Ghidra MCP server URL (default: http://127.0.0.1:8089)"
    )
    
    # Advanced options
    parser.add_argument(
        "--pytest-args", 
        help="Additional arguments to pass to pytest"
    )
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Find project root
    script_dir = Path(__file__).parent
    project_root = script_dir
    
    # Ensure we're in the right directory
    if not (project_root / "tests").exists():
        print("Error: tests directory not found")
        print(f"Expected to find tests in: {project_root / 'tests'}")
        return 1
    
    runner = TestRunner(project_root)
    return runner.run_tests(args)


if __name__ == "__main__":
    sys.exit(main())
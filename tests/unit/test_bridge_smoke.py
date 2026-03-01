"""
Smoke tests for the thin MCP bridge.

Verifies basic module structure without requiring mcp dependencies
or a running Ghidra instance.
"""

import ast
import sys
from pathlib import Path


BRIDGE_PATH = Path(__file__).parent.parent.parent / "bridge_mcp_ghidra.py"


class TestBridgeStructure:
    """Verify bridge module structure via AST (no import needed)."""

    def test_bridge_parses(self):
        """Bridge script should be valid Python."""
        source = BRIDGE_PATH.read_text()
        tree = ast.parse(source, filename=str(BRIDGE_PATH))
        assert isinstance(tree, ast.Module)

    def test_bridge_has_main_block(self):
        """Bridge should have an if __name__ == '__main__' block."""
        source = BRIDGE_PATH.read_text()
        assert 'if __name__' in source

    def test_bridge_defines_key_functions(self):
        """Bridge should define dispatch and connection functions."""
        source = BRIDGE_PATH.read_text()
        tree = ast.parse(source, filename=str(BRIDGE_PATH))
        func_names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        # Core functions that must exist in the thin bridge
        assert "dispatch_get" in func_names or "dispatch_post" in func_names, \
            f"Missing dispatch functions. Found: {sorted(func_names)}"

    def test_bridge_under_1000_lines(self):
        """Thin bridge should stay under 1000 lines."""
        lines = BRIDGE_PATH.read_text().splitlines()
        assert len(lines) < 1000, f"Bridge is {len(lines)} lines, expected < 1000"

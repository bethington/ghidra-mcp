"""
Endpoint Catalog Consistency Tests.

Verifies that:
1. Java services have @McpTool annotations that AnnotationScanner discovers
2. endpoints.json catalog stays in sync
3. Bridge dynamically registers from /mcp/schema (no hardcoded tools)
"""

import json
import os
import re
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
JAVA_SRC = PROJECT_ROOT / "src" / "main" / "java" / "com" / "xebyte"
CORE_SRC = JAVA_SRC / "core"
ENDPOINTS_JSON = PROJECT_ROOT / "tests" / "endpoints.json"


def count_mcptool_annotations() -> int:
    """Count @McpTool annotations across all service files."""
    count = 0
    for java_file in CORE_SRC.glob("*Service.java"):
        content = java_file.read_text()
        count += len(re.findall(r"@McpTool\(", content))
    return count


def extract_annotated_paths() -> set[str]:
    """Extract all HTTP paths from @McpTool annotations."""
    paths = set()
    pattern = re.compile(r'@McpTool\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
    for java_file in CORE_SRC.glob("*Service.java"):
        content = java_file.read_text()
        for match in pattern.finditer(content):
            paths.add(match.group(1))
    return paths


def extract_gui_only_paths() -> set[str]:
    """Extract GUI-only endpoint paths from GhidraMCPPlugin.java."""
    paths = set()
    plugin_file = JAVA_SRC / "GhidraMCPPlugin.java"
    if plugin_file.exists():
        content = plugin_file.read_text()
        for match in re.finditer(r'server\.createContext\("([^"]+)"', content):
            paths.add(match.group(1))
    return paths


class TestAnnotatedEndpoints(unittest.TestCase):
    """Verify annotation-driven endpoint registration."""

    def test_has_annotated_endpoints(self):
        """Services should have @McpTool annotations."""
        count = count_mcptool_annotations()
        self.assertGreater(
            count, 100, f"Expected >100 annotated endpoints, found {count}"
        )

    def test_all_paths_start_with_slash(self):
        """All @McpTool paths should start with /."""
        for path in extract_annotated_paths():
            self.assertTrue(path.startswith("/"), f"Path should start with /: {path}")

    def test_no_duplicate_paths(self):
        """No two @McpTool annotations should have the same path."""
        paths = []
        pattern = re.compile(r'@McpTool\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
        for java_file in CORE_SRC.glob("*Service.java"):
            content = java_file.read_text()
            for match in pattern.finditer(content):
                paths.append(match.group(1))
        duplicates = [p for p in paths if paths.count(p) > 1]
        # Some paths may appear twice (with/without program param overload)
        # but should not appear more than twice
        triplicates = [p for p in set(duplicates) if paths.count(p) > 2]
        self.assertEqual(len(triplicates), 0, f"Triplicate paths: {triplicates}")

    def test_services_exist(self):
        """Expected service files should exist."""
        expected_services = [
            "ListingService",
            "FunctionService",
            "CommentService",
            "SymbolLabelService",
            "XrefCallGraphService",
            "DataTypeService",
            "AnalysisService",
            "DocumentationHashService",
            "MalwareSecurityService",
            "ProgramScriptService",
        ]
        for svc in expected_services:
            path = CORE_SRC / f"{svc}.java"
            self.assertTrue(path.exists(), f"Missing service: {path}")


class TestEndpointsJson(unittest.TestCase):
    """Verify endpoints.json catalog validity."""

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_valid_json(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        self.assertIn("endpoints", data)

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_no_duplicate_paths(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        paths = [ep["path"] for ep in data.get("endpoints", [])]
        self.assertEqual(
            len(paths), len(set(paths)), "Duplicate paths in endpoints.json"
        )

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_endpoints_have_required_fields(self):
        data = json.loads(ENDPOINTS_JSON.read_text())
        for ep in data.get("endpoints", []):
            self.assertIn("path", ep, f"Missing 'path' in endpoint: {ep}")
            self.assertIn("method", ep, f"Missing 'method' in endpoint: {ep}")

    @unittest.skipUnless(ENDPOINTS_JSON.exists(), "endpoints.json not found")
    def test_catalog_tool_names_are_capi_safe_after_bridge_parsing(self):
        """The generated endpoint catalog should produce valid exposed MCP names."""
        from bridge_mcp_ghidra import _parse_schema

        data = json.loads(ENDPOINTS_JSON.read_text())
        raw_schema = {
            "tools": [
                {
                    "path": ep["path"],
                    "method": ep.get("method", "GET"),
                    "params": [],
                }
                for ep in data.get("endpoints", [])
            ]
        }
        invalid = [
            tool["name"] for tool in _parse_schema(raw_schema)
            if not re.fullmatch(r"^[a-zA-Z0-9_-]+$", tool["name"])
        ]
        self.assertEqual(invalid, [])


class TestBridgeIsDynamic(unittest.TestCase):
    """Verify the bridge uses dynamic registration, not hardcoded tools."""

    def test_bridge_has_few_static_tools(self):
        """Bridge static tool decorators should match the explicit static tool allowlist."""
        import bridge_mcp_ghidra as bridge

        bridge_path = PROJECT_ROOT / "bridge_mcp_ghidra.py"
        content = bridge_path.read_text()
        tool_count = len(re.findall(r"@mcp\.tool\(\)", content))
        self.assertEqual(
            tool_count,
            len(bridge.STATIC_TOOL_NAMES),
            f"Bridge has {tool_count} @mcp.tool() decorators but "
            f"{len(bridge.STATIC_TOOL_NAMES)} static tool names",
        )

    def test_bridge_has_schema_registration(self):
        """Bridge should have register_tools_from_schema function."""
        bridge_path = PROJECT_ROOT / "bridge_mcp_ghidra.py"
        content = bridge_path.read_text()
        self.assertIn("register_tools_from_schema", content)
        self.assertIn("/mcp/schema", content)

    def test_bridge_size_reasonable(self):
        """Thin bridge should stay manageable while allowing debugger/tool-group growth."""
        bridge_path = PROJECT_ROOT / "bridge_mcp_ghidra.py"
        lines = len(bridge_path.read_text().splitlines())
        self.assertLess(
            lines, 2000, f"Bridge is {lines} lines, expected <2000 for thin multiplexer"
        )


class TestAnnotationScannerExists(unittest.TestCase):
    """Verify AnnotationScanner infrastructure."""

    def test_annotation_scanner_exists(self):
        path = CORE_SRC / "AnnotationScanner.java"
        self.assertTrue(path.exists())

    def test_mcptool_annotation_exists(self):
        path = CORE_SRC / "McpTool.java"
        self.assertTrue(path.exists())

    def test_param_annotation_exists(self):
        path = CORE_SRC / "Param.java"
        self.assertTrue(path.exists())

    def test_mcp_tool_group_annotation_exists(self):
        path = CORE_SRC / "McpToolGroup.java"
        self.assertTrue(path.exists())

    def test_scanner_has_schema_method(self):
        content = (CORE_SRC / "AnnotationScanner.java").read_text()
        self.assertIn("generateSchema", content)
        self.assertIn("ToolDescriptor", content)

    def test_all_services_have_tool_group(self):
        """All service files should have @McpToolGroup annotation."""
        expected = [
            "ListingService",
            "FunctionService",
            "CommentService",
            "SymbolLabelService",
            "XrefCallGraphService",
            "DataTypeService",
            "AnalysisService",
            "DocumentationHashService",
            "MalwareSecurityService",
            "ProgramScriptService",
        ]
        for name in expected:
            path = CORE_SRC / f"{name}.java"
            if path.exists():
                content = path.read_text()
                self.assertIn(
                    "@McpToolGroup",
                    content,
                    f"{name}.java missing @McpToolGroup annotation",
                )


if __name__ == "__main__":
    unittest.main()

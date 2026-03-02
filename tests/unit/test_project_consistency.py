"""
Project Consistency Tests.

Validates version consistency, bridge configuration, and architectural
invariants across the project. All tests run without a server.
"""

import json
import os
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
JAVA_SRC = PROJECT_ROOT / "src" / "main" / "java" / "com" / "xebyte"
CORE_SRC = JAVA_SRC / "core"
POM_XML = PROJECT_ROOT / "pom.xml"
PYTHON_BRIDGE = PROJECT_ROOT / "bridge_mcp_ghidra.py"


def get_pom_version() -> str:
    """Extract version from pom.xml."""
    tree = ET.parse(POM_XML)
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    version = tree.find(".//m:version", ns)
    return version.text if version is not None else ""


class TestVersionConsistency(unittest.TestCase):
    """Verify version strings are consistent across sources."""

    def test_pom_version_exists(self):
        version = get_pom_version()
        self.assertTrue(version, "pom.xml should have a version")
        self.assertRegex(version, r'\d+\.\d+\.\d+')

    def test_java_version_matches_pom(self):
        """VersionInfo in GhidraMCPPlugin.java should match pom.xml."""
        pom_version = get_pom_version()
        plugin_path = JAVA_SRC / "GhidraMCPPlugin.java"
        if plugin_path.exists():
            content = plugin_path.read_text()
            match = re.search(r'VERSION\s*=\s*"([^"]+)"', content)
            if match:
                self.assertEqual(match.group(1), pom_version,
                    f"VersionInfo VERSION={match.group(1)} != pom.xml {pom_version}")


class TestBridgeConfiguration(unittest.TestCase):
    """Verify bridge configuration and imports."""

    def test_bridge_importable(self):
        """Bridge should be importable without errors."""
        try:
            import bridge_mcp_ghidra
        except ImportError as e:
            self.fail(f"Bridge import failed: {e}")

    def test_bridge_has_uds_support(self):
        """Bridge should support Unix domain sockets."""
        content = PYTHON_BRIDGE.read_text()
        self.assertIn("UnixHTTPConnection", content)
        self.assertIn("AF_UNIX", content)

    def test_bridge_has_tcp_fallback(self):
        """Bridge should support TCP as fallback."""
        content = PYTHON_BRIDGE.read_text()
        self.assertIn("tcp_request", content)
        self.assertIn("DEFAULT_TCP_URL", content)

    def test_bridge_has_auto_connect(self):
        """Bridge should auto-connect on startup."""
        content = PYTHON_BRIDGE.read_text()
        self.assertIn("_auto_connect", content)

    def test_bridge_dependencies_minimal(self):
        """Bridge should only depend on mcp (no requests library)."""
        content = PYTHON_BRIDGE.read_text()
        # The thin bridge uses stdlib http.client, not requests
        self.assertNotIn("import requests", content)


class TestJavaArchitecture(unittest.TestCase):
    """Verify Java architectural invariants."""

    def test_annotation_scanner_exists(self):
        self.assertTrue((CORE_SRC / "AnnotationScanner.java").exists())

    def test_endpoint_registry_deleted(self):
        """EndpointRegistry.java should be deleted (replaced by annotations)."""
        self.assertFalse((CORE_SRC / "EndpointRegistry.java").exists(),
            "EndpointRegistry.java should be deleted — replaced by AnnotationScanner")

    def test_endpoint_def_deleted(self):
        """EndpointDef.java should be deleted (replaced by ToolDef in AnnotationScanner)."""
        self.assertFalse((CORE_SRC / "EndpointDef.java").exists(),
            "EndpointDef.java should be deleted — replaced by AnnotationScanner.ToolDef")

    def test_uds_server_exists(self):
        self.assertTrue((CORE_SRC / "UdsHttpServer.java").exists())

    def test_server_manager_exists(self):
        self.assertTrue((CORE_SRC / "ServerManager.java").exists())

    def test_http_exchange_interface_exists(self):
        self.assertTrue((CORE_SRC / "HttpExchange.java").exists())

    def test_services_use_response_type(self):
        """Service methods should return Response type."""
        for svc_file in CORE_SRC.glob("*Service.java"):
            content = svc_file.read_text()
            if "@McpTool" in content:
                # At least some methods should return Response
                self.assertIn("Response", content,
                    f"{svc_file.name} has @McpTool but no Response return type")

    def test_all_services_have_annotations(self):
        """All service files should have at least one @McpTool annotation."""
        expected = [
            "ListingService", "FunctionService", "CommentService",
            "SymbolLabelService", "XrefCallGraphService", "DataTypeService",
            "AnalysisService", "DocumentationHashService",
            "MalwareSecurityService", "ProgramScriptService",
        ]
        for name in expected:
            path = CORE_SRC / f"{name}.java"
            if path.exists():
                content = path.read_text()
                self.assertIn("@McpTool", content,
                    f"{name}.java missing @McpTool annotations")


class TestProjectStructure(unittest.TestCase):
    """Verify key project files exist."""

    def test_pom_xml_exists(self):
        self.assertTrue(POM_XML.exists())

    def test_bridge_exists(self):
        self.assertTrue(PYTHON_BRIDGE.exists())

    def test_plugin_exists(self):
        self.assertTrue((JAVA_SRC / "GhidraMCPPlugin.java").exists())

    def test_headless_server_exists(self):
        self.assertTrue(
            (JAVA_SRC / "headless" / "GhidraMCPHeadlessServer.java").exists()
        )


if __name__ == "__main__":
    unittest.main()

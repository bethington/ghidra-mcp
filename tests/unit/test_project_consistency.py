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
PYPROJECT_TOML = PROJECT_ROOT / "pyproject.toml"
# The bridge is now a package split across modules under python/.
BRIDGE_PKG = PROJECT_ROOT / "python" / "bridge_mcp_ghidra"
ENDPOINTS_JSON = PROJECT_ROOT / "tests" / "endpoints.json"


def bridge_source_text() -> str:
    """Concatenated text of every bridge module."""
    return "\n".join(p.read_text() for p in sorted(BRIDGE_PKG.glob("*.py")))


def get_pom_version() -> str:
    """Extract version from pom.xml."""
    tree = ET.parse(POM_XML)
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    version = tree.find(".//m:version", ns)
    return version.text if version is not None else ""


def get_pyproject_version() -> str:
    """Extract the [project] version from pyproject.toml."""
    match = re.search(
        r'(?m)^version = "(\d+\.\d+\.\d+)"', PYPROJECT_TOML.read_text(encoding="utf-8")
    )
    return match.group(1) if match else ""


def get_bridge_fallback_version() -> str:
    """Extract the from-source __version__ fallback in the bridge package __init__.

    This is the version reported when the bridge runs from an uninstalled
    source tree (the importlib.metadata lookup fails). version_bump.py keeps it
    in sync with pyproject/pom, so it's a real version source and must not drift.
    """
    init_py = BRIDGE_PKG / "__init__.py"
    match = re.search(
        r'__version__ = "(\d+\.\d+\.\d+)"', init_py.read_text(encoding="utf-8")
    )
    return match.group(1) if match else ""


class TestVersionConsistency(unittest.TestCase):
    """Verify version strings are consistent across sources."""

    def test_pom_version_exists(self):
        version = get_pom_version()
        self.assertTrue(version, "pom.xml should have a version")
        self.assertRegex(version, r'\d+\.\d+\.\d+')

    def test_pyproject_version_matches_pom(self):
        """The wheel's version (pyproject.toml) must track pom.xml."""
        self.assertEqual(
            get_pyproject_version(),
            get_pom_version(),
            "pyproject.toml [project] version != pom.xml version",
        )

    def test_bridge_fallback_version_matches_pom(self):
        """The bridge package's from-source __version__ fallback must track pom.xml.

        version_bump.py maintains this alongside pyproject.toml; without this
        guard it can silently drift (a running-from-source bridge would then
        report a stale version). Regression: it shipped as 5.14.1 while the repo
        was 5.15.0 until this check was added.
        """
        self.assertEqual(
            get_bridge_fallback_version(),
            get_pom_version(),
            "python/bridge_mcp_ghidra/__init__.py __version__ fallback != pom.xml version",
        )

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

    def test_user_visible_tool_counts_match_endpoint_catalog(self):
        """Marketing/extension metadata should not drift from endpoints.json."""
        expected = json.loads(ENDPOINTS_JSON.read_text())["total_endpoints"]
        checks = {
            "README.md": PROJECT_ROOT / "README.md",
            "CLAUDE.md": PROJECT_ROOT / "CLAUDE.md",
            "AGENTS.md": PROJECT_ROOT / "AGENTS.md",
            "extension.properties": PROJECT_ROOT / "src" / "main" / "resources" / "extension.properties",
            "MANIFEST.MF": PROJECT_ROOT / "src" / "main" / "resources" / "META-INF" / "MANIFEST.MF",
        }
        pattern = re.compile(r"(\d+)\s+MCP tools?", re.IGNORECASE)
        mismatches = []
        for name, path in checks.items():
            for match in pattern.finditer(path.read_text(encoding="utf-8")):
                found = int(match.group(1))
                if found != expected:
                    mismatches.append(f"{name}: {found} != {expected}")
        self.assertEqual(mismatches, [])


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
        content = bridge_source_text()
        self.assertIn("UnixHTTPConnection", content)
        self.assertIn("AF_UNIX", content)

    def test_bridge_has_tcp_fallback(self):
        """Bridge should support TCP as fallback."""
        content = bridge_source_text()
        self.assertIn("tcp_request", content)
        self.assertIn("DEFAULT_TCP_URL", content)

    def test_bridge_has_auto_connect(self):
        """Bridge should auto-connect on startup."""
        content = bridge_source_text()
        self.assertIn("_auto_connect", content)

    def test_bridge_dependencies_minimal(self):
        """Bridge code should use stdlib http.client, not the requests library."""
        content = bridge_source_text()
        # The thin bridge uses stdlib http.client, not requests
        self.assertNotIn("import requests", content)


class TestJavaArchitecture(unittest.TestCase):
    """Verify Java architectural invariants."""

    def test_annotation_scanner_exists(self):
        self.assertTrue((CORE_SRC / "AnnotationScanner.java").exists())

    def test_endpoint_registry_exists(self):
        """EndpointRegistry.java coexists with AnnotationScanner (upstream keeps both)."""
        self.assertTrue((CORE_SRC / "EndpointRegistry.java").exists())

    def test_endpoint_def_exists(self):
        """EndpointDef.java is used by AnnotationScanner for endpoint handling."""
        self.assertTrue((CORE_SRC / "EndpointDef.java").exists())

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

    def test_manual_gui_headless_shared_endpoints_do_not_drift(self):
        """Manual createContext registrations need explicit GUI/headless parity."""
        gui_file = JAVA_SRC / "GhidraMCPPlugin.java"
        headless_file = JAVA_SRC / "headless" / "GhidraMCPHeadlessServer.java"
        gui = set(re.findall(r'server\.createContext\("([^"]+)"', gui_file.read_text()))
        headless = set(re.findall(r'safeContext\("([^"]+)"', headless_file.read_text()))
        annotated = set()
        for java_file in list(CORE_SRC.glob("*Service.java")) + list((JAVA_SRC / "headless").glob("*Service.java")):
            annotated.update(
                re.findall(r'@McpTool\(\s*(?:path\s*=\s*)?"([^"]+)"', java_file.read_text())
            )

        gui_only_expected = {
            "/batch_apply_documentation",
            # /get_current_selection — added 2026-05-23 (@I-Knight-I, #153).
            # Selection is the CodeBrowser listing's highlight state — a UI
            # concept with no equivalent in headless mode, so it lives only
            # on the GUI plugin alongside the other current_* sibling tools
            # (which DO have headless equivalents because address + function
            # generalize to "currentProgram-relative" outside a UI context).
            "/get_current_selection",
            "/mcp/health",
            "/mcp/instance_info",
            "/project/info",
            "/server/authenticate",
            "/tool/goto_address",
            "/tool/launch_codebrowser",
            "/tool/running_tools",
        }
        headless_only_expected = {
            "/configure_analyzer",
            "/delete_project",
            "/health",
            "/list_projects",
            "/move_file",
            "/move_folder",
        }

        self.assertEqual(gui - headless - annotated, gui_only_expected)
        self.assertEqual(headless - gui - annotated, headless_only_expected)

    def test_manual_admin_endpoint_params_are_cataloged(self):
        """Hand-registered admin routes should document mode-specific params."""
        catalog = {
            entry["path"]: set(entry.get("params", []))
            for entry in json.loads(ENDPOINTS_JSON.read_text())["endpoints"]
        }

        expected_params = {
            "/server/admin/terminate_all_checkouts": {"repo", "path"},
            "/server/admin/terminate_checkout": {
                "repo", "path", "checkoutId", "checkout_id"
            },
        }
        for path, params in expected_params.items():
            self.assertIn(path, catalog)
            self.assertTrue(
                params.issubset(catalog[path]),
                f"{path} missing params: {sorted(params - catalog[path])}",
            )


class TestProjectStructure(unittest.TestCase):
    """Verify key project files exist."""

    def test_pom_xml_exists(self):
        self.assertTrue(POM_XML.exists())

    def test_bridge_exists(self):
        self.assertTrue((BRIDGE_PKG / "__init__.py").exists())

    def test_plugin_exists(self):
        self.assertTrue((JAVA_SRC / "GhidraMCPPlugin.java").exists())

    def test_headless_server_exists(self):
        self.assertTrue(
            (JAVA_SRC / "headless" / "GhidraMCPHeadlessServer.java").exists()
        )


if __name__ == "__main__":
    unittest.main()

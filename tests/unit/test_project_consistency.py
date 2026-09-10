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


def strip_jsonc_comments(text: str) -> str:
    """Remove // line comments from JSONC, leaving string literals intact."""
    out = []
    in_string = False
    escaped = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if text[i:i + 2] == "//":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


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
        expected = json.loads(ENDPOINTS_JSON.read_text(encoding="utf-8"))["total_endpoints"]
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

    def test_readme_api_reference_matches_endpoint_catalog(self):
        """README's API Reference section is generated from endpoints.json.

        Any @McpTool addition that passes EndpointsJsonParityTest must also
        refresh the README listing:
            python -m tools.gen_readme_api_reference --write
        """
        from tools.gen_readme_api_reference import readme_section, render_api_reference

        readme_text = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(
            readme_section(readme_text),
            render_api_reference(),
            "README API Reference is stale — run "
            "'python -m tools.gen_readme_api_reference --write'",
        )


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

    def test_endpoint_registry_removed(self):
        """EndpointRegistry.java was dead code (never instantiated; routing is 100%
        AnnotationScanner-driven in both GUI and headless) and was removed in 7.0.0."""
        self.assertFalse((CORE_SRC / "EndpointRegistry.java").exists())

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
            # /move_file and /move_folder used to be listed here. They were
            # hand-routed headless-only while tests/endpoints.json advertised
            # them globally, so a FrontEnd-mode /mcp/schema never served them
            # and every bridge call 404'd. They are now @McpTool methods on
            # ProgramScriptService, i.e. `annotated`, and must NOT come back
            # to this set -- see ProjectMoveEndpointsOfflineTest.
        }

        self.assertEqual(gui - headless - annotated, gui_only_expected)
        self.assertEqual(headless - gui - annotated, headless_only_expected)

    def test_manual_admin_endpoint_params_are_cataloged(self):
        """Hand-registered admin routes should document mode-specific params."""
        catalog = {
            entry["path"]: set(entry.get("params", []))
            for entry in json.loads(ENDPOINTS_JSON.read_text(encoding="utf-8"))["endpoints"]
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


class TestMarkdownLintConfig(unittest.TestCase):
    """The documentation-quality gate must actually be able to run.

    Until 2026-08-30 `.github/workflows/tests.yml` passed
    `config: '.markdownlintrc'` to markdownlint-cli2-action. markdownlint-cli2
    rejects that filename outright, so every run aborted before reading a
    Markdown file -- and `continue-on-error: true` reported the abort as a
    green check. The gate had never linted anything. These tests pin the two
    halves of that failure so it cannot come back silently.
    """

    # markdownlint-cli2's accepted configuration-file names, quoted from the
    # error it raises for anything else: one of the supported base names, a
    # prefixed form of one, or a supported extension.
    SUPPORTED_BASENAMES = (
        ".markdownlint-cli2.jsonc",
        ".markdownlint-cli2.yaml",
        ".markdownlint-cli2.cjs",
        ".markdownlint-cli2.mjs",
        ".markdownlint.jsonc",
        ".markdownlint.json",
        ".markdownlint.yaml",
        ".markdownlint.yml",
        ".markdownlint.cjs",
        ".markdownlint.mjs",
    )
    SUPPORTED_EXTENSIONS = (".jsonc", ".json", ".yaml", ".yml", ".cjs", ".mjs")

    def workflow_text(self) -> str:
        path = PROJECT_ROOT / ".github" / "workflows" / "tests.yml"
        return path.read_text(encoding="utf-8")

    def lint_step_config(self) -> str:
        """The `config:` value the markdown-lint job passes to the action."""
        parts = self.workflow_text().split("markdown-lint:", 1)
        self.assertEqual(len(parts), 2, "markdown-lint job missing from tests.yml")
        match = re.search(r"^\s*config:\s*'([^']+)'", parts[1], re.M)
        self.assertIsNotNone(match, "markdown-lint job passes no config: path")
        return match.group(1)

    def test_lint_config_file_exists(self):
        """The configured path must resolve; a wrong one lints nothing."""
        configured = self.lint_step_config()
        self.assertTrue(
            (PROJECT_ROOT / configured).is_file(),
            "tests.yml points markdownlint at %r, which does not exist" % configured,
        )

    def test_lint_config_name_is_one_markdownlint_cli2_accepts(self):
        """`.markdownlintrc` is markdownlint-cli v1; cli2 refuses to load it."""
        name = Path(self.lint_step_config()).name
        accepted = name in self.SUPPORTED_BASENAMES or name.endswith(
            self.SUPPORTED_EXTENSIONS
        )
        self.assertTrue(
            accepted,
            "markdownlint-cli2 cannot load %r: it needs one of %s or an "
            "extension in %s" % (name, self.SUPPORTED_BASENAMES,
                                 self.SUPPORTED_EXTENSIONS),
        )

    def test_lint_config_parses_and_keeps_every_disable_justified(self):
        """Every rule set to false must carry a comment saying why.

        Reaching zero findings by switching rules off is the same non-gate in
        a different disguise, so the config is JSONC specifically to keep the
        reason next to the setting.
        """
        text = (PROJECT_ROOT / self.lint_step_config()).read_text(encoding="utf-8")
        config = json.loads(strip_jsonc_comments(text)).get("config", {})
        disabled = [rule for rule, value in config.items() if value is False]
        self.assertTrue(disabled, "expected at least the historical disables")
        for rule in disabled:
            self.assertRegex(
                text,
                r"//[^\n]*\b" + re.escape(rule) + r"\b",
                "%s is disabled with no comment explaining why" % rule,
            )

    def test_lint_job_does_not_swallow_its_own_failure(self):
        """`continue-on-error` is what made the broken gate look green.

        The job stays advisory by being absent from build-status's `needs`,
        not by discarding its own result.
        """
        workflow = self.workflow_text()
        job = workflow.split("markdown-lint:", 1)[1].split("\n  pester-tests:", 1)[0]
        # A YAML key, not the phrase -- the job carries a comment block
        # explaining at length why the key is gone, and that prose must
        # not itself satisfy or trip this test.
        self.assertIsNone(
            re.search(r"^\s*continue-on-error\s*:", job, re.M),
            "the markdown-lint job must be able to report failure",
        )
        needs = re.search(r"^    needs: \[([^\]]*)\]", workflow, re.M)
        self.assertIsNotNone(needs, "build-status needs: list not found")
        self.assertNotIn(
            "markdown-lint",
            needs.group(1),
            "markdown-lint is advisory and must not gate build-status",
        )

    def test_no_stale_markdownlintrc(self):
        """A leftover .markdownlintrc would silently be the wrong source."""
        self.assertFalse(
            (PROJECT_ROOT / ".markdownlintrc").exists(),
            ".markdownlintrc is unreadable by markdownlint-cli2; "
            "the live config is .markdownlint-cli2.jsonc",
        )


if __name__ == "__main__":
    unittest.main()

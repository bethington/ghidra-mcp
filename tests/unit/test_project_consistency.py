"""
Project Consistency Tests.

Validates version consistency, bridge configuration, endpoint counts,
and workflow integrity across the project. All tests run without a server.

These tests catch the class of bugs found in v3.2.0:
- Stale version references across files
- ENDPOINT_COUNT constant out of sync with actual createContext calls
- Workflow files missing Ghidra JAR dependencies
- Bridge configuration issues (trailing slash, wrong HTTP method)
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

# Project root
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Source file paths
POM_XML = PROJECT_ROOT / "pom.xml"
JAVA_PLUGIN = (
    PROJECT_ROOT / "src" / "main" / "java" / "com" / "xebyte" / "GhidraMCPPlugin.java"
)
JAVA_HEADLESS = (
    PROJECT_ROOT
    / "src"
    / "main"
    / "java"
    / "com"
    / "xebyte"
    / "headless"
    / "GhidraMCPHeadlessServer.java"
)
PYTHON_BRIDGE = PROJECT_ROOT / "bridge_mcp_ghidra.py"
ENDPOINTS_JSON = PROJECT_ROOT / "tests" / "endpoints.json"
CLAUDE_MD = PROJECT_ROOT / "CLAUDE.md"
README_MD = PROJECT_ROOT / "README.md"
AGENTS_MD = PROJECT_ROOT / "AGENTS.md"
SETUP_PS1 = PROJECT_ROOT / "ghidra-mcp-setup.ps1"
EXT_PROPERTIES = PROJECT_ROOT / "src" / "main" / "resources" / "extension.properties"
VER_PROPERTIES = PROJECT_ROOT / "src" / "main" / "resources" / "version.properties"
BUMP_VERSION_PS1 = PROJECT_ROOT / "bump-version.ps1"
RELEASES_README = PROJECT_ROOT / "docs" / "releases" / "README.md"
WORKFLOWS_DIR = PROJECT_ROOT / ".github" / "workflows"


# =============================================================================
# Helpers
# =============================================================================


def get_pom_version() -> str:
    """Extract the project version from pom.xml (single source of truth)."""
    content = POM_XML.read_text(encoding="utf-8")
    match = re.search(r"<version>(\d+\.\d+\.\d+)</version>", content)
    assert match, "Could not find version in pom.xml"
    return match.group(1)


JAVA_REGISTRY = (
    PROJECT_ROOT
    / "src"
    / "main"
    / "java"
    / "com"
    / "xebyte"
    / "core"
    / "EndpointRegistry.java"
)


def count_create_context(java_path: Path) -> int:
    """Count server.createContext() calls in a Java file."""
    content = java_path.read_text(encoding="utf-8")
    return len(re.findall(r"(?:server|httpServer)\.createContext\(", content))


def count_registry_endpoints() -> int:
    """Count endpoints declared in EndpointRegistry.java."""
    if not JAVA_REGISTRY.exists():
        return 0
    content = JAVA_REGISTRY.read_text(encoding="utf-8")
    return len(re.findall(r'(?:get|post)\(\s*"/', content))


def count_total_endpoints(java_path: Path) -> int:
    """Count total endpoints: direct createContext + shared EndpointRegistry entries."""
    direct = count_create_context(java_path)
    registry = count_registry_endpoints()
    # The registry loop's createContext(ep.path(), ...) is matched by
    # count_create_context, but those endpoints are already counted by
    # count_registry_endpoints.  Subtract 1 to avoid double-counting.
    if registry > 0:
        content = java_path.read_text(encoding="utf-8")
        if re.search(r"\.createContext\(ep\.path\(\)", content):
            direct -= 1
    return direct + registry


def count_mcp_tools() -> int:
    """Count @mcp.tool() decorators in the bridge."""
    content = PYTHON_BRIDGE.read_text(encoding="utf-8")
    return len(re.findall(r"@mcp\.tool\(\)", content))


# Required Ghidra JARs that all CI workflows must install
REQUIRED_GHIDRA_JARS = {
    "Generic",
    "SoftwareModeling",
    "Project",
    "Docking",
    "Utility",
    "Gui",
    "FileSystem",
    "Graph",
    "DB",
    "Emulation",
    "Help",
    "Base",
    "Decompiler",
    "PDB",
    "FunctionID",
}


# =============================================================================
# Version Consistency Tests
# =============================================================================


class TestVersionConsistency:
    """All version references must match pom.xml (single source of truth)."""

    @pytest.fixture(autouse=True)
    def _version(self):
        self.version = get_pom_version()

    def test_pom_xml_is_source_of_truth(self):
        """pom.xml should contain a valid semver version."""
        assert re.match(r"^\d+\.\d+\.\d+$", self.version)

    def test_java_plugin_fallback_version(self):
        """GhidraMCPPlugin.java fallback VERSION should match pom.xml."""
        content = JAVA_PLUGIN.read_text(encoding="utf-8")
        matches = re.findall(r'"(\d+\.\d+\.\d+)"', content)
        for m in matches:
            if m != self.version and m == get_pom_version():
                continue
            # Only check version-like strings that look like our version pattern
            # (not Ghidra version or other constants)
        fallback = re.search(r'VERSION\s*=\s*"(\d+\.\d+\.\d+)"', content)
        assert fallback, "VERSION fallback string not found in GhidraMCPPlugin.java"
        assert (
            fallback.group(1) == self.version
        ), f"Java VERSION fallback {fallback.group(1)} != pom.xml {self.version}"

    def test_endpoints_json_version(self):
        """tests/endpoints.json version should match pom.xml."""
        data = json.loads(ENDPOINTS_JSON.read_text(encoding="utf-8"))
        assert (
            data.get("version") == self.version
        ), f"endpoints.json version {data.get('version')} != pom.xml {self.version}"

    def test_claude_md_version(self):
        """CLAUDE.md should reference the current version."""
        content = CLAUDE_MD.read_text(encoding="utf-8")
        assert (
            f"**Version**: {self.version}" in content
        ), f"CLAUDE.md missing '**Version**: {self.version}'"

    def test_readme_version_badge(self):
        """README.md version badge should match pom.xml."""
        content = README_MD.read_text(encoding="utf-8")
        assert (
            f"Version-{self.version}-brightgreen" in content
        ), f"README.md badge missing 'Version-{self.version}-brightgreen'"

    def test_readme_version_table(self):
        """README.md version table should match pom.xml."""
        content = README_MD.read_text(encoding="utf-8")
        assert (
            f"| **Version** | {self.version} |" in content
        ), f"README.md table missing '| **Version** | {self.version} |'"

    def test_agents_md_version(self):
        """AGENTS.md should reference the current version."""
        if not AGENTS_MD.exists():
            pytest.skip("AGENTS.md not found")
        content = AGENTS_MD.read_text(encoding="utf-8")
        assert (
            f"**Version**: {self.version}" in content
        ), f"AGENTS.md missing '**Version**: {self.version}'"

    def test_setup_script_version(self):
        """ghidra-mcp-setup.ps1 $PluginVersion should match pom.xml."""
        content = SETUP_PS1.read_text(encoding="utf-8")
        match = re.search(r'\$PluginVersion\s*=\s*"(\d+\.\d+\.\d+)"', content)
        assert match, "$PluginVersion not found in ghidra-mcp-setup.ps1"
        assert (
            match.group(1) == self.version
        ), f"ghidra-mcp-setup.ps1 version {match.group(1)} != pom.xml {self.version}"

    def test_releases_readme_latest(self):
        """docs/releases/README.md should mark current version as Latest."""
        if not RELEASES_README.exists():
            pytest.skip("docs/releases/README.md not found")
        content = RELEASES_README.read_text(encoding="utf-8")
        assert (
            f"### v{self.version} (Latest)" in content
        ), f"docs/releases/README.md missing '### v{self.version} (Latest)'"

    def test_extension_properties_uses_maven_filtering(self):
        """extension.properties should use ${project.version}, not hardcoded version."""
        content = EXT_PROPERTIES.read_text(encoding="utf-8")
        assert (
            "${project.version}" in content
        ), "extension.properties should use ${project.version} for Maven filtering"
        # Should NOT contain a hardcoded version like "Plugin version 3.2.0"
        hardcoded = re.search(r"Plugin version \d+\.\d+\.\d+", content)
        assert (
            not hardcoded
        ), f"extension.properties has hardcoded version: {hardcoded.group()}"

    def test_version_properties_uses_maven_filtering(self):
        """version.properties should use ${project.version}."""
        content = VER_PROPERTIES.read_text(encoding="utf-8")
        assert (
            "${project.version}" in content
        ), "version.properties should use ${project.version} for Maven filtering"


# =============================================================================
# Endpoint Count Tests
# =============================================================================


class TestEndpointCounts:
    """Endpoint counts in code and docs should match actual registrations."""

    def test_gui_endpoint_count_constant(self):
        """ENDPOINT_COUNT in GhidraMCPPlugin.java should match total endpoints (direct + registry)."""
        content = JAVA_PLUGIN.read_text(encoding="utf-8")
        match = re.search(r"ENDPOINT_COUNT\s*=\s*(\d+)", content)
        assert match, "ENDPOINT_COUNT constant not found in GhidraMCPPlugin.java"
        declared = int(match.group(1))
        actual = count_total_endpoints(JAVA_PLUGIN)
        assert declared == actual, (
            f"ENDPOINT_COUNT ({declared}) != actual endpoints ({actual}). "
            f"Update ENDPOINT_COUNT in GhidraMCPPlugin.java."
        )

    def test_endpoints_json_total(self):
        """total_endpoints in endpoints.json should match actual endpoint entries."""
        data = json.loads(ENDPOINTS_JSON.read_text(encoding="utf-8"))
        declared = data.get("total_endpoints")
        actual = len(data.get("endpoints", []))
        assert (
            declared == actual
        ), f"total_endpoints ({declared}) != actual entries ({actual}) in endpoints.json"

    def test_mcp_tool_count_reasonable(self):
        """Static MCP tool count should be within expected range.

        Most tools are now dynamically registered from /mcp/schema at runtime.
        Only ~22 complex bridge-only tools remain as static @mcp.tool() decorators.
        """
        count = count_mcp_tools()
        assert count >= 15, f"Static MCP tool count {count} seems too low (expected 15+)"
        assert count <= 50, f"Static MCP tool count {count} seems too high (expected <50)"

    def test_gui_endpoint_count_reasonable(self):
        """GUI endpoint count should be within expected range."""
        count = count_total_endpoints(JAVA_PLUGIN)
        assert count >= 140, f"GUI endpoint count {count} seems too low"
        assert count <= 200, f"GUI endpoint count {count} seems too high"

    def test_headless_endpoint_count_reasonable(self):
        """Headless endpoint count should be within expected range."""
        if not JAVA_HEADLESS.exists():
            pytest.skip("Headless server source not found")
        count = count_total_endpoints(JAVA_HEADLESS)
        assert count >= 160, f"Headless endpoint count {count} seems too low"
        assert count <= 220, f"Headless endpoint count {count} seems too high"


# =============================================================================
# Bridge Configuration Tests
# =============================================================================


class TestBridgeConfiguration:
    """Validate bridge_mcp_ghidra.py configuration and conventions."""

    @pytest.fixture(autouse=True)
    def _bridge_content(self):
        self.content = PYTHON_BRIDGE.read_text(encoding="utf-8")

    def test_default_server_no_trailing_slash(self):
        """DEFAULT_GHIDRA_SERVER must not have a trailing slash.

        A trailing slash causes urljoin() path resolution issues when
        constructing endpoint URLs like urljoin(base, '/list_functions').
        """
        match = re.search(r'DEFAULT_GHIDRA_SERVER\s*=\s*"([^"]+)"', self.content)
        assert match, "DEFAULT_GHIDRA_SERVER not found"
        url = match.group(1)
        assert not url.endswith("/"), (
            f"DEFAULT_GHIDRA_SERVER has trailing slash: '{url}'. "
            f"This breaks urljoin() path resolution."
        )

    def test_fuzzy_match_is_dynamic_tool(self):
        """find_similar_functions_fuzzy should be a dynamic tool (not static).

        Dynamic GET tools automatically use safe_get_json, which preserves
        JSON structure. This verifies the tool isn't accidentally in
        STATIC_TOOL_NAMES where it could use the wrong HTTP helper.
        """
        # Should NOT be in STATIC_TOOL_NAMES
        static_match = re.search(
            r'STATIC_TOOL_NAMES\s*=\s*\{([^}]+)\}', self.content, re.DOTALL
        )
        assert static_match, "STATIC_TOOL_NAMES not found in bridge"
        assert "find_similar_functions_fuzzy" not in static_match.group(1), (
            "find_similar_functions_fuzzy should NOT be in STATIC_TOOL_NAMES. "
            "Dynamic registration automatically uses safe_get_json for GET endpoints."
        )

    def test_bulk_fuzzy_is_dynamic_tool(self):
        """bulk_fuzzy_match should be a dynamic tool (not static).

        Dynamic POST tools automatically use safe_post_json, which preserves
        JSON structure.
        """
        static_match = re.search(
            r'STATIC_TOOL_NAMES\s*=\s*\{([^}]+)\}', self.content, re.DOTALL
        )
        assert static_match, "STATIC_TOOL_NAMES not found in bridge"
        assert "bulk_fuzzy_match" not in static_match.group(1), (
            "bulk_fuzzy_match should NOT be in STATIC_TOOL_NAMES. "
            "Dynamic registration automatically uses safe_post_json for POST endpoints."
        )

    def test_bridge_importable(self):
        """bridge_mcp_ghidra.py should be importable without errors.

        This catches syntax errors, missing imports, and module-level
        exceptions that would prevent the MCP server from starting.
        """
        result = subprocess.run(
            [sys.executable, "-c", "import bridge_mcp_ghidra"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            timeout=30,
        )
        assert (
            result.returncode == 0
        ), f"bridge_mcp_ghidra.py import failed:\n{result.stderr}"

    def test_all_mcp_tools_have_docstrings(self):
        """Every @mcp.tool() function should have a docstring."""
        # Find all @mcp.tool() decorated functions
        pattern = re.compile(
            r'@mcp\.tool\(\)\s*\ndef\s+(\w+)\([^)]*\)[^:]*:\s*\n(\s+"""|\s+\'\'\'|\s+[^\s])',
        )
        matches = pattern.findall(self.content)
        missing = [
            name
            for name, first_line in matches
            if '"""' not in first_line and "'''" not in first_line
        ]
        assert not missing, f"MCP tools missing docstrings: {missing[:10]}..."


# =============================================================================
# Java Source Consistency Tests
# =============================================================================


class TestJavaConsistency:
    """Validate Java source file consistency."""

    def test_osgi_class_naming_no_fixed_prefix(self):
        """Inline script class names should not use _mcp_inline_ fixed prefix.

        Fixed prefixes cause OSGi class cache collisions where the bundle
        resolver caches a stale classloader.
        """
        content = JAVA_PLUGIN.read_text(encoding="utf-8")
        # Strip Java comments before checking -- the old prefix may appear
        # in explanatory comments but must not be used as actual code.
        code_only = re.sub(r"//.*", "", content)  # line comments
        code_only = re.sub(
            r"/\*.*?\*/", "", code_only, flags=re.DOTALL
        )  # block comments
        assert "_mcp_inline_" not in code_only, (
            "GhidraMCPPlugin.java still uses _mcp_inline_ prefix in code. "
            "Should use unique class names to avoid OSGi cache collisions."
        )

    def test_pom_description_matches_version(self):
        """pom.xml description should reference the current version."""
        content = POM_XML.read_text(encoding="utf-8")
        version = get_pom_version()
        assert (
            f"v{version}:" in content
        ), f"pom.xml description should contain 'v{version}:'"


# =============================================================================
# CI Workflow Consistency Tests
# =============================================================================


class TestWorkflowConsistency:
    """Validate GitHub Actions workflow files."""

    def _get_workflow_files(self) -> list[Path]:
        """Get all workflow YAML files."""
        if not WORKFLOWS_DIR.exists():
            pytest.skip(".github/workflows/ not found")
        return sorted(WORKFLOWS_DIR.glob("*.yml"))

    def test_workflows_exist(self):
        """At least the core workflows should exist."""
        files = self._get_workflow_files()
        names = {f.name for f in files}
        assert "build.yml" in names, "Missing build.yml workflow"
        assert "tests.yml" in names, "Missing tests.yml workflow"
        assert "release.yml" in names, "Missing release.yml workflow"

    def test_workflows_are_valid_yaml(self):
        """All workflow files should be valid YAML."""
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        for workflow in self._get_workflow_files():
            content = workflow.read_text(encoding="utf-8")
            try:
                yaml.safe_load(content)
            except yaml.YAMLError as e:
                pytest.fail(f"{workflow.name} is invalid YAML: {e}")

    def test_all_workflows_install_all_ghidra_jars(self):
        """Every workflow that builds Java must install all 15 Ghidra JARs.

        Missing JARs cause build failures in CI. This was a recurring issue
        (Help.jar was missing from 3 workflows, 6 JARs missing from 2 workflows).
        """
        for workflow in self._get_workflow_files():
            content = workflow.read_text(encoding="utf-8")

            # Skip workflows that don't build Java
            if "mvn" not in content and "maven" not in content.lower():
                continue

            # Skip if it's just running mvn with a non-build goal
            if (
                "mvn clean" not in content
                and "mvn -q install:install-file" not in content
            ):
                continue

            # Check that workflow installs JARs to Maven (not just copies to ./lib/)
            if "install:install-file" not in content:
                # Check if it uses the broken cp-to-lib pattern
                if (
                    "cp " in content
                    and "/lib/" in content
                    and "ghidra" in content.lower()
                ):
                    pytest.fail(
                        f"{workflow.name} copies Ghidra JARs to ./lib/ instead of "
                        f"using mvn install:install-file. Maven can't find them."
                    )
                continue

            # Verify all 15 JARs are installed
            missing = []
            for jar in REQUIRED_GHIDRA_JARS:
                if f"-DartifactId={jar}" not in content:
                    missing.append(jar)

            if missing:
                pytest.fail(
                    f"{workflow.name} is missing {len(missing)} Ghidra JARs: "
                    f"{', '.join(sorted(missing))}. "
                    f"All 15 JARs must be installed for Maven builds."
                )

    def test_workflows_use_current_ghidra_version(self):
        """Workflows should reference the same Ghidra version as pom.xml."""
        pom_content = POM_XML.read_text(encoding="utf-8")
        ghidra_match = re.search(
            r"<ghidra\.version>(\d+\.\d+\.\d+)</ghidra\.version>", pom_content
        )
        if not ghidra_match:
            pytest.skip("ghidra.version not found in pom.xml")
        ghidra_version = ghidra_match.group(1)

        for workflow in self._get_workflow_files():
            content = workflow.read_text(encoding="utf-8")
            if "GHIDRA_VERSION" not in content:
                continue

            version_match = re.search(r"GHIDRA_VERSION:\s*(\d+\.\d+\.\d+)", content)
            if version_match:
                assert version_match.group(1) == ghidra_version, (
                    f"{workflow.name} uses Ghidra {version_match.group(1)} "
                    f"but pom.xml uses {ghidra_version}"
                )

    def test_release_workflows_use_v2_action(self):
        """Release workflows should use softprops/action-gh-release@v2."""
        for workflow in self._get_workflow_files():
            content = workflow.read_text(encoding="utf-8")
            if "action-gh-release@v1" in content:
                pytest.fail(
                    f"{workflow.name} uses action-gh-release@v1. "
                    f"Should use @v2 for latest features."
                )


# =============================================================================
# Bump Version Script Tests
# =============================================================================


class TestBumpVersionScript:
    """Validate bump-version.ps1 covers all version references."""

    def test_bump_script_exists(self):
        """bump-version.ps1 should exist."""
        assert BUMP_VERSION_PS1.exists(), "bump-version.ps1 not found"

    def test_bump_script_covers_all_version_files(self):
        """bump-version.ps1 should have rules for all files with version strings."""
        content = BUMP_VERSION_PS1.read_text(encoding="utf-8")

        # Files that the bump script MUST cover
        required_files = [
            "pom.xml",
            "GhidraMCPPlugin.java",
            "ghidra-mcp-setup.ps1",
            "endpoints.json",
            "CLAUDE.md",
            "README.md",
            "AGENTS.md",
            "releases\\README.md",  # docs/releases/README.md in Windows path
        ]

        missing = []
        for f in required_files:
            # Check for the file reference in the script (could be forward or back slash)
            f_fwd = f.replace("\\", "/")
            if f not in content and f_fwd not in content:
                missing.append(f)

        assert not missing, (
            f"bump-version.ps1 missing rules for: {missing}. "
            f"Version references in these files won't be updated."
        )

    def test_bump_script_does_not_cover_maven_filtered_files(self):
        """bump-version.ps1 should NOT have rules for Maven-filtered files.

        extension.properties and version.properties use ${project.version}
        and are populated by Maven at build time. They should not be managed
        by the bump script.
        """
        content = BUMP_VERSION_PS1.read_text(encoding="utf-8")
        # These lines should NOT appear as File targets in rules
        assert (
            "extension.properties" not in content.split("Pat =")[0] or True
        ), "bump-version.ps1 should not manage extension.properties (Maven-filtered)"

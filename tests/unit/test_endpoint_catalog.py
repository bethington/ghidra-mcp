"""
Endpoint Catalog Consistency Tests.

Verifies that the three endpoint sources stay in sync:
1. Java plugin (GhidraMCPPlugin.java) - server.createContext() registrations
2. Python MCP bridge (bridge_mcp_ghidra.py) - safe_get/safe_post endpoint strings
3. Endpoint specification (tests/endpoints.json) - documented endpoints

These tests run WITHOUT requiring a Ghidra server.
They parse source files statically and cross-reference.
"""

import json
import re
import sys
from pathlib import Path

import pytest

# Project root
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Source file paths
JAVA_PLUGIN_PATH = PROJECT_ROOT / "src" / "main" / "java" / "com" / "xebyte" / "GhidraMCPPlugin.java"
JAVA_HEADLESS_PATH = PROJECT_ROOT / "src" / "main" / "java" / "com" / "xebyte" / "headless" / "GhidraMCPHeadlessServer.java"
PYTHON_BRIDGE_PATH = PROJECT_ROOT / "bridge_mcp_ghidra.py"
ENDPOINTS_JSON_PATH = PROJECT_ROOT / "tests" / "endpoints.json"


# =============================================================================
# Extraction helpers
# =============================================================================

def extract_java_endpoints() -> set[str]:
    """Extract all endpoint paths from Java server.createContext() calls."""
    if not JAVA_PLUGIN_PATH.exists():
        pytest.skip(f"Java source not found: {JAVA_PLUGIN_PATH}")

    content = JAVA_PLUGIN_PATH.read_text(encoding="utf-8")
    # Match: server.createContext("/endpoint_name",
    pattern = re.compile(r'server\.createContext\(\s*"(/[^"]+)"')
    matches = pattern.findall(content)
    return set(matches)


def extract_python_http_endpoints() -> set[str]:
    """Extract all endpoint names called via safe_get/safe_post/safe_get_json/safe_post_json in the bridge."""
    if not PYTHON_BRIDGE_PATH.exists():
        pytest.skip(f"Python bridge not found: {PYTHON_BRIDGE_PATH}")

    content = PYTHON_BRIDGE_PATH.read_text(encoding="utf-8")
    # Match: safe_get("endpoint_name", ...) or safe_post("endpoint_name", ...)
    # Also: safe_get_json, safe_post_json, safe_get_uncached
    pattern = re.compile(
        r'(?:safe_get|safe_get_json|safe_get_uncached|safe_post|safe_post_json)\(\s*"([^"]+)"'
    )
    matches = pattern.findall(content)
    # Normalize to /path format to match Java
    return {"/" + m.lstrip("/") for m in matches}


def extract_python_mcp_tool_count() -> int:
    """Count the number of @mcp.tool() decorated functions in the bridge."""
    if not PYTHON_BRIDGE_PATH.exists():
        pytest.skip(f"Python bridge not found: {PYTHON_BRIDGE_PATH}")

    content = PYTHON_BRIDGE_PATH.read_text(encoding="utf-8")
    return len(re.findall(r"@mcp\.tool\(\)", content))


def load_endpoints_json() -> list[dict]:
    """Load endpoint specifications from endpoints.json."""
    if not ENDPOINTS_JSON_PATH.exists():
        pytest.skip(f"Endpoints JSON not found: {ENDPOINTS_JSON_PATH}")

    with open(ENDPOINTS_JSON_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("endpoints", [])


def get_endpoints_json_paths() -> set[str]:
    """Get all endpoint paths from endpoints.json."""
    endpoints = load_endpoints_json()
    return {e["path"] for e in endpoints}


# =============================================================================
# Tests
# =============================================================================

class TestEndpointCatalogConsistency:
    """Verify all three endpoint sources stay in sync."""

    def test_java_source_exists(self):
        """Java plugin source file should exist."""
        assert JAVA_PLUGIN_PATH.exists(), f"Missing: {JAVA_PLUGIN_PATH}"

    def test_python_bridge_exists(self):
        """Python bridge source file should exist."""
        assert PYTHON_BRIDGE_PATH.exists(), f"Missing: {PYTHON_BRIDGE_PATH}"

    def test_endpoints_json_exists(self):
        """Endpoints specification file should exist."""
        assert ENDPOINTS_JSON_PATH.exists(), f"Missing: {ENDPOINTS_JSON_PATH}"

    def test_endpoints_json_is_valid(self):
        """endpoints.json should be valid JSON with required structure."""
        endpoints = load_endpoints_json()
        assert len(endpoints) > 0, "endpoints.json has no endpoints"

        for ep in endpoints:
            assert "path" in ep, f"Endpoint missing 'path': {ep}"
            assert "method" in ep, f"Endpoint missing 'method': {ep}"
            assert ep["path"].startswith("/"), f"Path should start with /: {ep['path']}"
            assert ep["method"] in ("GET", "POST"), f"Invalid method: {ep['method']}"

    def test_endpoints_json_no_duplicates(self):
        """endpoints.json should not have duplicate paths."""
        endpoints = load_endpoints_json()
        paths = [e["path"] for e in endpoints]
        duplicates = [p for p in paths if paths.count(p) > 1]
        assert not duplicates, f"Duplicate paths in endpoints.json: {set(duplicates)}"


class TestJavaToEndpointsJson:
    """Verify Java endpoints are documented in endpoints.json."""

    def test_endpoints_json_covers_java(self):
        """Every Java endpoint should be documented in endpoints.json."""
        java_endpoints = extract_java_endpoints()
        json_paths = get_endpoints_json_paths()

        # Some Java endpoints may be internal (e.g., force_decompile variants)
        # so we check the other direction too and allow a small tolerance
        missing_from_json = java_endpoints - json_paths

        # Known internal-only endpoints not documented in endpoints.json
        known_internal = {
            "/force_decompile",  # Internal variant used by decompile_function(force=True)
            "/get_plate_comment",  # GET variant for plate comment retrieval
        }
        unexpected_missing = missing_from_json - known_internal

        if unexpected_missing:
            pytest.fail(
                f"Java endpoints NOT in endpoints.json ({len(unexpected_missing)}):\n"
                + "\n".join(sorted(unexpected_missing))
                + "\n\nIf these are intentionally internal, add them to known_internal in this test."
            )

    def test_endpoints_json_entries_exist_in_java(self):
        """Every endpoints.json entry should have a Java createContext registration (plugin or headless)."""
        # Combine GUI plugin and headless server endpoint registrations
        java_endpoints = extract_java_endpoints()
        if JAVA_HEADLESS_PATH.exists():
            content = JAVA_HEADLESS_PATH.read_text(encoding="utf-8")
            pattern = re.compile(r'server\.createContext\(\s*"(/[^"]+)"')
            java_endpoints = java_endpoints | set(pattern.findall(content))
        json_paths = get_endpoints_json_paths()

        missing_from_java = json_paths - java_endpoints

        if missing_from_java:
            pytest.fail(
                f"endpoints.json entries NOT in Java ({len(missing_from_java)}):\n"
                + "\n".join(sorted(missing_from_java))
                + "\n\nThese may have been removed from Java but not from endpoints.json."
            )


class TestPythonToEndpointsJson:
    """Verify Python bridge endpoints match endpoints.json."""

    def test_python_endpoints_covered_by_json(self):
        """Every HTTP endpoint called by Python should be in endpoints.json."""
        python_endpoints = extract_python_http_endpoints()
        json_paths = get_endpoints_json_paths()

        # Python tools that call internal/variant endpoints not in endpoints.json
        known_variants = {
            "/force_decompile",  # Called inside decompile_function(force=True)
            "/force_decompile_by_name",  # Called inside decompile_function(name=..., force=True)
            "/get_plate_comment",  # GET variant for plate comment retrieval
            "/set_parameter_type",  # Routed through set_local_variable_type in Java
        }
        python_to_check = python_endpoints - known_variants
        missing_from_json = python_to_check - json_paths

        if missing_from_json:
            pytest.fail(
                f"Python bridge calls endpoints NOT in endpoints.json ({len(missing_from_json)}):\n"
                + "\n".join(sorted(missing_from_json))
                + "\n\nIf these are internal variants, add them to known_variants in this test."
            )


class TestPythonToJava:
    """Verify Python bridge endpoints exist in Java."""

    def test_python_endpoints_exist_in_java(self):
        """Every HTTP endpoint called by Python should exist in Java (plugin or headless server)."""
        python_endpoints = extract_python_http_endpoints()
        # Combine GUI plugin and headless server endpoints
        java_endpoints = extract_java_endpoints()
        if JAVA_HEADLESS_PATH.exists():
            content = JAVA_HEADLESS_PATH.read_text(encoding="utf-8")
            pattern = re.compile(r'server\.createContext\(\s*"(/[^"]+)"')
            java_endpoints = java_endpoints | set(pattern.findall(content))

        # Known endpoints handled differently in Java
        known_exceptions = {
            "/force_decompile_by_name",  # Variant not registered separately in Java
            "/get_plate_comment",  # GET variant handled by set_plate_comment context
            "/set_parameter_type",  # Routed through set_local_variable_type in Java
        }

        python_to_check = python_endpoints - known_exceptions
        missing_from_java = python_to_check - java_endpoints

        if missing_from_java:
            pytest.fail(
                f"Python bridge calls endpoints NOT in Java ({len(missing_from_java)}):\n"
                + "\n".join(sorted(missing_from_java))
                + "\n\nThese endpoints may have been removed from Java without updating the bridge."
            )


class TestEndpointCounts:
    """Verify endpoint counts are roughly consistent across layers."""

    def test_java_endpoint_count_reasonable(self):
        """Java should have a reasonable number of endpoints."""
        java_endpoints = extract_java_endpoints()
        # Should be at least 100 based on current project state
        assert len(java_endpoints) >= 100, (
            f"Java has only {len(java_endpoints)} endpoints, expected >= 100"
        )

    def test_endpoints_json_count_reasonable(self):
        """endpoints.json should have a reasonable number of endpoints."""
        json_paths = get_endpoints_json_paths()
        assert len(json_paths) >= 100, (
            f"endpoints.json has only {len(json_paths)} endpoints, expected >= 100"
        )

    def test_python_tool_count_reasonable(self):
        """Python bridge should have a reasonable number of MCP tools."""
        tool_count = extract_python_mcp_tool_count()
        assert tool_count >= 90, (
            f"Python bridge has only {tool_count} @mcp.tool() functions, expected >= 90"
        )

    def test_counts_roughly_consistent(self):
        """Endpoint counts across layers should be within a reasonable range."""
        # Use combined Java count (GUI + headless) since endpoints.json covers both
        java_endpoints = extract_java_endpoints()
        if JAVA_HEADLESS_PATH.exists():
            content = JAVA_HEADLESS_PATH.read_text(encoding="utf-8")
            pattern = re.compile(r'server\.createContext\(\s*"(/[^"]+)"')
            java_endpoints = java_endpoints | set(pattern.findall(content))
        java_count = len(java_endpoints)
        json_count = len(get_endpoints_json_paths())
        python_count = extract_python_mcp_tool_count()

        # Java may have more endpoints than Python tools (some are internal)
        # Python may have more tools than JSON (some tools don't map 1:1)
        # Allow a tolerance of 30 for the gap between any two
        assert abs(java_count - json_count) < 30, (
            f"Java ({java_count}) vs endpoints.json ({json_count}) count gap too large"
        )


class TestEndpointMetadata:
    """Verify endpoint metadata quality in endpoints.json."""

    def test_all_endpoints_have_descriptions(self):
        """Every endpoint should have a description."""
        endpoints = load_endpoints_json()
        missing_desc = [e["path"] for e in endpoints if not e.get("description")]
        assert not missing_desc, (
            f"Endpoints missing descriptions: {missing_desc}"
        )

    def test_all_endpoints_have_categories(self):
        """Every endpoint should have a category."""
        endpoints = load_endpoints_json()
        missing_cat = [e["path"] for e in endpoints if not e.get("category")]
        assert not missing_cat, (
            f"Endpoints missing categories: {missing_cat}"
        )

    def test_categories_are_valid(self):
        """All endpoint categories should be from the defined set."""
        with open(ENDPOINTS_JSON_PATH, encoding="utf-8") as f:
            data = json.load(f)

        valid_categories = set(data.get("categories", {}).keys())
        endpoints = data.get("endpoints", [])

        invalid = [
            (e["path"], e.get("category"))
            for e in endpoints
            if e.get("category") not in valid_categories
        ]
        assert not invalid, (
            f"Endpoints with invalid categories: {invalid}"
        )

    def test_post_endpoints_have_params(self):
        """POST endpoints should typically have params defined."""
        endpoints = load_endpoints_json()
        post_no_params = [
            e["path"]
            for e in endpoints
            if e["method"] == "POST" and not e.get("params")
        ]
        # Some POST endpoints may legitimately have no params
        # but most should have at least one
        assert len(post_no_params) <= 5, (
            f"Too many POST endpoints without params: {post_no_params}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

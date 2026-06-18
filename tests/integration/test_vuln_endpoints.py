"""
Integration tests for VulnAnalysisService endpoints.

Auto-skips when no MCP server is running, and when the loaded program has no
resolvable sinks (e.g. stripped firmware with nothing tagged yet).

Run with: pytest tests/integration/test_vuln_endpoints.py -v

Endpoints covered:
- GET  /list_vuln_detectors      — detector inventory + sink/source catalog
- POST /detect_vuln_patterns     — capped whole-program scan, no bookmarks
- GET  /enumerate_attack_surface — taint-source reachability, depth-clamped
"""

import pytest
import json


# Mark all tests as readonly integration tests
pytestmark = [
    pytest.mark.integration,
    pytest.mark.readonly,
    pytest.mark.usefixtures("require_server"),
]


@pytest.fixture(scope="module")
def require_server(server_available):
    """Skip all tests in module if server is not available."""
    if not server_available:
        pytest.skip(
            "MCP server is not running (start with Tools → GhidraMCP → Start MCP Server)"
        )


class TestVulnEndpoints:

    def test_list_vuln_detectors(self, http_client):
        r = http_client.get("/list_vuln_detectors")
        assert r.status_code == 200
        body = json.loads(r.text)
        ids = {d["id"] for d in body["detectors"]}
        assert {"format_string", "unbounded_copy",
                "integer_overflow_alloc", "command_injection"} <= ids
        assert "catalog" in body
        assert body["catalog"]["sink_count"] >= 5
        assert body["catalog"]["source_count"] >= 4

    def test_detect_vuln_patterns_whole_program_capped(self, http_client):
        # POST with body params (program goes as query param per convention)
        r = http_client.post("/detect_vuln_patterns",
                             json_data={"max_functions": 200,
                                        "write_bookmarks": False})
        assert r.status_code == 200
        body = json.loads(r.text)
        assert "findings" in body and "scanned_functions" in body
        assert "decompile_failures" in body and "detectors_run" in body
        if body.get("note", "").startswith("no catalog sinks resolved"):
            pytest.skip("no sinks in this program — tag SINK_*/SOURCE_* first")
        # Findings may legitimately be empty on a clean binary; just assert shape.
        for f in body["findings"]:
            assert {"detector_id", "vuln_class", "address",
                    "function", "sink", "confidence", "why"} <= set(f)
            assert f["confidence"] in ("high", "medium", "low")

    def test_enumerate_attack_surface(self, http_client):
        r = http_client.get("/enumerate_attack_surface",
                            params={"max_depth": "2"})
        assert r.status_code == 200
        body = json.loads(r.text)
        assert "by_source_class" in body
        assert "source_count" in body
        assert body["max_depth"] <= 8  # clamped

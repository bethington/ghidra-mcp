"""Unit tests for ``tools/audit_endpoint_categories.py``.

The script exists so the category-drift finding is reproducible by anyone. That
only holds if the script itself is right, so the parser is pinned against
synthetic Java rather than against the live tree — a fixture that cannot quietly
change underneath the assertion.

The one live-tree assertion is the important one: the repo must currently have
zero drift, which is the same invariant ``EndpointsJsonParityTest`` enforces on
the Java side. Two independent implementations agreeing is what makes the count
trustworthy.
"""

from __future__ import annotations

import json

import pytest

from tools import audit_endpoint_categories as audit


# --------------------------------------------------------------------------
# Category resolution — mirrors AnnotationScanner.scanService
# --------------------------------------------------------------------------


def test_default_category_strips_service_suffix():
    assert audit._default_category("FunctionService") == "function"
    assert audit._default_category("XrefCallGraphService") == "xrefcallgraph"


def test_default_category_only_strips_trailing_service():
    # "service" mid-name must survive; Java's regex is anchored with $.
    assert audit._default_category("ServiceHelper") == "servicehelper"


def _write_service(tmp_path, name, body, group=None):
    pkg = tmp_path / "core"
    pkg.mkdir(parents=True, exist_ok=True)
    header = f'@McpToolGroup(value = "{group}")\n' if group else ""
    (pkg / f"{name}.java").write_text(
        f"package com.xebyte.core;\n{header}public class {name} {{\n{body}\n}}\n",
        encoding="utf-8",
    )


def test_explicit_category_wins_over_group(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "SCANNED_SERVICES", ("DemoService",))
    _write_service(
        tmp_path,
        "DemoService",
        '    @McpTool(path = "/a", method = "GET", category = "malware")\n'
        "    public Response a() { return null; }\n",
        group="analysis",
    )
    scanned, unscanned = audit.scan_annotations(tmp_path)
    assert unscanned == []
    assert scanned["/a"]["category"] == "malware"
    assert scanned["/a"]["explicit_category"] == "malware"
    assert scanned["/a"]["group_category"] == "analysis"


def test_group_category_used_when_no_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "SCANNED_SERVICES", ("DemoService",))
    _write_service(
        tmp_path,
        "DemoService",
        '    @McpTool(path = "/b", method = "POST")\n    public Response b() { return null; }\n',
        group="xref",
    )
    scanned, _ = audit.scan_annotations(tmp_path)
    assert scanned["/b"]["category"] == "xref"
    assert scanned["/b"]["method"] == "POST"


def test_class_name_used_when_no_group_annotation(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "SCANNED_SERVICES", ("CommentService",))
    _write_service(
        tmp_path,
        "CommentService",
        '    @McpTool(path = "/c")\n    public Response c() { return null; }\n',
    )
    scanned, _ = audit.scan_annotations(tmp_path)
    assert scanned["/c"]["category"] == "comment"
    # method defaults to GET, matching @McpTool's own default.
    assert scanned["/c"]["method"] == "GET"


def test_unregistered_service_is_reported_separately(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "SCANNED_SERVICES", ("RegisteredService",))
    _write_service(
        tmp_path,
        "OrphanService",
        '    @McpTool(path = "/orphan", category = "system")\n'
        "    public Response o() { return null; }\n",
    )
    scanned, unscanned = audit.scan_annotations(tmp_path)
    assert scanned == {}
    assert [e["path"] for e in unscanned] == ["/orphan"]


def test_commented_out_and_javadoc_annotations_are_ignored(tmp_path, monkeypatch):
    """A worked example in javadoc is not an endpoint.

    ``McpTool.java``'s own javadoc documents ``@McpTool(path = "/list_methods")``;
    counting it inflated the endpoint total by one until the parser learned to
    skip comment lines.
    """
    monkeypatch.setattr(audit, "SCANNED_SERVICES", ("DemoService",))
    _write_service(
        tmp_path,
        "DemoService",
        "    /**\n"
        '     * @McpTool(path = "/from_javadoc", category = "ghost")\n'
        "     */\n"
        '    // @McpTool(path = "/from_line_comment", category = "ghost")\n'
        '    @McpTool(path = "/real", category = "listing")\n'
        "    public Response r() { return null; }\n",
    )
    scanned, unscanned = audit.scan_annotations(tmp_path)
    assert list(scanned) == ["/real"]
    assert unscanned == []


def test_paren_in_string_literal_does_not_end_the_annotation(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "SCANNED_SERVICES", ("DemoService",))
    _write_service(
        tmp_path,
        "DemoService",
        '    @McpTool(path = "/d", description = "Does a thing (carefully)",\n'
        '             category = "datatype")\n'
        "    public Response d() { return null; }\n",
    )
    scanned, _ = audit.scan_annotations(tmp_path)
    assert scanned["/d"]["category"] == "datatype"


def test_unterminated_annotation_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "SCANNED_SERVICES", ("DemoService",))
    _write_service(
        tmp_path, "DemoService", '    @McpTool(path = "/x", category = "listing"\n'
    )
    with pytest.raises(ValueError):
        audit.scan_annotations(tmp_path)


def test_manual_descriptors_are_parsed(tmp_path):
    pkg = tmp_path / "core"
    pkg.mkdir(parents=True)
    (pkg / "ManualToolDescriptors.java").write_text(
        "public final class ManualToolDescriptors {\n"
        '    add(m, "/health", "GET", "utility", "Health check");\n'
        '    // add(m, "/removed", "GET", "ghost", "gone");\n'
        '    add(m, "/server/connect", "POST", "server", "Connect", "host");\n'
        "}\n",
        encoding="utf-8",
    )
    assert audit.scan_manual_descriptors(tmp_path) == {
        "/health": "utility",
        "/server/connect": "server",
    }


def test_manual_descriptors_absent_returns_empty(tmp_path):
    assert audit.scan_manual_descriptors(tmp_path) == {}


def test_load_catalog_keys_by_path(tmp_path):
    p = tmp_path / "endpoints.json"
    p.write_text(
        json.dumps({"endpoints": [{"path": "/a", "category": "listing"}]}),
        encoding="utf-8",
    )
    assert audit.load_catalog(p)["/a"]["category"] == "listing"


# --------------------------------------------------------------------------
# Live tree — the invariant this whole change exists to hold
# --------------------------------------------------------------------------


def test_repo_has_no_category_drift():
    result = audit.audit()
    assert result["drift"] == [], (
        f"{result['drift_count']} endpoint(s) drifted; regenerate with "
        "mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true"
    )
    assert result["manual_drift"] == []


def test_every_catalog_category_names_a_real_runtime_group():
    """No catalog category may name a group ``load_tool_group`` cannot resolve."""
    result = audit.audit()
    assert result["catalog_only_groups"] == []


def test_every_annotated_endpoint_is_actually_registered():
    """An @McpTool nobody hands to the scanner is a route the bridge never sees."""
    result = audit.audit()
    assert result["unscanned_annotated"] == []


def test_main_exits_zero_when_clean(capsys):
    assert audit.main([]) == 0
    out = capsys.readouterr().out
    assert "CATEGORY DRIFT (scanned): 0" in out


def test_main_json_mode_is_parseable(capsys):
    assert audit.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["drift_count"] == 0
    assert "listing" in payload["runtime_groups"]


def test_main_quiet_prints_nothing(capsys):
    assert audit.main(["--quiet"]) == 0
    assert capsys.readouterr().out == ""

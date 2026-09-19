"""Unit tests for ``tools/audit_server_scope.py`` and the catalog's ``servers`` field.

Two jobs, matching the shape of ``test_audit_endpoint_categories.py``:

1. Pin the parser against synthetic Java, so the derivation is checked by a
   fixture that cannot quietly change underneath the assertion.
2. Assert the live tree currently has zero drift. That is the drift guard: the
   ``servers`` field is derived from each server's own ``AnnotationScanner``
   argument list and ``ManualToolDescriptors.addAll`` path list, so adding a
   service to one server, or a route to one ``addAll``, fails here until
   ``python -m tools.audit_server_scope --write`` is re-run. Nobody has to
   remember to hand-flag a new endpoint, and nobody can hand-flag one wrongly.

Why this cannot live in the Java offline tier: ``RegenerateEndpointsJson`` scans
the *union* of both servers' services in one bag (``ServiceFactory``), so it has
no way to attribute a scanned tool back to a server. The attribution only exists
in the two server sources, which is what this reads.
"""

from __future__ import annotations

import json

import pytest

from tools import audit_server_scope as audit


# --------------------------------------------------------------------------
# Java source parsing
# --------------------------------------------------------------------------


def test_split_args_ignores_commas_inside_calls_and_strings():
    assert audit._split_args('a, b.get(), "x,y", new C(1, 2)') == [
        "a",
        "b.get()",
        '"x,y"',
        "new C(1, 2)",
    ]


def test_strip_comments_blanks_javadoc_and_line_comments():
    src = '\n'.join([
        "public class X {",
        '  // server.createContext("/commented_out", h);',
        '   * @McpTool(path = "/javadoc_example")',
        '  register("/real");  // trailing note about "/fake"',
        "}",
    ])
    out = audit._strip_comments(src)
    assert "/commented_out" not in out
    assert "/javadoc_example" not in out
    assert "/fake" not in out
    assert "/real" in out


def test_balanced_handles_parens_inside_string_literals():
    text = 'f("a)b", g(1))rest'
    body, end = audit._balanced(text, text.index("("))
    assert body == '"a)b", g(1)'
    assert text[end:] == "rest"


def test_scan_annotations_skips_the_annotation_javadoc_example(tmp_path):
    """``McpTool.java``'s own javadoc shows a worked ``@McpTool(path = ...)``."""
    (tmp_path / "Demo.java").write_text(
        "public class Demo {\n"
        '    /** Example: @McpTool(path = "/not_real", method = "GET") */\n'
        '    @McpTool(path = "/real", method = "POST")\n'
        "    public Response real() { return null; }\n"
        "}\n",
        encoding="utf-8",
    )
    found = audit.scan_annotations(tmp_path)
    assert set(found) == {"/real"}
    assert found["/real"]["method"] == "POST"
    assert found["/real"]["class"] == "Demo"


# --------------------------------------------------------------------------
# Per-server resolution
# --------------------------------------------------------------------------


def _fake_repo(tmp_path, gui_args, headless_args, gui_manual=(), headless_manual=()):
    """Build a miniature tree with the same shape the real resolver reads."""
    xb = tmp_path / "src" / "main" / "java" / "com" / "xebyte"
    (xb / "headless").mkdir(parents=True)
    (xb / "core").mkdir(parents=True)

    (xb / "core" / "AlphaService.java").write_text(
        'public class AlphaService {\n    @McpTool(path = "/alpha")\n'
        "    public Response a() { return null; }\n}\n",
        encoding="utf-8",
    )
    (xb / "core" / "BetaService.java").write_text(
        'public class BetaService {\n    @McpTool(path = "/beta")\n'
        "    public Response b() { return null; }\n}\n",
        encoding="utf-8",
    )
    (xb / "headless" / "GammaService.java").write_text(
        'public class GammaService {\n    @McpTool(path = "/gamma")\n'
        "    public Response c() { return null; }\n}\n",
        encoding="utf-8",
    )
    (xb / "core" / "StubProvider.java").write_text(
        "public class StubProvider implements ProgramProvider {\n}\n", encoding="utf-8"
    )

    def add_all(paths):
        if not paths:
            return ""
        quoted = ", ".join(f'"{p}"' for p in paths)
        return f"        ManualToolDescriptors.addAll(scanner, {quoted});\n"

    (xb / "GhidraMCPPlugin.java").write_text(
        "public class GhidraMCPPlugin {\n"
        "    private final StubProvider programProvider;\n"
        "    private final AlphaService alphaService;\n"
        "    private final BetaService betaService;\n"
        "    void start() {\n"
        f"        AnnotationScanner scanner = new AnnotationScanner({gui_args});\n"
        f"{add_all(gui_manual)}"
        "    }\n}\n",
        encoding="utf-8",
    )
    (xb / "headless" / "GhidraMCPHeadlessServer.java").write_text(
        "public class GhidraMCPHeadlessServer {\n"
        "    private GammaService gammaService;\n"
        "    void start() {\n"
        f"        AnnotationScanner scanner = new AnnotationScanner({headless_args});\n"
        f"{add_all(headless_manual)}"
        "    }\n}\n",
        encoding="utf-8",
    )
    (xb / "headless" / "HeadlessEndpointHandler.java").write_text(
        "public class HeadlessEndpointHandler {\n"
        "    public StubProvider getProgramProvider() { return provider; }\n"
        "    public AlphaService getAlphaService() { return alphaService; }\n"
        "}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_provider_argument_is_dropped_by_its_declared_type(tmp_path):
    """The scanner's leading argument is a provider, passed as its concrete type."""
    repo = _fake_repo(
        tmp_path,
        gui_args="programProvider, alphaService, betaService",
        headless_args="endpointHandler.getProgramProvider(), endpointHandler.getAlphaService()",
    )
    assert audit.server_service_classes(repo, audit.GUI_SERVER) == [
        "AlphaService",
        "BetaService",
    ]
    assert audit.server_service_classes(repo, audit.HEADLESS_SERVER) == ["AlphaService"]


def test_delegating_getter_resolves_through_the_handler(tmp_path):
    repo = _fake_repo(
        tmp_path,
        gui_args="programProvider, alphaService",
        headless_args="endpointHandler.getProgramProvider(), endpointHandler.getAlphaService(), gammaService",
    )
    assert audit.server_service_classes(repo, audit.HEADLESS_SERVER) == [
        "AlphaService",
        "GammaService",
    ]


def test_unresolvable_scanner_argument_is_loud(tmp_path):
    """A shape the resolver does not understand must fail, never silently drop."""
    repo = _fake_repo(
        tmp_path,
        gui_args="programProvider, alphaService, somethingUndeclared",
        headless_args="endpointHandler.getProgramProvider()",
    )
    with pytest.raises(ValueError, match="cannot resolve AnnotationScanner argument"):
        audit.server_service_classes(repo, audit.GUI_SERVER)


def test_manual_paths_skip_the_scanner_argument(tmp_path):
    repo = _fake_repo(
        tmp_path,
        gui_args="programProvider, alphaService",
        headless_args="endpointHandler.getProgramProvider()",
        gui_manual=("/one", "/two"),
    )
    assert audit.server_manual_paths(repo, audit.GUI_SERVER) == ["/one", "/two"]
    assert audit.server_manual_paths(repo, audit.HEADLESS_SERVER) == []


def test_scope_unions_both_registration_mechanisms(tmp_path):
    """A route hand-registered on one server and annotated on the other is `both`.

    This is not hypothetical: ``/open_project`` and ``/server/status`` are exactly
    this shape in the real tree. Treating the two mechanisms as alternatives
    instead of a union would mislabel both as GUI-only.
    """
    repo = _fake_repo(
        tmp_path,
        gui_args="programProvider, alphaService",
        headless_args="endpointHandler.getProgramProvider(), gammaService",
        gui_manual=("/gamma",),
    )
    scope = audit.derive_scope(repo)["scope"]
    assert scope["/alpha"] == ["gui"]
    assert scope["/gamma"] == ["gui", "headless"]
    assert "/beta" not in scope  # annotated but no server scans BetaService
    assert audit.derive_scope(repo)["orphan_classes"] == ["BetaService"]


def test_scope_order_is_stable_regardless_of_discovery_order(tmp_path):
    repo = _fake_repo(
        tmp_path,
        gui_args="programProvider, alphaService",
        headless_args="endpointHandler.getProgramProvider(), endpointHandler.getAlphaService()",
    )
    assert audit.derive_scope(repo)["scope"]["/alpha"] == list(audit.SERVERS)


# --------------------------------------------------------------------------
# Live tree — the drift guard
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def live():
    return audit.audit()


def test_catalog_servers_field_matches_the_sources(live):
    assert live["drift"] == [], (
        "tests/endpoints.json `servers` disagrees with the two servers' "
        "registration. Re-run: python -m tools.audit_server_scope --write"
    )


def test_every_catalog_entry_is_stamped(live):
    assert live["unstamped"] == [], (
        "catalog entries with no `servers` field (a new endpoint was added, or "
        "RegenerateEndpointsJson dropped it). Re-run: "
        "python -m tools.audit_server_scope --write"
    )


def test_no_endpoint_is_served_by_neither_server(live):
    assert live["unreachable"] == [], (
        "@McpTool endpoints on a class no server hands to an AnnotationScanner -- "
        "advertised in the catalog but reachable nowhere"
    )
    assert live["orphan_classes"] == []


def test_derivation_and_catalog_cover_the_same_paths(live):
    assert live["uncatalogued"] == []
    assert live["missing_from_derivation"] == []


def test_scope_counts_partition_the_catalog(live):
    """GUI + headless - both == total. Arithmetic, not narrative."""
    total = live["catalog_endpoints"]
    both = live["by_scope"].get("gui+headless", 0)
    assert live["gui_endpoints"] + live["headless_endpoints"] - both == total
    assert sum(live["by_scope"].values()) == total


def test_both_servers_actually_differ(live):
    """If this ever went symmetric the field would be dead weight; it is not."""
    assert live["by_scope"].get("gui", 0) > 0
    assert live["by_scope"].get("headless", 0) > 0


def test_the_asymmetry_is_wiring_not_per_tool_annotation(live):
    """The split is a property of which services each server constructs.

    DebuggerService needs a live ``PluginTool`` (TraceRmi is GUI-only) and
    PromptPolicyService drives GUI prompt handling, so neither is wired into the
    headless server; HeadlessManagementService owns the headless program/project
    lifecycle and has no GUI counterpart. Every *shared* service takes a
    ``ThreadingStrategy`` precisely so one ``@McpTool`` serves both modes -- which
    is why the split is derived from the wiring and never declared per tool.
    """
    gui = set(live["gui_service_classes"])
    headless = set(live["headless_service_classes"])
    assert gui - headless == {"DebuggerService", "PromptPolicyService"}
    assert headless - gui == {"HeadlessManagementService"}
    assert len(gui & headless) == 11


# --------------------------------------------------------------------------
# The published numbers — README and the release-notes workflow
# --------------------------------------------------------------------------


REPO = audit._repo_root()


def test_release_counts_match_the_derivation(live):
    mcp_tools, gui, headless = audit.release_counts()
    assert mcp_tools == live["catalog_endpoints"]
    assert gui == live["gui_endpoints"]
    assert headless == live["headless_endpoints"]


def test_release_counts_refuse_a_partially_stamped_catalog(tmp_path, monkeypatch):
    """No silent default. The old workflow's `|| echo "0"` is why v6.0.0 shipped 1."""
    catalog = json.loads(audit.catalog_path(REPO).read_text(encoding="utf-8"))
    catalog["endpoints"][0].pop("servers", None)
    target = tmp_path / "tests"
    target.mkdir()
    (target / "endpoints.json").write_text(json.dumps(catalog), encoding="utf-8")
    with pytest.raises(KeyError):
        audit.release_counts(tmp_path)


def test_release_workflow_derives_counts_from_the_catalog():
    """release.yml must not resurrect the EndpointRegistry.java grep.

    That file was deleted on 2026-07-25. The grep kept "working" because of a
    ``|| echo "0"`` fallback, so v6.0.0's release notes published
    ``Headless Endpoints: 1``.
    """
    workflow = (REPO / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    # Comment lines are allowed to name it — the fix documents what it replaced.
    live_lines = "\n".join(
        line for line in workflow.splitlines() if not line.lstrip().startswith("#")
    )
    assert "EndpointRegistry" not in live_lines
    assert "tools.audit_server_scope --release-counts" in live_lines


def test_readme_production_status_matches_the_catalog():
    """The hand-written "Production Status" table is the other place these numbers live.

    It carried 249 / 196 / 195 against a real 253 / 239 / 226 -- three numbers
    that the existing ``test_user_visible_tool_counts_match_endpoint_catalog``
    cannot see, because its regex wants ``<N> MCP tools`` and this table writes
    the count *after* the label (``| **MCP Tools** | 253 ... |``).
    """
    import re

    readme = (REPO / "README.md").read_text(encoding="utf-8")
    mcp_tools, gui, headless = audit.release_counts()
    expected = {
        "MCP Tools": mcp_tools,
        "GUI Endpoints": gui,
        "Headless Endpoints": headless,
    }
    found = {}
    for label in expected:
        m = re.search(rf"\|\s*\*\*{label}\*\*\s*\|\s*(\d+)", readme)
        assert m is not None, f"README Production Status row for {label!r} is missing"
        found[label] = int(m.group(1))
    assert found == expected, (
        "README's Production Status table drifted from tests/endpoints.json"
    )


def test_catalog_json_round_trips_byte_identically(tmp_path):
    """``--write`` must not churn the file that ``RegenerateEndpointsJson`` (Gson) emits.

    Two writers, one file: the Java regenerator pretty-prints with Gson and this
    script with ``json.dumps``. If their formatting disagreed, every alternation
    would produce a whole-file diff.
    """
    path = audit.catalog_path(audit._repo_root())
    original = path.read_text(encoding="utf-8")
    data = json.loads(original)
    assert json.dumps(data, indent=2, ensure_ascii=False) + "\n" == original

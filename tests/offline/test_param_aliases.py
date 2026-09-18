"""Pin the @Param alias extractor.

The extractor exists to stop the contract checks calling a valid back-compat
spelling a breach (see ``tests/offline/param_aliases``). It can fail in two
directions and only one of them is safe:

* finding TOO FEW aliases turns valid calls into breaches -- loud, and the
  ratchet goes red;
* finding an alias that is not really declared EXCUSES a real breach -- silent,
  and it is the failure mode this file is here to prevent.

So the known alias sets are asserted exactly, not merely as a subset.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.offline.param_aliases import (
    JAVA_ROOT,
    _params_of_signature,
    _scan_source,
    aliases_for,
    load_param_aliases,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA = REPO_ROOT / "tests" / "conformance" / "snapshots" / "mcp_schema.snap"


def test_java_sources_are_where_we_think():
    assert JAVA_ROOT.is_dir()
    assert list(JAVA_ROOT.rglob("*.java")), "no Java sources found to scan"


def test_scan_finds_most_of_the_catalog():
    """A parser that quietly matched nothing would satisfy every other test."""
    routes = load_param_aliases()
    assert len(routes) > 200, f"only {len(routes)} @McpTool routes parsed"


@pytest.mark.parametrize(
    "path,method,expected",
    [
        (
            "/get_function_labels",
            "GET",
            {"function": "name", "address": "name", "function_address": "name"},
        ),
        (
            "/rename_function",
            "POST",
            {
                "function_address": "old_name",
                "function": "old_name",
                "oldName": "old_name",
            },
        ),
        (
            "/rename_symbol",
            "POST",
            {"address": "target", "function_address": "target"},
        ),
        ("/set_function_no_return", "POST", {"noReturn": "no_return"}),
        ("/set_function_this_type", "POST", {"thisType": "this_type"}),
        ("/set_variable_type", "POST", {"parameter_name": "variable_name"}),
    ],
)
def test_known_alias_sets_exactly(path, method, expected):
    assert aliases_for(path, method) == expected


def test_endpoints_without_aliases_report_none():
    """The discriminator that makes the ten breaches real.

    /analyze_function_completeness declares `function_address` and no alias
    for `address`, so a call sending `address` really is dropped. If this ever
    returns a mapping, the contract checks would start excusing it.
    """
    assert aliases_for("/analyze_function_completeness", "GET") == {}
    assert aliases_for("/list_functions", "GET") == {}
    assert aliases_for("/search_functions_enhanced", "GET") == {}


def test_every_alias_target_is_a_real_declared_parameter():
    """An alias must map to a parameter the schema actually advertises.

    This is what catches a parse that drifted onto the wrong method: a
    canonical name that does not exist on that route means the annotation
    block and the signature were mismatched.
    """
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))["tools"]
    declared = {
        (t["path"], t["method"].upper()): {p["name"] for p in t.get("params", [])}
        for t in schema
    }
    for route, mapping in load_param_aliases().items():
        if not mapping or route not in declared:
            continue
        for alias, canonical in mapping.items():
            assert canonical in declared[route], (
                f"{route} maps alias '{alias}' to '{canonical}', which is not a "
                f"declared parameter: {sorted(declared[route])}"
            )


# Empty, and it must stay empty: a name that is both a real parameter and an
# alias of another parameter is a dispatch ambiguity, fixed in the annotation.
# /rename_symbol was the one entry here until #470 removed the old_name alias.
KNOWN_ALIAS_COLLISIONS: dict[tuple[str, str], set[str]] = {}


def test_no_alias_collides_with_a_declared_parameter():
    """An alias that shadows a real parameter is ambiguous at dispatch.

    ``AnnotationScanner`` resolves the canonical name first and each alias
    after, so when a name is both, ONE request value binds to TWO parameters.

    /rename_symbol used to do exactly this: ``target`` listed ``old_name``
    among its aliases while ``old_name`` was also its own declared parameter,
    so ``{kind: "label", old_name: "LAB_x", new_name: "y"}`` with no
    ``target`` filled both from one value and handed ``renameLabel`` a label
    name where it expects an address. #470 removed that alias and routes the
    fallback through resolveRenameTarget instead, so the expected set is now
    empty -- a new entry here is a defect to fix in the annotation.
    """
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))["tools"]
    declared = {
        (t["path"], t["method"].upper()): {p["name"] for p in t.get("params", [])}
        for t in schema
    }
    found: dict[tuple[str, str], set[str]] = {}
    for route, mapping in load_param_aliases().items():
        clashing = {a for a in mapping if a in declared.get(route, set())}
        if clashing:
            found[route] = clashing
    assert found == KNOWN_ALIAS_COLLISIONS, (
        "alias/parameter collisions changed. A NEW one is a dispatch ambiguity "
        "to fix in the annotation, not to record here."
    )


def test_signature_parser_handles_parens_inside_descriptions():
    """Descriptions contain ')' -- naive paren matching ends the block early."""
    signature = (
        '@Param(value = "start", description = "Address (0x<hex> or space:hex)") '
        'String start, '
        '@Param(value = "name", aliases = {"address", "function"}) String name'
    )
    assert _params_of_signature(signature) == {
        "start": (),
        "name": ("address", "function"),
    }


def test_scan_source_reads_method_and_path():
    source = """
    @McpTool(path = "/thing", method = "POST", description = "Does (a) thing")
    public Response thing(
            @Param(value = "target", aliases = {"address"}) String target) {
        return null;
    }
    """
    assert _scan_source(source) == {("/thing", "POST"): {"target": ("address",)}}


def test_scan_source_defaults_to_get():
    source = """
    @McpTool(path = "/thing", description = "no method attribute")
    public Response thing(@Param(value = "x") String x) { return null; }
    """
    assert ("/thing", "GET") in _scan_source(source)


def test_published_schema_aliases_match_the_annotation_parser():
    """The two sources of "which spellings does this route accept" must agree.

    This assertion was impossible until 2026-09-18. ``ParamDescriptor.toJson``
    did not emit ``aliases``, so ``/mcp/schema`` advertised only canonical
    names -- which is the entire reason ``param_aliases.py`` exists, parsing
    the Java annotations directly to reconstruct what the schema withheld.
    #470 made the scanner publish them, and the re-recorded snapshot is the
    first one that carries them.

    That turns a one-sided gap into a two-writers-of-one-field problem, which
    this repo has paid for repeatedly: whichever source a consumer happens to
    read wins, and a divergence is invisible until something calls a valid
    alias and is told it is a breach. Asserting equality makes the divergence
    loud instead.

    When ``param_aliases.py`` is finally retired in favour of the published
    schema (the fix its own README names), this test is what proves the
    replacement is not losing aliases on the way out.
    """
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))["tools"]

    published: dict[tuple[str, str], dict[str, str]] = {}
    for tool in schema:
        route = (tool["path"], tool["method"].upper())
        for param in tool.get("params", []):
            for alias in param.get("aliases") or []:
                published.setdefault(route, {})[alias] = param["name"]

    assert published, (
        "the recorded /mcp/schema publishes no aliases at all. Either the "
        "snapshot predates #470 and needs re-recording against a deployed "
        "server, or ParamDescriptor stopped emitting them."
    )

    parsed = {route: dict(mapping)
              for route, mapping in load_param_aliases().items() if mapping}

    assert published == parsed, (
        "the published schema and the annotation parser disagree about which "
        "aliases exist.\n"
        f"  only in schema: { {k: v for k, v in published.items() if parsed.get(k) != v} }\n"
        f"  only in parser: { {k: v for k, v in parsed.items() if published.get(k) != v} }\n"
        "Fewer in the parser turns valid calls into breaches; more in the "
        "parser excuses a real one."
    )

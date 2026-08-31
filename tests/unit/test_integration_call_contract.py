"""Every integration test's HTTP call must be one the catalog can serve.

Why this exists
---------------
The read-only integration suite shipped ten calls the server does not support:
parameters spelled wrong, one endpoint GET-ed that is declared POST, and three
endpoints that do not exist at all. Every one of them still passed. A live
Ghidra answers 200 for an undeclared parameter -- ``AnnotationScanner`` simply
does not find it and uses the default -- and the tests that hit a missing route
had already been written to accept ``[200, 404]``, so the permanent 404 was
indistinguishable from success. Ten tests asserting nothing, green for years.

The offline HTTP tier (#112) can see this, but only for the one file it
replays, and only when a fixture exists to drive the call. This check is the
cheap, total version:

* pure AST, no server, no fixtures, no Ghidra -- so it runs in the unit tier
  that CI always executes, on every integration file at once;
* it fails on a call that could not possibly work, which is a defect in the
  test whatever the server is doing.

Source of truth is ``tests/endpoints.json`` for routing and method, and
``tests/conformance/snapshots/mcp_schema.snap`` for declared parameters. PR
#459 settled that the ``@McpTool``/``@Param`` annotations are authoritative and
made regeneration stop copying stale catalog values forward, so a test calling
a route that is not there is a broken test, not a missing feature.

The baseline
------------
``fixtures/known_integration_call_breaches.json`` holds the breaches that
already existed OUTSIDE the read-only suite when this check was written. It is
a ratchet in both directions: a new breach fails, and so does a stale entry, so
fixing one means deleting its line. It is not an exemption list -- every entry
is a test that cannot fail today, recorded so it can be paid off deliberately
rather than rediscovered.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from tests.offline.param_aliases import aliases_for

REPO_ROOT = Path(__file__).resolve().parents[2]
INTEGRATION_DIR = REPO_ROOT / "tests" / "integration"
CATALOG = REPO_ROOT / "tests" / "endpoints.json"
SCHEMA = REPO_ROOT / "tests" / "conformance" / "snapshots" / "mcp_schema.snap"
BASELINE = Path(__file__).resolve().parent / "fixtures" / (
    "known_integration_call_breaches.json"
)

# Served by the plugin's HTTP layer rather than by an @McpTool, so absent from
# both the catalog and the schema. Same list the offline fake carries.
INFRASTRUCTURE_PATHS = frozenset({"/mcp/schema", "/mcp/instance_info", "/mcp/health"})

# Synthesised by the bridge for POST endpoints that do not declare their own
# `dry_run`; a bridge-side convention, not a schema-declared parameter.
BRIDGE_SYNTHETIC_PARAMS = frozenset({"dry_run"})

_HTTP_METHODS = {"get", "post", "put", "delete", "patch"}
_PARAM_KWARGS = ("params", "json", "data")


def _read_json(path: Path):
    # Explicit encoding: tests/endpoints.json is UTF-8 and a bare open() on a
    # cp1252 Windows default aborts collection (see tests/offline).
    return json.loads(path.read_text(encoding="utf-8"))


def _catalog_routes() -> dict[str, str]:
    """``path -> declared METHOD``."""
    return {
        entry["path"]: entry.get("method", "GET").upper()
        for entry in _read_json(CATALOG)["endpoints"]
    }


def _declared_params() -> dict[tuple[str, str], set[str]]:
    """``(path, METHOD) -> declared parameter names``."""
    out: dict[tuple[str, str], set[str]] = {}
    for tool in _read_json(SCHEMA)["tools"]:
        route = (tool["path"], tool["method"].upper())
        out[route] = {p["name"] for p in tool.get("params", [])}
    return out


class _CallVisitor(ast.NodeVisitor):
    """Collect ``<client>.get("/path", params={...})``-shaped calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, str, str, set[str]]] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _HTTP_METHODS:
            args = node.args
            if args and isinstance(args[0], ast.Constant) and isinstance(
                args[0].value, str
            ):
                path = args[0].value
                if path.startswith("/"):
                    self.calls.append(
                        (
                            node.lineno,
                            func.attr.upper(),
                            path,
                            self._param_names(node),
                        )
                    )
        self.generic_visit(node)

    @staticmethod
    def _param_names(node: ast.Call) -> set[str]:
        names: set[str] = set()
        for keyword in node.keywords:
            if keyword.arg not in _PARAM_KWARGS:
                continue
            if not isinstance(keyword.value, ast.Dict):
                # Built dynamically -- the keys are not statically knowable,
                # so this check has nothing to say about it. Deliberately not
                # a failure: guessing would be worse than abstaining.
                continue
            for key in keyword.value.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    names.add(key.value)
        return names


def _collect_calls() -> list[tuple[str, int, str, str, set[str]]]:
    """``(file, line, METHOD, path, sent parameter names)`` for the whole tier."""
    found: list[tuple[str, int, str, str, set[str]]] = []
    for source in sorted(INTEGRATION_DIR.rglob("*.py")):
        visitor = _CallVisitor()
        visitor.visit(ast.parse(source.read_text(encoding="utf-8"), str(source)))
        for lineno, method, path, sent in visitor.calls:
            found.append((source.name, lineno, method, path, sent))
    return found


def _scan() -> list[str]:
    """Return every breach, as stable ``file CODE METHOD path`` identities."""
    routes = _catalog_routes()
    params_by_route = _declared_params()
    breaches: list[str] = []

    for name, _lineno, method, path, sent in _collect_calls():
        if path in INFRASTRUCTURE_PATHS:
            continue
        declared_method = routes.get(path)
        if declared_method is None:
            breaches.append(f"{name} no_such_endpoint {method} {path}")
            continue
        if declared_method != method:
            breaches.append(
                f"{name} method_not_allowed {method} {path} "
                f"(declared {declared_method})"
            )
            # Parameters are declared per (path, method); checking them against
            # the wrong method would pile a second, derived failure onto one
            # root cause.
            continue
        declared = params_by_route.get((path, method))
        if declared is None:
            # In the catalog but not in the recorded schema snapshot (the
            # headless-only project-management endpoints). Routing is checked;
            # there is nothing to check parameters against.
            continue
        aliases = aliases_for(path, method)
        for param in sorted(sent - BRIDGE_SYNTHETIC_PARAMS):
            if aliases.get(param, param) not in declared:
                breaches.append(
                    f"{name} unknown_parameter {method} {path} [{param}]"
                )
    return sorted(set(breaches))


def test_no_integration_test_calls_an_endpoint_that_cannot_serve_it():
    """The ratchet. New breaches fail; so do stale baseline entries."""
    baseline = set(_read_json(BASELINE)["breaches"])
    observed = set(_scan())

    new = sorted(observed - baseline)
    fixed = sorted(baseline - observed)

    message = []
    if new:
        message.append(
            "These integration calls cannot succeed as written. Against a live\n"
            "server they still return 200, so the test passes while asserting\n"
            "nothing -- fix the call, do not add it to the baseline:\n  "
            + "\n  ".join(new)
        )
    if fixed:
        message.append(
            "These baseline entries no longer occur. Delete them from\n"
            f"{BASELINE.name} so they cannot come back unnoticed:\n  "
            + "\n  ".join(fixed)
        )
    assert not message, "\n\n".join(message)


def test_readonly_suite_is_clean():
    """The read-only suite specifically must have ZERO breaches.

    It is the file the offline tier replays, so it is the one a contributor
    without Ghidra actually runs. Its ten breaches were fixed on 2026-08-30
    and no baseline entry may reintroduce one.
    """
    offending = [b for b in _scan() if b.startswith("test_readonly_endpoints.py ")]
    assert offending == [], (
        "test_readonly_endpoints.py went back to calling the API wrongly:\n  "
        + "\n  ".join(offending)
    )


def test_baseline_carries_no_readonly_entries():
    """A baseline that could re-admit a read-only breach is not a ratchet."""
    baseline = _read_json(BASELINE)["breaches"]
    assert [b for b in baseline if b.startswith("test_readonly_endpoints.py ")] == []


def test_scanner_actually_sees_the_suite():
    """Guard the guard.

    Every check above is satisfied by a scanner that finds nothing -- which is
    the failure mode this whole file is about. Pin that it still parses the
    tier and extracts calls WITH their parameters, so an AST or path
    regression fails loudly here instead of going quiet and green.
    """
    calls = _collect_calls()
    assert len(calls) > 300, f"only {len(calls)} HTTP calls found in the tier"
    assert len({c[0] for c in calls}) >= 10, "expected calls across many files"
    assert sum(1 for c in calls if c[4]) > 150, "no parameters were extracted"
    assert any(
        c[0] == "test_readonly_endpoints.py" for c in calls
    ), "the replayed read-only file was not scanned at all"


@pytest.mark.parametrize(
    "path,method,alias,canonical",
    [
        ("/get_function_labels", "GET", "address", "name"),
        ("/rename_function", "POST", "function_address", "old_name"),
        ("/rename_symbol", "POST", "address", "target"),
    ],
)
def test_declared_aliases_are_not_reported_as_breaches(path, method, alias, canonical):
    """@Param aliases are valid spellings the schema does not advertise.

    Without this the check would manufacture breaches for correct calls -- the
    reason tests/offline/param_aliases.py exists.
    """
    aliases = aliases_for(path, method)
    assert aliases.get(alias) == canonical
    assert canonical in _declared_params()[(path, method.upper())]

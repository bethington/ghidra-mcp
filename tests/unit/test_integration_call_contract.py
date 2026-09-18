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
``fixtures/known_integration_call_breaches.json`` **is empty and must stay
empty**. It held the 29 breaches this check found outside the read-only suite
on its first run; they were paid off in #475. It is a ratchet in both
directions: a new breach fails, and so does a stale entry, so fixing one means
deleting its line. It is not an exemption list -- a line here is a decision to
ship a test that cannot fail.

What the first pass over those 29 taught the check itself, all fixed here:

* ``by_path.get("/set_global")`` is a dict lookup over the endpoint catalog,
  not an HTTP GET. Three of the 29 were this -- ``method_not_allowed`` reported
  against POST endpoints no test ever called with GET. A checker that
  manufactures breaches teaches people to edit the baseline, so receivers are
  now classified and an unclassified one fails loudly.
* ``http_client.post`` takes ``json_data=``, not ``json=``. Every JSON body in
  the tier was invisible; four real breaches were hiding there.
* ``http_session.get(f"{server_url}/list_functions", params=...)`` was not
  parsed at all, hiding a fifth.
* ``tests/conftest.py`` is not in ``tests/integration/`` but supplies the
  tier's shared fixtures, and two of them made the same bad call -- inherited
  by every test that asks for them.

Each of those is the same failure this file exists to catch, one level up: a
check that quietly sees less than it claims to.
"""

from __future__ import annotations

import ast
import json
from functools import lru_cache
from pathlib import Path

import pytest

from tests.offline.param_aliases import aliases_for

REPO_ROOT = Path(__file__).resolve().parents[2]
INTEGRATION_DIR = REPO_ROOT / "tests" / "integration"
# tests/conftest.py is not in that directory but supplies the tier's shared
# fixtures, and they make HTTP calls of exactly the same kind -- `sample_address`
# and `sample_function` both sent an undeclared `limit` to /list_functions.
# A fixture breach is worse than a test breach: it is inherited by every test
# that asks for it.
SHARED_FIXTURES = REPO_ROOT / "tests" / "conftest.py"
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

# `http_client.post` takes `json_data=`, not `json=` -- see the HttpClient
# fixture in tests/conftest.py, which forwards it to `requests` as `json=`.
# Leaving it out made every JSON body in the tier invisible to this check.
_PARAM_KWARGS = ("params", "json", "data", "json_data")

# Receivers whose `.get`/`.post` is an HTTP call. `dict.get(key)` has the exact
# same shape, and the tier contains six `by_path.get("/some_endpoint")` catalog
# lookups -- three of which the first version of this check reported as
# `method_not_allowed GET` breaches against POST endpoints that were never
# called. Anything not classified here fails
# test_every_receiver_is_classified rather than being quietly dropped.
HTTP_RECEIVERS = frozenset({"http_client", "http_session", "requests"})
NON_HTTP_RECEIVERS = frozenset({"by_path"})

# For the `f"{base}/path"` form, which base variables address THIS server. The
# tier also probes the fun-doc dashboard on a different port
# (`requests.get(f"{DASHBOARD_URL}/api/worker/status")`), and checking that
# against the Ghidra endpoint catalog would report a permanent, meaningless
# `no_such_endpoint`.
SERVER_URL_NAMES = frozenset({"server_url", "base_url"})
FOREIGN_URL_NAMES = frozenset({"DASHBOARD_URL"})


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


def _endpoint_path(arg: ast.expr) -> tuple[str | None, str | None]:
    """``(path, base-url name)`` for a call's first argument.

    Two spellings occur in the tier and both must be seen:

    * ``http_client.get("/list_functions")`` -- the client prepends the base
      URL, so the literal is the path and the base is implicit (``None``);
    * ``http_session.get(f"{server_url}/list_functions")`` -- a whole URL, of
      which only the trailing literal is the path. Skipping the f-string form
      hid a real ``limit=`` breach on ``/list_functions``.

    ``(None, ...)`` means "nothing statically checkable here".
    """
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        literal, base = arg.value, None
    elif isinstance(arg, ast.JoinedStr) and len(arg.values) >= 2:
        head, tail = arg.values[0], arg.values[-1]
        if not (isinstance(tail, ast.Constant) and isinstance(tail.value, str)):
            # `f"{base}{path}"` -- the path is computed, nothing to check.
            return None, None
        if not (
            isinstance(head, ast.FormattedValue)
            and isinstance(head.value, ast.Name)
        ):
            return None, None
        literal, base = tail.value, head.value.id
    else:
        return None, None
    if not literal.startswith("/"):
        return None, None
    # A query string in the literal would be a different shape of call; none
    # exist today, and splitting keeps the path key comparable to the catalog.
    return literal.split("?", 1)[0], base


def _receiver_name(func: ast.Attribute) -> str | None:
    """``http_client`` for ``http_client.get(...)``; ``None`` if not a plain name."""
    return func.value.id if isinstance(func.value, ast.Name) else None


class _CallVisitor(ast.NodeVisitor):
    """Collect ``<client>.get("/path", params={...})``-shaped calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, str, str, set[str]]] = []
        self.receivers: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _HTTP_METHODS:
            path, base = (
                _endpoint_path(node.args[0]) if node.args else (None, None)
            )
            if path is not None:
                receiver = _receiver_name(func)
                self.receivers.add(receiver or "<expression>")
                if base is not None:
                    self.receivers.add(f"url:{base}")
                if receiver in HTTP_RECEIVERS and base not in FOREIGN_URL_NAMES:
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


def _sources() -> list[Path]:
    """Every file whose HTTP calls belong to the integration tier."""
    return sorted(INTEGRATION_DIR.rglob("*.py")) + [SHARED_FIXTURES]


@lru_cache(maxsize=1)
def _walk() -> tuple[list[tuple[str, int, str, str, frozenset[str]]], frozenset[str]]:
    """One pass over the tier: ``(calls, receivers seen)``.

    Both answers come from the same walk deliberately. Two traversals that
    disagree about which calls exist is the shape of bug this file was written
    to catch, and it would be a poor place to reintroduce it.
    """
    calls: list[tuple[str, int, str, str, frozenset[str]]] = []
    receivers: set[str] = set()
    for source in _sources():
        visitor = _CallVisitor()
        visitor.visit(ast.parse(source.read_text(encoding="utf-8"), str(source)))
        for lineno, method, path, sent in visitor.calls:
            calls.append((source.name, lineno, method, path, frozenset(sent)))
        receivers |= visitor.receivers
    return calls, frozenset(receivers)


def _collect_calls() -> list[tuple[str, int, str, str, frozenset[str]]]:
    """``(file, line, METHOD, path, sent parameter names)`` for the whole tier."""
    return _walk()[0]


def _collect_receivers() -> frozenset[str]:
    """Every receiver in the tier whose ``.get``/``.post`` names an endpoint."""
    return _walk()[1]


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
    assert any(
        c[0] == "test_global_endpoints.py" and c[3] == "/list_functions"
        for c in calls
    ), "the f-string URL form (http_session.get(f'{server_url}/...')) was missed"


def test_every_receiver_is_classified():
    """No call may be skipped because nobody decided what its receiver is.

    The check discriminates HTTP calls from ``dict.get(key)`` by receiver name,
    which is a judgement, so it is recorded rather than inferred. An
    unclassified receiver fails here -- loudly, with the name -- instead of
    silently dropping every call made through it, which is the exact failure
    mode this whole file exists to catch.
    """
    known = (
        HTTP_RECEIVERS
        | NON_HTTP_RECEIVERS
        | {f"url:{n}" for n in SERVER_URL_NAMES | FOREIGN_URL_NAMES}
    )
    unclassified = sorted(_collect_receivers() - known)
    assert unclassified == [], (
        "Unclassified receivers/base URLs calling .get/.post with an endpoint "
        "path:\n  " + "\n  ".join(unclassified)
        + "\nA bare name goes in HTTP_RECEIVERS (its calls get checked) or "
        "NON_HTTP_RECEIVERS (it is a dict/mapping lookup, not a request). A "
        "`url:NAME` entry goes in SERVER_URL_NAMES (this server) or "
        "FOREIGN_URL_NAMES (some other service)."
    )


def test_catalog_lookups_are_not_reported_as_breaches():
    """``by_path.get("/set_global")`` is a dict lookup, not a GET.

    Three of the twenty-nine baseline entries were this: /set_global,
    /add_memory_reference and /remove_reference reported ``method_not_allowed
    GET`` against POST endpoints that no test ever called with GET. A checker
    that manufactures breaches teaches people to edit the baseline.
    """
    assert "by_path" in NON_HTTP_RECEIVERS
    breaches = _scan()
    for path in ("/set_global", "/add_memory_reference", "/remove_reference"):
        assert not [b for b in breaches if b.endswith(f"GET {path} (declared POST)")], (
            f"{path} is only ever reached through a catalog dict lookup"
        )


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

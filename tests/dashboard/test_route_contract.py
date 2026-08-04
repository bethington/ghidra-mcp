"""Every dashboard route answers, and answers with the shape the page reads.

The inventory is taken from the BUILT APP's ``url_map``, not from a hand
list. A hand list is a list that goes stale: a route added next month would
not be covered and nothing would say so. Driving off ``url_map`` means a new
route is either covered automatically or shows up in
``test_every_get_route_is_accounted_for`` as an explicit, deliberate
exclusion.

Two things are asserted, and they are different:

* **Liveness** -- no route 500s, including when its backend is broken. A
  dashboard panel whose endpoint 500s takes the page's render path with it;
  every route here has an except-and-report path, and this proves it.
* **Contract** -- the specific keys the template reads. `pipeline.html`
  reads `bands.in_scope`, `matrix.cell`, `health.subsystems`; a rename that
  keeps the route 200 and drops the key is invisible to a liveness check and
  renders an empty panel.
"""

from __future__ import annotations

import pytest

import fake_ghidra as fg

# --------------------------------------------------------------------------
# route inventory
# --------------------------------------------------------------------------

#: Routes a blind GET must not be pointed at, with the reason. Everything not
#: listed here is swept by `test_every_get_route_is_accounted_for`.
GET_EXCLUSIONS: dict[str, str] = {
    "/static/<path:filename>": "Flask's own static handler, not ours",
    "/api/admin/restart": "restarts the dashboard process",
    "/api/oracle/kill": "kills the game",
    "/api/oracle/relaunch": "launches the game",
}

#: Routes that need a parameter to mean anything. Value is the query string.
GET_PARAMS: dict[str, dict] = {
    "/api/conformance/function/<addr>": {"addr": fg._fn_addr(0)},
    "/api/conformance/draft_content": {"path": "nonexistent"},
    "/api/conformance/sidebyside": {"program": fg.PROGRAM, "address": fg._fn_addr(0)},
}


def _get_routes(app) -> list[str]:
    out = []
    for rule in app.url_map.iter_rules():
        if "GET" not in (rule.methods or set()):
            continue
        out.append(str(rule.rule))
    return sorted(set(out))


#: Panels whose backend is Ghidra and which the operator reads constantly.
#: Named explicitly so that a route DISAPPEARING is a failure -- a url_map
#: sweep alone would happily pass over a page that lost half its endpoints.
CORE_GET_ROUTES = {
    "/",
    "/pipeline",
    "/api/stats",
    "/api/queue",
    "/api/queue/config",
    "/api/health/all",
    "/api/worker/status",
    "/api/worker/roster",
    "/api/worker/pause_state",
    "/api/oracle/status",
    "/api/ghidra/status",
    "/api/context",
    "/api/inventory/status",
    "/api/global_inventory/status",
    "/api/provider_pauses",
    "/api/conformance/matrix",
    "/api/conformance/bands",
    "/api/conformance/glob_bands",
    "/api/conformance/intake",
    "/api/conformance/inventory",
    "/api/conformance/globals",
    "/api/conformance/summary",
    "/api/conformance/binaries",
}


def test_every_core_route_still_exists(harness):
    """A route the page fetches must not silently vanish.

    `pipeline.html` fetches each of these on load; a removed or renamed one
    leaves a permanently empty panel and no error anywhere the operator can
    see it.
    """
    routes = set(_get_routes(harness.app))
    missing = sorted(CORE_GET_ROUTES - routes)
    assert not missing, f"the page fetches these, and the app no longer serves them: {missing}"


def test_route_surface_is_not_silently_shrinking(harness):
    routes = _get_routes(harness.app)
    assert len(routes) >= 30, (
        f"only {len(routes)} GET routes; the app built with a blueprint missing. "
        f"got: {routes}"
    )


def test_no_get_route_returns_a_server_error(harness):
    """Sweep every GET route. None may 5xx.

    Run as one test rather than a parametrised sweep because the app has to
    be built once per test and building it dominates the runtime; the failure
    message lists every offender, so a single failure still names all of them.
    """
    failures = []
    for route in _get_routes(harness.app):
        if route in GET_EXCLUSIONS:
            continue
        params = GET_PARAMS.get(route, {})
        if "<" in route and route not in GET_PARAMS:
            continue  # a converter route with no sample value; covered explicitly below
        path = route
        for key, value in params.items():
            path = path.replace(f"<{key}>", str(value))
        query = {k: v for k, v in params.items() if f"<{k}>" not in route}
        r = harness.client.get(path, query_string=query or None)
        if r.status_code >= 500:
            failures.append(f"{route} -> {r.status_code}: {r.get_data(as_text=True)[:200]}")
    assert not failures, "routes returned a server error:\n" + "\n".join(failures)


# --------------------------------------------------------------------------
# degradation when Ghidra is unreachable
# --------------------------------------------------------------------------
#
# A Ghidra restart is a ROUTINE event here -- `tools.setup deploy` performs
# one on every deploy -- so "Ghidra is briefly gone" is a state the dashboard
# is in regularly, and it is exactly when the operator is staring at it.
#
# Most readers in `conformance_dashboard` already degrade: `_tag_addrs`,
# `summary`, `_image_range`, `_prop_map` and `_scope_excluded_globals` all
# catch OSError and return an empty result. Exactly TWO call sites do not --
# `_function_rows` (/list_functions) and `_global_rows` (/list_globals) --
# and because `matrix`, `bands`, `intake`, `inventory`, `glob_bands`,
# `globals`, `binaries/progress` and `recommended` all reach one of those
# two, those eight routes raise instead, and Flask turns the exception into
# a 500.
#
# The eight are recorded here rather than quietly excluded. `strict=True`
# means the xfail becomes a FAILURE the moment the underlying bug is fixed,
# which is what stops this list from outliving the defect.

KNOWN_5XX_WHEN_GHIDRA_DOWN = {
    "/api/conformance/bands",
    "/api/conformance/binaries/progress",
    "/api/conformance/glob_bands",
    "/api/conformance/globals",
    "/api/conformance/intake",
    "/api/conformance/inventory",
    "/api/conformance/matrix",
    "/api/conformance/recommended",
}


def _sweep_with_ghidra_down(harness) -> dict[str, int]:
    harness.ghidra_corpus.fail_with = OSError("ghidra went away")
    out: dict[str, int] = {}
    for route in _get_routes(harness.app):
        if route in GET_EXCLUSIONS or ("<" in route and route not in GET_PARAMS):
            continue
        params = GET_PARAMS.get(route, {})
        path = route
        for key, value in params.items():
            path = path.replace(f"<{key}>", str(value))
        query = {k: v for k, v in params.items() if f"<{k}>" not in route}
        out[route] = harness.client.get(path, query_string=query or None).status_code
    return out


def test_routes_that_degrade_today_keep_degrading(harness):
    """The 25 routes that survive a dead Ghidra must not join the other eight.

    This is the regression guard that has teeth right now: it fails the
    moment a new uncaught `_get` call site is added to a path that currently
    degrades cleanly.
    """
    statuses = _sweep_with_ghidra_down(harness)
    regressions = {
        route: code
        for route, code in statuses.items()
        if code >= 500 and route not in KNOWN_5XX_WHEN_GHIDRA_DOWN
    }
    assert not regressions, (
        "these routes newly 500 with Ghidra down -- an uncaught `_get` was "
        f"added to their path: {regressions}"
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known defect: `_function_rows` and `_global_rows` are the only two "
        "`_get` call sites in conformance_dashboard without `except OSError`, "
        "so eight panels 500 during any Ghidra restart instead of degrading. "
        "Fixing those two functions to return [] on OSError makes this pass."
    ),
)
def test_no_get_route_5xxs_when_ghidra_dies_midway(harness):
    statuses = _sweep_with_ghidra_down(harness)
    failed = {r: c for r, c in statuses.items() if c >= 500}
    assert not failed, (
        "routes 500'd with Ghidra down (the dashboard must degrade, not "
        f"collapse): {sorted(failed)}"
    )


# --------------------------------------------------------------------------
# response contracts -- the keys pipeline.html actually reads
# --------------------------------------------------------------------------


def test_matrix_contract(harness):
    m = harness.json("/api/conformance/matrix", program=fg.PROGRAM)
    for key in ("rows", "cols", "cell", "in_scope", "evaluated"):
        assert key in m, f"/matrix dropped {key!r}; renderBars reads it"
    assert isinstance(m["cell"], dict)
    for row in m["rows"]:
        assert row in m["cell"], f"matrix row {row!r} missing from cell map"
        for col in m["cols"]:
            assert col in m["cell"][row]


def test_bands_contract(harness):
    b = harness.json("/api/conformance/bands", program=fg.PROGRAM)
    for key in ("bands", "tagged", "in_scope", "untagged"):
        assert key in b, f"/bands dropped {key!r}; renderBandBar reads it"


def test_glob_bands_contract(harness):
    g = harness.json("/api/conformance/glob_bands", program=fg.PROGRAM)
    for key in ("bands", "tagged", "in_scope", "untagged", "reviewed"):
        assert key in g, f"/glob_bands dropped {key!r}; renderGlobBandBar reads it"


def test_health_all_contract(harness):
    h = harness.json("/api/health/all")
    assert h["subsystems"].keys() >= {"dashboard", "ghidra", "oracle", "provider", "store"}, (
        "the header strip renders exactly five dots; a missing subsystem "
        "renders as a permanently 'unknown' dot"
    )
    for name, sub in h["subsystems"].items():
        assert sub["state"] in ("ok", "degraded", "down", "unknown"), (
            f"{name} reported state {sub['state']!r}, which the strip cannot style"
        )
        assert "label" in sub and "detail" in sub


def test_worker_status_contract(harness):
    s = harness.json("/api/worker/status")
    assert "workers" in s and isinstance(s["workers"], list)


def test_queue_config_contract(harness):
    c = harness.json("/api/queue/config")
    assert isinstance(c, dict) and c, "/api/queue/config returned nothing"


# --------------------------------------------------------------------------
# arithmetic -- the class of bug a request/response assertion cannot see
# --------------------------------------------------------------------------


def test_matrix_subtracts_library_from_both_sides_of_the_division(harness):
    """The 105.3% / 172.6% overcount.

    `matrix()` must exclude LIB_-tagged functions from the numerator because
    `in_scope` already excludes them from the denominator. With 10 of 50
    functions tagged LIB_CRT, an unsubtracted numerator shows up immediately.
    """
    m = harness.json("/api/conformance/matrix", program=fg.PROGRAM)
    assert m["in_scope"] == fg.N_IN_SCOPE
    assert m["evaluated"] == harness.ghidra_corpus.expected_evaluated
    assert m["evaluated"] <= m["in_scope"], (
        f"evaluated ({m['evaluated']}) exceeds in_scope ({m['in_scope']}) -- "
        f"the numerator covers a wider population than the denominator, which "
        f"is what rendered 326700%"
    )


def test_never_evaluated_cell_is_the_exact_remainder(harness):
    m = harness.json("/api/conformance/matrix", program=fg.PROGRAM)
    assert m["cell"]["none"]["none"] == harness.ghidra_corpus.expected_untriaged == 12


def test_no_band_count_exceeds_in_scope(harness):
    b = harness.json("/api/conformance/bands", program=fg.PROGRAM)
    assert b["tagged"] <= b["in_scope"]
    assert b["tagged"] + b["untagged"] == b["in_scope"]
    assert sum(b["bands"].values()) == b["tagged"]


def test_globals_bar_denominator_excludes_scope_marked_library_data(harness):
    g = harness.json("/api/conformance/glob_bands", program=fg.PROGRAM)
    assert g["in_scope"] == fg.N_GLOBALS_IN_SCOPE, (
        "the Scope property map marks library data; excluding it from the "
        "inventory but not the denominator is the globals half of the "
        "228600% bar"
    )
    assert g["tagged"] <= g["in_scope"]


def test_one_row_per_global_address_not_per_symbol(harness):
    """Ghidra puts many labels on one data address (D2Client: up to seven).

    Both property maps are keyed by ADDRESS, so counting symbol LINES
    inflates the scope while band counts stay per-address -- measured as
    3,398 scored against 3,219 for the same binary.
    """
    inv = harness.json("/api/conformance/globals", program=fg.PROGRAM)
    addrs = [r["address"] for r in inv["rows"]]
    assert len(addrs) == len(set(addrs)), "a global address is rendered twice"
    # the corpus deliberately puts two labels on address 0
    assert len(addrs) == fg.N_GLOBALS_IN_SCOPE


def test_function_inventory_excludes_library_functions(harness):
    inv = harness.json("/api/conformance/inventory", program=fg.PROGRAM)
    names = [r["name"] for r in inv["rows"]]
    assert "_strlen" not in names and "_memset" not in names, (
        "LIB_CRT functions are out of scope and must not appear in the inventory"
    )
    assert inv["total"] == fg.N_IN_SCOPE


def test_intake_agrees_with_the_matrix(harness):
    intake = harness.json("/api/conformance/intake", program=fg.PROGRAM)
    matrix = harness.json("/api/conformance/matrix", program=fg.PROGRAM)
    assert intake["untriaged"] == matrix["cell"]["none"]["none"], (
        "the intake header and the matrix disagree about the same number"
    )
    assert intake["in_scope"] == matrix["in_scope"]


# --------------------------------------------------------------------------
# the 7.0.0 envelope regression
# --------------------------------------------------------------------------


def test_pre_7_0_0_string_shape_still_yields_rows(harness):
    """Both inventories returned ZERO rows for days after 7.0.0.

    `/list_functions`, `/list_globals` and `/list_segments` went from
    newline text to a record envelope; the `isinstance(txt, str) else ""`
    fallbacks parsed an empty string. `_envelope_items` handles both shapes
    and this proves the legacy one still works -- if it ever stops, the
    symptom is a silently empty panel, not an error.
    """
    harness.ghidra_corpus.drop_envelope = True
    inv = harness.json("/api/conformance/inventory", program=fg.PROGRAM)
    assert inv["total"] == fg.N_IN_SCOPE, (
        "the legacy string shape parsed to zero rows -- this is exactly the "
        "regression that rendered 0/0 while the property maps held 17k entries"
    )


def test_envelope_shape_and_string_shape_agree(harness):
    """Whichever shape the plugin speaks, the dashboard must show the same corpus."""
    harness.ghidra_corpus.drop_envelope = False
    modern = harness.json("/api/conformance/inventory", program=fg.PROGRAM)
    harness.ghidra_corpus.drop_envelope = True
    legacy = harness.json("/api/conformance/inventory", program=fg.PROGRAM)
    assert modern["total"] == legacy["total"]
    assert {r["address"] for r in modern["rows"]} == {r["address"] for r in legacy["rows"]}


# --------------------------------------------------------------------------
# security-shaped contracts
# --------------------------------------------------------------------------


def test_health_payload_carries_no_store_credentials(harness):
    """`_health_store` must report `config.backend`, never `config.url`.

    A Postgres URL carries credentials and this payload renders in a browser.
    """
    import json as _json

    blob = _json.dumps(harness.json("/api/health/all"))
    for smell in ("postgresql://", "postgres://", "password=", "@10.", "sqlite:///"):
        assert smell not in blob, f"health payload leaked {smell!r}"


def test_draft_content_rejects_a_path_outside_the_staging_dir(harness):
    r = harness.get("/api/conformance/draft_content", path=r"C:\Windows\win.ini")
    assert r.status_code == 403, (
        "draft_content served a path outside _generated_candidates/ -- this is "
        "an arbitrary-file-read on a route that renders in a browser"
    )

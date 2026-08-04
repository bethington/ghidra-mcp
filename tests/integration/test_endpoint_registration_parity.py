"""Every catalogued endpoint must actually be reachable, or provably headless-only.

Why this exists
---------------
Three checks already sit near this ground and none of them covers it:

* ``EndpointsJsonParityTest`` (offline Java) compares ``tests/endpoints.json``
  against the ``@McpTool`` **annotations in the source**. It proves the catalog
  matches what the code *declares*.
* ``ManualToolDescriptorsParityTest`` (offline Java) does the same for
  hand-registered routes.
* ``test_live_safe_smoke.py`` asserts ``/get_version.endpoint_count`` equals
  ``len(/mcp/schema.tools)`` -- an internal self-consistency check that holds
  perfectly well while both numbers are wrong together.

None of them asks the question an operator actually cares about: *is the tool I
was promised there when I call it?* An endpoint can be annotated, catalogued,
and counted, and still fail to register at runtime -- a route registration
guarded by a mode check, a service that threw during construction, a deploy that
shipped a stale JAR. Every one of those is invisible to all three checks above
and to ``/mcp/schema``, because the schema is generated from what registered.

On 2026-08-04 this had to be resolved BY HAND after a merge: the live server
served 238 tools while the catalog listed 252, and confirming the 14-endpoint
gap was benign meant grepping the Java sources one path at a time. The gap was
benign -- all 14 are headless-only. That is exactly why it needs a test: a
benign difference nobody can distinguish from a regression at a glance is a
place where a real regression will be waved through.

The carve-out is derived, not declared
--------------------------------------
Missing endpoints are not compared against a hardcoded allowlist -- an allowlist
is edited to match reality the first time it fails, which converts the test into
paperwork. Instead each one must be **found registered in the headless server
source and nowhere else**. That is evidence, and it decays correctly: move an
endpoint out of headless-only and the test starts demanding it be live.

Note ``category`` in the catalog cannot do this job: it is a domain label, not a
mode label. Of the 14 genuinely headless-only endpoints, four are filed under
``analysis``/``project``/``utility`` rather than ``headless``.
"""

from __future__ import annotations

import json
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADLESS_DIR = REPO_ROOT / "src" / "main" / "java" / "com" / "xebyte" / "headless"

pytestmark = [pytest.mark.readonly, pytest.mark.requires_server]


@pytest.fixture(scope="module")
def live_tool_paths(http_session, server_url):
    """Paths the RUNNING server actually advertises, normalised to '/name'.

    Uses the session-scoped `http_session`/`server_url` rather than the
    function-scoped `http_client`: the schema is one fetch that every test here
    shares, and a module-scoped fixture cannot depend on a function-scoped one.
    The timeout is generous on purpose -- /mcp/schema is a large response and
    this call can queue behind a busy fun-doc worker fleet.
    """
    response = http_session.get(f"{server_url}/mcp/schema", timeout=90)
    assert response.status_code == 200, (
        f"/mcp/schema returned {response.status_code}; cannot establish what "
        f"this server registered."
    )
    tools = response.json().get("tools") or []
    assert tools, "/mcp/schema advertised zero tools"
    paths = set()
    for tool in tools:
        name = tool.get("name") or tool.get("path") or ""
        if name:
            paths.add("/" + name.lstrip("/"))
    return paths


@pytest.fixture(scope="module")
def catalog_paths():
    catalog = json.loads((REPO_ROOT / "tests" / "endpoints.json").read_text(encoding="utf-8"))
    return {e["path"] for e in catalog["endpoints"] if e.get("path")}


@pytest.fixture(scope="module")
def headless_only_sources():
    """Concatenated source of the headless server package."""
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(HEADLESS_DIR.rglob("*.java"))
    )


def test_no_live_endpoint_is_missing_from_the_catalog(live_tool_paths, catalog_paths):
    """A reachable tool absent from the catalog is an undocumented tool.

    This direction needs no carve-out at all: whatever mode the server is in,
    anything it serves should be described in `tests/endpoints.json`, which is
    what the bridge, the docs and the agents read.
    """
    undocumented = sorted(live_tool_paths - catalog_paths)
    assert not undocumented, (
        f"{len(undocumented)} endpoint(s) are served but not in "
        f"tests/endpoints.json: {undocumented[:15]}. Regenerate with "
        f"`mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`."
    )


def test_every_catalogued_endpoint_is_live_or_provably_headless_only(
    live_tool_paths, catalog_paths, headless_only_sources
):
    """The direction that catches a silent registration failure."""
    missing = sorted(catalog_paths - live_tool_paths)

    not_headless = [p for p in missing if f'"{p}"' not in headless_only_sources]

    assert not not_headless, (
        f"{len(not_headless)} catalogued endpoint(s) are NOT served by this "
        f"server and are NOT registered in {HEADLESS_DIR.name}/: {not_headless}. "
        f"Either the route failed to register at runtime (a stale deployed JAR "
        f"is the usual cause -- rebuild and redeploy, then re-run), or the "
        f"endpoint was removed from the code but left in tests/endpoints.json."
    )


def test_headless_only_endpoints_are_not_silently_growing(
    live_tool_paths, catalog_paths
):
    """A soft ceiling on how much of the catalog a GUI server does not serve.

    Not a correctness rule -- it is a smoke alarm. Every individually-justified
    absence still adds up, and a slow drift toward "half the catalog only works
    headless" is a design change that should be argued for, not arrived at. The
    bound is deliberately loose (a quarter of the catalog) so that ordinary
    additions never trip it; if this fires, the question to answer is whether
    the split was intended.
    """
    missing = catalog_paths - live_tool_paths
    ratio = len(missing) / max(len(catalog_paths), 1)
    assert ratio < 0.25, (
        f"{len(missing)} of {len(catalog_paths)} catalogued endpoints "
        f"({ratio:.0%}) are not served by a FrontEnd-mode server. That is a "
        f"large share to be headless-only; confirm the split is deliberate."
    )

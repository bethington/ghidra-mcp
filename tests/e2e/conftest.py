"""Playwright end-to-end suite for the fun-doc pipeline dashboard.

These tests drive the REAL dashboard in a real browser at ``--base-url``
(default ``http://127.0.0.1:5000``) and cross-check what the page RENDERS
against what the server's own JSON APIs REPORT. That pairing is the whole
point: every historical dashboard bug in this repo was a rendering /
denominator bug that left the API perfectly correct and the suite green
(the ``326700%`` band bar, the two inventories silently returning 0 rows).
A test that only calls the API cannot see those.

Tiers
-----
``-m "not destructive"``   read-only: page loads, health strip, bars,
                           inventories, settings round-trip is reverted.
``-m destructive``         starts and stops REAL workers.

Worker safety
-------------
``start_worker`` parks a new worker at the TOP of its lane loop when the
fleet is paused (``WorkerManager._park_if_paused``), i.e. before selecting
a function and before any provider call — so on a paused dashboard the
lifecycle test costs zero tokens. ``require_paused_fleet`` enforces that
precondition rather than assuming it, and ``worker_guard`` stops anything
this suite started even if a test fails midway.

Run:
    uv run pytest tests/e2e -m "not destructive" --no-cov
    uv run pytest tests/e2e -m destructive --no-cov
"""

from __future__ import annotations

import re
import time
from typing import Any

import pytest
import requests

DEFAULT_BASE_URL = "http://127.0.0.1:5000"

# Wall-clock budget for the page's first full hydration (bars fetch
# /matrix + /bands + /glob_bands + /summary serially on a large corpus).
HYDRATE_TIMEOUT_MS = 45_000


def pytest_addoption(parser):
    group = parser.getgroup("fun-doc e2e")
    group.addoption(
        "--dashboard-url",
        action="store",
        default=None,
        help=f"fun-doc dashboard base URL (default {DEFAULT_BASE_URL})",
    )
    group.addoption(
        "--allow-unpaused",
        action="store_true",
        default=False,
        help="Permit destructive worker tests against an UNPAUSED fleet "
        "(a started worker will then do real, token-spending work).",
    )


# --------------------------------------------------------------------------
# server-side fixtures
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def base_url(request) -> str:
    return (request.config.getoption("--dashboard-url") or DEFAULT_BASE_URL).rstrip("/")


@pytest.fixture(scope="session")
def live_dashboard(base_url: str) -> str:
    """Skip the whole suite unless a dashboard is answering."""
    try:
        r = requests.get(f"{base_url}/api/health/all", timeout=10)
        r.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"no fun-doc dashboard at {base_url} ({exc})")
    return base_url


class Api:
    """Thin JSON client against the dashboard under test.

    ``/api/conformance/*`` reads are automatically scoped to the binary the
    PAGE is focused on. This is not convenience — it is correctness. Those
    endpoints fall back to ``conformance_dashboard.PROGRAM`` (a module
    constant from ``FUNDOC_GHIDRA_PROGRAM``) when no ``program`` is given,
    while the page passes its own ``PROGRAM`` on every call. Forget the
    param in one test and you compare D2Client's DOM against D2Common's
    numbers and get a failure that looks like a rendering bug.

    Pass ``program=`` explicitly to override; pass ``program=None`` to
    deliberately exercise the server's default.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.program: str | None = None

    def get(self, path: str, **params) -> Any:
        if (
            path.startswith("/api/conformance/")
            and "program" not in params
            and self.program
            # these two are whole-project, not per-binary
            and not path.startswith("/api/conformance/binaries")
        ):
            params["program"] = self.program
        params = {k: v for k, v in params.items() if v is not None}
        r = self.session.get(f"{self.base_url}{path}", params=params or None, timeout=120)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, json: dict | None = None) -> requests.Response:
        return self.session.post(f"{self.base_url}{path}", json=json or {}, timeout=120)


@pytest.fixture(scope="session")
def api_client(live_dashboard: str) -> Api:
    client = Api(live_dashboard)
    try:
        client.program = client.get("/api/conformance/binaries/progress").get("active")
    except Exception:  # noqa: BLE001 — leave unscoped; per-test skips will explain
        client.program = None
    return client


@pytest.fixture
def api(api_client: Api) -> Api:
    """The API client, re-pointed at the currently-focused binary.

    Function-scoped so a test that doesn't take `dashboard` still sees the
    live focus rather than the session-start snapshot.
    """
    try:
        active = api_client.get("/api/conformance/binaries/progress").get("active")
        if active:
            api_client.program = active
    except Exception:  # noqa: BLE001
        pass
    return api_client


@pytest.fixture
def health(api: Api) -> dict:
    return api.get("/api/health/all")


@pytest.fixture
def active_program(api: Api) -> str:
    """The binary the PAGE is focused on — every count on it is per-binary.

    Sourced from ``/api/conformance/binaries/progress``, which is what
    ``loadBinaries()`` assigns to ``PROGRAM`` — NOT from
    ``/api/conformance/binaries``, whose ``active`` is still the
    process-start default (``FUNDOC_GHIDRA_PROGRAM``) and disagrees with
    it. Comparing rendered counts against the wrong binary produces
    failures that look like rendering bugs and aren't.
    """
    if not api.program:
        pytest.skip("dashboard reports no active binary")
    return api.program


# --------------------------------------------------------------------------
# browser-side fixtures
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args: dict) -> dict:
    return {**browser_context_args, "viewport": {"width": 1680, "height": 1050}}


class PageErrors:
    """Console errors + failed responses collected while a page is open."""

    def __init__(self):
        self.console: list[str] = []
        self.pageerrors: list[str] = []
        self.bad_responses: list[str] = []

    @property
    def all(self) -> list[str]:
        return self.console + self.pageerrors + self.bad_responses


@pytest.fixture
def dashboard(page, live_dashboard: str, api_client: "Api"):
    """Load the dashboard and wait for the bars to hydrate.

    Returns ``(page, errors)``. Errors are collected for the page's whole
    lifetime so any test can assert the console stayed clean.
    """
    errors = PageErrors()
    page.on(
        "console",
        lambda m: errors.console.append(f"console.{m.type}: {m.text}")
        if m.type == "error"
        else None,
    )
    page.on("pageerror", lambda e: errors.pageerrors.append(f"pageerror: {e}"))
    page.on(
        "response",
        lambda r: errors.bad_responses.append(f"HTTP {r.status} {r.url}")
        if r.status >= 400
        else None,
    )

    page.goto(live_dashboard, wait_until="domcontentloaded")
    # Hydration means ALL FOUR bars, not just the first one. `renderBandBar`
    # and `renderGlobBandBar` are async and each makes two further round trips
    # (`/bands` + `/api/queue/config`) AFTER renderBars has already filled the
    # doc and conformance bars — so waiting on `#docPct` alone returns a page
    # whose completeness bars are still showing their "-" placeholder, and
    # every assertion against them reads an empty legend.
    page.wait_for_function(
        """() => ['docLegend','bandLegend','confLegend','globBandLegend']
                  .every(id => document.querySelectorAll('#' + id + ' .lg').length > 0)""",
        timeout=HYDRATE_TIMEOUT_MS,
    )
    page.wait_for_function(
        """() => ['docPct','bandPct','confPct','globBandPct']
                  .every(id => (document.getElementById(id).textContent || '').trim() !== '-')""",
        timeout=HYDRATE_TIMEOUT_MS,
    )
    # Bind the API client to the binary THIS page ended up focused on, rather
    # than the one that was focused when the session started. Focus is server
    # state that several tests legitimately change, so a session-scoped
    # snapshot goes stale mid-run and later tests then compare one binary's
    # DOM against another's counts (seen: intake read 21 on screen, 76 from
    # the API, with nothing wrong on either side).
    try:
        program = page.evaluate("() => (typeof PROGRAM !== 'undefined') ? PROGRAM : null")
        if program:
            api_client.program = program
    except Exception:  # noqa: BLE001
        pass

    page.errors = errors  # type: ignore[attr-defined]
    return page, errors


# --------------------------------------------------------------------------
# destructive-test guards
# --------------------------------------------------------------------------


@pytest.fixture
def require_paused_fleet(api: Api, request):
    """Destructive worker tests require a PAUSED fleet unless overridden.

    Paused is not a limitation here, it is the safety property: a worker
    started against a paused fleet parks before it selects a function, so
    the lifecycle is exercised end to end without spending a token or
    mutating a single function's documentation.
    """
    state = api.get("/api/worker/pause_state")
    if not state.get("paused") and not request.config.getoption("--allow-unpaused"):
        pytest.skip(
            "fleet is not paused — a started worker would do real work. "
            "Pause the fleet, or pass --allow-unpaused to accept that."
        )
    return state


@pytest.fixture(scope="session", autouse=True)
def restore_server_context(live_dashboard: str):
    """Put the operator's binary focus back, whatever the tests did to it.

    Several tests legitimately switch focus, and each restores its own. That
    is not enough: a test that fails between the switch and its `finally`,
    or an interrupted run, leaves the operator's dashboard pointing at a
    binary they did not choose — and every count on it is per-binary, so the
    next thing they read is quietly about the wrong program. This is the
    session-level backstop.
    """
    session = requests.Session()
    try:
        before = session.get(f"{live_dashboard}/api/context", timeout=60).json().get(
            "active_binary"
        )
    except Exception:  # noqa: BLE001
        before = None
    yield before
    if not before:
        return
    try:
        after = session.get(f"{live_dashboard}/api/context", timeout=60).json().get(
            "active_binary"
        )
        if after != before:
            session.post(
                f"{live_dashboard}/api/context/binary", json={"binary": before}, timeout=60
            )
            print(f"\n[e2e] restored dashboard focus: {after} -> {before}")
    except Exception as exc:  # noqa: BLE001
        print(f"\n[e2e] WARNING: could not restore dashboard focus to {before}: {exc}")


@pytest.fixture
def worker_guard(api: Api):
    """Stop every worker this test started, even if it failed midway."""
    before = {w["id"] for w in api.get("/api/worker/status").get("workers", [])}
    yield before
    after = api.get("/api/worker/status").get("workers", [])
    for w in after:
        if w["id"] not in before and w.get("status") in (
            "starting",
            "running",
            "stopping",
            "paused",
            "quota_paused",
        ):
            api.post("/api/worker/stop", {"worker_id": w["id"]})


# --------------------------------------------------------------------------
# shared DOM helpers
# --------------------------------------------------------------------------

_LEGEND_RE = re.compile(r"^(?P<label>.*?)\s+(?P<n>[\d,]+)$")


def read_legend(page, legend_id: str) -> dict[str, int]:
    """Parse a ``.seg-legend`` into ``{label: count}``.

    Entries render as ``<swatch>LABEL N`` — the label may itself contain
    digits (``80+``, ``<80``, ``100``), so anchor on the LAST whitespace-
    separated integer rather than splitting greedily.
    """
    out: dict[str, int] = {}
    for text in page.locator(f"#{legend_id} .lg").all_inner_texts():
        m = _LEGEND_RE.match(text.strip())
        assert m, f"unparseable legend entry {text!r} in #{legend_id}"
        out[m.group("label").strip()] = int(m.group("n").replace(",", ""))
    return out


def read_segments(page, bar_id: str) -> list[tuple[str, float]]:
    """Return ``[(title, width_pct)]`` for a segmented bar's drawn spans.

    Only segments with n > 0 are drawn, so this is the bar as the operator
    actually SEES it — which is what a width-overflow bug shows up in.
    """
    return page.evaluate(
        """(id) => Array.from(document.querySelectorAll('#' + id + ' > span'))
              .map(s => [s.title, parseFloat(s.style.width) || 0])""",
        bar_id,
    )


def pct_from_label(text: str) -> float | None:
    """Extract the leading percentage from a bar's ``.p`` label.

    Returns None for the em-dash the renderers print when the denominator
    is unknown — that is a legitimate, deliberate state, not a parse error.
    """
    m = re.search(r"(-?[\d.]+)\s*%", text)
    return float(m.group(1)) if m else None


def wait_for(predicate, timeout: float = 30.0, interval: float = 0.5, what: str = "condition"):
    """Poll a server-side predicate. Playwright's expect() cannot see the API."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {what} (last={last!r})")

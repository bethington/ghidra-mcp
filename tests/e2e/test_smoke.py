"""Does the page load at all, and does it load clean?

The dashboard is one 1,700-line template with no build step and no unit
tests behind it, so a typo in a renderer is caught by exactly nothing
today. These checks are the floor: the shell renders, every panel the
operator steers from is present, and the browser reported no errors.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_page_loads_with_title(dashboard):
    page, _ = dashboard
    expect(page).to_have_title("Fun-Doc Command Center")


def test_no_console_errors_on_load(dashboard):
    page, errors = dashboard
    page.wait_for_timeout(3000)  # let the deferred fetch fan-out settle
    assert not errors.all, "browser reported errors on load:\n  " + "\n  ".join(errors.all)


@pytest.mark.parametrize(
    "selector,what",
    [
        ("#healthStrip", "dependency health strip"),
        ("#focusBtn", "binary focus button"),
        ("#lane", "lane picker"),
        ("#provider", "provider picker"),
        ("#count", "count input"),
        ("#docBar", "documentation bar"),
        ("#bandBar", "function completeness bar"),
        ("#confBar", "conformance bar"),
        ("#globBandBar", "globals completeness bar"),
        ("#workerCards", "worker panes"),
        ("#intakeN", "intake counter"),
        ("#invBody", "function inventory"),
        ("#globBody", "globals inventory"),
        ("#settingsPopout", "settings popout"),
    ],
)
def test_core_controls_present(dashboard, selector, what):
    page, _ = dashboard
    assert page.locator(selector).count() == 1, f"missing {what} ({selector})"


def test_start_button_is_reachable(dashboard):
    page, _ = dashboard
    expect(page.locator("header button.go[onclick='startLane()']")).to_be_visible()


def test_pipeline_alias_serves_the_same_page(page, live_dashboard):
    """`/pipeline` is kept as an alias for bookmarks and specs that predate
    the root swap; a redirect loop or 404 here breaks those silently."""
    resp = page.goto(f"{live_dashboard}/pipeline", wait_until="domcontentloaded")
    assert resp is not None and resp.status == 200
    expect(page.locator("#docBar")).to_have_count(1)


def test_theme_switch_persists(dashboard):
    """Theme is stored per-operator; a broken setter leaves a light-theme
    user on a dark dashboard after every refresh."""
    page, _ = dashboard
    original = page.locator("#themeSel").input_value()
    other = "neutral-light" if original != "neutral-light" else "d2-dark"
    try:
        page.locator("#themeSel").select_option(other)
        expect(page.locator("html")).to_have_attribute("data-theme", other)
        page.reload(wait_until="domcontentloaded")
        expect(page.locator("#themeSel")).to_have_value(other)
    finally:
        page.locator("#themeSel").select_option(original)


def test_intake_count_matches_api(dashboard, api, active_program):
    """The intake tile renders `untriaged / in_scope in scope · N excluded`."""
    page, _ = dashboard
    shown = page.locator("#intakeN").inner_text().strip()
    if shown in ("-", "—", ""):
        pytest.skip("intake counter not populated")
    served = api.get("/api/conformance/intake", program=active_program)
    assert shown.split()[0].replace(",", "") == str(served["untriaged"])
    assert f"{served['in_scope']:,}" in shown


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known defect: /api/conformance/intake returns excluded_lib=null for "
        "most binaries (measured 2026-08-04: D2Common 247, but D2Client, "
        "Benchmark.dll and a nonexistent path all null), while the template "
        "renders `${ik.excluded_lib||0}`. So a binary whose library-exclusion "
        "count was NEVER COMPUTED draws as '0 excluded' -- identical to one "
        "with genuinely nothing excluded. That is the shadowed_globals rule "
        "verbatim: a zero reads as 'clean', which is the false reassurance the "
        "panel exists to remove. The fix is to render an explicit unknown "
        "(and/or have the route report a real number) rather than coerce null "
        "to 0 in the template; this xfail turns red the moment it lands."
    ),
)
def test_intake_excluded_lib_is_not_a_fabricated_zero(dashboard, api, active_program):
    """A null exclusion count must not be rendered as the number zero."""
    page, _ = dashboard
    shown = page.locator("#intakeN").inner_text().strip()
    if shown in ("-", "—", ""):
        pytest.skip("intake counter not populated")
    served = api.get("/api/conformance/intake", program=active_program)
    excluded = served.get("excluded_lib")

    if excluded is None:
        assert "0 excluded" not in shown, (
            f"intake tile shows {shown!r} while the API reports "
            f"excluded_lib=null for {active_program}. 'Not computed' is being "
            f"displayed as 'none excluded'."
        )
    else:
        assert str(excluded) in shown, (
            f"intake tile {shown!r} omits the API's excluded_lib={excluded}"
        )

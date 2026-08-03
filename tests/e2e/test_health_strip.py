"""The five-dot dependency health strip.

Each dot is a claim about a subsystem the fleet cannot work without. The
failure mode that matters is not "a dot is red" — it's a dot that is GREEN
while the subsystem is dead, which is exactly what happened when
`ghidra_health` stopped emitting and `ghidra_offline_sustained` silently
went dead. So every assertion here compares the RENDERED dot against
`/api/health/all`, and the socket-precedence rule gets its own test:
a page with no socket must not show four reassuring green dots.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e

SUBSYSTEMS = {
    "hs-dashboard": ("dashboard", "Dashboard"),
    "hs-ghidra": ("ghidra", "Ghidra"),
    "hs-oracle": ("oracle", "Oracle + Game"),
    "hs-provider": ("provider", "Provider"),
    "hs-store": ("store", "Store"),
}

VALID_STATES = {"ok", "degraded", "down", "unknown"}


def _dot_state(page, item_id: str) -> str:
    cls = page.locator(f"#{item_id} .hs-dot").get_attribute("class") or ""
    states = [c for c in cls.split() if c in VALID_STATES]
    assert len(states) == 1, f"#{item_id} dot has ambiguous state classes: {cls!r}"
    return states[0]


def test_strip_has_all_five_dots(dashboard):
    page, _ = dashboard
    expect(page.locator("#healthStrip .hs-item")).to_have_count(5)
    for item_id in SUBSYSTEMS:
        expect(page.locator(f"#{item_id}")).to_be_visible()


def test_no_dot_is_stuck_unknown(dashboard):
    """`unknown` is the pre-hydration placeholder. Still showing it after
    the page has hydrated means that subsystem's render path never ran."""
    page, _ = dashboard
    page.wait_for_timeout(2000)
    stuck = [i for i in SUBSYSTEMS if _dot_state(page, i) == "unknown"]
    assert not stuck, f"dots never left the placeholder state: {stuck}"


@pytest.mark.parametrize("item_id", list(SUBSYSTEMS))
def test_dot_state_matches_api(dashboard, api, item_id):
    page, _ = dashboard
    key, _label = SUBSYSTEMS[item_id]
    served = api.get("/api/health/all")["subsystems"][key]
    expected = served.get("state", "unknown")
    rendered = _dot_state(page, item_id)
    assert rendered == expected, (
        f"{key}: strip shows '{rendered}' but /api/health/all says '{expected}' "
        f"({served.get('detail')})"
    )


@pytest.mark.parametrize("item_id", list(SUBSYSTEMS))
def test_dot_tooltip_carries_title_and_detail(dashboard, api, item_id):
    """The dot is 8px wide; the tooltip is the entire diagnosis. An empty
    detail is a dot that tells the operator a colour and nothing else."""
    page, _ = dashboard
    key, label = SUBSYSTEMS[item_id]
    served = api.get("/api/health/all")["subsystems"][key]
    tip = page.locator(f"#{item_id} .hs-tip")
    assert tip.locator(".t").inner_text().strip() == label
    detail = tip.locator(".d").inner_text().strip()
    assert detail, f"{key} tooltip has no detail line"
    if served.get("detail"):
        assert detail == served["detail"].strip()
    if served.get("endpoint"):
        assert tip.locator(".e").inner_text().strip() == served["endpoint"]


@pytest.mark.parametrize("item_id", list(SUBSYSTEMS))
def test_bad_class_tracks_unhealthy_state(dashboard, api, item_id):
    """`.bad` is what makes a dot legible at a glance; it must be set for
    exactly down+degraded and for nothing else."""
    page, _ = dashboard
    key, _ = SUBSYSTEMS[item_id]
    state = api.get("/api/health/all")["subsystems"][key].get("state")
    classes = page.locator(f"#{item_id}").get_attribute("class") or ""
    should_be_bad = state in ("down", "degraded")
    assert ("bad" in classes.split()) == should_be_bad, (
        f"{key} state={state} but .bad={'bad' in classes.split()}"
    )


def test_socket_loss_downgrades_the_dashboard_dot(dashboard, page):
    """Server-owned dots are stale the moment the socket dies. The
    dashboard dot must go `down` and say so, rather than leaving a page
    that is talking to nothing looking healthy."""
    _page, _ = dashboard
    assert _dot_state(page, "hs-dashboard") in ("ok", "degraded")

    page.evaluate("() => { window.socket && window.socket.disconnect(); }")
    # The template holds `socket` in a closure, not on window; fall back to
    # cutting the transport at the network layer if the handle isn't exposed.
    if _dot_state(page, "hs-dashboard") != "down":
        page.context.set_offline(True)
        try:
            page.wait_for_function(
                "() => (document.querySelector('#hs-dashboard .hs-dot').className || '')"
                ".includes('down')",
                timeout=30_000,
            )
            detail = page.locator("#hs-dashboard .hs-tip .d").inner_text()
            assert "socket" in detail.lower(), (
                f"dashboard dot went down but the tooltip does not explain why: {detail!r}"
            )
        finally:
            page.context.set_offline(False)


def test_paused_fleet_is_surfaced(dashboard, api):
    """A paused fleet is deliberate parking, not a fault — it must not be
    a red dot, but it MUST be visible somewhere or an operator will spend
    an hour wondering why nothing is progressing."""
    page, _ = dashboard
    state = api.get("/api/worker/pause_state")
    if not state.get("paused"):
        pytest.skip("fleet is not paused")
    body = page.locator("body").inner_text().lower()
    assert "pause" in body or "resume" in body, (
        "fleet is paused but the word never appears on the page"
    )

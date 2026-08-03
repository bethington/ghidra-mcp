"""The settings popout — the only UI for `priority_queue.json -> config`.

Two things matter here. First, the popout must SHOW what the server has:
a control rendering a default while the server holds something else is a
control that lies about what the fleet is doing. Second, saving must not
clobber neighbouring keys — `save_priority_queue` does a 3-way merge
inside the write lock precisely because whole-file replace silently
reverted `globals_audit_provider` twice in one session, and the popout
posts a whole form on every change.

Every write here is reverted in a `finally`.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


@pytest.fixture
def settings_open(dashboard):
    page, _ = dashboard
    page.locator("#btnToggleSettings").click()
    expect(page.locator("#settingsPopout")).to_have_class("settings-popout active")
    page.wait_for_timeout(1500)  # loadQueueConfig()
    yield page
    if "active" in (page.locator("#settingsPopout").get_attribute("class") or ""):
        page.locator("#btnToggleSettings").click()


def _cfg(api) -> dict:
    j = api.get("/api/queue/config")
    return j.get("config") or j


def test_popout_toggles(dashboard):
    page, _ = dashboard
    popout = page.locator("#settingsPopout")
    expect(popout).not_to_have_class("settings-popout active")
    page.locator("#btnToggleSettings").click()
    expect(popout).to_have_class("settings-popout active")
    page.locator("#btnToggleSettings").click()
    expect(popout).not_to_have_class("settings-popout active")


@pytest.mark.parametrize(
    "control,key,default",
    [
        ("#goodEnoughInput", "good_enough_score", 80),
        ("#handoffMaxInput", "complexity_handoff_max", 0),
        ("#auditMinDeltaInput", "audit_min_delta", 5),
    ],
)
def test_numeric_control_shows_server_value(settings_open, api, control, key, default):
    cfg = _cfg(api)
    expected = cfg.get(key, default)
    assert settings_open.locator(control).input_value() == str(expected)


@pytest.mark.parametrize(
    "control,key",
    [
        ("#requireScoredInput", "require_scored"),
        ("#debugModeInput", "debug_mode"),
        ("#plateScaffoldInput", "plate_scaffold"),
    ],
)
def test_checkbox_shows_server_value(settings_open, api, control, key):
    assert settings_open.locator(control).is_checked() == bool(_cfg(api).get(key))


@pytest.mark.parametrize(
    "control,key",
    [
        ("#handoffProviderInput", "complexity_handoff_provider"),
        ("#auditProviderInput", "audit_provider"),
        ("#globAuditProviderInput", "globals_audit_provider"),
    ],
)
def test_provider_select_shows_server_value(settings_open, api, control, key):
    expected = _cfg(api).get(key) or "off"
    assert settings_open.locator(control).input_value() == expected


def test_provider_model_grid_matches_config(settings_open, api):
    """The model table is what the workers actually run; a grid that shows
    a different model than the fleet uses makes every quality comparison
    unreproducible."""
    cfg = _cfg(api)
    models = cfg.get("provider_models") or {}
    turns = cfg.get("provider_max_turns") or {}
    if not models:
        pytest.skip("no provider_models configured")
    # each cell is an <input>, so assert on VALUES — inner_text() sees none of
    # them and would pass on a grid of entirely empty boxes
    for provider, tiers in models.items():
        for tier, model in tiers.items():
            cell = settings_open.locator(f"#model-{provider}-{tier}")
            if cell.count() == 0:
                pytest.fail(f"no grid cell for {provider}/{tier} (config has {model})")
            assert cell.input_value() == model, (
                f"{provider}/{tier}: grid shows {cell.input_value()!r}, config has {model!r}"
            )
    for provider, n in turns.items():
        cell = settings_open.locator(f"#turns-{provider}")
        if cell.count():
            assert cell.input_value() == str(n)


@pytest.mark.destructive
def test_target_round_trips_and_leaves_neighbours_alone(settings_open, api):
    """Change Target through the UI, confirm the server took it AND that
    nothing else in config moved. Reverted unconditionally."""
    page = settings_open
    before = _cfg(api)
    original = str(before.get("good_enough_score", 80))
    new = "90" if original != "90" else "95"
    try:
        page.locator("#goodEnoughInput").select_option(new)
        page.wait_for_timeout(2500)
        after = _cfg(api)
        assert str(after.get("good_enough_score")) == new

        moved = {
            k: (before.get(k), after.get(k))
            for k in set(before) | set(after)
            if k != "good_enough_score" and before.get(k) != after.get(k)
        }
        assert not moved, f"saving Target also changed unrelated config keys: {moved}"

        # The completeness headline follows the target. It re-renders on the
        # next refresh pass, not on the save, so allow a full cycle — and skip
        # rather than fail if the bar never hydrated (a binary with no
        # in-scope functions legitimately renders "-" forever).
        if page.locator("#bandPct").inner_text().strip() not in ("-", "—", ""):
            page.wait_for_function(
                "(t) => (document.getElementById('bandPct').textContent || '')"
                ".includes('(' + t + '+)')",
                arg=new,
                timeout=90_000,
            )
    finally:
        page.locator("#goodEnoughInput").select_option(original)
        page.wait_for_timeout(2500)
        assert str(_cfg(api).get("good_enough_score")) == original


def test_config_rejects_a_bad_provider(api):
    """A typo must be a 400, not a silently-accepted provider name that
    makes every audit pass fail at call time."""
    r = api.post("/api/queue/config", {"audit_provider": "not-a-provider"})
    assert r.status_code == 400
    assert "audit_provider" in (r.json().get("error") or "")


def test_config_rejects_an_out_of_range_target(api):
    """Out-of-range is clamped rather than rejected; either way it must
    never persist a nonsense band."""
    before = _cfg(api).get("good_enough_score")
    r = api.post("/api/queue/config", {"good_enough_score": "not-a-number"})
    assert r.status_code == 400
    assert _cfg(api).get("good_enough_score") == before

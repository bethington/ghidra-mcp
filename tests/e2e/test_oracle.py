"""The Oracle + Game dot and the oracle slide-out bar.

`oracle_health.py` distinguishes FOUR fault shapes, and the two that matter
most are the ones that answer HTTP perfectly:

  WEDGED  process up, oracle dead        -> reachable False, game_wedged
  DEAD    process gone                   -> reachable False, game_dead
  IDLE    oracle fine, parked at a menu  -> reachable TRUE,  game_idle
  FROZEN  oracle fine, drawing nothing   -> reachable TRUE,  game_frozen

IDLE and FROZEN were reported as `ok` / "live-prove enabled" with the bar
hidden, because both the dot and the bar keyed on `reachable` alone. That is
not a hypothetical: on 2026-07-31 a deploy restart left the game at the main
menu and the fleet sat idle behind a green banner for 70 minutes.

The two reachable-but-useless shapes cannot be produced on demand against a
live game, so those tests drive the page's own renderer with a synthetic
payload — the same function `checkOracleStatus()` calls. That tests the
rendering contract, which is exactly where the bug was.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.e2e


HEALTHY = {
    "reachable": True, "game_running": True, "game_wedged": False,
    "game_dead": False, "game_idle": False, "game_frozen": False,
    "relaunching": False, "relaunch_stage": None, "relaunch_error": None,
    "present_rate": 25.0,
}


def _bar_classes(page) -> list[str]:
    return (page.locator("#oracleBar").get_attribute("class") or "").split()


def _render(page, **overrides) -> None:
    """Drive the page's own oracle renderer with a synthetic payload."""
    page.evaluate("(h) => renderOracleBar(h)", {**HEALTHY, **overrides})


# ---------------------------------------------------------------------------
# live state
# ---------------------------------------------------------------------------


def test_oracle_dot_matches_oracle_status(dashboard, api):
    """The dot must agree with `/api/oracle/status`, including for the two
    shapes where `reachable` is True but the game is useless."""
    page, _ = dashboard
    page.wait_for_timeout(2000)
    s = api.get("/api/oracle/status")
    dot = page.locator("#hs-oracle .hs-dot").get_attribute("class") or ""

    if s.get("reachable") and not s.get("game_frozen") and not s.get("game_idle"):
        assert "ok" in dot.split(), f"healthy oracle but dot is {dot!r}"
    elif s.get("game_frozen"):
        assert "down" in dot.split(), f"game is FROZEN but dot is {dot!r}"
    elif s.get("game_idle"):
        assert "degraded" in dot.split(), f"game is IDLE but dot is {dot!r}"
    elif s.get("reachable") is False:
        assert dot.split() and dot.split()[-1] in ("down", "degraded"), (
            f"oracle unreachable but dot is {dot!r}"
        )


def test_oracle_bar_hidden_only_when_genuinely_healthy(dashboard, api):
    page, _ = dashboard
    page.wait_for_timeout(2000)
    s = api.get("/api/oracle/status")
    healthy = (
        s.get("reachable")
        and not s.get("game_frozen")
        and not s.get("game_idle")
        and not s.get("relaunching")
    )
    if healthy:
        assert "active" not in _bar_classes(page), (
            "oracle is healthy but the warning bar is showing"
        )


def test_health_payload_exposes_the_reachable_but_useless_flags(api):
    """The UI cannot distinguish FROZEN/IDLE from a plain outage unless the
    health payload carries them."""
    oracle = api.get("/api/health/all")["subsystems"]["oracle"]
    assert "game_frozen" in oracle, "health payload drops game_frozen"
    assert "game_idle" in oracle, "health payload drops game_idle"


# ---------------------------------------------------------------------------
# the four fault shapes, driven through the page's own renderer
# ---------------------------------------------------------------------------


def test_healthy_hides_the_bar(dashboard):
    page, _ = dashboard
    _render(page)
    assert "active" not in _bar_classes(page)


def test_frozen_game_raises_the_bar_and_offers_relaunch(dashboard):
    """A hang raises no exception, so /crash stays null and every other probe
    is green. The frame counter is the only tell — say so on screen."""
    page, _ = dashboard
    _render(page, game_frozen=True, present_rate=0)
    assert "active" in _bar_classes(page), "FROZEN game did not raise the oracle bar"
    msg = page.locator("#oracleBarMsg").inner_text()
    assert "frozen" in msg.lower()
    assert page.locator("#oracleBarBtn").is_enabled(), (
        "FROZEN recovers on the wedged path, so a relaunch must be offered"
    )


def test_idle_game_raises_the_bar_but_offers_no_relaunch(dashboard):
    """IDLE passes every liveness check while proving is stalled. It must be
    visible — but relaunching a HEALTHY game is the mistake oracle_health
    exists to prevent, so no relaunch affordance."""
    page, _ = dashboard
    _render(page, game_idle=True)
    assert "active" in _bar_classes(page), "IDLE game did not raise the oracle bar"
    msg = page.locator("#oracleBarMsg").inner_text().lower()
    assert "menu" in msg or "parked" in msg
    assert not page.locator("#oracleBarBtn").is_enabled(), (
        "an IDLE game must not offer a one-click relaunch of a healthy game"
    )


def test_wedged_game_tells_you_to_close_the_corpse_first(dashboard):
    """D2 Halt leaves Game.exe alive and Responding, which blocks a relaunch."""
    page, _ = dashboard
    _render(page, reachable=False, game_running=True, game_wedged=True)
    assert "active" in _bar_classes(page)
    msg = page.locator("#oracleBarMsg").inner_text().lower()
    assert "still running" in msg or "close game.exe" in msg


def test_dead_game_says_the_process_is_gone(dashboard):
    page, _ = dashboard
    _render(page, reachable=False, game_running=False, game_dead=True)
    assert "active" in _bar_classes(page)
    assert "not running" in page.locator("#oracleBarMsg").inner_text().lower()


def test_relaunch_in_progress_disables_the_button(dashboard):
    """A second click mid-relaunch is how you get two games."""
    page, _ = dashboard
    _render(page, reachable=False, relaunching=True, relaunch_stage="launching")
    assert "busy" in _bar_classes(page)
    assert not page.locator("#oracleBarBtn").is_enabled()
    assert "launching" in page.locator("#oracleBarMsg").inner_text().lower()


def test_relaunch_failure_offers_a_retry_with_the_error(dashboard):
    page, _ = dashboard
    _render(
        page,
        reachable=False,
        relaunch_stage="failed",
        relaunch_error="UAC prompt timed out",
    )
    assert "active" in _bar_classes(page)
    msg = page.locator("#oracleBarMsg").inner_text()
    assert "UAC prompt timed out" in msg, f"relaunch error not surfaced: {msg!r}"
    assert page.locator("#oracleBarBtn").is_enabled()


def test_oracle_dot_is_clickable_only_when_it_can_act(dashboard, api):
    """The dot doubles as the relaunch trigger when there is something to
    relaunch — and must NOT when the right recovery is navigation."""
    page, _ = dashboard
    page.wait_for_timeout(2000)
    oracle = api.get("/api/health/all")["subsystems"]["oracle"]
    actionable = "actionable" in (
        page.locator("#hs-oracle").get_attribute("class") or ""
    ).split()
    assert actionable == (oracle.get("action") == "relaunch_oracle"), (
        f"dot actionable={actionable} but health action={oracle.get('action')}"
    )
    if oracle.get("game_idle"):
        assert not actionable, "an IDLE game must not offer click-to-relaunch"

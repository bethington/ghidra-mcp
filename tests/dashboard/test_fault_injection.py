"""The failure states, driven directly, because they cannot be summoned.

Every fault below has cost real debugging time, and every one of them is
hard or impossible to reproduce on demand against a live system: you cannot
ask a game to freeze, and you cannot ask Ghidra to die at the moment you are
looking at the health strip. Faking the monitor is not a shortcut around
testing the real thing -- the monitors' own probes are unit-tested in
``tests/performance/test_oracle_health.py`` and ``test_ghidra_health.py``.
What is tested HERE is the layer above: given that state, does the dashboard
tell the operator the truth?

The 2026-07-31 incident is the shape of the whole file. A deploy restart
left the game at a menu; the oracle answered every probe perfectly; the dot
was green; the fleet did nothing for 70 minutes. Nothing was "down". The bug
was that ``reachable`` was being read as health.
"""

from __future__ import annotations

import pytest

# From `monitors`, NOT from `conftest`: sibling test tiers each have a
# conftest.py, and a bare `from conftest import X` resolves to whichever one
# reached sys.modules first -- running two tiers together imported the wrong
# module and failed at collection.
from monitors import ORACLE_FAULTS

OK, DEGRADED, DOWN, UNKNOWN = "ok", "degraded", "down", "unknown"


def _oracle_dot(harness) -> dict:
    return harness.json("/api/health/all")["subsystems"]["oracle"]


def _ghidra_dot(harness) -> dict:
    return harness.json("/api/health/all")["subsystems"]["ghidra"]


# --------------------------------------------------------------------------
# the four oracle fault shapes
# --------------------------------------------------------------------------


def test_healthy_oracle_is_green_and_offers_nothing_to_click(harness):
    harness.set_oracle("healthy")
    dot = _oracle_dot(harness)
    assert dot["state"] == OK
    assert dot["action"] is None, "a healthy oracle must not offer a relaunch button"


@pytest.mark.parametrize("shape", sorted(ORACLE_FAULTS))
def test_no_fault_shape_is_reported_as_healthy(harness, shape):
    """The single assertion that would have caught all four incidents.

    Whatever the shape, "not healthy" must not render as `ok`. This is
    parametrised over the fault table itself, so a fifth shape added to
    `oracle_health` is covered the moment it is added to that table.
    """
    harness.set_oracle(shape)
    state = _oracle_dot(harness)["state"]
    if shape == "healthy":
        assert state == OK
    else:
        assert state != OK, (
            f"the {shape.upper()} game reported as {state!r} -- this is the "
            f"green-dot-over-a-dead-fleet bug"
        )


def test_frozen_game_is_down_not_degraded(harness):
    """FROZEN answers HTTP perfectly and draws nothing.

    A stalled render thread raises no exception, so `/crash` stays null and
    every liveness probe passes. It is detected from the game's own frame
    counter, and it is `down` because a frozen game can do no work at all.
    """
    harness.set_oracle("frozen")
    dot = _oracle_dot(harness)
    assert dot["state"] == DOWN
    assert dot["game_frozen"] is True
    assert "FROZEN" in dot["detail"]
    assert dot["action"] == "relaunch_oracle", (
        "a frozen game cannot be asked to exit (the menu pump is on the "
        "stalled thread), so recovery goes down the WEDGED path and the dot "
        "must offer it"
    )


def test_idle_game_is_degraded_and_offers_no_relaunch(harness):
    """IDLE is healthy-but-parked; relaunching it is the documented mistake.

    Recovery is to NAVIGATE. A one-click relaunch of a game that is working
    fine is exactly what `oracle_health.py` exists to prevent, so the absence
    of the action is the assertion.
    """
    harness.set_oracle("idle")
    dot = _oracle_dot(harness)
    assert dot["state"] == DEGRADED, "IDLE is not an outage; the game is fine"
    assert dot["game_idle"] is True
    assert dot["action"] is None, (
        "the dot offered a relaunch for a HEALTHY game parked at a menu"
    )


def test_wedged_game_says_the_process_is_still_up(harness):
    """WEDGED: process alive, oracle dead. The corpse must be closed first."""
    harness.set_oracle("wedged")
    dot = _oracle_dot(harness)
    assert dot["state"] == DOWN
    assert "wedged" in dot["detail"].lower()
    assert dot["action"] == "relaunch_oracle"


def test_dead_game_says_the_process_is_gone(harness):
    """DEAD: a plain launch. Gating recovery on `game_wedged` left this shape
    with no unattended path at all -- measured 70 min / 94 polls / zero
    attempts on 2026-07-30."""
    harness.set_oracle("dead")
    dot = _oracle_dot(harness)
    assert dot["state"] == DOWN
    assert "not running" in dot["detail"].lower()
    assert dot["action"] == "relaunch_oracle"


def test_idle_and_frozen_are_distinguishable_without_re_deriving_them(harness):
    """The UI must not have to guess which answering-but-useless shape it is."""
    harness.set_oracle("idle")
    idle = _oracle_dot(harness)
    harness.set_oracle("frozen")
    frozen = _oracle_dot(harness)
    assert (idle["game_idle"], idle["game_frozen"]) == (True, False)
    assert (frozen["game_idle"], frozen["game_frozen"]) == (False, True)


def test_relaunch_in_progress_is_degraded_and_names_its_stage(harness):
    harness.set_oracle("dead", relaunching=True, relaunch_stage="launching")
    dot = _oracle_dot(harness)
    assert dot["state"] == DEGRADED
    assert "launching" in dot["detail"]


def test_relaunch_failure_surfaces_the_error(harness):
    harness.set_oracle("dead", relaunch_error="UAC prompt timed out")
    assert "UAC prompt timed out" in _oracle_dot(harness)["detail"]


def test_unprobed_oracle_is_unknown_not_healthy(harness):
    """`reachable: None` means "not probed yet", which is not the same as OK.

    Collapsing unknown into either OK or DOWN is how a dot starts lying
    during startup.
    """
    harness.set_oracle("healthy", reachable=None)
    assert _oracle_dot(harness)["state"] == UNKNOWN


# --------------------------------------------------------------------------
# Ghidra
# --------------------------------------------------------------------------


def test_ghidra_offline_is_not_green(harness):
    """`ghidra_health` is the ONLY emitter of the `ghidra_health` event.

    `audit/rules.yaml` has consumed it since Phase 1, and it once had no
    emitter at all -- a green dot over a dead Ghidra, and
    `ghidra_offline_sustained` silently dead.
    """
    harness.set_ghidra(running=False, reachable=False)
    assert _ghidra_dot(harness)["state"] != OK


def test_ghidra_running_but_unreachable_is_not_reported_as_simply_down(harness):
    """Running-but-not-answering is the state you must NOT resolve by killing it.

    A running Ghidra can hold unsaved programs and checked-out files, so the
    distinction between "gone" and "busy" is the difference between a launch
    and data loss.
    """
    harness.set_ghidra(running=True, reachable=False)
    dot = _ghidra_dot(harness)
    assert dot["state"] in (DEGRADED, DOWN)
    assert dot["detail"], "a non-green Ghidra dot must say what is wrong"


def _explode(*_args, **_kwargs):
    raise RuntimeError("probe blew up")


def test_a_broken_ghidra_probe_downgrades_only_its_own_dot(harness):
    """A health endpoint that can fail as a unit is one you stop trusting."""
    harness.ghidra.get_state = _explode
    payload = harness.json("/api/health/all")
    assert payload["subsystems"]["ghidra"]["state"] == UNKNOWN
    for name in ("dashboard", "oracle", "provider", "store"):
        assert payload["subsystems"][name]["state"] != UNKNOWN, (
            f"a broken ghidra probe took the {name} dot down with it"
        )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known defect, and one the code contradicts itself on. "
        "`get_health_summary`'s own docstring promises 'Never raises: a broken "
        "probe reports unknown for its own dot rather than 500-ing the whole "
        "strip.' `_health_oracle` guards its `get_state()` call; "
        "`_health_dashboard` does NOT -- it reads the same oracle monitor "
        "unguarded, just for the `elevated` flag -- so a broken oracle probe "
        "500s the entire health strip. Wrapping that one read makes this pass."
    ),
)
def test_a_broken_oracle_probe_downgrades_only_its_own_dot(harness):
    harness.oracle.get_state = _explode
    payload = harness.json("/api/health/all")
    assert payload["subsystems"]["oracle"]["state"] == UNKNOWN
    for name in ("dashboard", "ghidra", "provider", "store"):
        assert payload["subsystems"][name]["state"] != UNKNOWN, (
            f"a broken oracle probe took the {name} dot down with it"
        )


# --------------------------------------------------------------------------
# fleet pause -- deliberate, and must not read as a fault
# --------------------------------------------------------------------------


def test_a_paused_fleet_is_surfaced_at_the_top_level_not_as_a_sixth_dot(harness):
    """A pause is a decision, not a dependency fault.

    Rendering it as one trains the operator to read a deliberate pause as
    something broken.
    """
    payload = harness.json("/api/health/all")
    assert "paused" in payload and "pause_reason" in payload
    assert "paused" not in payload["subsystems"], (
        "the pause is a top-level field; as a sixth dot it reads as an outage"
    )


# --------------------------------------------------------------------------
# the backend going away mid-render
# --------------------------------------------------------------------------


def test_health_strip_still_answers_when_ghidra_is_unreachable(harness):
    """The strip is what you look at WHEN things are broken.

    It must be the last thing to fail, so it may not depend on the subsystem
    it is reporting on.
    """
    harness.ghidra_corpus.fail_with = OSError("ghidra went away")
    payload = harness.json("/api/health/all")
    assert payload["subsystems"].keys() >= {
        "dashboard", "ghidra", "oracle", "provider", "store"
    }

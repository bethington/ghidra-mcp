"""Fake dependency monitors, and the fault shapes they can be driven to.

Separate from ``conftest.py`` on purpose. Two sibling test tiers each have a
``conftest.py``, and a bare ``from conftest import X`` resolves to whichever
one landed in ``sys.modules`` first -- so running ``tests/dashboard`` and
``tests/benchmark_e2e`` in the same session imported the wrong module and
failed at collection. Shared values live in uniquely-named modules instead.
"""

from __future__ import annotations

from typing import Any


class FakeMonitor:
    """Stands in for OracleHealthMonitor / GhidraHealthMonitor.

    Health state is a plain mutable dict so a test can drive any fault shape
    by assigning to it. The four oracle shapes (WEDGED / DEAD / IDLE /
    FROZEN) cannot be produced against a real game on demand -- that is the
    whole reason they went undetected for 70 minutes on 2026-07-31 -- so
    being able to set them directly is the feature, not a shortcut.
    """

    #: Overridden per subclass so the two monitors report distinguishable state.
    DEFAULT: dict[str, Any] = {}

    def __init__(self, *_args: Any, **kwargs: Any) -> None:
        self.state: dict[str, Any] = dict(self.DEFAULT)
        self.started = False
        self.stopped = False
        self.bus = kwargs.get("bus")

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def get_state(self) -> dict[str, Any]:
        return dict(self.state)

    def check_once(self) -> dict[str, Any]:
        return dict(self.state)


class FakeOracleMonitor(FakeMonitor):
    DEFAULT = {
        "reachable": True,
        "game_running": True,
        "game_wedged": False,
        "game_dead": False,
        "game_idle": False,
        "game_frozen": False,
        "relaunching": False,
        "relaunch_stage": None,
        "relaunch_error": None,
        "present_rate": 25.0,
        "elevated": True,
        "checked_at": "2026-08-03T00:00:00",
    }


class FakeGhidraMonitor(FakeMonitor):
    DEFAULT = {
        "running": True,
        "reachable": True,
        "launching": False,
        "launch_error": None,
        "install_dir": r"F:\ghidra_12.1.2_PUBLIC",
        "checked_at": "2026-08-03T00:00:00",
    }


#: The four oracle fault shapes, by name. Keyed exactly as `oracle_health`
#: reports them so a test reads like the incident it guards against.
ORACLE_FAULTS: dict[str, dict[str, Any]] = {
    "healthy": {},
    "wedged": {"reachable": False, "game_running": True, "game_wedged": True},
    "dead": {"reachable": False, "game_running": False, "game_dead": True},
    # IDLE and FROZEN are the dangerous pair: both answer HTTP perfectly.
    "idle": {"reachable": True, "game_running": True, "game_idle": True},
    "frozen": {"reachable": True, "game_running": True, "game_frozen": True,
               "present_rate": 0.0},
}

"""Coverage for the orphaned-provider-subprocess reaper.

Context: `_invoke_provider_with_watchdog` terminates its spawned provider child
in a `finally` block, which handles every in-process path. It cannot handle the
DASHBOARD being force-killed -- no handler runs, and a wedged provider child
never exits on its own. Four such orphans were found alive on 2026-07-29, aged
up to five days, each born minutes after a dashboard start whose session later
ended hard.

The risk in a reaper is misattribution, so these tests are mostly about what it
must REFUSE to kill.
"""

import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

orphan_reaper = pytest.importorskip("orphan_reaper")


def _runner(records):
    return lambda prefix: records


def test_finds_orphan_with_dead_parent_in_our_prefix():
    found = orphan_reaper.find_orphans(
        prefix="/venv",
        runner=_runner([{"pid": 111, "ppid": 999,
                         "parent_alive": False, "in_prefix": True}]))
    assert found == [111]


def test_spares_children_of_a_LIVE_dashboard():
    """The current dashboard's in-flight provider children must never be
    touched -- reaping those would kill active work on every startup."""
    found = orphan_reaper.find_orphans(
        prefix="/venv",
        runner=_runner([{"pid": 222, "ppid": 1,
                         "parent_alive": True, "in_prefix": True}]))
    assert found == []


def test_spares_foreign_processes_even_when_orphaned():
    """A dead-parent Python process that is NOT running out of our venv belongs
    to somebody else. This is also the PID-reuse guard: a recycled PID will not
    have our prefix mapped."""
    found = orphan_reaper.find_orphans(
        prefix="/venv",
        runner=_runner([{"pid": 333, "ppid": 999,
                         "parent_alive": False, "in_prefix": False}]))
    assert found == []


def test_never_reaps_itself():
    import os
    found = orphan_reaper.find_orphans(
        prefix="/venv",
        runner=_runner([{"pid": os.getpid(), "ppid": 999,
                         "parent_alive": False, "in_prefix": True}]))
    assert found == []


def test_mixed_roster_picks_only_the_orphans():
    """Mirrors the real 2026-07-29 roster: four orphans plus one live child."""
    records = [
        {"pid": 158776, "ppid": 389676, "parent_alive": False, "in_prefix": True},
        {"pid": 300756, "ppid": 209244, "parent_alive": False, "in_prefix": True},
        {"pid": 325684, "ppid": 304008, "parent_alive": False, "in_prefix": True},
        {"pid": 371956, "ppid": 299556, "parent_alive": False, "in_prefix": True},
        {"pid": 381172, "ppid": 281908, "parent_alive": True, "in_prefix": False},
    ]
    found = orphan_reaper.find_orphans(prefix="/venv", runner=_runner(records))
    assert sorted(found) == [158776, 300756, 325684, 371956]


def test_a_broken_sweep_never_blocks_startup():
    """This runs on the dashboard's startup path; a diagnostic must not be able
    to prevent the dashboard from coming up."""
    def _boom(prefix):
        raise OSError("WMI unavailable")

    assert orphan_reaper.find_orphans(prefix="/venv", runner=_boom) == []


def test_reap_reports_successes_and_failures():
    records = [
        {"pid": 1, "ppid": 99, "parent_alive": False, "in_prefix": True},
        {"pid": 2, "ppid": 99, "parent_alive": False, "in_prefix": True},
    ]
    logged = []
    reaped, failed = orphan_reaper.reap_orphans(
        prefix="/venv", runner=_runner(records),
        killer=lambda pid: pid == 1, log=logged.append)

    assert reaped == [1]
    assert failed == [2]
    # Loud on failure: a silent reaper is indistinguishable from one that never
    # ran, which is how four orphans went unnoticed for five days.
    assert any("FAILED" in m for m in logged)


def test_reap_is_quiet_and_cheap_when_nothing_to_do():
    logged = []
    reaped, failed = orphan_reaper.reap_orphans(
        prefix="/venv", runner=_runner([]),
        killer=lambda pid: pytest.fail("must not kill anything"),
        log=logged.append)

    assert (reaped, failed) == ([], [])
    assert logged == []


def test_killer_exception_counts_as_failure_not_a_crash():
    def _killer(pid):
        raise PermissionError("access denied")

    reaped, failed = orphan_reaper.reap_orphans(
        prefix="/venv",
        runner=_runner([{"pid": 7, "ppid": 99,
                         "parent_alive": False, "in_prefix": True}]),
        killer=_killer, log=lambda _m: None)

    assert (reaped, failed) == ([], [7])

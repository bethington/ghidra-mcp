"""Integration-tier fixtures.

Contains one thing: a fleet detector that makes contention failures legible.

The problem it solves
---------------------
The integration tier talks to the same Ghidra instance the fun-doc worker fleet
uses, and Ghidra serialises program access. A prove-mode worker can hold that
access for tens of seconds at a time, so an ordinary read queues behind it and
blows the 30 s client timeout.

The resulting failure is deeply misleading. Measured on 2026-08-04 with three
port workers running: ``test_get_function_variables`` failed on a
``ReadTimeout``, ten sibling tests then ERRORed on the shared fixture, and the
output pointed at ``/get_function_variables`` as though that endpoint were
broken. It was not -- the same call, isolated moments later, returned in
**1.8 ms**, and the entire tier passed on a clean re-run. Roughly a
16,000x apparent slowdown, none of it a defect.

Anyone reading that output without knowing the fleet was running would go
debug an endpoint that works.

Why a warning and not a skip
----------------------------
Running the integration tier against a working machine is legitimate, and
skipping would quietly reduce coverage exactly when someone chose to run it.
Nor does this widen the timeout: a slow Ghidra is sometimes a real finding, and
papering over it would remove a genuine signal. The only thing wrong before was
that the cause was invisible, so the only thing added is visibility.
"""

from __future__ import annotations

import os

import pytest

try:
    import requests
except ImportError:  # pragma: no cover - requests is an integration-tier dep
    requests = None

DASHBOARD_URL = os.environ.get("FUN_DOC_DASHBOARD_URL", "http://127.0.0.1:5000")


def _busy_workers():
    """Return names of workers that are running and not paused.

    Returns an empty list when the dashboard is absent, unreachable or
    unparseable. This is a diagnostic, and a diagnostic that can fail the run it
    is trying to explain is worse than no diagnostic at all.
    """
    if requests is None:
        return []
    try:
        response = requests.get(f"{DASHBOARD_URL}/api/worker/status", timeout=3)
        if response.status_code != 200:
            return []
        workers = response.json().get("workers") or []
    except Exception:
        return []

    busy = []
    for worker in workers:
        if not isinstance(worker, dict):
            continue
        if worker.get("paused_reason") or worker.get("paused_until"):
            continue
        if worker.get("is_stale"):
            continue
        busy.append(
            f"{worker.get('id', '?')}:{worker.get('mode', '?')}"
            f"@{(worker.get('binary') or '?').rsplit('/', 1)[-1]}"
        )
    return busy


@pytest.fixture(scope="session", autouse=True)
def warn_if_worker_fleet_is_busy(request):
    """Announce a running fleet up front, and again if the tier failed.

    Reported twice on purpose. The header note is easy to scroll past during a
    long run; the terminal-summary note lands next to the failures it explains,
    which is where somebody actually reads it.
    """
    busy = _busy_workers()
    if not busy:
        yield
        return

    message = (
        f"{len(busy)} fun-doc worker(s) are RUNNING against the same Ghidra "
        f"instance: {', '.join(busy[:6])}"
        f"{' ...' if len(busy) > 6 else ''}. Ghidra serialises program access, "
        f"so reads here may queue behind them and hit the "
        f"{os.environ.get('GHIDRA_MCP_TIMEOUT', '30')}s client timeout. A "
        f"ReadTimeout in this run is far more likely to be contention than a "
        f"broken endpoint -- confirm by re-running the failing test alone "
        f"before investigating it. Pause the fleet for a clean run."
    )

    reporter = request.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line("")
        reporter.write_line(f"[fleet] {message}", yellow=True)

    yield

    # Repeat next to the failure list, where it is actually read.
    if reporter is not None and getattr(reporter, "stats", None):
        if reporter.stats.get("failed") or reporter.stats.get("error"):
            reporter.write_line("")
            reporter.write_line(f"[fleet] {message}", yellow=True)

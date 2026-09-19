"""Run the existing integration tier against the fake, with no Ghidra.

    pytest tests/integration/test_readonly_endpoints.py -p tests.offline.replay_plugin

That single command is the point of issue #112: a contributor with no Ghidra
installed gets a real pass or fail out of the suite that previously required a
live instance on :8089 with a binary open.

The plugin does three things and nothing else:

1. Boots a :class:`FakeGhidraServer` on an ephemeral port and points
   ``GHIDRA_MCP_URL`` at it, so ``tests/conftest.py`` wires the whole suite to
   the fake without a single edit to the integration files.
2. Skips the node ids listed in ``fixtures/known_offline_gaps.json``, each with
   its recorded reason. A listed id that no longer exists is an ERROR, so the
   list cannot rot into a permanent excuse.
3. At the end of the session, compares the contract violations the fake
   observed against ``fixtures/expected_contract_violations.json`` and fails
   the run on ANY difference -- new violations *and* stale entries.

Point 3 is the one that carries weight. The fake runs lenient here (see
``FakeGhidraServer.strict``): it serves the response and records the breach
rather than refusing, because refusing at the first breach aborts a shared
fixture and hides everything behind it. The breaches are not forgiven, they are
collected -- and then asserted against a committed baseline, which is what makes
this tier able to go red.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
if str(_HERE.parents[1]) not in sys.path:
    sys.path.insert(0, str(_HERE.parents[1]))

from tests.offline.fake_ghidra import FakeGhidraServer  # noqa: E402

KNOWN_GAPS = _HERE / "fixtures" / "known_offline_gaps.json"
EXPECTED_VIOLATIONS = _HERE / "fixtures" / "expected_contract_violations.json"

_STATE: dict[str, object] = {}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pytest_configure(config: pytest.Config) -> None:
    server = FakeGhidraServer(strict=False).start()
    _STATE["server"] = server
    _STATE["previous_url"] = os.environ.get("GHIDRA_MCP_URL")
    os.environ["GHIDRA_MCP_URL"] = server.url
    # The fake answers instantly; a 30 s default only slows a genuine hang.
    _STATE["previous_timeout"] = os.environ.get("GHIDRA_MCP_TIMEOUT")
    os.environ.setdefault("GHIDRA_MCP_TIMEOUT", "15")
    config.stash[_stash_key()] = server


def _stash_key():
    if "key" not in _STATE:
        _STATE["key"] = pytest.StashKey[FakeGhidraServer]()
    return _STATE["key"]


def pytest_unconfigure(config: pytest.Config) -> None:
    server = _STATE.pop("server", None)
    if server is not None:
        server.stop()
    for env, saved in (
        ("GHIDRA_MCP_URL", _STATE.pop("previous_url", None)),
        ("GHIDRA_MCP_TIMEOUT", _STATE.pop("previous_timeout", None)),
    ):
        if saved is None:
            os.environ.pop(env, None)
        else:
            os.environ[env] = saved


def pytest_collection_modifyitems(config: pytest.Config, items: list) -> None:
    gaps = _load(KNOWN_GAPS)["gaps"]
    by_id = {g["node_id"]: g for g in gaps}
    seen: set[str] = set()

    for item in items:
        # Node ids are recorded without the file's directory separator style,
        # which differs between Windows and POSIX runners.
        node_id = item.nodeid.replace("\\", "/")
        gap = by_id.get(node_id)
        if gap is None:
            continue
        seen.add(node_id)
        item.add_marker(
            pytest.mark.skip(
                reason=f"offline gap [{gap['cause']}]: {gap['reason']}"
            )
        )

    stale = sorted(set(by_id) - seen)
    if stale:
        raise pytest.UsageError(
            "known_offline_gaps.json lists node ids that no longer exist: "
            + ", ".join(stale)
            + ". Remove them -- a quarantine list that outlives its tests is "
            "an excuse, not a record."
        )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    server = _STATE.get("server")
    if server is None:
        return

    expected = _load(EXPECTED_VIOLATIONS)
    baseline = {entry["violation"] for entry in expected["violations"]}
    observed = set(server.violation_keys())

    new = sorted(observed - baseline)
    gone = sorted(baseline - observed)
    if not new and not gone:
        return

    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    lines = ["", "[offline] contract-violation baseline mismatch"]
    for v in new:
        lines.append(f"  NEW   {v}")
    for v in gone:
        lines.append(f"  GONE  {v}")
    lines.append(
        "  Baseline: tests/offline/fixtures/expected_contract_violations.json"
    )
    lines.append(
        "  A NEW entry means a call was added that the endpoint catalog does "
        "not support. A GONE entry means one was fixed -- delete it from the "
        "baseline so it cannot come back unnoticed."
    )
    if reporter is not None:
        for line in lines:
            reporter.write_line(line, red=True)
    else:  # pragma: no cover - terminalreporter is always present under pytest
        print("\n".join(lines))

    session.exitstatus = 1

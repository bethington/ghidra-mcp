"""/api/falsify/sweep — the Falsifiability panel's one-click loop.

The route wraps scripts/falsify_sweep.py's importable pieces (scan → apply →
pin → launch) behind a background thread. These tests stub the sweep pieces at
the module level (the thread imports ``falsify`` and ``scripts.falsify_sweep``
fresh each run) and drive the route through the hermetic harness — no Ghidra,
no providers, no workers.

The loop-mode test runs with ``workers=0`` deliberately: WorkerManager is real
in this harness, and a started worker would try to invoke a provider. Worker
launch refusal is already covered by the manager's own tests; what this tier
owns is the route contract — apply ran, the pins landed, and the report shape
is right.
"""
from __future__ import annotations

import json
import time
from typing import Any

import pytest


def _wait_done(harness, timeout: float = 10.0) -> dict:
    """Poll sweep_status until the background thread finishes."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = harness.json("/api/falsify/sweep_status")
        if not s.get("running"):
            return s
        time.sleep(0.05)
    raise AssertionError("falsify sweep did not finish within timeout")


@pytest.fixture
def sweep_stubs(monkeypatch):
    """Stub the sweep's scan/apply surface. Returns a call recorder."""
    import falsify
    from scripts import falsify_sweep as fsweep

    calls: dict[str, Any] = {"apply_sql": 0, "apply_ghidra": 0}

    monkeypatch.setattr(falsify, "enabled_check_ids", lambda en, dis: ["arity_contradiction"])
    monkeypatch.setattr(
        falsify, "scan_program_verdicts",
        lambda program, enabled, limit=0, pause_every=0, pause_secs=0: [
            ("00401000", "GoodFunc", "passed", []),
            ("00402000", "BadFunc", "contradicted", []),
        ],
    )
    monkeypatch.setattr(fsweep, "merge_doclint", lambda vbp, programs: None)

    def _apply_sql(vbp, now):
        calls["apply_sql"] += 1
        return {"updated": 2, "upserted": 0}

    def _apply_ghidra(vbp, date):
        calls["apply_ghidra"] += 1
        return {"synced": 1, "failed": 0, "programs_touched": []}

    monkeypatch.setattr(fsweep, "apply_sql", _apply_sql)
    monkeypatch.setattr(fsweep, "apply_ghidra", _apply_ghidra)
    return calls


def test_sweep_requires_program(harness):
    r = harness.post("/api/falsify/sweep", body={"mode": "report"})
    assert r.status_code == 400
    assert "program" in r.get_json()["error"]


def test_sweep_rejects_unknown_mode(harness):
    r = harness.post(
        "/api/falsify/sweep",
        body={"program": "/Mods/PD2-S12/Game.exe", "mode": "yolo"},
    )
    assert r.status_code == 400


def test_report_mode_scans_but_never_applies(harness, sweep_stubs):
    r = harness.post(
        "/api/falsify/sweep",
        body={"program": "/Mods/PD2-S12/Game.exe", "mode": "report"},
    )
    assert r.status_code == 200 and r.get_json()["ok"]
    s = _wait_done(harness)
    assert s["error"] is None
    res = s["result"]
    assert res["mode"] == "report"
    assert [c["name"] for c in res["contradicted"]] == ["BadFunc"]
    # Report-first means REPORT: nothing may have been written.
    assert sweep_stubs["apply_sql"] == 0
    assert sweep_stubs["apply_ghidra"] == 0
    assert "sql" not in res and "ghidra" not in res


def test_loop_mode_applies_and_pins_contradicted(harness, sweep_stubs):
    program = "/Mods/PD2-S12/Game.exe"
    r = harness.post(
        "/api/falsify/sweep",
        body={"program": program, "mode": "loop", "workers": 0},
    )
    assert r.status_code == 200 and r.get_json()["ok"]
    s = _wait_done(harness)
    assert s["error"] is None
    res = s["result"]
    assert res["sql"] == {"updated": 2, "upserted": 0}
    assert res["ghidra"]["synced"] == 1
    assert res["pinned"] == 1
    assert res["workers_started"] == []
    # The pin must land in the queue file — that is what makes the refuted
    # function eligible past the selector's library skip.
    queue = json.loads(
        (harness.sandbox / "priority_queue.json").read_text(encoding="utf-8")
    )
    assert f"{program}::00402000" in queue.get("pinned", [])
    assert f"{program}::00401000" not in queue.get("pinned", [])


def test_second_sweep_conflicts_while_running(harness, monkeypatch):
    import falsify
    from scripts import falsify_sweep as fsweep
    import threading

    release = threading.Event()

    monkeypatch.setattr(falsify, "enabled_check_ids", lambda en, dis: ["x"])

    def _slow_scan(program, enabled, limit=0, pause_every=0, pause_secs=0):
        release.wait(timeout=10)
        return []

    monkeypatch.setattr(falsify, "scan_program_verdicts", _slow_scan)
    monkeypatch.setattr(fsweep, "merge_doclint", lambda vbp, programs: None)
    try:
        r1 = harness.post(
            "/api/falsify/sweep",
            body={"program": "/Mods/PD2-S12/Game.exe", "mode": "report"},
        )
        assert r1.status_code == 200
        r2 = harness.post(
            "/api/falsify/sweep",
            body={"program": "/Mods/PD2-S12/D2Game.dll", "mode": "report"},
        )
        assert r2.status_code == 409
        assert "already running" in r2.get_json()["error"]
    finally:
        release.set()
    _wait_done(harness)

"""The worker-side falsify stage: bundle assembly, verdict persistence,
forced-audit prompt seeding.

Covers fun_doc's falsify-stage helpers with all I/O monkeypatched:
  _falsify_bundle       — live-state fetch -> falsify.py bundle (or None, loudly)
  _run_falsify_pass     — checks -> func fields -> update_function_state ->
                          falsify.sync_to_ghidra -> bus events
  _falsify_prompt_block — the seeded section for a findings-forced audit

The audit-gate override itself (`force_audit` bypassing skipped_good_enough /
skipped_delta inside process_function) is exercised live in the deploy
verification — a full process_function rig would stub more than it tests.

Offline: no Ghidra, no SQL writes (update_function_state is a recorder).
"""
import sys
from pathlib import Path

import pytest

FUN_DOC = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC) not in sys.path:
    sys.path.insert(0, str(FUN_DOC))

fd = pytest.importorskip("fun_doc")
fz = pytest.importorskip("falsify")


GOOD_DOC = {
    "function_name": "DATATBLS_GetRecordCount",
    "calling_convention": "__stdcall",
    "return_type": "int",
    "parameters": [{"name": "nRecordId", "type": "int"}],
    "plate_comment": "Counts records.\n\nReturns:\n  int: the count\n",
}

# stdcall, 1 param, matching RET 0x4 — passes every check.
CLEAN_DISASM = {"instructions": [
    {"address": "6fd51000", "instruction": "MOV EAX,dword ptr [ESP + 0x4]"},
    {"address": "6fd51004", "instruction": "RET 0x4"},
]}

# stdcall with 1 declared param but RET 0x8 — arity_contradiction (tier 1).
WRONG_DISASM = {"instructions": [
    {"address": "6fd51000", "instruction": "MOV EAX,dword ptr [ESP + 0x4]"},
    {"address": "6fd51004", "instruction": "RET 0x8"},
]}


def _ghidra_get_stub(doc=GOOD_DOC, dis=CLEAN_DISASM):
    def stub(path, params=None, timeout=60):
        if path == "/get_function_documentation":
            return dict(doc)
        if path == "/disassemble_function":
            return dict(dis)
        raise AssertionError(f"unexpected GET {path}")
    return stub


@pytest.fixture
def rig(monkeypatch):
    """Recorders for every side effect _run_falsify_pass produces."""
    calls = {"state": [], "sync": [], "bus": []}
    monkeypatch.setattr(fd, "update_function_state",
                        lambda k, f: calls["state"].append((k, dict(f))))
    monkeypatch.setattr(fz, "sync_to_ghidra",
                        lambda *a, **kw: calls["sync"].append((a, kw)) or True)
    monkeypatch.setattr(fd, "bus_emit",
                        lambda evt, data=None: calls["bus"].append((evt, data)))
    return calls


# ------------------------------------------------------- _falsify_bundle ----

def test_bundle_assembles_from_live_state(monkeypatch):
    monkeypatch.setattr(fd, "ghidra_get", _ghidra_get_stub())
    b = fd._falsify_bundle("D2Common.dll", "6fd51000")
    assert b["name"] == "DATATBLS_GetRecordCount"
    assert b["calling_convention"] == "__stdcall"
    assert b["params"] == [{"name": "nRecordId", "type": "int"}]
    assert "RET 0x4" in b["disasm_text"]
    assert b["address"] == "0x6fd51000"


def test_bundle_returns_none_on_error_payload(monkeypatch, capsys):
    monkeypatch.setattr(fd, "ghidra_get",
                        lambda path, params=None, timeout=60: {"error": "no function"})
    assert fd._falsify_bundle("D2Common.dll", "6fd51000") is None
    assert "bundle unavailable" in capsys.readouterr().out


def test_bundle_returns_none_on_transport_failure(monkeypatch, capsys):
    def boom(path, params=None, timeout=60):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(fd, "ghidra_get", boom)
    assert fd._falsify_bundle("D2Common.dll", "6fd51000") is None
    assert "bundle fetch failed" in capsys.readouterr().out


# ----------------------------------------------------- _run_falsify_pass ----

def test_clean_function_passes_and_persists(rig, monkeypatch):
    monkeypatch.setattr(fd, "ghidra_get", _ghidra_get_stub())
    func = {"program": "/Mods/PD2-S12/D2Common.dll", "address": "6fd51000"}
    outcome, findings = fd._run_falsify_pass(
        "/Mods/PD2-S12/D2Common.dll::6fd51000", func, "D2Common.dll", "6fd51000")
    assert outcome == "passed"
    assert findings == []
    assert func["falsify_status"] == "passed"
    assert func["falsify_source"] == "worker"
    assert func["falsify_findings"] == []
    assert func["falsify_checked_at"]
    assert len(rig["state"]) == 1, "verdict must be persisted"
    (args, _kw) = rig["sync"][0]
    assert args[2] == "passed"
    events = [e for e, _ in rig["bus"]]
    assert events == ["falsify_start", "falsify_complete"]
    assert rig["bus"][1][1]["outcome"] == "passed"


def test_contradicted_function_records_findings(rig, monkeypatch, capsys):
    monkeypatch.setattr(fd, "ghidra_get", _ghidra_get_stub(dis=WRONG_DISASM))
    func = {"program": "/Mods/PD2-S12/D2Common.dll", "address": "6fd51000"}
    outcome, findings = fd._run_falsify_pass(
        "k", func, "D2Common.dll", "6fd51000")
    assert outcome == "contradicted"
    assert any(f.check_id == "arity_contradiction" and f.tier == 1
               for f in findings)
    assert func["falsify_status"] == "contradicted"
    assert func["falsify_findings"][0]["check_id"] == "arity_contradiction"
    (args, _kw) = rig["sync"][0]
    assert args[2] == "contradicted"
    assert "CONTRADICTED" in capsys.readouterr().out
    done = [d for e, d in rig["bus"] if e == "falsify_complete"][0]
    assert done["tier1"] == 1
    assert "arity_contradiction" in done["checks"]


def test_bundle_failure_reports_error_not_pass(rig, monkeypatch):
    """No data must never read as a clean bill (the CONF_BLOCKED rule)."""
    monkeypatch.setattr(fd, "ghidra_get",
                        lambda path, params=None, timeout=60: {"error": "down"})
    func = {}
    outcome, findings = fd._run_falsify_pass("k", func, "D2Common.dll", "1000")
    assert outcome == "error"
    assert findings == []
    assert "falsify_status" not in func, "an error run must not stamp a verdict"
    assert rig["sync"] == [], "no verdict -> no Ghidra write"


def test_state_persist_failure_is_loud_but_nonfatal(rig, monkeypatch, capsys):
    monkeypatch.setattr(fd, "ghidra_get", _ghidra_get_stub())
    def boom(k, f):
        raise RuntimeError("db locked")
    monkeypatch.setattr(fd, "update_function_state", boom)
    outcome, _ = fd._run_falsify_pass("k", {}, "D2Common.dll", "6fd51000")
    assert outcome == "passed"
    assert "state persist failed" in capsys.readouterr().out
    assert rig["sync"], "Ghidra sync still happens after a SQL hiccup"


def test_source_is_threaded_through(rig, monkeypatch):
    monkeypatch.setattr(fd, "ghidra_get", _ghidra_get_stub())
    func = {}
    fd._run_falsify_pass("k", func, "D2Common.dll", "6fd51000", source="sweep")
    assert func["falsify_source"] == "sweep"
    (args, _kw) = rig["sync"][0]
    assert args[4] == "sweep"


# -------------------------------------------------- _falsify_prompt_block ---

def _finding(check_id, tier):
    return fz.Finding(check_id=check_id, tier=tier, program="p", address="0x1",
                      function="F", claim=f"claim-{check_id}",
                      evidence=f"evidence-{check_id}")


def test_prompt_block_carries_tier1_only():
    block = fd._falsify_prompt_block([
        _finding("arity_contradiction", 1),
        _finding("return_contradiction", 2),
    ])
    assert "CONTRADICTIONS FOUND" in block
    assert "claim-arity_contradiction" in block
    assert "evidence-arity_contradiction" in block
    assert "claim-return_contradiction" not in block, \
        "tier-2 findings are report-only, never audit directives"
    assert "DISASSEMBLY IS THE AUTHORITY" in block


# ------------------------------------------------------- config plumbing ----

def test_falsify_enabled_defaults_on_in_config_and_snapshot():
    assert fd.DEFAULT_QUEUE_CONFIG["falsify_enabled"] is True
    snap = fd.build_worker_config_snapshot({"config": {}}, "minimax")
    assert snap["falsify_enabled"] is True
    snap_off = fd.build_worker_config_snapshot(
        {"config": {"falsify_enabled": False}}, "minimax")
    assert snap_off["falsify_enabled"] is False

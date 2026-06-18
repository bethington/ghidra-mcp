"""Regression tests for the globals worker (v5.7.x — Q1-Q12 design).

Covers:
  * `process_global` — pre-audit short-circuit, completed/no_change/regressed
    classification, runs.jsonl row shape with `mode="globals"`.
  * `run_globals_worker_pass` — count cap, continuous-mode binary rotation,
    stop_flag interruption.
  * `WorkerManager` mode dispatch — requires binary for globals, rejects
    a second launch on the same binary (per-binary lock, Q11).

Tests mock every Ghidra HTTP call and the provider invocation so they
run in the offline tier with no live server.
"""

from __future__ import annotations

import importlib
import json
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest


FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))

import fun_doc  # noqa: E402


# ---------- process_global ----------


def _stub_audit(issues):
    """Build the audit_global response shape the scorer expects."""
    return {
        "address": "ffd0",
        "name": "g_dwSomething",
        "type": "dword",
        "length": 4,
        "plate_comment": "summary",
        "xref_count": 3,
        "issues": list(issues),
        "fully_documented": not issues,
    }


@pytest.fixture
def isolated_run_log(tmp_path, monkeypatch):
    """Redirect _append_run_log to a tmp file so tests can inspect rows."""
    log_path = tmp_path / "runs.jsonl"

    def _writer(entry):
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    monkeypatch.setattr(fun_doc, "_append_run_log", _writer)
    yield log_path


def _read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def test_build_global_prompt_starts_with_program_mandatory_banner():
    """Regression for production bug: when multiple programs are open
    and the model omits `program=` on its tool calls, Ghidra routes
    writes to the wrong binary. The CRITICAL banner must be the first
    thing in the prompt and must include the exact program path so the
    model literally cannot miss it.

    Symptom this catches: worker reports `set_global → success`
    repeatedly but `audit_global` keeps reporting unchanged state on
    the target address — because the writes went to a different program."""
    prog_path = "/Mods/PD2-S12/Fog.dll"
    prompt = fun_doc._build_global_prompt(
        prog_path,
        "0x6ff82f48",
        {"name": "DAT_6ff82f48", "type": "undefined4", "issues": ["untyped"]},
    )
    # CRITICAL banner must be first non-empty line.
    first_chunk = prompt.lstrip().split("\n\n", 1)[0]
    assert "CRITICAL" in first_chunk, (
        "The CRITICAL program-mandatory banner must lead the prompt; "
        "it's the only thing keeping the model from omitting program= "
        "and routing writes to the wrong binary. First chunk was:\n" + first_chunk
    )
    # Banner must include the exact program path so the model can't
    # invent a shorter / mismatched value.
    assert prog_path in first_chunk, (
        f"Banner must explicitly name the program path '{prog_path}'."
    )
    # The banner must enumerate the writers that need program= — set_global,
    # apply_data_type, rename_or_label at minimum.
    for tool in ("set_global", "apply_data_type", "rename_or_label", "audit_global"):
        assert tool in prompt, f"Banner / prompt should mention `{tool}` so the model knows program= applies to it."


def test_process_global_uses_watchdog(monkeypatch):
    """H24: process_global must route provider calls through invoke_claude
    (→ _invoke_provider_with_watchdog), not _invoke_provider_direct.
    A wedged provider call must not stall the globals worker indefinitely.
    Matches the function-worker path that was already using the watchdog."""
    called = {"watchdog": 0, "direct": 0}

    def fake_watchdog(*a, **kw):
        called["watchdog"] += 1
        return ("ok", {"tool_calls": 0})

    def fake_direct(*a, **kw):
        called["direct"] += 1
        return ("ok", {"tool_calls": 0})

    monkeypatch.setattr(fun_doc, "_invoke_provider_with_watchdog", fake_watchdog)
    monkeypatch.setattr(fun_doc, "_invoke_provider_direct", fake_direct)
    # Stub everything else process_global touches.
    monkeypatch.setattr(
        fun_doc, "_audit_global_via_http",
        lambda *a, **kw: {"name": "g_x", "score": 0, "issues": ["missing_prefix"]},
        raising=False,
    )
    monkeypatch.setattr(fun_doc, "_build_global_prompt",
                        lambda *a, **kw: "PROMPT", raising=False)
    monkeypatch.setattr(fun_doc, "_append_run_log", lambda *a, **kw: None, raising=False)
    monkeypatch.setattr(fun_doc, "bus_emit", lambda *a, **kw: None, raising=False)

    fun_doc.process_global(
        "/proj/Foo.exe", "00401000",
        provider="test", model="test-model", max_turns=5,
        worker_id="w-test",
    )
    assert called["direct"] == 0, (
        "process_global still calls _invoke_provider_direct (no watchdog): "
        "a hung provider call can stall the globals worker indefinitely (H24)"
    )
    assert called["watchdog"] == 1, (
        "process_global must call _invoke_provider_with_watchdog exactly once per global"
    )


def test_process_global_skips_when_pre_audit_clean(isolated_run_log, monkeypatch):
    """Q8: a clean global short-circuits before invoking the provider —
    no provider call burned, runs.jsonl row tagged 'skipped'."""
    audits = iter([_stub_audit([])])  # pre-audit only
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: next(audits))

    invoked = {"called": False}
    def _bad(*a, **k):
        invoked["called"] = True
        raise AssertionError("provider should not be invoked for clean globals")
    monkeypatch.setattr(fun_doc, "invoke_claude", _bad)

    result = fun_doc.process_global(
        "/proj/A.dll", "0xffd0", provider="minimax", model="m1"
    )
    assert result == "skipped"
    assert not invoked["called"]
    rows = _read_jsonl(isolated_run_log)
    assert len(rows) == 1
    row = rows[0]
    assert row["mode"] == "globals"
    assert row["result"] == "skipped"
    assert row["reason"] == "already_clean"
    assert row["issues_before"] == []


def test_process_global_completed_when_post_audit_clean(isolated_run_log, monkeypatch):
    """Pre-audit has issues, provider runs, post-audit clean → completed."""
    audits = iter([
        _stub_audit(["untyped", "missing_plate_comment"]),  # pre
        _stub_audit([]),                                     # post
    ])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: next(audits))
    monkeypatch.setattr(
        fun_doc, "invoke_claude",
        lambda *a, **k: ("ok", {"tool_calls": 3, "tool_calls_known": True}),
    )

    result = fun_doc.process_global(
        "/proj/A.dll", "0xffd0", provider="minimax", model="m1"
    )
    assert result == "completed"
    row = _read_jsonl(isolated_run_log)[0]
    assert row["mode"] == "globals"
    assert row["result"] == "completed"
    assert row["fixed_count"] == 2
    assert row["issues_before"] == ["untyped", "missing_plate_comment"]
    assert row["issues_after"] == []
    assert row["tool_calls"] == 3


def test_process_global_no_change_when_provider_does_nothing(isolated_run_log, monkeypatch):
    """Provider runs but issue count stays the same → no_change."""
    audits = iter([
        _stub_audit(["untyped"]),
        _stub_audit(["untyped"]),
    ])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: next(audits))
    monkeypatch.setattr(
        fun_doc, "invoke_claude",
        lambda *a, **k: ("nope", {"tool_calls": 0, "tool_calls_known": True}),
    )
    result = fun_doc.process_global(
        "/proj/A.dll", "0xffd0", provider="minimax", model="m1"
    )
    assert result == "no_change"
    row = _read_jsonl(isolated_run_log)[0]
    assert row["fixed_count"] == 0


def test_process_global_blocked_on_quota_pause(isolated_run_log, monkeypatch):
    audits = iter([
        _stub_audit(["untyped"]),
        _stub_audit(["untyped"]),
    ])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: next(audits))
    monkeypatch.setattr(
        fun_doc, "invoke_claude",
        lambda *a, **k: (None, {
            "tool_calls": 0, "tool_calls_known": True,
            "quota_paused": True, "quota_paused_until": "2030-01-01T00:00:00",
            "quota_paused_reason": "rate limited",
        }),
    )
    result = fun_doc.process_global(
        "/proj/A.dll", "0xffd0", provider="minimax", model="m1"
    )
    assert result == "blocked"
    row = _read_jsonl(isolated_run_log)[0]
    assert row["result"] == "blocked"
    assert row["quota_paused"] is True


def test_process_global_resolves_model_from_dashboard_config(
    isolated_run_log, monkeypatch
):
    """Regression: when the dashboard hands `model=None` (the default if
    no override), `process_global` must look up the configured FULL-mode
    model for the provider rather than passing None straight through —
    otherwise `_invoke_provider_direct` raises 'No model configured for
    provider'. This was the production bug seen by the user when MiniMax
    had no explicit model in the launch payload."""
    audits = iter([_stub_audit(["untyped"]), _stub_audit([])])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: next(audits))
    # Pretend the dashboard config has a configured FULL model for minimax.
    monkeypatch.setattr(
        fun_doc, "get_configured_model",
        lambda provider, mode: "MiniMax-M2.7" if (provider == "minimax" and mode == "FULL") else None,
    )
    captured = {}
    def _fake_provider(prompt, *, model=None, max_turns=None, provider=None, complexity_tier=None):
        captured["model"] = model
        captured["provider"] = provider
        return ("ok", {"tool_calls": 1, "tool_calls_known": True})
    monkeypatch.setattr(fun_doc, "invoke_claude", _fake_provider)

    result = fun_doc.process_global(
        "/proj/A.dll", "0xffd0", provider="minimax", model=None
    )
    assert result == "completed"
    assert captured["model"] == "MiniMax-M2.7", (
        "process_global should have resolved the configured FULL-mode model "
        "for minimax instead of passing None to invoke_claude"
    )


def test_process_global_skips_function_label_by_name(isolated_run_log, monkeypatch):
    """Regression: addresses labeled as `FID_conflict:*`, `FUN_*`, `thunk_*`
    etc. are function entries / library helpers that slipped into
    /list_globals. Worker must skip without a provider call (the model
    just wastes turns confirming-and-skipping)."""
    audit = {
        "name": "FID_conflict:__time32",
        "type": "",
        "issues": ["untyped", "missing_plate_comment"],
    }
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: audit)
    monkeypatch.setattr(fun_doc, "invoke_claude",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("not invoked")))
    result = fun_doc.process_global(
        "/proj/A.dll", "0x6fc2287c", provider="minimax", model="m1"
    )
    assert result == "skipped"
    row = _read_jsonl(isolated_run_log)[0]
    assert row["reason"] == "function_label"


def test_process_global_skips_when_audit_says_code_address(
    isolated_run_log, monkeypatch
):
    """Post-Java-redeploy path: audit_global returns is_code_address=true
    for any address with an instruction at it. Worker honors that flag
    and skips even when the symbol name doesn't match the function-label
    prefixes (e.g., a user-renamed function entry that lost the FUN_ prefix
    but still sits on code)."""
    audit = {
        "name": "MyCustomHelper",
        "type": "",
        "issues": ["untyped"],
        "is_code_address": True,
    }
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: audit)
    monkeypatch.setattr(fun_doc, "invoke_claude",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("not invoked")))
    result = fun_doc.process_global(
        "/proj/A.dll", "0x6fc2287c", provider="minimax", model="m1"
    )
    assert result == "skipped"
    row = _read_jsonl(isolated_run_log)[0]
    assert row["reason"] == "function_label"


def test_looks_like_function_label_recognizes_known_prefixes():
    """Pure-rule test for the symbol-name predicate."""
    assert fun_doc._looks_like_function_label("FID_conflict:__time32")
    assert fun_doc._looks_like_function_label("FID_conflict:_lock_file2")
    assert fun_doc._looks_like_function_label("FID_VsnprintfHelper")
    assert fun_doc._looks_like_function_label("FUN_6fc2287c")
    assert fun_doc._looks_like_function_label("thunk_FUN_6fd1458a")
    assert fun_doc._looks_like_function_label("j_atexit")
    assert fun_doc._looks_like_function_label("__imp_HeapAlloc")
    # Not function labels — should pass through.
    assert not fun_doc._looks_like_function_label("g_dwActiveQuestState")
    assert not fun_doc._looks_like_function_label("ExceptionList")
    assert not fun_doc._looks_like_function_label("DAT_6fdf64d8")
    assert not fun_doc._looks_like_function_label("")
    assert not fun_doc._looks_like_function_label(None)


def test_process_global_skips_os_canonical_label_by_name(isolated_run_log, monkeypatch):
    """OS-canonical labels (TIB/PEB/KUSER members) must short-circuit
    before invoking the provider — the audit flags them as missing g_
    prefix today, but renaming them to g_* form is wrong (Microsoft's
    name is canonical). Skipping at the worker pre-filter avoids paying
    for a provider call that just confirms 'yes, OS label, skipping'."""
    audit = {
        "name": "ExceptionList",
        "type": "void *32",
        "issues": ["name_missing_g_prefix"],
    }
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: audit)
    invoked = {"called": False}
    def _bad(*a, **k):
        invoked["called"] = True
        raise AssertionError("provider must not be invoked for OS-canonical labels")
    monkeypatch.setattr(fun_doc, "invoke_claude", _bad)

    result = fun_doc.process_global(
        "/proj/A.dll", "0xffdff000", provider="minimax", model="m1"
    )
    assert result == "skipped"
    assert not invoked["called"]
    row = _read_jsonl(isolated_run_log)[0]
    assert row["reason"] == "os_canonical_label"


def test_process_global_skips_os_address_range_even_with_unknown_name(
    isolated_run_log, monkeypatch
):
    """Unknown name in the TIB range (0xffdf0000-0xffdfffff) still gets
    skipped — the address range is enough by itself. User-set names in
    the PEB range are rare; skipping a real one is much cheaper than
    re-renaming an OS field."""
    audit = {"name": "Unknown_TibField", "type": "uint", "issues": ["name_missing_g_prefix"]}
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: audit)
    monkeypatch.setattr(fun_doc, "invoke_claude",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("not invoked")))
    result = fun_doc.process_global(
        "/proj/A.dll", "0xffdff100", provider="minimax", model="m1"
    )
    assert result == "skipped"


def test_process_global_completed_when_only_soft_issues_remain(
    isolated_run_log, monkeypatch
):
    """Regression for design Q1=A: soft issues like `generic_descriptor`
    don't block `completed`. The audit returns `severity_summary` with
    blocking (hard+medium) and non-blocking (soft) counts; the worker
    treats blocking==0 as completion regardless of soft remainders."""
    audits = iter([
        # Pre: hard untyped + soft generic_descriptor
        {
            "name": "g_pData",
            "type": "",
            "issues": ["untyped", "generic_descriptor"],
            "severity_summary": {"hard": 1, "medium": 0, "soft": 1},
        },
        # Post: hard fixed (typed), only soft remains
        {
            "name": "g_pData",
            "type": "void *",
            "issues": ["generic_descriptor"],
            "severity_summary": {"hard": 0, "medium": 0, "soft": 1},
        },
    ])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: next(audits))
    monkeypatch.setattr(fun_doc, "invoke_claude",
                        lambda *a, **k: ("ok", {"tool_calls": 1, "tool_calls_known": True}))

    result = fun_doc.process_global(
        "/proj/A.dll", "0x1000", provider="minimax", model="m1"
    )
    assert result == "completed"


def test_process_global_blocked_progress_uses_severity_when_present(
    isolated_run_log, monkeypatch
):
    """When severity_summary is present, the improved/regressed/no_change
    classification compares blocking counts (hard+medium), not raw issue
    counts. A run that fixes 1 hard issue but introduces 2 soft ones
    should classify as `improved` (blocking went down), not `regressed`
    (raw count went up)."""
    audits = iter([
        # Pre: 2 hard issues
        {
            "name": "g_pData",
            "type": "",
            "issues": ["untyped", "missing_plate_comment"],
            "severity_summary": {"hard": 2, "medium": 0, "soft": 0},
        },
        # Post: 1 hard fixed, 2 softs added
        {
            "name": "g_pData",
            "type": "void *",
            "issues": ["missing_plate_comment", "generic_descriptor", "bytes_size_unknown"],
            "severity_summary": {"hard": 1, "medium": 0, "soft": 2},
        },
    ])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: next(audits))
    monkeypatch.setattr(fun_doc, "invoke_claude",
                        lambda *a, **k: ("ok", {"tool_calls": 1, "tool_calls_known": True}))

    result = fun_doc.process_global(
        "/proj/A.dll", "0x1000", provider="minimax", model="m1"
    )
    assert result == "improved"


def test_process_global_falls_back_to_count_when_no_severity_summary(
    isolated_run_log, monkeypatch
):
    """When the deployed Ghidra plugin is older and doesn't return
    severity_summary, the worker falls back to legacy issue-count
    classification — preserves backward compatibility during rolling
    plugin upgrades."""
    audits = iter([
        # No severity_summary in either response (old plugin shape)
        {"name": "g_pData", "type": "", "issues": ["untyped"]},
        {"name": "g_pData", "type": "void *", "issues": []},
    ])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: next(audits))
    monkeypatch.setattr(fun_doc, "invoke_claude",
                        lambda *a, **k: ("ok", {"tool_calls": 1, "tool_calls_known": True}))

    result = fun_doc.process_global(
        "/proj/A.dll", "0x1000", provider="minimax", model="m1"
    )
    assert result == "completed"


def test_process_global_lateral_change_when_issue_set_differs(
    isolated_run_log, monkeypatch
):
    """Same issue count but different issue content used to be reported
    as 'no_change' — masking real provider work that fixed one thing
    and introduced another. Should now classify as 'lateral_change'."""
    audits = iter([
        {"name": "FooBar", "type": "uint", "issues": ["name_missing_g_prefix"]},
        {"name": "g_dwFoo", "type": "byte", "issues": ["prefix_type_mismatch"]},
    ])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: next(audits))
    monkeypatch.setattr(fun_doc, "invoke_claude",
                        lambda *a, **k: ("ok", {"tool_calls": 2, "tool_calls_known": True}))

    result = fun_doc.process_global(
        "/proj/A.dll", "0x1000", provider="minimax", model="m1"
    )
    assert result == "lateral_change"


def test_process_global_no_change_only_when_issue_set_matches(
    isolated_run_log, monkeypatch
):
    """Identical issue lists → real no_change. Order-insensitive (both
    sides sorted before compare)."""
    audits = iter([
        {"name": "FooBar", "type": "uint", "issues": ["a", "b", "c"]},
        {"name": "FooBar", "type": "uint", "issues": ["c", "b", "a"]},  # reordered
    ])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: next(audits))
    monkeypatch.setattr(fun_doc, "invoke_claude",
                        lambda *a, **k: ("ok", {"tool_calls": 0, "tool_calls_known": True}))

    result = fun_doc.process_global(
        "/proj/A.dll", "0x1000", provider="minimax", model="m1"
    )
    assert result == "no_change"


def test_process_global_pre_audit_failure(isolated_run_log, monkeypatch):
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", lambda *a, **k: None)
    monkeypatch.setattr(fun_doc, "invoke_claude", lambda *a, **k: ("x", {}))
    result = fun_doc.process_global(
        "/proj/A.dll", "0xffd0", provider="minimax", model="m1"
    )
    assert result == "audit_fail"
    row = _read_jsonl(isolated_run_log)[0]
    assert row["error"] == "audit_global returned None (pre)"


# ---------- run_globals_worker_pass ----------


def test_run_globals_worker_pass_respects_count_cap(isolated_run_log, monkeypatch):
    """count=2 caps non-skipped processed work, even if more issues remain."""
    addresses = [f"0x{i:04x}" for i in range(10)]
    monkeypatch.setattr(fun_doc, "_list_global_addresses", lambda p: addresses)
    monkeypatch.setattr(fun_doc, "_invalidate_global_inventory", lambda p: None)
    # Every global has issues; provider always succeeds.
    audits_per_call = {"i": 0}
    def _audit(prog, addr):
        # Alternate pre / post: pre returns issues, post returns clean
        # (so each tick is a "completed", not a "skipped")
        n = audits_per_call["i"]
        audits_per_call["i"] += 1
        return _stub_audit([] if n % 2 == 1 else ["untyped"])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", _audit)
    monkeypatch.setattr(
        fun_doc, "invoke_claude",
        lambda *a, **k: ("ok", {"tool_calls": 1, "tool_calls_known": True}),
    )

    summary = fun_doc.run_globals_worker_pass(
        worker_id="w1",
        initial_binary="/proj/A.dll",
        provider="minimax",
        model="m1",
        count=2,
        continuous=False,
        stop_flag=threading.Event(),
    )
    assert summary["processed"] == 2
    assert summary["totals"]["completed"] == 2
    assert summary["binaries_visited"] == ["/proj/A.dll"]


def test_run_globals_worker_pass_skipped_globals_dont_count(isolated_run_log, monkeypatch):
    """Pre-audit clean globals don't burn the count budget — worker keeps
    going past them until it hits N actual fixes (or runs out of globals)."""
    addresses = [f"0x{i:04x}" for i in range(10)]
    monkeypatch.setattr(fun_doc, "_list_global_addresses", lambda p: addresses)
    monkeypatch.setattr(fun_doc, "_invalidate_global_inventory", lambda p: None)
    # First 5 globals are clean (skip), next ones have issues + get fixed.
    state = {"audit_idx": 0, "post_pending": False}
    def _audit(prog, addr):
        if state["post_pending"]:
            state["post_pending"] = False
            return _stub_audit([])  # post: cleaned up
        idx = state["audit_idx"]
        state["audit_idx"] += 1
        if idx < 5:
            return _stub_audit([])  # pre: already clean → skip
        state["post_pending"] = True
        return _stub_audit(["untyped"])  # pre: needs work
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", _audit)
    monkeypatch.setattr(
        fun_doc, "invoke_claude",
        lambda *a, **k: ("ok", {"tool_calls": 1, "tool_calls_known": True}),
    )

    summary = fun_doc.run_globals_worker_pass(
        worker_id="w2",
        initial_binary="/proj/A.dll",
        provider="minimax",
        model="m1",
        count=3,
        continuous=False,
        stop_flag=threading.Event(),
    )
    assert summary["processed"] == 3
    assert summary["totals"]["completed"] == 3
    assert summary["totals"]["skipped"] == 5


def test_run_globals_worker_pass_stop_flag_interrupts(isolated_run_log, monkeypatch):
    addresses = [f"0x{i:04x}" for i in range(20)]
    monkeypatch.setattr(fun_doc, "_list_global_addresses", lambda p: addresses)
    monkeypatch.setattr(fun_doc, "_invalidate_global_inventory", lambda p: None)
    stop_flag = threading.Event()
    state = {"i": 0}
    def _audit(prog, addr):
        if state["i"] >= 4:
            stop_flag.set()
        state["i"] += 1
        return _stub_audit(["untyped"])  # always has issues so never short-circuits
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", _audit)
    monkeypatch.setattr(
        fun_doc, "invoke_claude",
        lambda *a, **k: ("ok", {"tool_calls": 1, "tool_calls_known": True}),
    )
    summary = fun_doc.run_globals_worker_pass(
        worker_id="w3",
        initial_binary="/proj/A.dll",
        provider="minimax",
        model="m1",
        count=100,
        continuous=False,
        stop_flag=stop_flag,
    )
    assert summary["stopped"] is True
    assert summary["stopped_reason"] == "user_stop"


def test_run_globals_worker_pass_continuous_ignores_count_cap(
    isolated_run_log, monkeypatch
):
    """Auto/continuous mode keeps processing past `count` until the binary
    is drained — mirrors the function-worker semantic at web.py:619-621
    (`worker["continuous"] or processed < worker["count"]`).

    Regression test for the bug where the dashboard's "Auto" toggle on the
    globals worker stopped after `count` (default 10) iterations instead of
    running unbounded until the binary was complete.
    """
    addresses = [f"0x{i:04x}" for i in range(25)]
    monkeypatch.setattr(fun_doc, "_list_global_addresses", lambda p: addresses)
    monkeypatch.setattr(fun_doc, "_invalidate_global_inventory", lambda p: None)
    # No follow-on binary — return None so continuous mode exits naturally
    # after the single binary is exhausted (lets the assertion reach the
    # "exhausted" reason rather than hopping to a second binary).
    monkeypatch.setattr(fun_doc, "_pick_next_globals_binary", lambda *a, **k: None)
    monkeypatch.setattr(
        fun_doc, "_fetch_programs",
        lambda *a, **k: [{"path": "/proj/A.dll", "name": "A.dll"}],
    )
    monkeypatch.setattr(fun_doc, "load_state", lambda: {"project_folder": "/proj"})

    audits_per_call = {"i": 0}
    def _audit(prog, addr):
        n = audits_per_call["i"]
        audits_per_call["i"] += 1
        return _stub_audit([] if n % 2 == 1 else ["untyped"])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", _audit)
    monkeypatch.setattr(
        fun_doc, "invoke_claude",
        lambda *a, **k: ("ok", {"tool_calls": 1, "tool_calls_known": True}),
    )

    summary = fun_doc.run_globals_worker_pass(
        worker_id="auto1",
        initial_binary="/proj/A.dll",
        provider="minimax",
        model="m1",
        count=2,           # Deliberately small — pre-fix this stopped at 2.
        continuous=True,   # Auto mode — should bypass the cap.
        stop_flag=threading.Event(),
    )
    # All 25 addresses should have been processed (continuous=True ignores
    # the count cap; the binary drains naturally).
    assert summary["processed"] == 25, (
        f"Expected continuous mode to process all 25 globals, got "
        f"{summary['processed']} (count cap was 2)"
    )
    assert summary["totals"]["completed"] == 25
    # Continuous mode drains the binary then asks `_pick_next_globals_binary`
    # for another; our mock returns None, so the loop sets "no_more_binaries".
    assert summary["stopped_reason"] == "no_more_binaries"


def test_run_globals_worker_pass_continuous_advances_to_next_binary(
    isolated_run_log, monkeypatch
):
    """Auto mode should also rotate to the next most-needy binary once the
    current one is drained (continuous-mode rotation, separate from the
    count-cap bypass)."""
    addresses_by_binary = {
        "/proj/A.dll": ["0x0001", "0x0002"],
        "/proj/B.dll": ["0x1001", "0x1002", "0x1003"],
    }
    monkeypatch.setattr(
        fun_doc, "_list_global_addresses",
        lambda p: addresses_by_binary.get(p, []),
    )
    monkeypatch.setattr(fun_doc, "_invalidate_global_inventory", lambda p: None)

    # First call after A.dll drains → B.dll. Second call → None (stop).
    rotation = iter(["/proj/B.dll", None])
    monkeypatch.setattr(
        fun_doc, "_pick_next_globals_binary", lambda *a, **k: next(rotation, None)
    )
    monkeypatch.setattr(fun_doc, "_fetch_programs", lambda *a, **k: [])
    monkeypatch.setattr(fun_doc, "load_state", lambda: {"project_folder": "/proj"})

    audits_per_call = {"i": 0}
    def _audit(prog, addr):
        n = audits_per_call["i"]
        audits_per_call["i"] += 1
        return _stub_audit([] if n % 2 == 1 else ["untyped"])
    monkeypatch.setattr(fun_doc, "_audit_global_via_http", _audit)
    monkeypatch.setattr(
        fun_doc, "invoke_claude",
        lambda *a, **k: ("ok", {"tool_calls": 1, "tool_calls_known": True}),
    )

    summary = fun_doc.run_globals_worker_pass(
        worker_id="auto2",
        initial_binary="/proj/A.dll",
        provider="minimax",
        model="m1",
        count=1,           # Tiny cap — proves continuous bypass.
        continuous=True,
        stop_flag=threading.Event(),
    )
    assert summary["processed"] == 5  # 2 from A + 3 from B
    assert summary["binaries_visited"] == ["/proj/A.dll", "/proj/B.dll"]
    # Continuous mode drains the binary then asks `_pick_next_globals_binary`
    # for another; our mock returns None, so the loop sets "no_more_binaries".
    assert summary["stopped_reason"] == "no_more_binaries"


# ---------- WorkerManager mode dispatch + per-binary lock ----------


def _make_mgr():
    """Build a WorkerManager wired to mocks (mirrors test_worker_watchdog)."""
    import web

    bus = MagicMock()
    socketio = MagicMock()
    load_queue = MagicMock(return_value={"config": {}, "meta": {}})
    save_queue = MagicMock()
    mgr = web.WorkerManager(
        state_file=Path("/tmp/none.json"),
        bus=bus,
        socketio=socketio,
        load_queue=load_queue,
        save_queue=save_queue,
    )
    return mgr


def test_workermanager_globals_requires_binary(monkeypatch):
    mgr = _make_mgr()
    with pytest.raises(ValueError, match="requires a binary"):
        mgr.start_worker(
            provider="minimax", count=1, binary=None, mode="globals"
        )


def test_workermanager_globals_per_binary_lock(monkeypatch):
    """Q11: a second launch on the same binary is rejected with a clear
    error rather than silently fighting the first worker for writes."""
    mgr = _make_mgr()
    # Manually mark the binary as held — equivalent to a worker starting
    # on it and not yet finishing.
    mgr._globals_active_binaries.add("/proj/A.dll")

    with pytest.raises(ValueError, match="already running on /proj/A.dll"):
        mgr.start_worker(
            provider="minimax", count=1, binary="/proj/A.dll", mode="globals"
        )

    # Different binary launches fine — only the per-binary path is locked,
    # not the worker pool. (Skip thread spawn by patching out the run.)
    monkeypatch.setattr(mgr, "_run_worker", lambda wid: None)
    wid = mgr.start_worker(
        provider="minimax", count=1, binary="/proj/B.dll", mode="globals"
    )
    assert wid is not None
    assert "/proj/B.dll" in mgr._globals_active_binaries


def test_minimax_allowlist_includes_globals_tools():
    """Regression: the MiniMax provider filters Ghidra's full tool set
    against `_MINIMAX_DOC_TOOL_ALLOWLIST` before exposing them to the
    model. Production hit "Unknown tool: set_global" because the
    globals-specific tools weren't in the allowlist — the model had to
    fight `apply_data_type` + `rename_or_label` + `batch_set_comments`
    individually, burning ~10 wasted calls + getting confused by
    `set_plate_comment` (which is function-only). Locking these in so a
    future allowlist edit can't silently regress globals work."""
    required = {
        "set_global",
        "audit_global",
        "audit_globals_in_function",
    }
    missing = required - fun_doc._MINIMAX_DOC_TOOL_ALLOWLIST
    assert not missing, (
        f"MiniMax allowlist is missing globals tools: {missing}. "
        "Without these, the globals worker can't use the canonical writer "
        "and falls back to a multi-tool fight that often fails."
    )


def test_workermanager_function_worker_unaffected_by_globals_lock(monkeypatch):
    """Sanity check: holding a globals lock on a binary doesn't block a
    function worker from also running on that binary."""
    mgr = _make_mgr()
    mgr._globals_active_binaries.add("/proj/A.dll")
    monkeypatch.setattr(mgr, "_run_worker", lambda wid: None)

    wid = mgr.start_worker(
        provider="minimax", count=1, binary="/proj/A.dll", mode="functions"
    )
    assert wid is not None

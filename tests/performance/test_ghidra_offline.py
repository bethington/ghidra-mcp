"""
Regression tests: worker must NOT invoke AI models when Ghidra is offline.

These tests mock the HTTP layer so no real Ghidra instance is needed.
"""

import sys
import threading
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

FUN_DOC = Path(__file__).parent.parent.parent / "fun-doc"
sys.path.insert(0, str(FUN_DOC))

import requests  # noqa: E402 — needed for exception types

import fun_doc  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_OFFLINE_FUNC = {
    "address": "6fcee520",
    "program": "/Mods/PD2-S12/D2Common.dll",
    "name": "GetSkillManaCost_9d00",
    "program_name": "D2Common.dll",
    "score": 60,
    "deductions": [],
    "consecutive_fails": 0,
}


def _make_offline_requests_get(*args, **kwargs):
    """Simulate Ghidra being fully offline (connection refused)."""
    raise requests.exceptions.ConnectionError(
        "HTTPConnectionPool: Max retries exceeded (Errno 10061 Connection refused)"
    )


# ---------------------------------------------------------------------------
# Unit: ghidra_get marks the offline flag on ConnectionError
# ---------------------------------------------------------------------------


def test_ghidra_get_marks_offline_on_connection_error():
    with patch("fun_doc.requests.get", side_effect=_make_offline_requests_get):
        result = fun_doc.ghidra_get("/decompile_function")
    assert result is None
    assert fun_doc.ghidra_last_call_offline() is True
    assert fun_doc.ghidra_last_call_timed_out() is False


def test_ghidra_post_marks_offline_on_connection_error():
    with patch(
        "fun_doc.requests.post",
        side_effect=requests.exceptions.ConnectionError("refused"),
    ):
        result = fun_doc.ghidra_post("/some_endpoint", data={})
    assert result is None
    assert fun_doc.ghidra_last_call_offline() is True


def test_ghidra_get_does_not_mark_offline_on_timeout():
    with patch(
        "fun_doc.requests.get",
        side_effect=requests.exceptions.ReadTimeout("timed out"),
    ):
        result = fun_doc.ghidra_get("/decompile_function")
    assert result is None
    assert fun_doc.ghidra_last_call_timed_out() is True
    assert fun_doc.ghidra_last_call_offline() is False


# ---------------------------------------------------------------------------
# Unit: fetch_function_data returns ghidra_offline=True when server is down
# ---------------------------------------------------------------------------


def test_fetch_function_data_returns_offline_flag():
    with patch("fun_doc.requests.get", side_effect=_make_offline_requests_get):
        data = fun_doc.fetch_function_data(
            "/Mods/PD2-S12/D2Common.dll", "6fcee520", mode="FULL"
        )
    assert data["ghidra_offline"] is True
    assert data["decompile_timeout"] is False
    assert data["decompiled"] is None
    assert data["completeness"] is None


# ---------------------------------------------------------------------------
# Unit: fetch_function_data detects "not a function" (data address) when
# Ghidra is online but both /decompile_function and
# /analyze_function_completeness come back with no usable result. Without
# this signal the worker burns 100K-500K input tokens on the LLM
# confirming "this address is data, not code." Observed in production:
# 21 archive_applied loops on 0x10101014 in BH.dll in one hour.
# ---------------------------------------------------------------------------


def _mock_ghidra_response(json_payload):
    """Mock helper: return a MagicMock response that .json() to the payload."""
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = json_payload
    # ghidra_get also inspects .text for the "Error" string-shape fallback
    m.text = json.dumps(json_payload) if isinstance(json_payload, dict) else str(json_payload)
    return m


def test_fetch_function_data_marks_not_a_function_when_data_address():
    """When the address is raw data (no function body, no name), both
    Ghidra endpoints return error-shaped responses and fetch_function_data
    must set not_a_function=True so the caller can flag the function
    once-and-done. The dual-signal check (decompile error + completeness
    missing function_name) keeps false positives down — a transient
    decompile failure on a real function would still have a function_name
    in completeness and is therefore not marked."""

    def fake_get(url, *args, **kwargs):
        if "/decompile_function" in url:
            return _mock_ghidra_response({"error": "No function found at 0x10101014"})
        if "/analyze_function_completeness" in url:
            return _mock_ghidra_response({"error": "No function at 0x10101014"})
        # variables / analyze_for_doc — irrelevant for the gate
        return _mock_ghidra_response({})

    with patch("fun_doc.requests.get", side_effect=fake_get):
        data = fun_doc.fetch_function_data(
            "/Mods/PD2-S12/BH.dll", "10101014", mode="FIX"
        )

    assert data["not_a_function"] is True
    assert data["ghidra_offline"] is False
    assert data["decompile_timeout"] is False


def test_fetch_function_data_does_not_mark_not_a_function_when_decompile_succeeds():
    """Sanity: if /decompile_function returns a real body, not_a_function
    must stay False even if completeness scoring happens to fail. A real
    function with a temporarily broken scorer is a retryable condition,
    not a permanent blacklist."""

    def fake_get(url, *args, **kwargs):
        if "/decompile_function" in url:
            return _mock_ghidra_response({"decompiled": "void FUN_x() { return; }"})
        if "/analyze_function_completeness" in url:
            return _mock_ghidra_response({"error": "scorer hiccup"})
        return _mock_ghidra_response({})

    with patch("fun_doc.requests.get", side_effect=fake_get):
        data = fun_doc.fetch_function_data(
            "/Mods/PD2-S12/BH.dll", "10001000", mode="FIX"
        )

    assert data["not_a_function"] is False


def test_fetch_function_data_does_not_mark_not_a_function_when_completeness_has_name():
    """Sanity: completeness reporting a function_name even with no
    decompiled body means Ghidra knows the function exists — keep it
    retryable, don't blacklist."""

    def fake_get(url, *args, **kwargs):
        if "/decompile_function" in url:
            return _mock_ghidra_response({"error": "decompile transient"})
        if "/analyze_function_completeness" in url:
            return _mock_ghidra_response({
                "function_name": "RealFunc",
                "effective_score": 40,
                "deduction_breakdown": [],
            })
        return _mock_ghidra_response({})

    with patch("fun_doc.requests.get", side_effect=fake_get):
        data = fun_doc.fetch_function_data(
            "/Mods/PD2-S12/BH.dll", "10001000", mode="FIX"
        )

    assert data["not_a_function"] is False


def test_fetch_function_data_does_not_mark_not_a_function_when_offline():
    """The offline path short-circuits BEFORE the not_a_function gate.
    Offline is retryable; not_a_function is a one-shot blacklist —
    confusing the two would permanently exclude functions during a
    transient Ghidra outage."""
    with patch("fun_doc.requests.get", side_effect=_make_offline_requests_get):
        data = fun_doc.fetch_function_data(
            "/Mods/PD2-S12/BH.dll", "10001000", mode="FIX"
        )
    assert data["ghidra_offline"] is True
    assert data["not_a_function"] is False


# ---------------------------------------------------------------------------
# Unit: check_ghidra_online returns False when server is down
# ---------------------------------------------------------------------------


def test_check_ghidra_online_returns_false_when_offline():
    with patch("fun_doc.requests.get", side_effect=_make_offline_requests_get):
        assert fun_doc.check_ghidra_online() is False


def test_check_ghidra_online_returns_true_when_reachable():
    mock_response = MagicMock()
    mock_response.status_code = 200
    with patch("fun_doc.requests.get", return_value=mock_response):
        assert fun_doc.check_ghidra_online() is True


# ---------------------------------------------------------------------------
# Integration: process_function returns "ghidra_offline" without calling the model
# ---------------------------------------------------------------------------


def test_process_function_skips_model_when_ghidra_offline(monkeypatch, tmp_path):
    """process_function must return the distinct 'ghidra_offline' result and never
    reach the model when Ghidra is unreachable. It must NOT park the function
    (no sticky last_result) so the selector re-picks it once Ghidra recovers; the
    distinct result lets the worker loop back off instead of churning the queue."""
    state = {"functions": {}}
    func = dict(_OFFLINE_FUNC)
    func_key = f"{func['program']}::{func['address']}"
    state["functions"][func_key] = func

    model_invoked = []
    log_file = tmp_path / "runs.jsonl"
    monkeypatch.setattr(fun_doc, "LOG_DIR", tmp_path)
    monkeypatch.setattr(fun_doc, "LOG_FILE", log_file)

    def _fake_invoke(*args, **kwargs):
        model_invoked.append(True)
        return "should not be called"

    offline_events = []

    def _capture_event(event, **fields):
        if event == "ghidra.offline":
            offline_events.append(fields)

    with (
        patch("fun_doc.requests.get", side_effect=_make_offline_requests_get),
        patch("fun_doc.update_function_state", return_value=None),
        patch("fun_doc.bus_emit", return_value=None),
        patch("event_log.log_event", side_effect=_capture_event),
        patch("fun_doc._invoke_minimax", side_effect=_fake_invoke),
        patch("fun_doc.invoke_claude", side_effect=_fake_invoke),
        patch("fun_doc.try_launch_ghidra", return_value=False),
    ):
        result = fun_doc.process_function(func_key, func, state)

    assert result == "ghidra_offline", f"Expected 'ghidra_offline', got {result!r}"
    assert not model_invoked, "Model was invoked despite Ghidra being offline"
    # Must NOT park the function: leaving last_result unset keeps it re-pickable so
    # it is retried automatically once Ghidra recovers (no manual refresh needed).
    assert func.get("last_result") != "ghidra_offline", (
        "function was parked as ghidra_offline; it should be left re-pickable"
    )
    # An infra outage must NOT write a heavyweight run-log row — during a long
    # outage that would flood runs.jsonl with hundreds of identical rows per
    # function. The row is skipped; a single lightweight ghidra.offline event
    # carries the audit trail instead.
    assert not log_file.exists() or log_file.read_text(encoding="utf-8").strip() == "", (
        "ghidra_offline must not append a run-log row"
    )
    assert offline_events, "expected a lightweight ghidra.offline event to be emitted"
    assert offline_events[0].get("reason") == (
        f"server not reachable at {fun_doc.GHIDRA_URL}"
    )
    assert offline_events[0].get("address") == func["address"]


def test_process_function_resumes_after_ghidra_comes_online():
    """When auto-launch succeeds and Ghidra comes back, processing should
    continue normally (not bail early)."""
    state = {"functions": {}}
    func = dict(_OFFLINE_FUNC)
    func_key = f"{func['program']}::{func['address']}"
    state["functions"][func_key] = func

    # First check_ghidra_online call returns False (offline), second returns True (online)
    online_toggle = iter([False, True])

    def _toggling_online():
        try:
            return next(online_toggle)
        except StopIteration:
            return True

    # After "launch", pretend model completes successfully
    def _fake_process_inner(*args, **kwargs):
        return "completed"

    with (
        patch("fun_doc.check_ghidra_online", side_effect=_toggling_online),
        patch("fun_doc.try_launch_ghidra", return_value=True),
        patch("fun_doc.wait_for_ghidra", return_value=True),
        # Stub out the rest so we don't need a real Ghidra
        patch(
            "fun_doc.fetch_function_data",
            return_value={
                "decompiled": "int FUN_6fcee520(void) { return 0; }",
                "completeness": {
                    "effective_score": 80,
                    "has_plate_comment": True,
                    "has_custom_name": True,
                    "fixable_deductions": 0,
                    "deduction_breakdown": [],
                },
                "variables": [],
                "analyze_for_doc": None,
                "score": 80,
                "deductions": [],
                "fixable_categories": [],
                "decompile_timeout": False,
                "ghidra_offline": False,
            },
        ),
        patch("fun_doc.update_function_state", return_value=None),
        patch("fun_doc.bus_emit", return_value=None),
        patch(
            "fun_doc.load_priority_queue",
            return_value={
                "config": {
                    "good_enough_score": 90,
                    "provider_models": {
                        "minimax": {
                            "FULL": "MiniMax-M2.7",
                            "FIX": "MiniMax-M2.7",
                            "VERIFY": "MiniMax-M2.7",
                        }
                    },
                },
                "pinned": [],
            },
        ),
    ):
        # process_function will get past the pre-flight and hit select_model,
        # which will raise ValueError because no invocation path is fully
        # stubbed — that's fine; the key assertion is that we didn't bail
        # at the Ghidra-offline gate.
        try:
            fun_doc.process_function(func_key, func, state)
        except (ValueError, Exception):
            pass
        # As long as last_result is NOT 'ghidra_offline' the gate did not fire
        assert (
            func.get("last_result") != "ghidra_offline"
        ), "process_function bailed at offline gate even after Ghidra came online"

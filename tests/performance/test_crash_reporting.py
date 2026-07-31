"""D2 fault reporting.

Built 2026-07-31 after an "UNHANDLED EXCEPTION: ACCESS_VIOLATION (c0000005)"
box sat on screen while every health probe read green, and the existing
dismisser -- which required the word "error" -- could not match a dialog titled
"Diablo II Exception".
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "fun-doc"))

import oracle_health as oh


CRASH = {
    "origin": "unhandled_filter", "code": "0xC0000005",
    "codeName": "ACCESS_VIOLATION", "module": "D2Common.dll",
    "rva": "0x0001A2B4", "address": "0x6FD6A2B4",
    "proving": "DATATBLS_GetLevelRecordBitfield06",
}


def test_fetch_crash_consumes_by_default(monkeypatch):
    """Each crash must report exactly once, however often we poll."""
    seen = {}
    def fake_get(path, timeout=10.0):
        seen["path"] = path
        return {"ok": True, "firstChanceFatal": 2, "crash": CRASH}
    monkeypatch.setattr(oh, "_oracle_get", fake_get)
    assert oh._fetch_crash()["module"] == "D2Common.dll"
    assert "consume=1" in seen["path"]


def test_fetch_crash_none_when_clean(monkeypatch):
    monkeypatch.setattr(oh, "_oracle_get",
                        lambda p, timeout=10.0: {"ok": True, "crash": None})
    assert oh._fetch_crash() is None


def test_fetch_crash_survives_an_unreachable_oracle(monkeypatch):
    def boom(p, timeout=10.0): raise OSError("connection refused")
    monkeypatch.setattr(oh, "_oracle_get", boom)
    assert oh._fetch_crash() is None, "a dead oracle must not raise into the poll loop"


def test_report_emits_event_with_attribution(monkeypatch):
    m = oh.OracleHealthMonitor(auto_recover=False)
    monkeypatch.setattr(oh, "_fetch_crash", lambda consume=True: CRASH)
    events = []
    monkeypatch.setattr(m, "_log_event", lambda name, **kw: events.append((name, kw)))
    m._report_crash_if_any()
    assert events and events[0][0] == "d2_exception"
    payload = events[0][1]
    assert payload["module"] == "D2Common.dll"
    # The whole point: blame the candidate, not whatever timed out afterwards.
    assert payload["proving"] == "DATATBLS_GetLevelRecordBitfield06"


def test_report_is_silent_when_there_is_no_crash(monkeypatch):
    m = oh.OracleHealthMonitor(auto_recover=False)
    monkeypatch.setattr(oh, "_fetch_crash", lambda consume=True: None)
    events = []
    monkeypatch.setattr(m, "_log_event", lambda name, **kw: events.append(name))
    m._report_crash_if_any()
    assert not events


def test_dismisser_matches_an_exception_dialog():
    """THE regression: the title is 'Diablo II Exception', not '... Error'."""
    import inspect
    src = inspect.getsource(oh._dismiss_diablo_error_dialog)
    assert '"exception" in title' in src, \
        "the dialog that hard-blocks the game must be matchable"

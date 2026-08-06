"""A crashed documentation run must record itself.

MEASURED 2026-08-06. An IndexError in a newly-added predicate killed three
documentation runs outright. Each left `last_result='scanned'` -- the initial
value, never updated -- and NO runs.jsonl entry, so it presented as a
completed-looking skip, indistinguishable from an abstention in the results. It
survived a whole 24-function measurement pass before the outcomes were read.

The bug was survivable; the SILENCE is what made it expensive, and that silence
applied to every exception on this path.

The guard RE-RAISES rather than swallowing: control flow is unchanged, so no
caller's error handling is altered and nothing is quietly turned into a success.
The only difference is that a crash leaves a trace.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

fd = pytest.importorskip("fun_doc")


@pytest.fixture
def boom(monkeypatch):
    saved = {}

    def explode(*a, **k):
        raise ValueError("synthetic explosion")

    monkeypatch.setattr(fd, "_process_function_inner", explode)
    monkeypatch.setattr(fd, "update_function_state",
                        lambda key, f: saved.update(key=key, func=dict(f)))
    monkeypatch.setattr(fd, "_append_run_log", lambda e: saved.setdefault("runs", []).append(e))
    monkeypatch.setattr(fd, "bus_emit", lambda *a, **k: None)
    return saved


def _func():
    return {"name": "FUN_1000", "address": "1000", "program": "/P",
            "last_result": "scanned"}


def test_the_crash_still_propagates(boom):
    """Control flow is unchanged -- a crash must not become a silent success."""
    with pytest.raises(ValueError):
        fd.process_function("/P::1000", _func(), {"functions": {}})


def test_the_state_records_it(boom):
    with pytest.raises(ValueError):
        fd.process_function("/P::1000", _func(), {"functions": {}})
    assert boom["func"]["last_result"] == "crashed"
    assert "synthetic explosion" in boom["func"]["last_error"]


def test_it_no_longer_looks_like_scanned(boom):
    """`scanned` is the initial value -- leaving it is what made the crash
    indistinguishable from a function nobody had processed yet."""
    with pytest.raises(ValueError):
        fd.process_function("/P::1000", _func(), {"functions": {}})
    assert boom["func"]["last_result"] != "scanned"


def test_a_run_log_entry_is_written(boom):
    with pytest.raises(ValueError):
        fd.process_function("/P::1000", _func(), {"functions": {}})
    runs = boom.get("runs") or []
    assert runs and runs[0]["result"] == "crashed"
    assert runs[0]["address"] == "1000"


def test_a_broken_recorder_does_not_mask_the_original_error(monkeypatch):
    """If the recording itself fails, the ORIGINAL exception must still be what
    reaches the caller -- otherwise the diagnosis is replaced by a red herring."""
    def explode(*a, **k):
        raise ValueError("original")
    monkeypatch.setattr(fd, "_process_function_inner", explode)
    monkeypatch.setattr(fd, "update_function_state",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("recorder down")))
    monkeypatch.setattr(fd, "_append_run_log",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("log down")))
    monkeypatch.setattr(fd, "bus_emit", lambda *a, **k: None)
    with pytest.raises(ValueError, match="original"):
        fd.process_function("/P::1000", _func(), {"functions": {}})

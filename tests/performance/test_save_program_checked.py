"""A failed `/save_program` must never be silent.

MEASURED 2026-08-06. Documentation written by COMPLETED runs vanished when
Ghidra went down: `CLIENT_CheckViewportVisible` and two get/set functions
reverted to `FUN_*`, while others documented in the same session survived. The
pipeline writes into Ghidra's in-memory program; the write only reaches disk on
a save, and the save in `process_function` was fire-and-forget.

The reason it could not be noticed is the sharper half. `ghidra_post` NEVER
RAISES -- it returns None on failure and prints to stderr -- so the
`try/except Exception` wrapped around the OTHER save sites, complete with a
"[warn] save_program failed" message, could not fire. It read as loud-failure
handling and was unreachable code. Two sites looked protected and were not.

That makes eight mechanisms in one session that were correct, tested or
plausible-looking, and wired to nothing. The countermeasure here is the same as
everywhere else: detect the failure by the value actually returned, and say so.

Non-fatal on purpose -- a failed save must not kill a pass that already did the
work -- but never silent, because silence let a completed function quietly
become undocumented again while SQL still recorded it as scoring 90.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

fd = pytest.importorskip("fun_doc")


# --- the contract that made this invisible ----------------------------------

def test_ghidra_post_does_not_raise_on_failure():
    """The whole reason the old try/except guards were dead code. If this ever
    changes, the guards below should be revisited -- but until it does,
    catching exceptions around a save detects nothing."""
    src = (_FUNDOC / "fun_doc.py").read_text(encoding="utf-8")
    i = src.index("def ghidra_post(")
    body = src[i:src.index("\ndef ", i + 10)]
    assert "return None" in body
    assert "raise " not in body.replace("raise_for_status", "")


# --- detection ---------------------------------------------------------------

def test_a_successful_save_reports_true(monkeypatch):
    monkeypatch.setattr(fd, "ghidra_post", lambda *a, **k: {"success": True})
    assert fd.save_program_checked("/P/x.dll") is True


def test_none_is_a_failure(monkeypatch, capsys):
    """The measured shape: Ghidra unreachable, call returns None, work lost."""
    monkeypatch.setattr(fd, "ghidra_post", lambda *a, **k: None)
    assert fd.save_program_checked("/P/x.dll") is False
    assert "SAVE FAILED" in capsys.readouterr().out


def test_an_error_payload_is_a_failure(monkeypatch, capsys):
    """The plugin answers a rejected write with HTTP 200 and an error body."""
    monkeypatch.setattr(fd, "ghidra_post", lambda *a, **k: {"error": "no such program"})
    assert fd.save_program_checked("/P/x.dll") is False
    assert "no such program" in capsys.readouterr().out


# --- what the operator is told -----------------------------------------------

def test_the_message_says_the_work_is_at_risk(monkeypatch, capsys):
    """A warning that does not say what is at stake gets scrolled past."""
    monkeypatch.setattr(fd, "ghidra_post", lambda *a, **k: None)
    fd.save_program_checked("/P/x.dll", "after documenting 0x1000")
    out = capsys.readouterr().out
    assert "MEMORY ONLY" in out and "LOST" in out
    assert "/P/x.dll" in out and "0x1000" in out


def test_it_is_non_fatal(monkeypatch):
    """A failed save must not kill a pass that already did the work."""
    monkeypatch.setattr(fd, "ghidra_post", lambda *a, **k: None)
    fd.save_program_checked("/P/x.dll")          # must not raise


def test_a_broken_event_bus_does_not_break_the_save_report(monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("bus down")
    monkeypatch.setattr(fd, "ghidra_post", lambda *a, **k: None)
    monkeypatch.setattr(fd, "bus_emit", boom)
    assert fd.save_program_checked("/P/x.dll") is False
    assert "SAVE FAILED" in capsys.readouterr().out


def test_emit_is_used_when_supplied(monkeypatch):
    lines = []
    monkeypatch.setattr(fd, "ghidra_post", lambda *a, **k: None)
    fd.save_program_checked("/P/x.dll", "ctx", emit=lines.append)
    assert lines and "SAVE FAILED" in lines[0]


# --- the call sites ----------------------------------------------------------

def test_no_unchecked_save_remains_in_fun_doc():
    """Every save must go through the checked helper. An unchecked one is
    indistinguishable from a successful one, which is the defect."""
    src = (_FUNDOC / "fun_doc.py").read_text(encoding="utf-8")
    body = src[src.index("def save_program_checked("):]
    body = body[body.index("\ndef ", 10):]          # skip the helper itself
    offenders = [ln.strip() for ln in body.splitlines()
                 if 'ghidra_post("/save_program"' in ln]
    assert not offenders, offenders

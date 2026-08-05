"""Two defects that made infrastructure problems look like verdicts.

Both measured on 2026-08-05 while walking one function through the pipeline on a
newly imported binary.

F11  config.scope_folders AND config.audit_provider were set on disk, verified
     in effect, and later found reset to None with no error. The 3-way merge is
     correct, but it bailed out to last-writer-wins whenever the caller's queue
     dict carried no baseline -- and audit_provider is a KNOWN key, so this was
     not an unknown-key problem.

F12  With the scope config gone, every Ghidra call for the binary was refused,
     and fetch_function_data recorded not_a_function=True for a function that
     had just been documented. That flag is DURABLE: the selector skips the
     function permanently. An infrastructure refusal minted a verdict.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

fd = pytest.importorskip("fun_doc")


# --- F11: the merge must not clobber disk when no baseline was armed ---------

@pytest.fixture
def on_disk(tmp_path, monkeypatch):
    """Point the merge at a throwaway priority_queue.json."""
    qf = tmp_path / "priority_queue.json"

    def write(cfg):
        qf.write_text(json.dumps({"config": cfg}), encoding="utf-8")

    monkeypatch.setattr(fd, "PRIORITY_QUEUE_FILE", qf)
    return write


def test_unbaselined_save_keeps_a_disk_only_key(on_disk):
    """scope_folders was set on disk and the caller had never heard of it."""
    on_disk({"scope_folders": ["/Lab"]})
    merged = fd._merge_config_on_write({"audit_min_delta": 5}, None)
    assert merged["scope_folders"] == ["/Lab"]


def test_unbaselined_save_keeps_a_known_key_left_at_its_default(on_disk):
    """The audit_provider case: caller carries the DEFAULT None and has no
    opinion, so an operator's on-disk 'minimax' must survive."""
    assert fd.DEFAULT_QUEUE_CONFIG.get("audit_provider") is None
    on_disk({"audit_provider": "minimax"})
    merged = fd._merge_config_on_write({"audit_provider": None}, None)
    assert merged["audit_provider"] == "minimax"


def test_unbaselined_save_still_lets_a_real_change_win(on_disk):
    """A caller that moved a key OFF its default HAS an opinion; it wins."""
    on_disk({"audit_provider": "minimax"})
    merged = fd._merge_config_on_write({"audit_provider": "claude"}, None)
    assert merged["audit_provider"] == "claude"


def test_baselined_merge_is_unchanged(on_disk):
    """The existing contract: unchanged-from-baseline yields to disk."""
    on_disk({"audit_provider": "minimax"})
    merged = fd._merge_config_on_write({"audit_provider": None},
                                       {"audit_provider": None})
    assert merged["audit_provider"] == "minimax"


def test_baselined_caller_change_beats_disk(on_disk):
    on_disk({"audit_provider": "minimax"})
    merged = fd._merge_config_on_write({"audit_provider": "gemini"},
                                       {"audit_provider": None})
    assert merged["audit_provider"] == "gemini"


def test_missing_file_leaves_the_caller_alone(tmp_path, monkeypatch):
    monkeypatch.setattr(fd, "PRIORITY_QUEUE_FILE", tmp_path / "nope.json")
    cfg = {"audit_provider": "minimax"}
    assert fd._merge_config_on_write(dict(cfg), None) == cfg


# --- F12: an infrastructure refusal is not a verdict -------------------------

@pytest.mark.parametrize("err", [
    "scope guard blocked call: program path '/Lab/x.dll' is outside scoped project folder(s) '/Mods/PD2-S12'",
    "Program not found: /Lab/x.dll Available programs: a.dll, b.dll",
    "Connection refused",
    "Read timed out",
    "Ghidra offline",
])
def test_environmental_errors_are_recognised(err):
    assert fd._is_environmental_error({"error": err}) is True


def test_no_response_at_all_is_environmental():
    assert fd._is_environmental_error(None) is True


@pytest.mark.parametrize("err", [
    "No function at address 0x1001bcc0",
    "Address is not in an executable block",
    "undefined data at this location",
])
def test_real_answers_are_not_treated_as_environmental(err):
    """Conservative: an unrecognised error must count as a real answer, or a
    genuinely bad address retries forever."""
    assert fd._is_environmental_error({"error": err}) is False


def test_a_successful_response_is_not_environmental():
    assert fd._is_environmental_error({"decompiled": "void f(void){}"}) is False

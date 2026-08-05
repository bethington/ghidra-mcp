"""The project-folder scope guard: which programs a call may address.

Written after the guard silently blocked an entire binary on 2026-08-04. The
dashboard switched context to /Lab and its scan logged "Incremental scan in
/Lab", while the guard went on reading /Mods/PD2-S12 from a cache populated at
process start. Every call for the focused binary was refused, and the refusal
surfaced as "0 functions (0 non-thunk)" -- indistinguishable from an empty
binary, while Ghidra held 1,265 functions for it.

Two properties are pinned here:
  * the scope may name SEVERAL folders and can change without a restart;
  * a refusal must never be readable as data.
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


@pytest.fixture
def scope(tmp_path, monkeypatch):
    """Point the guard at throwaway state.json / priority_queue.json."""
    state = tmp_path / "state.json"
    queue = tmp_path / "priority_queue.json"
    state.write_text(json.dumps({}), encoding="utf-8")
    queue.write_text(json.dumps({"config": {}}), encoding="utf-8")

    monkeypatch.setattr(fd, "STATE_FILE", state)
    monkeypatch.setattr(fd, "SCRIPT_DIR", tmp_path)
    monkeypatch.setattr(fd, "_PROJECT_FOLDER_OVERRIDE", "")
    fd._reset_scope_cache()

    def configure(primary=None, extra=None):
        state.write_text(json.dumps(
            {"project_folder": primary} if primary else {}), encoding="utf-8")
        cfg = {"scope_folders": extra} if extra else {}
        queue.write_text(json.dumps({"config": cfg}), encoding="utf-8")
        fd._reset_scope_cache()

    yield configure
    fd._reset_scope_cache()


# --- back-compat: a single folder behaves exactly as before ------------------

def test_single_folder_admits_its_own_paths(scope):
    scope(primary="/Mods/PD2-S12")
    assert fd._validate_program_param("/Mods/PD2-S12/D2Common.dll") == (
        "/Mods/PD2-S12/D2Common.dll", None)


def test_single_folder_rejects_outsiders(scope):
    scope(primary="/Mods/PD2-S12")
    norm, err = fd._validate_program_param("/Lab/SGD2FreeRes-GDI.dll")
    assert err and "outside scoped project folder" in err


def test_bare_name_auto_prefixes_into_the_primary(scope):
    scope(primary="/Mods/PD2-S12", extra=["/Lab"])
    assert fd._validate_program_param("D2Common.dll") == (
        "/Mods/PD2-S12/D2Common.dll", None)


def test_unset_scope_enforces_nothing(scope):
    scope()
    assert fd._validate_program_param("/anywhere/at/all.dll") == (
        "/anywhere/at/all.dll", None)


def test_prefix_collision_is_still_rejected(scope):
    """/Mods/PD2-S12-OTHER must not pass as /Mods/PD2-S12."""
    scope(primary="/Mods/PD2-S12")
    _, err = fd._validate_program_param("/Mods/PD2-S12-OTHER/D2Common.dll")
    assert err, "prefix collision admitted"


# --- several folders ---------------------------------------------------------

def test_additional_folder_is_admitted(scope):
    scope(primary="/Mods/PD2-S12", extra=["/Lab"])
    assert fd._validate_program_param("/Lab/SGD2FreeRes-GDI.dll") == (
        "/Lab/SGD2FreeRes-GDI.dll", None)
    assert fd._validate_program_param("/Mods/PD2-S12/D2Common.dll")[1] is None


def test_still_rejects_folders_not_listed(scope):
    scope(primary="/Mods/PD2-S12", extra=["/Lab"])
    _, err = fd._validate_program_param("/Vanilla/1.13c/D2Common.dll")
    assert err, "the guard must not become permissive just because it is plural"
    assert "/Mods/PD2-S12" in err and "/Lab" in err, "error should name what IS allowed"


def test_primary_stays_first(scope):
    scope(primary="/Mods/PD2-S12", extra=["/Lab"])
    assert fd.get_scope_folders()[0] == "/Mods/PD2-S12"


def test_env_override_wins_and_may_name_several(scope, monkeypatch):
    monkeypatch.setattr(fd, "_PROJECT_FOLDER_OVERRIDE", "/Lab,/Mods/PD2-S12")
    fd._reset_scope_cache()
    assert fd.get_scope_folders() == ("/Lab", "/Mods/PD2-S12")
    assert fd._validate_program_param("/Lab/x.dll")[1] is None


def test_duplicate_folders_collapse(scope):
    scope(primary="/Lab", extra=["/Lab", "/Lab/"])
    assert fd.get_scope_folders() == ("/Lab",)


# --- the cache must not outlive a config change ------------------------------

def test_scope_change_takes_effect_without_a_restart(scope):
    """The 2026-08-04 defect: a process-lifetime cache silently disagreeing
    with the UI's own notion of the focused folder."""
    scope(primary="/Mods/PD2-S12")
    assert fd._validate_program_param("/Lab/x.dll")[1] is not None

    scope(primary="/Mods/PD2-S12", extra=["/Lab"])
    assert fd._validate_program_param("/Lab/x.dll")[1] is None, (
        "scope change did not take effect in-process")


# --- a refusal must never be readable as data --------------------------------

def test_blocked_listing_is_not_reported_as_an_empty_binary(monkeypatch, capsys):
    """_fetch_function_list must return None (-> caller warns), never []."""
    monkeypatch.setattr(
        fd, "ghidra_get",
        lambda *a, **k: {"error": "scope guard blocked call: outside scope"})
    out = fd._fetch_function_list("/Lab/SGD2FreeRes-GDI.dll")
    assert out is None, "an error was reported as a binary with no functions"
    assert "ERROR listing functions" in capsys.readouterr().out


def test_a_genuinely_empty_program_still_reads_as_empty(monkeypatch):
    """The converse: no error means no rows, and that must stay distinguishable."""
    monkeypatch.setattr(fd, "ghidra_get", lambda *a, **k: {"functions": []})
    assert fd._fetch_function_list("/Lab/empty.dll") == []

"""The sweep that re-opens authored functions the detector wrongly retired.

`library_code` makes the selector skip a function PERMANENTLY, so a false
positive is authored code deleted from the workload for good. Two detector
defects produced them (see `audit_library_misclassification` for the measured
cases), and this sweep is the repair.

The rules that matter are all about what it must NOT do:

    - never overturn an EXACT lane's verdict (tag / FID / BSim / bytes)
    - never clear on an unreadable function ("cannot tell" is not "cleared")
    - never remove a plate this detector did not write

Offline: scoping and plate recognition are pure functions, and the Ghidra read
is injected.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
for p in (str(_FUNDOC), str(_FUNDOC / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

alm = pytest.importorskip("audit_library_misclassification")


# --- scoping: only this detector's own verdicts are re-decidable -------------

@pytest.mark.parametrize("reasons", [
    ["LIB_* Ghidra tag (durable)"],
    ["retag: name-propagation (LIB_* elsewhere)"],
    ["LIB_CRT via fid: FID single match: _atexit"],
    ["pset harness curated bucket (library/import_thunk_external), bulk-tagged 2026-07-14"],
])
def test_exact_lane_verdicts_are_out_of_scope(reasons):
    """A byte / FID / BSim / tag verdict is not a heuristic re-read's to
    overturn. `backfill_library_code.py` refuses to clear for the same reason:
    clearing a verdict you cannot see the evidence for silently re-opens
    functions excluded on evidence you do not have."""
    assert not alm.is_heuristic(reasons)
    assert not alm.is_heuristic(json.dumps(reasons))


@pytest.mark.parametrize("reasons", [
    ["hard_callee:_invoke_watson", "soft_body:_invoke_watson"],
    ["hard_callee:_CxxThrowException", "soft_body:_CxxThrowException"],
    ["hard_name"],
    ["soft_name", "soft_body:__security_check_cookie"],
])
def test_heuristic_verdicts_are_in_scope(reasons):
    assert alm.is_heuristic(reasons)
    assert alm.is_heuristic(json.dumps(reasons))


def test_a_row_with_no_recorded_reason_is_out_of_scope():
    """No recorded evidence is not evidence of a bad verdict."""
    assert not alm.is_heuristic(None)
    assert not alm.is_heuristic("")
    assert not alm.is_heuristic([])


def test_a_mixed_reason_list_is_out_of_scope():
    """If ANY exact marker is present the row is not ours, whatever else it
    also says -- the strong evidence decides."""
    assert not alm.is_heuristic(["hard_callee:_invoke_watson", "LIB_* Ghidra tag (durable)"])


# --- re-evaluation ----------------------------------------------------------

def test_an_unreadable_function_is_left_alone(monkeypatch):
    """Returning None (not False) keeps it out of the findings entirely. A
    dropped HTTP call must never manufacture a repair."""
    monkeypatch.setattr(alm, "_get", lambda *a, **k: None)
    assert alm.reevaluate("/p/x.dll", "0x1000") is None


def test_an_empty_decompile_is_left_alone(monkeypatch):
    monkeypatch.setattr(alm, "_get", lambda path, **k: {"decompiled": "", "name": "FUN_1"})
    assert alm.reevaluate("/p/x.dll", "0x1000") is None


def test_the_measured_false_positive_is_reported(monkeypatch):
    """GetCel: the only mentions of the CRT symbol are in comments."""
    body = ("/* ...jump to thunk_FUN_10001e60 which calls _CxxThrowException. */\n"
            "puVar1 = InitializeRecordHeader(&local_20, *(uint *)this);\n"
            "return BuildLookupResult(puVar1, param_1);\n")

    def fake(path, **k):
        if "decompile" in path:
            return {"decompiled": body, "name": "FUN_1001e1f0"}
        return {"callees": ["InitializeRecordHeader", "thunk_FUN_10001e60"]}

    monkeypatch.setattr(alm, "_get", fake)
    out = alm.reevaluate("/p/x.dll", "0x1001e1f0")
    assert out is not None and out["still_library"] is False


def test_genuine_library_code_is_not_re_opened(monkeypatch):
    """The positive control. A sweep that re-opened everything would look like
    a total success while destroying the detector's real work."""
    def fake(path, **k):
        if "decompile" in path:
            return {"decompiled": "__SEH_prolog4();\n  _Xlength_error(\"v\");\n",
                    "name": "FUN_10052ba0"}
        return {"callees": ["__SEH_prolog4"]}

    monkeypatch.setattr(alm, "_get", fake)
    out = alm.reevaluate("/p/x.dll", "0x10052ba0")
    assert out is not None and out["still_library"] is True


# --- the plate --------------------------------------------------------------

def test_a_generated_plate_is_recognised(monkeypatch):
    from library_code_detector import format_plate, DetectionResult
    plate = format_plate(DetectionResult(True, 0.8, ["hard_callee:_invoke_watson"]))

    def fake(path, **k):
        if "decompile" in path:
            return {"decompiled": f"/* {plate} */\nvoid f(void) {{ g(); }}\n", "name": "FUN_1"}
        return {"callees": []}

    monkeypatch.setattr(alm, "_get", fake)
    out = alm.reevaluate("/p/x.dll", "0x1000")
    assert out["plate_is_generated"] is True
    # and, critically, the plate must not re-confirm the verdict it records
    assert out["still_library"] is False


def test_a_human_plate_is_not_ours_to_remove(monkeypatch):
    def fake(path, **k):
        if "decompile" in path:
            return {"decompiled": "/* Computes the visible tile bounds. */\nvoid f(void){}\n",
                    "name": "SetTileCullingBound"}
        return {"callees": []}

    monkeypatch.setattr(alm, "_get", fake)
    assert alm.reevaluate("/p/x.dll", "0x1000")["plate_is_generated"] is False


def test_the_script_defaults_to_dry_run():
    """Every sweep in this repo is report-first; --apply is the opt-in."""
    src = (_FUNDOC / "scripts" / "audit_library_misclassification.py").read_text(
        encoding="utf-8")
    assert '"--apply", action="store_true"' in src
    assert "DRY RUN" in src

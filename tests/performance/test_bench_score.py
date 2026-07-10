"""Offline unit tests for bench_score.py.

bench_score grades the facts the production translators recover from a fresh
binary against a known answer key -- pure comparison arithmetic, no Ghidra/LLM.
Runs the module's `_selftest()` (scoring axes) as a CI gate plus direct checks
on the `score_function` scoring contract.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

FUN_DOC_DIR = Path(__file__).resolve().parents[2] / "fun-doc"
if str(FUN_DOC_DIR) not in sys.path:
    sys.path.insert(0, str(FUN_DOC_DIR))

# bench_score sets os.environ["FUN_DOC_PROJECT_FOLDER"]="/benchmark" at import
# (it's a benchmark harness). Snapshot + restore around the import so it can't
# leak into sibling tests collected afterwards (e.g. test_ghidra_offline, which
# asserts on fetch_function_data's project-folder-dependent behavior).
_SAVED_PROJECT_FOLDER = os.environ.get("FUN_DOC_PROJECT_FOLDER", "\0__UNSET__")
import bench_score as bs  # noqa: E402
if _SAVED_PROJECT_FOLDER == "\0__UNSET__":
    os.environ.pop("FUN_DOC_PROJECT_FOLDER", None)
else:
    os.environ["FUN_DOC_PROJECT_FOLDER"] = _SAVED_PROJECT_FOLDER


def test_selftest_scoring_axes_pass():
    assert bs._selftest() == 0


def test_score_function_perfect_match():
    ak = {
        "ret": {"width": 2},
        "reads": [{"off": 0x8, "width": 4}, {"off": 0x4, "width": 2}],
        "gates": [{"off": 0, "imm": 2}],
    }
    rec = {
        "matched": "flat_getter",
        "ret": "u16",
        "reads": [{"off": 0x8, "width": 4}, {"off": 0x4, "width": 2}],
        "gates": [{"off": 0, "imm": 2}],
    }
    s = bs.score_function(ak, rec)
    assert s["score"] == 1.0
    assert s["axes"]["ret_width"] == 1.0
    assert s["axes"]["field_reads"] == 1.0


def test_score_function_penalizes_wrong_return_width():
    ak = {"ret": {"width": 2}, "reads": [{"off": 0x8, "width": 4}], "gates": []}
    rec = {"matched": "flat_getter", "ret": "u32",  # u32 != width 2
           "reads": [{"off": 0x8, "width": 4}], "gates": []}
    s = bs.score_function(ak, rec)
    assert s["axes"]["ret_width"] == 0.0
    assert s["score"] < 1.0

"""Regression tests for the globals clean cache's axis + rule-version gating.

The bug (2026-07-29): the dashboard reported "D2Client.dll: 873 untyped
(undefined*) ... start a globals worker", the user started one, and it exited
9 MICROSECONDS later with `no_more_binaries`, 0 processed. All 3,311 D2Client
globals were cached "clean", so the worker filtered every address out, found
nothing to do, advanced to the next binary, found none, and quit.

Two independent defects made that possible:

  1. ONE cache gated every kind of globals work. A pass that returned
     "skipped" for DOCUMENTATION marked the address clean for 7 days, which
     then suppressed TYPING work on the same address.
  2. The cache short-circuits BEFORE audit_global runs, so entries written
     under an older rule set replayed a "clean" verdict forever. audit_global
     now returns issues=['untyped'], severity={hard:1} for those same
     addresses -- the new rule could never fire.

Silent in both directions: the worker reported success, and the UI hid the
banner optimistically on click, so a worker that died instantly looked healthy.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

fd = pytest.importorskip("fun_doc")

PROG = "/Mods/PD2-S12/D2Client.dll"
ADDR = "0x6fbcb980"


def _cache():
    return {"version": 1, "programs": {}}


def _all_axes_clean(cache, prog=PROG, addr=ADDR):
    return all(
        fd._clean_cache_is_fresh(cache, prog, addr, axis=ax)
        for ax in fd.GLOBALS_CLEAN_AXES
    )


# --- the axis split ---------------------------------------------------------

def test_doc_clean_does_not_imply_type_clean():
    """The core conflation: clearing naming/plate work must not suppress
    typing work on the same global."""
    c = _cache()
    fd._clean_cache_mark(c, PROG, ADDR, axes=(fd.GLOBALS_AXIS_DOC,))
    assert fd._clean_cache_is_fresh(c, PROG, ADDR, axis=fd.GLOBALS_AXIS_DOC) is True
    assert fd._clean_cache_is_fresh(c, PROG, ADDR, axis=fd.GLOBALS_AXIS_TYPE) is False
    assert _all_axes_clean(c) is False, "must remain in the work list"


def test_marking_all_axes_clears_the_address():
    c = _cache()
    fd._clean_cache_mark(c, PROG, ADDR, axes=fd.GLOBALS_CLEAN_AXES)
    assert _all_axes_clean(c) is True


def test_marking_one_axis_preserves_the_other():
    c = _cache()
    fd._clean_cache_mark(c, PROG, ADDR, axes=(fd.GLOBALS_AXIS_DOC,))
    fd._clean_cache_mark(c, PROG, ADDR, axes=(fd.GLOBALS_AXIS_TYPE,))
    assert _all_axes_clean(c) is True


# --- rule-version gating ----------------------------------------------------

def test_old_rule_version_entries_are_stale():
    """audit_global's rule set moved (the `untyped` rule was added). Entries
    stamped with an older version must be re-checked, not replayed."""
    c = _cache()
    fd._clean_cache_mark(c, PROG, ADDR, axes=fd.GLOBALS_CLEAN_AXES)
    c["programs"][PROG][ADDR]["v"] = fd.GLOBALS_AUDIT_RULES_VERSION - 1
    assert _all_axes_clean(c) is False


def test_legacy_bare_timestamp_entries_are_stale():
    """The real on-disk shape before this change: a bare ISO string. Those
    predate BOTH the axis split and the current rules -- 3,311 of them were
    suppressing 873 genuinely untyped globals."""
    c = _cache()
    c["programs"][PROG] = {ADDR: datetime.now().isoformat()}
    assert fd._clean_cache_is_fresh(c, PROG, ADDR, axis=fd.GLOBALS_AXIS_DOC) is False
    assert fd._clean_cache_is_fresh(c, PROG, ADDR, axis=fd.GLOBALS_AXIS_TYPE) is False
    assert _all_axes_clean(c) is False


def test_remarking_an_old_version_entry_resets_it():
    """A stale entry must not keep a stale axis alive through a re-mark."""
    c = _cache()
    c["programs"][PROG] = {
        ADDR: {"doc": datetime.now().isoformat(),
               "type": datetime.now().isoformat(),
               "v": fd.GLOBALS_AUDIT_RULES_VERSION - 1}
    }
    fd._clean_cache_mark(c, PROG, ADDR, axes=(fd.GLOBALS_AXIS_DOC,))
    entry = c["programs"][PROG][ADDR]
    assert entry["v"] == fd.GLOBALS_AUDIT_RULES_VERSION
    assert "type" not in entry, "stale type stamp must not survive a doc re-mark"


# --- TTL still applies ------------------------------------------------------

def test_ttl_expiry_still_honoured():
    c = _cache()
    old = (datetime.now() - timedelta(seconds=fd.GLOBALS_CLEAN_CACHE_TTL_SECONDS + 60))
    c["programs"][PROG] = {
        ADDR: {"doc": old.isoformat(), "type": old.isoformat(),
               "v": fd.GLOBALS_AUDIT_RULES_VERSION}
    }
    assert _all_axes_clean(c) is False


def test_fresh_current_version_entry_is_clean():
    """The cache must still do its job -- it exists to stop re-auditing every
    global on every pass (40% of historic dispatches were redundant skips)."""
    c = _cache()
    fd._clean_cache_mark(c, PROG, ADDR, axes=fd.GLOBALS_CLEAN_AXES)
    assert _all_axes_clean(c) is True


def test_unknown_address_is_not_clean():
    assert _all_axes_clean(_cache(), addr="0xdeadbeef") is False

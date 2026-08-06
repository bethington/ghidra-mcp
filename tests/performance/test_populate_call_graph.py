"""`callees` has ONE writer and ONE source: references.

MEASURED 2026-08-06. `populate_call_graph` stamped `callees` from
`/get_full_call_graph`, which this codebase already documents as measurably
incomplete -- `__CxxFrameHandler3` has 7 UNCONDITIONAL_CALL xrefs and reports
ZERO call-graph edges (call_graph.py, written after scope analysis hit the same
wall). Meanwhile backfill_callees stamps the SAME field from xrefs. Two writers
of one field with different reliability is the shape behind several bugs already
recorded here.

The severity is not "an under-filled field". The stamp assigns `callees` for
EVERY function in the program, so a sparse fetch OVERWRITES good data with empty
lists -- the corpus-wide xref backfill that took coverage from 17.2% to 100%
would have been wiped by the next scan of any program.

And a failed fetch must REFUSE, not stamp: an unreadable graph is not "this
program has no calls", and proceeding blanks every callee list in it. That is
the same rule backfill_callees' EmptyGraph guard follows, and the reason it
caught a bad address format instead of writing [] across a whole binary.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

fd = pytest.importorskip("fun_doc")
cg = pytest.importorskip("call_graph")


def _state():
    return {"functions": {
        "/P::1000": {"program": "/P", "address": "1000", "name": "A",
                     "callees": ["dead1", "dead2"]},
        "/P::2000": {"program": "/P", "address": "2000", "name": "B",
                     "callees": ["dead3"]},
        "/Q::9000": {"program": "/Q", "address": "9000", "name": "Other",
                     "callees": ["keepme"]},
    }}


def test_edges_come_from_references(monkeypatch):
    """b references a => b calls a. Sourced from the shared xref builder."""
    monkeypatch.setattr(cg, "function_referrers",
                        lambda prog, addrs: {"0x1000": {"0x2000"}})
    st = _state()
    fd.populate_call_graph(st, "/P")
    assert st["functions"]["/P::2000"]["callees"] == ["1000"]


def test_a_failed_graph_leaves_callee_data_UNCHANGED(monkeypatch):
    """The measured risk: stamping on a failed fetch blanks every callee list
    in the program, wiping a good backfill."""
    def boom(prog, addrs):
        raise cg.EmptyGraph("no references came back")
    monkeypatch.setattr(cg, "function_referrers", boom)
    st = _state()
    assert fd.populate_call_graph(st, "/P") == 0
    assert st["functions"]["/P::1000"]["callees"] == ["dead1", "dead2"]
    assert st["functions"]["/P::2000"]["callees"] == ["dead3"]


def test_other_programs_are_never_touched(monkeypatch):
    monkeypatch.setattr(cg, "function_referrers",
                        lambda prog, addrs: {"0x1000": {"0x2000"}})
    st = _state()
    fd.populate_call_graph(st, "/P")
    assert st["functions"]["/Q::9000"]["callees"] == ["keepme"]


def test_a_function_with_no_callees_gets_an_empty_list(monkeypatch):
    """[] means scanned-and-calls-nothing and must be written; NULL means nobody
    looked. Collapsing those is what made the readiness sort inert."""
    monkeypatch.setattr(cg, "function_referrers",
                        lambda prog, addrs: {"0x1000": {"0x2000"}})
    st = _state()
    fd.populate_call_graph(st, "/P")
    assert st["functions"]["/P::1000"]["callees"] == []


def test_addresses_are_sent_0x_prefixed(monkeypatch):
    """library_scope._bulk_xrefs_to strips two characters rather than parsing,
    so a bare address is silently mangled -- 174 functions, zero edges, measured
    on D2Net.dll."""
    seen = {}

    def spy(prog, addrs):
        seen["addrs"] = list(addrs)
        return {}

    monkeypatch.setattr(cg, "function_referrers", spy)
    fd.populate_call_graph(_state(), "/P")
    assert all(a.startswith("0x") for a in seen["addrs"]), seen["addrs"]


def test_the_incomplete_endpoint_is_no_longer_CALLED():
    """Guards the reason this changed: /get_full_call_graph drops edges.

    Checks for an actual CALL, not the string -- the comment names the endpoint
    deliberately, so that it is obvious why the code does not use it.
    """
    import inspect
    src = inspect.getsource(fd.populate_call_graph)
    code = [ln for ln in src.splitlines() if not ln.strip().startswith("#")]
    assert not any('"/get_full_call_graph"' in ln for ln in code)


# --- coupled address normalisation ------------------------------------------
# `lstrip("0x")` takes a CHARACTER SET, so it eats leading zeros too:
# `00401000` -> `0x401000`, `0000` -> `0x`. library_scope.norm_addr documents
# this as a real bug it exists to avoid. In the band-tag sweep it is currently
# HARMLESS ONLY BECAUSE BOTH SIDES DO IT -- 178 corpus addresses are exposed
# (175 of them Game.exe, based at 0x00400000) and they still match because they
# are mangled identically.
#
# The hazard is therefore a well-meant half-fix. This pins the coupling so that
# correcting one side alone fails loudly here instead of silently dropping every
# Game.exe band tag.

def test_band_tag_normalisation_is_coupled():
    import inspect
    a = inspect.getsource(fd._assess_tag_addrs)
    b = inspect.getsource(fd.sync_band_tags_sweep)[:2000]
    assert 'lstrip("0x")' in a and 'lstrip("0x")' in b, (
        "one side of the band-tag comparison changed its address normalisation "
        "without the other -- see the COUPLED NORMALISATION notes in fun_doc")


def test_the_coupling_is_documented_at_both_sites():
    import inspect
    assert "COUPLED NORMALISATION" in inspect.getsource(fd._assess_tag_addrs)
    assert "COUPLED NORMALISATION" in inspect.getsource(fd.sync_band_tags_sweep)[:2000]

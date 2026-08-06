"""Backfilling `callees` so bottom-up ordering has data to order.

MEASURED 2026-08-06: 10,904 of 63,401 functions (17.2%) carry a callee list.
D2Client (3,679), D2Common (2,507), ProjectDiablo (15,248), glide3x (10,221)
and libcrypto (6,996) carry ZERO. The selector's readiness sort therefore
ordered nothing across most of the corpus, while reading as though it worked --
`_callee_readiness` returned 1.0, maximum readiness, for every unscanned
function. 802b2d4 made that gap honest; this closes it.

Two traps this file exists to pin:

  ADDRESS FORMAT. SQL stores bare lowercase hex; the xref helpers return
  0x-prefixed. Getting that wrong makes the backfill a silent no-op that
  reports success -- exactly what backfill_library_code documents and tests
  for, having been bitten by it.

  EMPTY IS NOT NULL. `[]` means "scanned, genuinely calls nothing"; NULL means
  "nobody looked". Collapsing those is the original defect, so the leaves must
  be WRITTEN rather than skipped, or the repair recreates the thing it repairs.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
for p in (_FUNDOC, _FUNDOC / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

bc = pytest.importorskip("backfill_callees")


# --- address normalisation ---------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("0x10001d70", "10001d70"),
    ("10001d70", "10001d70"),
    ("0X10001D70", "10001d70"),
    ("0x1d70", "00001d70"),          # padded, so the two sides can compare
])
def test_addresses_normalise_to_bare_lower_hex(raw, expected):
    assert bc._norm(raw) == expected


def test_the_two_sides_agree_after_normalising():
    """The measured silent-no-op: SQL bare, xrefs 0x-prefixed."""
    assert bc._norm("0x10001d70") == bc._norm("10001d70")


# --- edge derivation ---------------------------------------------------------

class _FakeCG:
    def __init__(self, referrers):
        self.referrers = referrers
        self.EmptyGraph = RuntimeError

    def function_referrers(self, program, addresses):
        return self.referrers

    @staticmethod
    def invert(referrers):
        out = {}
        for target, srcs in referrers.items():
            for s in srcs:
                if s == "?unattributed":
                    continue
                out.setdefault(s, set()).add(target)
        return out


def test_callees_come_from_inverted_referrers(monkeypatch):
    # b references a  =>  b calls a.
    monkeypatch.setattr(bc.cg, "function_referrers",
                        lambda prog, addrs: {"0xa": {"0xb"}})
    out = bc.callees_for_program("/P", ["0xa", "0xb"])
    assert out == {bc._norm("0xb"): {bc._norm("0xa")}}


def test_callees_outside_the_program_are_dropped(monkeypatch):
    """A referrer that is not one of this program's functions cannot be given a
    callee list here -- it belongs to another binary or to unattributed code."""
    monkeypatch.setattr(bc.cg, "function_referrers",
                        lambda prog, addrs: {"0xa": {"0xdead"}})
    assert bc.callees_for_program("/P", ["0xa"]) == {}


# --- planning ----------------------------------------------------------------

def _state(rows):
    return {"functions": rows}


def test_a_genuine_leaf_is_written_not_skipped(monkeypatch):
    """[] means scanned-and-calls-nothing; NULL means nobody looked. Skipping
    the leaves would recreate the exact defect this repairs."""
    monkeypatch.setattr(bc.cg, "function_referrers", lambda prog, addrs: {"0xa": {"0xb"}})
    st = _state({"/P::a": {"program": "/P", "address": "a"},
                 "/P::b": {"program": "/P", "address": "b"}})
    p = bc.plan("/P", st)
    assert p["would_write"] == 2
    assert p["of_which_leaves"] == 1          # 'a' calls nothing
    assert p["updates"]["/P::a"] == []


def test_already_populated_rows_are_left_alone(monkeypatch):
    monkeypatch.setattr(bc.cg, "function_referrers", lambda prog, addrs: {"0xa": {"0xb"}})
    st = _state({"/P::a": {"program": "/P", "address": "a", "callees": []},
                 "/P::b": {"program": "/P", "address": "b"}})
    p = bc.plan("/P", st)
    assert p["already_populated"] == 1 and p["would_write"] == 1
    assert "/P::a" not in p["updates"]


def test_an_empty_graph_refuses_rather_than_marking_everything_a_leaf(monkeypatch):
    """A failed read is not 'this binary has no calls'. Writing [] everywhere
    from it would mark a whole binary as leaves and look like a clean result."""
    def boom(prog, addrs):
        raise bc.cg.EmptyGraph("no references came back")
    monkeypatch.setattr(bc.cg, "function_referrers", boom)
    p = bc.plan("/P", _state({"/P::a": {"program": "/P", "address": "a"}}))
    assert p.get("error") and "updates" not in p


def test_a_program_with_no_rows_reports_rather_than_writing():
    p = bc.plan("/Missing", _state({}))
    assert p.get("error") and "updates" not in p


def test_other_programs_are_untouched(monkeypatch):
    monkeypatch.setattr(bc.cg, "function_referrers", lambda prog, addrs: {"0xa": {"0xb"}})
    st = _state({"/P::a": {"program": "/P", "address": "a"},
                 "/Q::z": {"program": "/Q", "address": "z"}})
    p = bc.plan("/P", st)
    assert all(k.startswith("/P::") for k in p["updates"])


# --- the dry-run default -----------------------------------------------------

def test_planning_writes_nothing():
    """Report-first, like every other sweep here: plan() must be pure."""
    src = (_FUNDOC / "scripts" / "backfill_callees.py").read_text(encoding="utf-8")
    plan_src = src[src.index("def plan("):src.index("def apply_plan(")]
    assert "update_function_state" not in plan_src
    assert "save_state" not in plan_src


# --- the 0x-prefix contract --------------------------------------------------
# MEASURED 2026-08-06 on D2Net.dll: 174 functions, ZERO edges, and the only
# thing that stopped `[]` being written over the whole binary was the EmptyGraph
# guard. `library_scope._bulk_xrefs_to` strips the first two characters
# (`a[2:]`) rather than parsing, so a BARE address is silently mangled --
# `6fbf1000` becomes `bf1000`, every lookup misses, and the empty result is
# indistinguishable from "this binary genuinely has no references".

def test_addresses_go_down_0x_prefixed(monkeypatch):
    seen = {}

    def spy(program, addrs):
        seen["addrs"] = list(addrs)
        return {}

    monkeypatch.setattr(bc.cg, "function_referrers", spy)
    bc.callees_for_program("/P", ["6fbf1000", "0x6fbf133d"])
    assert all(a.startswith("0x") for a in seen["addrs"]), seen["addrs"]
    assert "0x6fbf1000" in seen["addrs"]      # bare input is prefixed, not mangled


def test_is_leaf_is_not_asserted(monkeypatch):
    """An empty list means 'calls nothing else IN THIS PROGRAM' -- imports are
    filtered out. That is the right input for ordering but a weaker claim than
    'this is a leaf', and the selector derives its own is_leaf anyway."""
    src = (_FUNDOC / "scripts" / "backfill_callees.py").read_text(encoding="utf-8")
    apply_src = src[src.index("def apply_plan("):src.index("def main(")]
    assert 'f["is_leaf"]' not in apply_src

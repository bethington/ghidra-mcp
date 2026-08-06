"""The shared reference graph, and bottom-up documentation ordering.

WHY IT IS SHARED. `scope_graph` built this graph to answer "is this function
library-owned" -- every referrer is library code, transitively. Documentation
ordering needs the same graph pointed the other way: to document callees before
callers, you need what a function CALLS.

Two builders answering one question is the shape of most defects in this
codebase -- two definitions of "untyped" living in three places, two views of
"the globals in this binary" with different denominators, a hand-copied set of
symbol gates rendering beside the scanner they were copied from. So there is
one builder and both consumers import it.

WHY ORDERING AT ALL. Measured 2026-08-06: a documentation worker was handed
`return FUN_10001d70();` with no information about the callee, could not
decline, and invented `CLIENT_CheckViewportVisible` for a mouse-over hit test.
Supplying the callee's BODY fixed that specific case (recall 0.167 -> 1.000).
Ordering is the structural version: document the callee FIRST and the caller's
evidence is a name and a plate, which is cheaper and better than a raw body.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

cg = pytest.importorskip("call_graph")


# --- inversion ---------------------------------------------------------------

def test_referrers_invert_to_callees():
    # b and c both reference a  =>  b and c each call a.
    assert cg.invert({"a": {"b", "c"}}) == {"b": {"a"}, "c": {"a"}}


def test_the_unattributed_sentinel_is_not_a_node():
    """`?unattributed` exists to BLOCK a scope exclusion -- an unresolvable
    referrer might be authored code, so it keeps a function in scope. It names
    no function, so carrying it into the callee graph would invent a node."""
    out = cg.invert({"a": {"?unattributed", "b"}})
    assert out == {"b": {"a"}}
    assert "?unattributed" not in out


def test_inverting_nothing_is_empty_not_an_error():
    assert cg.invert({}) == {} and cg.invert(None) == {}


# --- ordering ----------------------------------------------------------------

def test_callees_come_before_their_callers():
    """The whole point: a caller's evidence exists by the time we reach it."""
    order = cg.documentation_order({"caller": {"callee"}})
    assert order.index("callee") < order.index("caller")


def test_a_chain_is_ordered_leaf_first():
    order = cg.documentation_order({"a": {"b"}, "b": {"c"}})
    assert order.index("c") < order.index("b") < order.index("a")


def test_a_leaf_with_no_callees_comes_first():
    order = cg.documentation_order({"a": {"leaf"}}, universe=["a", "leaf"])
    assert order[0] == "leaf"


def test_a_cycle_is_emitted_not_dropped():
    """Recursion and mutual recursion are ordinary. A topological sort that
    discarded them would silently omit whole subsystems from the queue."""
    order = cg.documentation_order({"a": {"b"}, "b": {"a"}})
    assert sorted(order) == ["a", "b"]


def test_a_cycle_does_not_block_the_rest():
    order = cg.documentation_order({"a": {"b"}, "b": {"a"}, "c": set(), "d": {"c"}})
    assert order.index("c") < order.index("d")
    assert set(order) == {"a", "b", "c", "d"}


def test_cycle_order_is_deterministic():
    """No valid relative order exists inside a cycle, so it is address-sorted --
    stated rather than left to dict iteration."""
    a = cg.documentation_order({"z": {"y"}, "y": {"z"}})
    b = cg.documentation_order({"y": {"z"}, "z": {"y"}})
    assert a == b


def test_out_of_universe_callees_are_not_blockers():
    """A function calling the CRT or an import must not wait forever for
    something that will never be documented in this binary."""
    order = cg.documentation_order({"a": {"malloc"}}, universe=["a"])
    assert order == ["a"]


def test_the_universe_bounds_the_output():
    order = cg.documentation_order({"a": {"b"}, "b": {"c"}}, universe=["a", "b"])
    assert set(order) == {"a", "b"}


def test_a_diamond_puts_the_shared_callee_first():
    order = cg.documentation_order({"top": {"l", "r"}, "l": {"base"}, "r": {"base"}})
    assert order[0] == "base"
    assert order.index("base") < order.index("l") < order.index("top")
    assert order.index("r") < order.index("top")


def test_depth_is_not_the_key():
    """A function whose callees are all documented is ready regardless of how
    deep it sits -- this is a peel, not a longest-path sort."""
    order = cg.documentation_order({"deep3": {"deep2"}, "deep2": {"deep1"},
                                    "deep1": set(), "shallow": set()})
    assert order.index("shallow") <= order.index("deep2")


# --- readiness ---------------------------------------------------------------

def test_unresolved_callees_names_exactly_what_is_missing():
    """A selector needs 'is the evidence ready?'; an abstention rule needs
    'what precisely is missing?'. Same question, one answer."""
    missing = cg.unresolved_callees("a", {"a": {"b", "c"}}, documented={"b"})
    assert missing == {"c"}


def test_nothing_missing_when_all_callees_are_documented():
    assert cg.unresolved_callees("a", {"a": {"b"}}, documented={"b"}) == set()


def test_out_of_universe_callees_are_not_missing():
    missing = cg.unresolved_callees("a", {"a": {"malloc"}}, documented=set(),
                                    universe=["a"])
    assert missing == set()


def test_a_function_with_no_callees_is_always_ready():
    assert cg.unresolved_callees("leaf", {}, documented=set()) == set()


# --- the shared-module guarantee ---------------------------------------------

def test_scope_graph_still_exposes_its_original_api():
    """Extracting the builder must not change scope_graph's surface -- its own
    tests and callers were written against these names."""
    sg = pytest.importorskip("scope_graph")
    assert sg.function_referrers is cg.function_referrers
    assert sg.EmptyGraph is cg.EmptyGraph


def test_there_is_only_one_referrer_builder():
    """Guards the reason this module exists: if a second definition appears,
    the two will drift and answer one question two ways."""
    sg_src = (_FUNDOC / "scope_graph.py").read_text(encoding="utf-8")
    assert "def function_referrers(" not in sg_src

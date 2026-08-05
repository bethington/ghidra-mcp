"""`outbuf_leaf`: a delegate-calling out-buffer mutator, proven via class-B shadow.

`mutator_leaf` already covers the no-callee case and refuses anything that calls
out, correctly: its proof runs on a SYNTH object whose pattern bytes are not
valid pointers, and a callee handed one can free/walk it and take the game down.
That gate is untouched.

`outbuf_leaf` is reached only after mutator_leaf declines, and routes to class-B
SHADOW dispatch instead, where the buffer is a REAL one from the live game and
the reimpl gets an independent copy. The hazard there is different: the reimpl's
callees actually RUN, so any effect past the out-buffer happens twice per call.
Hence the transitive purity gate -- and hence abstaining whenever purity cannot
be established, which is the same rule the byte/FID/BSim lanes use.

Measured 2026-08-05 on SGD2FreeRes-GDI's FUN_1001bcc0: shape qualifies, extent
derives to 36 bytes, and the gate still DECLINES it because a callee is a
magic-static lazy initialiser that writes a global. That is the intended answer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

pp = pytest.importorskip("port_pipeline")

# Shape of the measured specimen: void, one out-param, writes through it, calls out.
SPECIMEN = """
void __cdecl FUN_1001bcc0(uint *pViewports,int nLeft,int nTop,int nRight,int nBottom)
{
  LPRECT lprc;
  int iVar1;
  if (pViewports != (uint *)0x0) {
    SetRect((LPRECT)(pViewports + 1),nLeft,nTop,nRight,nBottom);
    iVar1 = FUN_100203b0();
    pViewports[6] = pViewports[6] - iVar1;
    pViewports[8] = pViewports[8] - 3;
    *pViewports = *pViewports | 1;
  }
  return;
}
"""

PURE_GETTER = "int FUN_100203b0(void) { return 42; }"
PURE_CHAIN_OUTER = "int FUN_100203b0(void) { int *p; p = FUN_10020320(); return *p; }"
PURE_CHAIN_INNER = "int * FUN_10020320(void) { return (int *)0x10042000; }"
GLOBAL_WRITER = "int FUN_100203b0(void) { DAT_10042e00 = 7; return DAT_10042e00; }"
ALLOCATOR = "int FUN_100203b0(void) { void *p; p = malloc(8); return 1; }"


def classify(bodies):
    return pp.classify_function(SPECIMEN, None, bodies)


# --- the class admits the measured shape when its callees are provably pure ---

def test_admits_a_delegate_calling_outbuf_mutator_with_pure_callees():
    assert classify({"FUN_100203b0": PURE_GETTER}) == "outbuf_leaf"


def test_purity_is_transitive_through_a_chain():
    assert classify({"FUN_100203b0": PURE_CHAIN_OUTER,
                     "FUN_10020320": PURE_CHAIN_INNER}) == "outbuf_leaf"


def test_known_pure_externals_need_no_body():
    """SetRect writes only through the RECT the caller owns."""
    assert "SetRect" in pp._PURE_EXTERNAL_CALLEES
    assert classify({"FUN_100203b0": PURE_GETTER}) == "outbuf_leaf"


# --- and abstains on every way of being unsure -------------------------------

def test_missing_callee_body_blocks_the_class():
    """Unproven is treated as unsafe: no body, no clearance."""
    assert classify({}) != "outbuf_leaf"


def test_a_callee_that_writes_a_global_blocks_the_class():
    """The measured case -- a magic-static lazy initialiser."""
    assert classify({"FUN_100203b0": GLOBAL_WRITER}) != "outbuf_leaf"


def test_an_allocating_callee_blocks_the_class():
    assert classify({"FUN_100203b0": ALLOCATOR}) != "outbuf_leaf"


def test_a_broken_chain_blocks_the_class():
    """Outer callee is clean but its own callee was not supplied."""
    assert classify({"FUN_100203b0": PURE_CHAIN_OUTER}) != "outbuf_leaf"


def test_reading_a_global_is_allowed():
    reader = "int FUN_100203b0(void) { return DAT_10042e00 + g_width; }"
    assert classify({"FUN_100203b0": reader}) == "outbuf_leaf"


def test_recursion_is_cycle_guarded():
    a = "int FUN_100203b0(void) { return FUN_10020320(); }"
    b = "int FUN_10020320(void) { return FUN_100203b0(); }"
    classify({"FUN_100203b0": a, "FUN_10020320": b})   # must terminate, not hang


# --- mutator_leaf keeps precedence, and its safety gate is untouched ---------

def test_a_callee_free_mutator_still_goes_to_mutator_leaf():
    """outbuf_leaf must never intercept what the safer synth path can prove."""
    no_calls = """
void __cdecl F(uint *pOut,int a)
{
  pOut[6] = a;
  *pOut = *pOut | 1;
  return;
}
"""
    assert pp.classify_function(no_calls, None, {}) == "mutator_leaf"


# --- extent derivation -------------------------------------------------------

def test_extent_is_the_highest_written_offset():
    _, _, body = pp._strip_comments(SPECIMEN).partition("{")
    assert pp.outbuf_extent(body, "pViewports") == 36     # p[8] -> 32, +4


def test_extent_abstains_on_a_computed_offset():
    body = "{ pOut[i] = 1; }"
    assert pp.outbuf_extent(body, "pOut") is None


def test_extent_is_none_when_nothing_is_written():
    assert pp.outbuf_extent("{ int x; x = 1; }", "pOut") is None


def test_a_function_whose_extent_cannot_be_derived_is_not_admitted():
    computed = """
void __cdecl F(uint *pOut,int i)
{
  int v;
  v = FUN_100203b0();
  pOut[i] = v;
  *pOut = *pOut | 1;
  return;
}
"""
    assert pp.classify_function(computed, None, {"FUN_100203b0": PURE_GETTER}) != "outbuf_leaf"

"""Abstention: the pipeline is allowed to say it does not know.

MEASURED ORIGIN, 2026-08-06. `Sgd2fr_D2Client_IsMouseOver800NewStatsButton` is
`return FUN_10001d70();`. The worker was shown the callee's NAME and nothing
else, had no way to decline, and produced `CLIENT_CheckViewportVisible` --
coherent, well-structured, honestly hedged, and a description of a function that
does not exist.

It scored well. It passed falsify. Neither could see it:
`analyze_function_completeness` is computed FROM the documentation, so no fact
about the binary can lower it, and falsify finds mechanical contradictions
against the disassembly, of which there were none -- the documentation was
internally consistent and simply about the wrong thing.

This is the same failure mode as four other defects found in this codebase on
the same day: a mechanism with no input degrading to a confident default rather
than announcing it has nothing to work with. `_callee_readiness` returned 1.0
for functions whose callees were never scanned. `_all_callees_pure` was never
fed. `low_frequency_status` was called from nowhere. In every case the system
answered instead of abstaining.

THE RULE IS DELIBERATELY NARROW. It fires only where the function's own body
carries essentially no information -- a few statements delegating to a callee
nobody has documented and whose body could not be read. A large function with an
undocumented callee has plenty of its own logic to describe and must not wait.

Deferral is not failure and not durable: no consecutive_fails, no blacklist. The
function becomes documentable the moment its callee is, which is exactly what
the bottom-up ordering arranges.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

fd = pytest.importorskip("fun_doc")

THIN = "uint FUN_10018860(void)\n{\n  byte bVar1;\n  bVar1 = FUN_10001d70();\n  return bVar1;\n}"
UNDOC_NO_BODY = [{"name": "FUN_10001d70", "undocumented": True}]


# --- the measured case -------------------------------------------------------

def test_the_measured_case_is_deferred():
    defer, reason = fd.insufficient_evidence(THIN, UNDOC_NO_BODY)
    assert defer
    assert "FUN_10001d70" in reason


def test_the_reason_states_what_is_missing():
    """A deferral nobody can act on is just a silent skip."""
    _, reason = fd.insufficient_evidence(THIN, UNDOC_NO_BODY)
    assert "wrapper" in reason and "could not be read" in reason


# --- what must NOT be deferred ----------------------------------------------

def test_a_readable_callee_is_evidence():
    """If we can SEE the callee, the wrapper is documentable -- that is exactly
    the fix that moved recall from 0.167 to 1.000."""
    ctx = [{"name": "FUN_10001d70", "undocumented": True,
            "body": "undefined1 f(void){ SetRect(&r,-0xc2,-0xa0,-0x2a,-8); }"}]
    assert fd.insufficient_evidence(THIN, ctx)[0] is False


def test_a_documented_callee_is_evidence():
    ctx = [{"name": "GetScreenHeight", "undocumented": False}]
    assert fd.insufficient_evidence(THIN, ctx)[0] is False


def test_one_documented_callee_among_several_is_enough():
    ctx = [{"name": "A", "undocumented": True},
           {"name": "GetWidth", "undocumented": False}]
    assert fd.insufficient_evidence(THIN, ctx)[0] is False


def test_a_function_with_no_callees_is_its_own_evidence():
    """A real leaf describes itself; there is nothing to wait for."""
    body = "int f(int a)\n{\n  return (a * 3 + 1) & 0xff;\n}"
    assert fd.insufficient_evidence(body, [])[0] is False


def test_a_substantial_function_is_never_deferred():
    """A large body has plenty of its own logic to describe. Deferring it would
    delay work that would have succeeded."""
    body = ("int f(int a)\n{\n  int x;\n" + "\n".join(
        f"  x = step{i}(x);" for i in range(20)) + "\n  return x;\n}")
    assert fd.insufficient_evidence(body, UNDOC_NO_BODY)[0] is False


def test_an_empty_decompilation_is_not_a_deferral():
    """No body is a different failure (not_a_function / decompile timeout) with
    its own handling -- this rule must not swallow it."""
    assert fd.insufficient_evidence("", UNDOC_NO_BODY)[0] is False
    assert fd.insufficient_evidence(None, UNDOC_NO_BODY)[0] is False


# --- statement counting ------------------------------------------------------

def test_declarations_do_not_count_as_statements():
    """Ghidra emits a block of local declarations that say nothing about what
    the function does; counting them would make every function look
    substantial and the rule would never fire."""
    body = ("uint f(void)\n{\n  int iVar1;\n  byte bVar2;\n  undefined4 uVar3;\n"
            "  char *pcVar4;\n  bVar2 = FUN_1000();\n  return bVar2;\n}")
    assert len(fd._body_statements(body)) == 2


def test_comments_and_braces_are_not_statements():
    body = "int f(void)\n{\n  /* a note */\n  // another\n  return 1;\n}"
    assert fd._body_statements(body) == ["return 1;"]


def test_the_threshold_is_where_the_measurement_put_it():
    assert fd._THIN_WRAPPER_MAX_STATEMENTS == 3


def test_just_over_the_threshold_is_kept():
    body = ("int f(void)\n{\n  a();\n  b();\n  c();\n  d();\n  return 1;\n}")
    assert fd.insufficient_evidence(body, UNDOC_NO_BODY)[0] is False


# --- lines that begin with "(" ----------------------------------------------
# MEASURED 2026-08-06. `first = ln.split("(")[0].split()[0] if ln.split() else ""`
# guards the RAW line while indexing a DIFFERENT split, so any decompiled line
# beginning with "(" raised IndexError and crashed the whole documentation run.
# Three runs in the blind sample died this way, each leaving last_result='scanned'
# and no runs.jsonl entry -- a completed-looking skip with no record of what
# happened. A silent-outcome bug inside the fix for silent outcomes.

@pytest.mark.parametrize("line", [
    "(*pfn)(a, b);",
    "(void)result;",
    "(char *)dest = src;",
    "()",
    "(",
])
def test_a_line_starting_with_a_paren_does_not_crash(line):
    body = "int f(void)\n{\n  %s\n  return 1;\n}" % line
    fd._body_statements(body)           # must not raise


def test_such_a_line_still_counts_as_a_statement():
    body = "void f(void)\n{\n  (*pfn)(a);\n}"
    assert fd._body_statements(body) == ["(*pfn)(a);"]


def test_the_predicate_survives_it_end_to_end():
    body = "void f(void)\n{\n  (*pfn)(a);\n}"
    fd.insufficient_evidence(body, [{"name": "X", "undocumented": True}])

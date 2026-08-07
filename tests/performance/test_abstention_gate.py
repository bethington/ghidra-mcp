"""The abstention gate must be able to fire.

F35, measured 2026-08-06. `insufficient_evidence()` exists so the pipeline can
decline instead of inventing a domain, and it has fired 0 times in 10,872
completed runs -- 0 of 48 on the subject binary the day it shipped. The decisive
case is `d2::CelFile_Api::GetCel`:

    Cel_View CelFile_Api::GetCel(unsigned int direction, unsigned int frame) {
      CelFile_Wrapper wrapper(this->Get_());
      return wrapper.GetCel(direction, frame);
    }

Three authored statements, delegating to a callee nobody has documented -- the
exact shape the gate describes. It did not fire. Instead the pipeline produced
`Sgd2fr_ResolveLookupResult`, a coherent, confident, entirely invented domain.

TWO CAUSES, both of which this file pins:

  COMMENTS   the decompile carries the plate and every inline comment, so the
             body measured 66 "statements". This is F31's defect in a second
             consumer, found the same day the first was fixed.

  SCAFFOLDING  strip the comments and 9 of the remaining 20 are MSVC exception
             bookkeeping -- pSehScopeTable, pSavedExceptionList,
             dwSecurityCookie, ExceptionList, dwSehState x3, two throw thunks.
             The compiler makes a three-line forwarder present as a
             twenty-statement body, so the gate declines to fire and the
             pipeline invents.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_FUNDOC = Path(__file__).resolve().parent.parent.parent / "fun-doc"
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

fd = pytest.importorskip("fun_doc")


# The real GetCel decompile, trimmed to its shape: a documentation comment
# block, the MSVC SEH preamble, three authored statements, the SEH epilogue.
_GETCEL = """
/* Resolves a single lookup result by validating and rebuilding via
   Sgd2fr_BuildLookupResult, returning the populated result.

   Algorithm:
   1. Validate this->bStatus != 0xFF; abort via C++ throw if uninitialized.
   2. Initialize a wrapper context with this->pData.
   3. On success copy pData into pLookupResult. */

sgd2fr_LookupResult * __thiscall
Sgd2fr_ResolveLookupResult(void *this,sgd2fr_LookupResult *pLookupResult,uint dwReserved,uint dwKey)
{
  pSehScopeTable = &sehScopeTable_ResolveLookupResult;
  pSavedExceptionList = ExceptionList;
  dwSecurityCookie = g_dwSecurityCookie ^ (uint)&stack0xfffffffc;
  ExceptionList = &pSavedExceptionList;
  dwSehState = 0;
  if (*(char *)((int)this + 4) == -1) {
    thunk_FUN_10001e60();
  }
  dwSehState = 0xffffffff;
  InitializeRecordHeader(&dwWrapperPad,*(uint *)this);
  pLookupResultBuilt = Sgd2fr_BuildLookupResult(&dwWrapperPad,&lookupResultBuf,dwKey);
  dwSehState = 1;
  ExceptionList = pSavedExceptionList;
  return pLookupResult;
}
"""


def test_comment_prose_is_not_a_statement():
    """MEASURED: 66 with comments, 20 without. A sentence about the function is
    not a statement of the function -- F31's rule, second consumer."""
    n = len(fd._body_statements(_GETCEL))
    assert n <= 20, f"comments still counted as statements ({n})"


def test_compiler_bookkeeping_is_not_authored_work():
    """The author wrote three statements. MSVC wrote nine. Counting the
    compiler's makes a forwarder look substantial and disarms the gate."""
    stmts = fd._body_statements(_GETCEL)
    assert len(stmts) <= 5, (
        f"scaffolding still counted: {len(stmts)} statements -> {stmts}")


def test_the_measured_case_is_counted_honestly():
    """MEASURED on the real function, not asserted: 66 statements before the
    fix, 9 after (comments 66->20, scaffolding 20->11, line-joining 11->8, and
    +1 restoring the delegated call the first filter wrongly dropped).

    NOTE what this does NOT claim. GetCel still does not ABSTAIN, because 9 is
    above `_THIN_WRAPPER_MAX_STATEMENTS = 3`. The counter was broken and is now
    fixed; whether the threshold is right for C++ forwarders -- which compile to
    ~9 statements once object returns and validation are included -- is a
    separate calibration question that needs corpus evidence, not an assertion
    here. Pinning `defer is True` would be encoding a hypothesis as a fact."""
    stmts = fd._body_statements(_GETCEL)
    assert len(stmts) <= 10, f"counter regressed: {len(stmts)} statements"
    assert any("Sgd2fr_BuildLookupResult" in s for s in stmts), (
        "the DELEGATED CALL must survive -- it is the whole subject of the gate")


def test_a_substantial_function_still_documents():
    """The control. A gate that abstained on everything would pass every test
    above while destroying the pipeline -- the same 'a detector that claims
    nothing' trap the library lanes guard against."""
    body = "\n".join(f"  iVar{i} = Compute{i}(a, b);" for i in range(25))
    body = "int Big(int a, int b)\n{\n" + body + "\n  return iVar1;\n}\n"
    defer, _ = fd.insufficient_evidence(body, "")
    assert defer is False


def test_a_small_function_with_a_DOCUMENTED_callee_still_documents():
    """Delegation is only fatal when the delegate is unknown. If the callee has
    a real name, the domain IS recoverable and abstaining would waste it."""
    body = ("void Small(void)\n{\n  CLIENT_DrawInterfaceBarBackground();\n"
            "  return;\n}\n")
    ctx = [{"name": "CLIENT_DrawInterfaceBarBackground",
            "undocumented": False, "body": ""}]
    defer, _ = fd.insufficient_evidence(body, ctx)
    assert defer is False


def test_a_scaffolding_NAME_in_an_argument_does_not_kill_a_real_call():
    """FOUND BY READING THE OUTPUT, not by a failing test. The first filter
    dropped any statement matching the scaffolding pattern, which discarded

        pLookupResultBuilt = Sgd2fr_BuildLookupResult(&wrap, &buf, ..., dwSecurityCookie);

    because MSVC passes the stack cookie as an ARGUMENT to it. That is the real
    delegated call -- the single statement a delegation gate exists to see --
    and losing it made the count look better while making the answer worse."""
    stmt = ("pRes = Sgd2fr_BuildLookupResult(&wrap,&buf,(T *)dwReserved,dwKey,"
            "dwSecurityCookie);")
    assert not fd._is_scaffolding_statement(stmt)


def test_pure_bookkeeping_is_still_dropped():
    """The mirror: a filter that stopped dropping anything would pass the test
    above while undoing the fix."""
    for stmt in ("puVar1 = *in_FS_OFFSET;",
                 "*in_FS_OFFSET = &pStack_10;",
                 "dwSecurityCookie = g_dwSecurityCookie ^ (uint)&stack0xfffffffc;",
                 "ExceptionList = pSavedExceptionList;",
                 "__security_check_cookie(uVar2);"):
        assert fd._is_scaffolding_statement(stmt), stmt


def test_wrapped_lines_count_as_one_statement():
    """Independent of comments and scaffolding: the decompiler breaks long
    calls across lines, and a line counter reported 4 for this one statement."""
    body = ("void f(void)\n{\n"
            "  pResult =\n"
            "  DoTheWork\n"
            "            (&a,&b,(T *)c,d,\n"
            "             e);\n"
            "  return;\n}\n")
    stmts = fd._body_statements(body)
    assert len(stmts) == 2, stmts
    assert any("DoTheWork" in s for s in stmts)

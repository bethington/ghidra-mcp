"""Unit tests for fun-doc's library-code heuristic detector.

The detector classifies functions as MSVC CRT / STL / iostream / SEH code
based on cheap structural signals (callee names, body substrings, function
name patterns). False positives are expensive (user code wrongly skipped) so
these tests verify the decision boundaries on both ends:

- True positives: synthetic decompile bodies that clearly evoke library code
- True negatives: realistic user-code decompile bodies that must not trip

Fast, pure Python, no Ghidra, no I/O.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


_FUN_DOC_DIR = Path(__file__).resolve().parent.parent.parent / "fun-doc"
sys.path.insert(0, str(_FUN_DOC_DIR))

from library_code_detector import (  # noqa: E402
    HARD_CALLEE_NAMES,
    detect_library_code,
    format_plate,
)


# ---------------------------------------------------------------------------
# True positives — library code must be flagged
# ---------------------------------------------------------------------------


def test_hard_callee_seh_prolog_flags_as_library():
    """A function that calls __SEH_prolog4 is statically-linked CRT machinery."""
    body = """
    void FUN_10052ba0(int param_1) {
        __SEH_prolog4();
        // ... user code ...
        __SEH_epilog4();
        return;
    }
    """
    result = detect_library_code("FUN_10052ba0", body)
    assert result.is_library
    assert result.confidence >= 0.6
    assert any("hard_callee" in r for r in result.reasons)


def test_security_check_cookie_alone_not_enough():
    """`__security_check_cookie` is the /GS stack-cookie helper -- present
    in MANY user functions compiled with /GS, NOT a library-only signal.
    It belongs in SOFT_BODY_SIGNALS, so its presence alone (no other
    signals) must NOT classify the function as library code. Without this
    rule the detector misfires on ~10% of an authored binary."""
    body = "int func() { do_user_stuff(); __security_check_cookie(local_cookie); return 0; }"
    result = detect_library_code("FUN_aaaa", body)
    assert not result.is_library, (
        "Single /GS signal must not classify -- "
        "/GS is emitted into user code, not library-only"
    )


def test_hard_callee_invoke_watson_flags_as_library():
    """_invoke_watson is the MSVC invalid-parameter handler (CRT only)."""
    body = "void func() { _invoke_watson(0,0,0,0,0); }"
    result = detect_library_code("FUN_bbbb", body)
    assert result.is_library


def test_cxx_throw_flags_as_library():
    """_CxxThrowException is the C++ exception-throwing runtime."""
    body = "void func() { _CxxThrowException(&ex, 0); }"
    result = detect_library_code("FUN_cccc", body)
    assert result.is_library


def test_canonical_crt_name_flags_as_library_without_body():
    """A function named `_strtoi64@4` is canonically a CRT export. The
    name alone is hard evidence even without decompile body."""
    result = detect_library_code("_strtoi64@4", "")
    assert result.is_library


def test_mangled_cxx_operator_new_flags_as_library():
    """`??2@YAPAXI@Z` is the mangled MSVC `operator new(size_t)` -- always
    a library function, never authored source."""
    result = detect_library_code("??2@YAPAXI@Z", "")
    assert result.is_library


def test_std_namespace_name_flags_as_library():
    """`std::_Allocator_base` and similar STL internals are library code."""
    result = detect_library_code("std::_Allocator_base", "")
    assert result.is_library


def test_parse_signed_short_pattern_matches_with_body_signal():
    """The motivating example: `ParseSignedShort` with iostream callees.
    The name alone is a soft signal; combined with a body signal it must
    classify as library."""
    body = """
    long FUN_10052ba0(int *istream, short *out_value) {
        // ... iostream parsing logic ...
        std::basic_istream::sentry sentry(*istream);
        if (!sentry) {
            return std::_Xinvalid_argument("bad istream");
        }
        return 0;
    }
    """
    result = detect_library_code("ParseSignedShort", body)
    assert result.is_library
    assert len(result.reasons) >= 2  # soft_name + soft_body OR hard_callee


def test_hard_callee_substring_in_body_without_callee_list():
    """When call-graph data isn't populated, the detector falls back to
    substring search on the decompile body for HARD_CALLEE_NAMES symbols.
    `__SEH_prolog4` is hard-callee, `__chkstk` is soft body (compiler-emitted)."""
    body = "void foo() { __SEH_prolog4(); user_helper(); }"
    result = detect_library_code("FUN_dddd", body)
    assert result.is_library


def test_explicit_callees_iterable_classifies():
    """Direct callee enumeration is more authoritative than substring."""
    result = detect_library_code(
        name="FUN_1234",
        decompile="",
        callees=["__SEH_prolog4", "user_helper_function"],
    )
    assert result.is_library


# ---------------------------------------------------------------------------
# True negatives — user code must not be flagged
# ---------------------------------------------------------------------------


def test_plain_user_function_not_flagged():
    """A simple user function with no library signals must pass through."""
    body = """
    int CalculateDamage(int base, int multiplier) {
        return base * multiplier + 10;
    }
    """
    result = detect_library_code("CalculateDamage", body)
    assert not result.is_library
    assert result.reasons == []


def test_function_calling_user_helpers_not_flagged():
    """A function that calls other game functions (not CRT) stays unflagged."""
    body = """
    void OnEnemyHit(Unit *unit) {
        DealDamage(unit, 100);
        TriggerEffect(unit, EFFECT_BLOOD);
        UpdateHealthBar(unit);
    }
    """
    result = detect_library_code("OnEnemyHit", body)
    assert not result.is_library


def test_fun_xxx_name_alone_not_flagged():
    """A bare `FUN_xxxxxxxx` name with no body signals must not trip."""
    result = detect_library_code("FUN_6fdb1234", "void foo() { return; }")
    assert not result.is_library


def test_soft_signal_alone_not_enough():
    """A single soft signal alone is not enough to classify -- requires 2+
    soft signals or 1 hard. Here we use `vsnprintf` which only matches
    SOFT_NAME_PATTERNS, without any body evidence."""
    result = detect_library_code("vsnprintf_helper", "void foo() { do_thing(); }")
    assert not result.is_library, "Single soft signal must not classify"


def test_user_function_with_security_cookie_assignment_flagged():
    """`__security_cookie` (the global) appearing in body is a soft signal --
    compiled code reads this for stack-canary checks. By itself it's not
    enough; needs corroborating evidence."""
    # Only soft body signal — should NOT flag
    body = "void foo() { uint local_var = __security_cookie; bar(); }"
    result = detect_library_code("DoUserThing", body)
    assert not result.is_library


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_inputs_safe():
    """Empty / None inputs must not crash."""
    assert not detect_library_code(None, None).is_library
    assert not detect_library_code("", "").is_library
    assert not detect_library_code(None, "", callees=[]).is_library


def test_format_plate_renders_reasons():
    """The auto-stamp plate must mention the matched reasons so a human
    reviewer can audit why a function was classified."""
    body = "void foo() { __SEH_prolog4(); }"
    result = detect_library_code("FUN_test", body)
    plate = format_plate(result)
    assert "MSVC CRT" in plate
    assert "__SEH_prolog4" in plate or "hard_callee" in plate


def test_hard_callee_names_set_is_nonempty_and_canonical():
    """Smoke-check the HARD_CALLEE_NAMES set holds the symbols that are
    NEVER emitted into authored user functions (SEH prologs, CRT init/exit,
    iostream-only helpers). /GS helpers like `__security_check_cookie`
    intentionally live in SOFT_BODY_SIGNALS instead."""
    expected_canonical = {
        "__SEH_prolog4", "__except_handler4",
        "_invoke_watson", "_CxxThrowException",
        "_Xinvalid_argument",
    }
    assert expected_canonical.issubset(HARD_CALLEE_NAMES)
    # /GS helpers must NOT be hard — would false-positive on user code.
    assert "__security_check_cookie" not in HARD_CALLEE_NAMES
    assert "__chkstk" not in HARD_CALLEE_NAMES


def test_v591_locale_atexit_patterns_added():
    """v5.9.1 added _Atexit / _Setgloballocale / TLS-lazy-init helpers to
    HARD_CALLEE_NAMES. Caught the SetGlobalLocale miss observed on release
    day where the worker spent 92K tokens documenting an msvcp library
    thunk. These symbols are MSVCP internals; user code uses `atexit()`
    (no underscore) and never calls `_Setgloballocale` directly."""
    for sym in ("_Atexit", "_Setgloballocale", "__dyn_tls_init", "__tlregdtor"):
        assert sym in HARD_CALLEE_NAMES, f"v5.9.1 pattern missing: {sym}"


def test_set_global_locale_pattern_classifies():
    """End-to-end check using a synthetic version of the BH.dll
    SetGlobalLocale body that escaped detection in v5.9.0. The decompile
    body contains a call to `_Atexit` (the MSVCP atexit-registration
    helper) and references `std::locale`, which together must classify
    as library."""
    body = '''
    void SetGlobalLocale(void *pFacet) {
        if (g_bGlobalLocaleFacetInitialized == 0) {
            g_bGlobalLocaleFacetInitialized = 1;
            _Atexit(_Cleanup_global_locale);
        }
        g_pGlobalLocaleFacet = pFacet;
        // see std::locale internal init
    }
    '''
    result = detect_library_code("SetGlobalLocale", body)
    assert result.is_library, f"v5.9.0 miss should now classify: {result}"
    assert any("_Atexit" in r for r in result.reasons), result.reasons


def test_confidence_increases_with_more_hits():
    """Multiple hard hits should push confidence higher than single hits."""
    body_one = "void foo() { __SEH_prolog4(); }"
    body_two = "void foo() { __SEH_prolog4(); __security_check_cookie(c); }"
    one = detect_library_code("FUN_a", body_one)
    two = detect_library_code("FUN_b", body_two)
    # Both classified; two has stronger evidence
    assert one.is_library and two.is_library
    # At minimum, two's confidence is no worse than one's
    assert two.confidence >= one.confidence


# ---------------------------------------------------------------------------
# Copilot review false-positive guards (v5.11.5)
#
# The original HARD_NAME_PATTERNS list had two regexes that were too broad
# and would misclassify legitimate user code:
#
#   1. `^\?[A-Za-z_].*@@` matched ANY MSVC-mangled name, including
#      user-authored exported C++ APIs whose mangled form happens to
#      share the same outer shape (e.g., `?MyApiFunc@MyApp@@YA...`).
#      Restricted to known STL/MSVCP namespace markers.
#
#   2. `^(Parse|Read|Write|Get|Put|Skip)?(Signed|Unsigned)?(Char|Short|
#      Int|Long|Float|Double|Hex|...)(Value|Field|Token)?$` matched
#      legitimate user functions like `GetInt`, `ReadLong`, `WriteFloat`,
#      and even just `Char` alone. Removed; the narrower
#      SOFT_NAME_PATTERNS entry already catches the real library cases
#      when corroborated by body evidence.
#
# These tests pin the false-positive prevention.
# ---------------------------------------------------------------------------


def test_user_mangled_cxx_export_not_misclassified():
    """A user-authored C++ class method with a non-std namespace and a
    clean body (no library callees) should NOT be classified as library
    code. The pre-v5.11.5 regex would catch this purely on the mangled
    name shape — losing real user code to the auto-skip."""
    # Mangled form: ?DoWork@MyApp@@QAEHXZ
    # = MyApp::DoWork (instance method, returns int, no params)
    result = detect_library_code("?DoWork@MyApp@@QAEHXZ", "iVar1 = this->field_4; return iVar1;")
    assert not result.is_library, (
        f"User-authored export was misclassified: reasons={result.reasons}"
    )


def test_std_mangled_name_still_classifies():
    """The restriction must not regress the actual library cases —
    `?_Xinvalid_argument@std@@YAXPBD@Z` (std::_Xinvalid_argument) is
    canonical STL and must still flag."""
    result = detect_library_code("?_Xinvalid_argument@std@@YAXPBD@Z", "")
    assert result.is_library


def test_chrono_namespace_mangled_classifies():
    """`?...@chrono@@` is std::chrono internals — must still classify."""
    result = detect_library_code("?duration_cast@chrono@@YA?AV12@H@Z", "")
    assert result.is_library


def test_GetInt_alone_not_misclassified():
    """`GetInt` is a common user-function name (config readers, deserializers,
    etc.). The pre-v5.11.5 broad HARD regex matched it directly. After the
    fix, with no body evidence, it must NOT classify as library."""
    result = detect_library_code("GetInt", "iVar1 = this->m_value; return iVar1;")
    assert not result.is_library, (
        f"GetInt was misclassified: reasons={result.reasons}"
    )


def test_ReadLong_with_user_body_not_misclassified():
    """`ReadLong` from a user binary deserializer. No library callees
    in the body. Must NOT classify."""
    body = """
    lVar1 = *(longlong *)(this->buffer + this->offset);
    this->offset = this->offset + 8;
    return lVar1;
    """
    result = detect_library_code("ReadLong", body)
    assert not result.is_library


def test_WriteFloat_isolated_not_misclassified():
    """Same as above but for `WriteFloat`. User-authored buffer writer."""
    body = "*(float *)(this->buf + this->pos) = fVar1; this->pos = this->pos + 4;"
    result = detect_library_code("WriteFloat", body)
    assert not result.is_library


def test_Char_function_alone_not_misclassified():
    """The original broad regex even matched a function literally named
    `Char`. Pin that this is no longer a HARD signal."""
    result = detect_library_code("Char", "return this->m_char;")
    assert not result.is_library


def test_ParseSignedShort_with_iostream_body_still_classifies():
    """The motivating original case (test_parse_signed_short_pattern_matches_with_body_signal
    above already covers this with iostream callees). Re-pinning here as
    part of the false-positive guard suite: when the name pattern IS
    corroborated by body evidence, classification still works through
    the SOFT pattern + body callee path."""
    body = """
    _Xinvalid_argument(s);
    iVar1 = std::ios_base::flags(this);
    """
    result = detect_library_code("ParseSignedShort", body)
    assert result.is_library

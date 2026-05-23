"""Heuristic library-code detector for fun-doc.

Some binaries statically link MSVC CRT / STL / iostream / vc-runtime code into
their `.text` section. Without a PDB, Ghidra cannot tell that code apart from
the user's actual source — so fun-doc workers happily queue and document
`ParseSignedShort` and other CRT internals, burning 100K+ tokens for marginal
score gain on code that is not even part of the binary's authored surface.

This module classifies a function as "library code" using cheap, structural
signals already available from the decompile we fetch on the cold path. When a
function trips the detector, the worker:

    1. Stamps a generic plate ("MSVC CRT helper — auto-classified")
    2. Sets `library_code: True` so the selector permanently skips it
    3. Returns without invoking the LLM

The detector is intentionally conservative — false positives cost real work
(a user-authored function gets wrongly skipped). We require at least one
hard-evidence signal (CRT-only callee or canonical CRT name) OR two
medium-confidence signals.

To clear the flag for a specific function: pin it (pinned bypasses skip), or
run `--scan --refresh` / dashboard "Refresh Top N", same as the other
one-shot blacklists (`recovery_pass_done`, `decompile_timeout`).

Public API:
    detect_library_code(name, decompile, callees=None) -> DetectionResult
    LIBRARY_PLATE_TEMPLATE -- canonical plate text for auto-stamping
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional


HARD_NAME_PATTERNS = (
    # MSVC CRT internal helpers
    re.compile(r"^_+(crt|invoke_watson|except_handler|security_check|amsg_exit|setjmp|aullshr|chkstk|alloca_probe|local_unwind|cinit|tlsdtor|RTC_)"),
    # Operator new/delete and CXX scalar/vector
    re.compile(r"^\?\?[23](@|_)"),
    # MSVC C++ mangled names with a recognized STL/MSVCP namespace.
    # The earlier `^\?[A-Za-z_].*@@` (any mangled name) was too broad:
    # it matched user-authored exported C++ APIs whose mangled names
    # happen to follow the same outer shape (e.g., `?MyApiFunc@MyApp@@YA…`).
    # Restricting to the std / experimental / chrono / filesystem /
    # ranges / regex / thread / locale / iostream namespace markers
    # keeps the CRT/STL cases (the actual library targets) without
    # catching every user-namespaced export.
    re.compile(r"^\?[A-Za-z_].*@(std|experimental|chrono|filesystem|ranges|regex|locale|ios_base|_System_error_category)@@"),
    # C++ standard library namespace
    re.compile(r"^(std::|__std_|__crt_|_Std|_VEC_memcpy|_VEC_memzero)"),
    # CRT internal mangled exports (e.g. `_strtoi64@4`, `_atof@4`)
    re.compile(r"^_(strtoi64|strtoui64|wcstoi64|wcstoui64|atof|atoi|atol|atoll|strtod|strtol|strtoul|memcpy_s|strcpy_s|wcscpy_s|sprintf_s|vsnprintf_s|fread_s)(@\d+)?$"),
    # (REMOVED v5.11.5) The iostream/locale parser HARD regex
    # `^(Parse|Read|Write|Get|Put|Skip)?(Signed|Unsigned)?(Char|Short|...)
    #  (Value|Field|Token)?$` was too broad — it matched user-authored
    # functions like `GetInt`, `ReadLong`, `WriteFloat`, even literally
    # `Char`. The narrower SOFT_NAME_PATTERNS entry (Parse|Read|Convert
    # + Signed/Unsigned + numeric type) catches the actual library
    # cases when corroborated by body/callee evidence; removing the
    # broad HARD form prevents false-positive classification.
)

# Functions decompile output calls when it's CRT or VC-runtime. Detecting any of
# these inside the body is strong evidence the function is statically-linked
# CRT, NOT user code (user code would only reach these through the import
# table, never via direct .text reference).
HARD_CALLEE_NAMES = frozenset({
    # SEH prologs/handlers (MSVC-only, generated, never authored). The /GS
    # stack-cookie helpers (`__security_check_cookie`, `__report_*`) are
    # NOT in this set -- they're emitted into ordinary user functions by
    # the compiler, so they live in SOFT_BODY_SIGNALS where they contribute
    # supporting evidence only.
    "__SEH_prolog4", "__SEH_epilog4",
    "__EH_prolog", "__EH_epilog",
    "__except_handler4", "__except_handler3",
    "__CxxFrameHandler", "__CxxFrameHandler3",
    "_CxxThrowException",
    "_local_unwind", "_global_unwind",
    # CRT init / shutdown — only the program-startup / exit path. These
    # symbols are referenced from CRT code itself, not from authored
    # functions.
    "_amsg_exit", "__crt_debugger_hook",
    "_cinit", "_initterm", "_initterm_e",
    "_invoke_watson", "_invalid_parameter", "_invalid_parameter_noinfo",
    "unhandled_exception", "_terminate",
    "__std_terminate", "__std_exception_copy", "__std_exception_destroy",
    # iostream helpers — dead giveaways for ParseSignedShort-style code
    # that never appear in authored user functions.
    "_Xinvalid_argument", "_Xout_of_range", "_Xlength_error", "_Xbad_alloc",
    # std::locale / atexit-registration helpers (v5.9.1 — caught the
    # SetGlobalLocale miss). These are MSVCP library internals; user code
    # registers atexit handlers via `atexit()` (no underscore) and never
    # calls `_Setgloballocale` / `_Atexit` directly.
    "_Atexit", "_Setgloballocale",
    "_Getcoll", "_Getfac", "_Getfmt",
    # CRT thread-local-storage lazy resolution. The DATATBLS_LazyResolve
    # family on BH.dll matched this pattern -- it's the MSVCRT lazy TLS
    # callback machinery, not user code.
    "__dyn_tls_init", "__dyn_tls_dtor",
    "__tlregdtor",
})

# Substrings that, when present in the decompile body, indicate library code.
# Lower confidence than HARD_CALLEE_NAMES (substring match → more false
# positives) but still useful as supporting evidence.
SOFT_BODY_SIGNALS = (
    # /GS stack-cookie machinery. Common in user code compiled with /GS, so
    # not a hard signal on its own -- but contributes evidence when paired
    # with library-typical names or other library signals.
    "__security_cookie",
    "__security_check_cookie",
    "__report_rangecheckfailure",
    "__report_gsfailure",
    "__chkstk",
    "_alloca_probe",
    # MSVCRT 64-bit integer arithmetic helpers (used by `long long` arithmetic).
    # User code with int64 ops will reference these too, hence soft.
    "_aulldiv", "_aullrem", "_aullshr", "_allshr", "_alldiv", "_allrem", "_allmul",
    # CRT errno / locale — appear in stdlib-touching user code as well.
    "_errno", "__doserrno",
    "_getmbcp", "_setmbcp", "___mb_cur_max_func",
    # SEH/CRT names visible in disassembly even of authored functions.
    "__except_handler",
    "_invoke_watson",
    "_invalid_parameter",
    "_amsg_exit",
    "__CxxFrameHandler",
    "_CxxThrowException",
    "_Xinvalid_argument",
    "_Xout_of_range",
    "_Xlength_error",
    "_Xbad_alloc",
    # std::basic_*, std::ios_*, std::locale -- usually library, but a
    # template instantiation in user code can name-leak into the function
    # body too. Soft.
    "std::basic_",
    "std::ios_",
    "std::locale",
    "std::_",
)

# Soft name signals. Less authoritative than HARD_NAME_PATTERNS but useful when
# combined with body signals.
SOFT_NAME_PATTERNS = (
    # Number parsing helpers: `ParseSignedShort`, `ReadUnsignedInt`, etc.
    re.compile(r"^(Parse|Read|Convert)(Signed|Unsigned)?\w*(Short|Int|Long|Float|Double|Hex)\w*$"),
    # MSVC mangled function names with `@@YA` (calling convention marker)
    re.compile(r"@@YA"),
    # vfprintf / vsprintf / vsnprintf family
    re.compile(r"^_?v?[sf]n?printf"),
    re.compile(r"^_?v?[sf]n?scanf"),
    # CRT internal lookup tables / locale helpers
    re.compile(r"^_?Get(LcMap|Loc|Locale|Mb|NumOf)"),
)


@dataclass
class DetectionResult:
    """Outcome of a library-code classification attempt."""

    is_library: bool
    confidence: float  # 0.0-1.0
    reasons: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.is_library


LIBRARY_PLATE_TEMPLATE = (
    "MSVC CRT / runtime helper - auto-classified by fun-doc library detector.\n"
    "\n"
    "This function is statically-linked compiler runtime code (CRT, STL,\n"
    "iostream, SEH machinery, or similar), NOT part of the binary's authored\n"
    "source. The library detector matched signals: {reasons}.\n"
    "\n"
    "Auto-classified to exclude from worker selection. To document anyway,\n"
    "pin this function or run `--scan --refresh` to reset the flag.\n"
    "\n"
    "For authoritative documentation of this code, load the matching\n"
    "msvcr*.pdb from the Microsoft symbol server. See Ghidra script\n"
    "Import_MSDL_PDB.py."
)


_HARD_NAME_HIT = "hard_name"
_HARD_CALLEE_HIT = "hard_callee:{}"
_SOFT_BODY_HIT = "soft_body:{}"
_SOFT_NAME_HIT = "soft_name"


def detect_library_code(
    name: Optional[str],
    decompile: Optional[str],
    callees: Optional[Iterable[str]] = None,
) -> DetectionResult:
    """Classify a function as library code or user code.

    Conservative: requires either one HARD signal (canonical CRT name OR
    direct call to a CRT-only helper) or two SOFT signals (soft name pattern +
    soft body substring). This keeps false positives low at the cost of some
    false negatives, which is the right trade — wrongly skipping a real
    function is more expensive than wrongly documenting a CRT one.

    Parameters:
        name: the function's display name (may be `FUN_xxxxxxxx` or anything)
        decompile: the C-like decompile body. May be None if not yet fetched.
        callees: optional iterable of callee names from analyze_for_doc or
            the call-graph endpoint. Direct enumeration beats substring search.

    Returns: DetectionResult. `is_library=True` means stamp+skip.
    """
    reasons: List[str] = []

    if name:
        for pat in HARD_NAME_PATTERNS:
            if pat.search(name):
                reasons.append(_HARD_NAME_HIT)
                break

    if callees:
        for cn in callees:
            if cn and cn in HARD_CALLEE_NAMES:
                reasons.append(_HARD_CALLEE_HIT.format(cn))
                # one hit is enough — don't blow up the reason list
                break

    body = decompile or ""
    # Cheap-callee substring search as a fallback when call-graph data isn't
    # populated yet. Each HARD_CALLEE_NAMES entry inside the body counts as a
    # hard hit because these symbols are never legitimate user-code call
    # targets (they're MSVC-internal, exposed only via direct .text linkage).
    if body and not any(r.startswith("hard_callee") for r in reasons):
        for cn in HARD_CALLEE_NAMES:
            if cn in body:
                reasons.append(_HARD_CALLEE_HIT.format(cn))
                break

    soft_hits = 0
    if name:
        for pat in SOFT_NAME_PATTERNS:
            if pat.search(name):
                reasons.append(_SOFT_NAME_HIT)
                soft_hits += 1
                break

    if body:
        for sig in SOFT_BODY_SIGNALS:
            if sig in body:
                reasons.append(_SOFT_BODY_HIT.format(sig))
                soft_hits += 1
                break

    hard_hits = sum(1 for r in reasons if r.startswith("hard_"))
    is_library = hard_hits >= 1 or soft_hits >= 2

    if is_library:
        confidence = min(1.0, 0.6 + 0.2 * hard_hits + 0.1 * soft_hits)
    else:
        confidence = 0.0

    return DetectionResult(is_library=is_library, confidence=confidence, reasons=reasons)


def format_plate(result: DetectionResult) -> str:
    """Render the canonical library-code plate using a detection result."""
    reasons_str = ", ".join(result.reasons) if result.reasons else "n/a"
    return LIBRARY_PLATE_TEMPLATE.format(reasons=reasons_str)


__all__ = [
    "DetectionResult",
    "detect_library_code",
    "format_plate",
    "LIBRARY_PLATE_TEMPLATE",
    "HARD_NAME_PATTERNS",
    "HARD_CALLEE_NAMES",
    "SOFT_BODY_SIGNALS",
    "SOFT_NAME_PATTERNS",
]

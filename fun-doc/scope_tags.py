"""The one canonical answer to "which tags take a function out of scope".

WHY THIS MODULE EXISTS

Six modules each declared their own literal copy of this vocabulary:

    conformance_dashboard.LIB_TAGS / EXCLUDE_TAGS   the panel denominators
    conf_ladder.OUT_OF_SCOPE_TAGS                  the conformance denominator
    fun_doc._ASSESS_LIB_TAGS                       the assess pass + selector
    library_scope.KNOWN_LIB_TAGS                   what the sweep emits
    retag_library_functions.LIB_TAGS               the retag lane
    scope_graph                                    the inference lane

They had already drifted. `conf_ladder.OUT_OF_SCOPE_TAGS` was missing
`LIB_MATH` and `LIB_UNKNOWN`, so a function tagged either one counted as
in-scope for conformance while every other panel counted it as library. That is
the same two-views-of-one-question shape as `listGlobals` vs
`/list_shadowed_globals` disagreeing on their denominator, and as the "untyped"
placeholder set living in three places -- both of which shipped as bugs. Six
copies means the seventh tag lands in five of them.

PROOF AND INFERENCE ARE DIFFERENT THINGS, AND STAY SEPARATE HERE

    KNOWN_LIB_TAGS   a lane MATCHED AN ARTIFACT: relocation-masked bytes against
                     a real .lib, a Function ID database hit, a BSim match above
                     calibrated floors. The claim is checkable and, being tied
                     to a durable Ghidra tag plus bookmark, recoverable.

    INFERRED_TAGS    nothing was matched. `SCOPE_EXCLUDED` says only that every
                     function referencing this one is library code -- which is
                     also true, by construction, of every mod entry point the
                     CRT calls. A swept function is not necessarily CRT: it may
                     be third-party, or authored and unreachable.

An inference must not be able to forge a claim, so the sweep writes
`SCOPE_EXCLUDED` and never a `LIB_*` tag, and no consumer folds the two counts
into one number. That distinction goes all the way down to SQL: `library_code`
means a lane matched an artifact, `scope_excluded` means the reference graph
inferred it. Recording an inference in a column whose name asserts the function
IS library code would make a later correction a string-parse instead of a
boolean flip.

WHICH SET DOES A CONSUMER WANT?

    "stop offering this to a worker"      ALL_EXCLUDING_TAGS
    "is this library code we identified"  KNOWN_LIB_TAGS
    "the in-scope denominator"            OUT_OF_SCOPE_TAGS  (adds the
                                          linker-generated structural tags)

This module holds constants only -- no imports, no I/O -- so the cheapest
consumer (a script that just needs the vocabulary) pays nothing for it.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# proof: a lane matched an artifact
# --------------------------------------------------------------------------

TAG_CRT = "LIB_CRT"
TAG_EH = "LIB_MSVC_EH"
TAG_MSVC = "LIB_MSVC"
TAG_SECURITY = "LIB_SECURITY"
TAG_MATH = "LIB_MATH"
TAG_UNKNOWN = "LIB_UNKNOWN"

#: Library code positively IDENTIFIED by a lane that matched an artifact.
KNOWN_LIB_TAGS = (TAG_CRT, TAG_EH, TAG_SECURITY, TAG_MATH, TAG_MSVC, TAG_UNKNOWN)

#: Alias for the dashboards, which have always called this `LIB_TAGS`.
LIBRARY_TAGS = KNOWN_LIB_TAGS


# --------------------------------------------------------------------------
# inference: the reference graph, not an artifact
# --------------------------------------------------------------------------

#: Written by `scope_graph`: every referrer is library code, to a fixed point.
#: Deliberately NOT a `LIB_*` tag -- see the module docstring.
SCOPE_EXCLUDED = "SCOPE_EXCLUDED"

INFERRED_TAGS = (SCOPE_EXCLUDED,)


# --------------------------------------------------------------------------
# structural: the linker made these, nobody wrote them
# --------------------------------------------------------------------------

STRUCTURAL_TAGS = ("STUB", "THUNK", "EXTERNAL")


# --------------------------------------------------------------------------
# the sets consumers actually ask for
# --------------------------------------------------------------------------

#: Retires a function from worker selection and from the conformance ladder.
#: Proof and inference both do that; they are still reported separately.
ALL_EXCLUDING_TAGS = KNOWN_LIB_TAGS + INFERRED_TAGS

#: The in-scope denominator: everything above, plus the structural tags. Panels
#: divide tagged counts by this population, so a numerator computed over a
#: WIDER set makes bars read past 100% (measured 105.3% on D2Common, 172.6% on
#: PD2_EXT before the subtraction was added).
OUT_OF_SCOPE_TAGS = ALL_EXCLUDING_TAGS + STRUCTURAL_TAGS


# --------------------------------------------------------------------------
# the property map that records WHY
# --------------------------------------------------------------------------

#: Ghidra string property map carrying the tag that justified an exclusion, so
#: the map is self-documenting when read raw. Shared by the globals rule
#: (`library_scope.apply_global_scope`), `scope_tag_library`, and `scope_graph`.
SCOPE_MAP = "Scope"


def is_excluding(tag: str) -> bool:
    """Does this tag take a function out of scope for documentation work?"""
    return tag in ALL_EXCLUDING_TAGS


def is_inference(tag: str) -> bool:
    """True for a tag that asserts no matched artifact -- only a graph verdict.

    Consumers that report counts use this to keep the two populations apart. A
    consumer that merely EXCLUDES does not need it: both kinds exclude equally.
    """
    return tag in INFERRED_TAGS

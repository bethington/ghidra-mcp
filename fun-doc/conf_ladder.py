"""conf_ladder.py -- the CONF_* equivalence-proof ladder, single-sourced.

Canonical spec: D2MOO/conformance/CONFORMANCE_TAXONOMY_V2.md.

Why this module exists: the ladder and fun-doc's `port_status` were two
disconnected state machines. `port_status` was written by the workers on every
transition; the CONF_ rung was written only by `port_live_prove.record_proof()`,
which the main worker path never called. The result was D2Client.dll carrying 0
CONF_ tags across 5,739 functions while SQL held 35 static-harness passes for
it, and CONF_DRAFT/CONF_VECTORS having zero writers anywhere in the codebase.

Everything that maps a `port_status` to a rung lives HERE, so `fun_doc.py`'s
live hook and `scripts/plan_conf_backfill.py`'s bulk backfill cannot drift.
Standalone -- imports nothing from fun_doc, so fun_doc may import it freely.
"""

from __future__ import annotations

# Ladder, low -> high. Index = rung strength.
CONF_LADDER = [
    "CONF_DRAFT",
    "CONF_VECTORS",
    "CONF_LIVE",
    "CONF_VETTED",
    "CONF_BATTLETESTED",
    "CONF_SHIPPED",
]

# OFF-ladder: attempted, not provable by the current oracle. Deliberately NOT a
# rung below CONF_DRAFT -- comparing it by strength would let a stale
# "stateful_skip" erase a real live proof.
CONF_BLOCKED = "CONF_BLOCKED"

# OFF-ladder: a rung was earned and then FALSIFIED (shadow divergence, failed
# adversarial re-proof, red regression case). Distinct from CONF_DRAFT on
# purpose: a refuted function carries a known counterexample and a known-wrong
# reimpl, so collapsing it into "untested" both hides the failure from tag
# queries and lets a worker re-draft -> re-prove against its own vectors ->
# re-promote the same broken reimpl, with no memory of the divergence.
CONF_REFUTED = "CONF_REFUTED"

# Retired rung (now the orthogonal `regression_frozen` flag in the Conf property
# map). 3 D2Common functions still carry it; it sorts top so the promote-only
# guard never demotes them before they are retagged.
LEGACY_TOP = "CONF_REGRESSION"

ALL_CONF_TAGS = CONF_LADDER + [CONF_BLOCKED, CONF_REFUTED, LEGACY_TOP]

# Promotion thresholds. SHIPPING_PROMOTION_PLAN.md: raw volume is not coverage
# ("1M calls with 3 inputs is not coverage"). Both must be met.
PROMOTION_THRESHOLDS = {
    "CONF_BATTLETESTED": {"calls": 1_000, "distinct_inputs": 20},
    "CONF_SHIPPED":      {"calls": 10_000, "distinct_inputs": 20},
}

CONF_PROPERTY_MAP = "Conf"

# Excluded from the ladder AND from the in-scope denominator (taxonomy v2
# "Scope"): the CRT comes from the toolchain, thunks are linker-generated.
OUT_OF_SCOPE_TAGS = [
    "LIB_CRT", "LIB_MSVC_EH", "LIB_MSVC", "LIB_SECURITY",
    "THUNK", "STUB", "EXTERNAL",
]

# --- port_status -> rung ----------------------------------------------------
PORT_STATUS_TO_RUNG = {
    "shadow_leaf_pending":        "CONF_DRAFT",
    "proven_pending_review":      "CONF_VECTORS",   # static harness, no game process
    "proven_live_pending_review": "CONF_LIVE",
    "proven_live":                "CONF_LIVE",
}

PORT_STATUS_TO_BLOCKED_REASON = {
    "stateful_skip":            "stateful",
    "unsupported_abi":          "unsupported_abi",
    "no_vectors":               "no_vectors",
    "oracle_unavailable":       "oracle_unavailable",
    "handle_abort_hazard_skip": "abort_hazard",
    "unknown_skip":             "unknown",
}

# Inverse map, for correcting SQL that has fallen behind Ghidra. Lossy on
# purpose: `port_status` tracks the PORT PIPELINE stage, and the pipeline has no
# state for "shadow-promoted" or "shipped" -- those are Ghidra-side facts earned
# after the porting work finished. So every rung at or above CONF_LIVE maps back
# to `proven_live`, the last pipeline stage that actually ran. Promote-only then
# keeps the higher Ghidra rung; the two are consistent, not equal.
RUNG_TO_PORT_STATUS = {
    "CONF_DRAFT":        "shadow_leaf_pending",
    "CONF_VECTORS":      "proven_pending_review",
    "CONF_LIVE":         "proven_live",
    "CONF_VETTED":       "proven_live",
    "CONF_BATTLETESTED": "proven_live",
    "CONF_SHIPPED":      "proven_live",
}

# Transient failures. The candidate was deleted and the detail lives in
# port_status -- a failed attempt is not a rung.
PORT_STATUS_NO_RUNG = {
    "live_prove_failed", "harness_failed", "malformed_response", "error", "blocked",
}

# Tag definitions written into each program so `list_function_tags` is
# self-documenting, matching the convention D2Common's CONF_ tags already use.
TAG_COMMENTS = {
    "CONF_DRAFT": (
        "CONF axis (equivalence proof), rung 1/6. A one-for-one equivalent exists but is "
        "UNTESTED (first-run draft/prototype). Untagged = no equivalent yet. Mutually "
        "exclusive with the other CONF_ rungs. Orthogonal to the DOC_* axis."),
    "CONF_VECTORS": (
        "CONF axis, rung 2/6. Equivalent passes OFFLINE/STATIC vectors (Ghidra "
        "/emulate_function or offline conformance vectors) -- no live game process. "
        "Mutually exclusive with the other CONF_ rungs."),
    "CONF_LIVE": (
        "CONF axis, rung 3/6. Proven bit-exact LIVE via the D2Debugger direct-call oracle "
        "against the running game, on THE DRAFTING MODEL'S OWN vectors. Not yet "
        "shipping-grade (self-consistency bias) -- see CONF_VETTED."),
    "CONF_VETTED": (
        "CONF axis, rung 4/6. CONF_LIVE PLUS survived an INDEPENDENT adversary's vectors "
        "(branch boundaries, dense sweep, 0/-1/INT_MIN/INT_MAX) with a DISCRIMINATING "
        "result -- a weak_proof=DEGENERATE capture does not qualify. Kills the "
        "self-consistency and input-coverage risks. See SHIPPING_PROMOTION_PLAN.md rung V1."),
    "CONF_BATTLETESTED": (
        "CONF axis, rung 5/6. Zero divergences under shadow mode during REAL gameplay -- "
        "volume x input diversity x state diversity, not raw call count. The primary route "
        "for stateful client code, where synthetic vectors cannot construct the state."),
    "CONF_SHIPPED": (
        "CONF axis, rung 6/6 (terminal). The reimpl is compiled into the shipping binary "
        "and dispatched by default. The binary is functionally equivalent when 100% of "
        "in-scope functions reach this rung."),
    CONF_REFUTED: (
        "CONF axis, OFF-LADDER. A rung was earned and then FALSIFIED -- a shadow divergence, "
        "a failed adversarial re-proof, or a red regression case. The counterexample (inputs, "
        "expected vs actual, source) and the rung it fell from are in the `Conf` property map. "
        "NOT the same as untested: the reimpl is known-wrong in a specific way, and this "
        "function will not re-promote until the counterexample is addressed."),
    CONF_BLOCKED: (
        "CONF axis, OFF-LADDER. Attempted; NOT provable by the current oracle. The specific "
        "reason (stateful / unsupported_abi / no_vectors / oracle_unavailable / "
        "abort_hazard) is in the `Conf` property map at this address. Doubles as the work "
        "queue for the next oracle capability -- NOT a permanent verdict."),
}


def rung_strength(tag):
    """Ladder position; -1 for off-ladder/untagged/unknown. LEGACY_TOP sorts at
    the top so the promote-only guard treats it as untouchable."""
    if tag == LEGACY_TOP:
        return len(CONF_LADDER)
    if tag in CONF_LADDER:
        return CONF_LADDER.index(tag)
    return -1


REFUTATION_SOURCES = ("shadow_divergence", "adversarial_failure", "regression_failure")


def decide_refutation(current, source, counterexample=None):
    """Should a falsification demote this function, and what gets recorded?

    Returns (should_demote, rung, record). A rung is a CLAIM; a divergence
    falsifies it. Before this existed nothing could take a tag back, so a
    disproven proof kept CONF_BATTLETESTED forever -- which under shadow-first
    is the primary failure mode, since divergences are the main signal.

    Only LADDER rungs can be refuted. An untagged, already-refuted, or
    CONF_BLOCKED function has no claim to falsify -- reporting a divergence
    against one means the caller is confused, not that a demotion is due.
    """
    if source not in REFUTATION_SOURCES:
        raise ValueError(f"unknown refutation source {source!r}; want one of {REFUTATION_SOURCES}")
    if rung_strength(current) < 0:
        return (False, None, None)
    record = {
        "conf": CONF_REFUTED,
        "refuted_from": current,
        "source": source,
    }
    if counterexample:
        # The whole point of a distinct CONF_REFUTED: the counterexample must
        # survive, or the next pass re-promotes the same broken reimpl.
        record["counterexample"] = counterexample
    return (True, CONF_REFUTED, record)


# Additional zero-divergence calls with NO new distinct input before the
# reachable input space is considered exhausted. Measured basis: 101 fresh calls
# across the ENTIRE Necromancer skill tree added zero new inputs to
# GetItemQualityStringId, which had already plateaued at 3.
SATURATION_HITS = 500


# Distinct game sessions in which saturation must be observed before it counts
# as coverage. One session is one process lifetime, i.e. one character, one act,
# one difficulty, one play pattern -- SHIPPING_PROMOTION_PLAN's "state
# diversity" axis, which within-session saturation cannot speak to at all.
# Raised from 1 to 2 on 2026-07-29 after ITEMS_GetUltraOrBaseCode promoted on
# 3.46M calls with 4 distinct inputs from a single session: technically
# saturated, but far too thin a basis for a "battle-tested" claim.
REQUIRED_SATURATED_SESSIONS = 2


def is_saturated(calls, calls_at_last_new_input):
    """Has the reachable input space stopped producing new distinct inputs
    WITHIN THE CURRENT SESSION?

    `calls_at_last_new_input` is the hit count recorded the last time
    `distinct_inputs` actually CHANGED. If the function has since taken
    SATURATION_HITS more calls without a single new input, every input this
    session's call paths can produce has been seen.

    This is necessary but NOT sufficient for promotion -- see
    saturation_qualifies().
    """
    if calls_at_last_new_input is None:
        return False
    return (calls - calls_at_last_new_input) >= SATURATION_HITS


def saturation_qualifies(saturated_sessions):
    """Is observed saturation broad enough to stand in for input diversity?

    Within-session saturation proves the *reachable* input space is exhausted
    for the paths that session exercised. It says nothing about a different
    act, character class, or difficulty passing a value this session never
    could. Requiring the observation to repeat across independent sessions is
    what turns "exhausted here" into evidence about the game rather than
    evidence about one playthrough.
    """
    return int(saturated_sessions or 0) >= REQUIRED_SATURATED_SESSIONS


def effective_distinct_floor(rung, argc=None, saturated=False):
    """The distinct-input floor that actually applies to this function.

    The flat floor (20) assumes a large reachable input space. Two exemptions:

      * argc == 0 -- exactly one possible input; diversity is not an axis.
      * SATURATED -- the input space provably stopped yielding new values, so
        the observed distinct count IS 100% of reachable coverage. Requiring
        more is requiring the impossible.

    Why saturation and not a declared domain (the approach this replaces): a
    declaration encodes the function's LEGAL domain, but promotion depends on
    the REACHABLE domain -- what live callers actually pass. Declaring
    input_domain=7 for GetItemQualityStringId (quality 0..6) merely swapped an
    unsatisfiable floor of 20 for an unsatisfiable floor of 7; the reachable
    paths only ever pass 3. Saturation is measured, not asserted, so it cannot
    be wrong about a domain it never observes.

    KNOWN LIMIT, recorded rather than hidden: saturation within one session is
    not saturation globally. A different act / character class / difficulty may
    pass values this session never did. Callers record the saturation basis
    into the Conf property map so the rung's evidence stays auditable.
    """
    bar = PROMOTION_THRESHOLDS.get(rung)
    if bar is None:
        return 0
    if argc == 0 or saturated:
        return 0
    return bar["distinct_inputs"]


def meets_promotion_bar(rung, calls, distinct_inputs, argc=None, saturated=False):
    """Both thresholds, never one. A function hammering two code paths 10,000
    times must NOT promote -- that is the exact evidence the plan calls
    worthless -- UNLESS those two paths are provably all the input the game can
    produce (saturation). The VOLUME bar always applies regardless."""
    bar = PROMOTION_THRESHOLDS.get(rung)
    if bar is None:
        return True
    return (calls >= bar["calls"]
            and distinct_inputs >= effective_distinct_floor(rung, argc, saturated))


def decide(status, current, *, out_of_scope=False, misattributed=None):
    """Pure decision for one function: which bucket, and what rung if promoted.

    Returns (bucket, proposed_rung_or_None, reason). Free of I/O so the safety
    rules -- promote-only, out-of-scope exclusion, quarantine -- are testable
    without Ghidra or state.db. Every rule that can silently corrupt thousands
    of tags lives here and nowhere else.

    Buckets: promote | already_correct | skipped_demotion | stale_sql_proven |
             skipped_out_of_scope | skipped_no_rung | quarantined
    """
    if misattributed:
        return ("quarantined", None,
                f"proof recorded under program={misattributed!r} "
                f"(wrong-binary default) -- re-prove, do not tag")
    if out_of_scope:
        return ("skipped_out_of_scope", None, "")
    if current == CONF_REFUTED:
        # A refuted function must NOT be re-promoted by an ordinary port_status
        # transition. Without this guard the regression loop is fully automatic:
        # worker re-drafts -> proves against its own vectors -> re-promotes the
        # same reimpl the divergence already disproved. Clearing CONF_REFUTED is
        # a deliberate act that addresses the recorded counterexample.
        return ("skipped_refuted", None,
                "refuted -- address the recorded counterexample before re-promoting")
    if status in PORT_STATUS_NO_RUNG:
        return ("skipped_no_rung", None, "")

    if status in PORT_STATUS_TO_RUNG:
        proposed, reason = PORT_STATUS_TO_RUNG[status], ""
    elif status in PORT_STATUS_TO_BLOCKED_REASON:
        proposed, reason = CONF_BLOCKED, PORT_STATUS_TO_BLOCKED_REASON[status]
    else:
        return ("skipped_no_rung", None, f"{status} (unmapped)")

    if current == proposed:
        return ("already_correct", proposed, reason)
    if current is not None and proposed == CONF_BLOCKED:
        # Holds a ladder rung, SQL says unprovable. Not a demotion -- STALE SQL.
        # Expected under shadow-first: the static oracle skips a function, the
        # live/shadow path proves it, and nothing writes that back to port_status.
        return ("stale_sql_proven", None, "")
    if current is not None and rung_strength(proposed) < rung_strength(current):
        return ("skipped_demotion", proposed, "")
    return ("promote", proposed, reason)

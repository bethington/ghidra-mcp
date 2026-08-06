"""The call/reference graph over a binary, built once and shared.

Extracted from `scope_graph.py`, which built it to answer "is this function
library-owned" (every referrer is library code, transitively). Documentation
ordering needs the SAME graph pointed the other way: to document callees before
callers, you need to know what a function calls.

Two builders answering one question -- "what references what" -- is the exact
shape of most of the defects found in this codebase: two definitions of
"untyped" in three places, two views of "the globals in this binary" with
different denominators, a hand-copied set of symbol gates rendering beside the
scanner it was copied from. So there is one builder, here, and both consumers
import it.

WHY XREFS AND NOT `/get_full_call_graph`, recorded because it is not obvious
and costs a day to rediscover: that endpoint is measurably incomplete.
`__CxxFrameHandler3` has 7 UNCONDITIONAL_CALL xrefs and reports ZERO call-graph
edges. References are the source of truth.

DATA references count as much as CALL references. A function whose only
referrer is a vtable slot or a dispatch table entry is still referenced, and
dropping those makes it look unreachable.
"""

from __future__ import annotations

import collections
import os
import sys
from typing import Dict, List, Optional, Sequence, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import library_scope as ls                                       # noqa: E402


class EmptyGraph(RuntimeError):
    """The reference source produced no edges at all.

    Raised rather than returned because a silently empty graph does not look
    like a failure -- it looks like a clean answer. The first version of the
    scope analysis parsed `/get_full_call_graph` with the wrong field names,
    dropped all 950 edges, and confidently reported that the four authored
    functions "call nothing else in the binary". That read as a finding. It was
    a bug.
    """


def function_referrers(program: str, fn_addrs: Sequence[str],
                       ranges: Optional[List[Tuple[int, int, str]]] = None
                       ) -> Dict[str, Set[str]]:
    """{function addr -> set of REFERRING function addrs}.

    Both CALL and DATA references, each resolved from the raw source address to
    the function that contains it -- a reference comes from an instruction or a
    table slot, never from a function entry, so it must be attributed before it
    can be compared against the library set.

    Raises EmptyGraph if nothing at all came back. See that class.
    """
    if ranges is None:
        ranges = ls._function_ranges(program)
    raw = ls._bulk_xrefs_to(program, list(fn_addrs))
    if not raw:
        raise EmptyGraph(
            f"{program}: /get_bulk_xrefs returned no references for "
            f"{len(fn_addrs)} functions. Refusing to report a scope verdict "
            f"from an empty graph.")
    out: Dict[str, Set[str]] = collections.defaultdict(set)
    unattributed: Dict[str, int] = collections.defaultdict(int)
    for target, sources in raw.items():
        for s in sources:
            owner = ls._owning_function(s, ranges)
            if owner is None:
                # A reference we cannot attribute to any function. It could be
                # authored code we failed to resolve, so it must BLOCK the
                # exclusion rather than be dropped -- recorded as a sentinel.
                unattributed[target] += 1
                out[target].add("?unattributed")
            elif owner != target:
                out[target].add(owner)          # self-recursion is not a referrer
    return dict(out)


def invert(referrers: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """{referrer addr -> set of addrs it references}, i.e. callees.

    The unattributed sentinel is dropped: it exists to BLOCK a scope exclusion
    (an unresolvable referrer might be authored code, so it must keep a function
    in scope), and it names no function, so it cannot be a callee of anything.
    Carrying it forward would invent a node.
    """
    out: Dict[str, Set[str]] = collections.defaultdict(set)
    for target, srcs in (referrers or {}).items():
        for s in srcs:
            if s == "?unattributed":
                continue
            out[s].add(target)
    return dict(out)


def documentation_order(callees: Dict[str, Set[str]],
                        universe: Optional[Sequence[str]] = None) -> List[str]:
    """Addresses in bottom-up order: callees before the functions that call them.

    This is what makes a caller's evidence exist by construction rather than be
    fetched per-prompt. A documented callee contributes its NAME AND PLATE,
    which is both cheaper and better evidence than a raw decompiled body.

    CYCLES ARE NOT AN ERROR and must not be dropped. Recursion and mutual
    recursion are ordinary in real code, and a topological sort that discards
    them would silently omit whole subsystems from the queue. Nodes still inside
    a cycle when progress stops are emitted in address order, deterministically:
    they have no valid relative order, and inventing one is preferable to
    losing them only if it is stated -- it is stated here.

    Depth is not the ordering key. A function whose callees are all documented
    is ready regardless of how deep it sits, which is why this is a Kahn-style
    peel rather than a longest-path sort.
    """
    nodes: Set[str] = set(universe or [])
    for a, bs in (callees or {}).items():
        nodes.add(a)
        nodes.update(bs)
    if universe is not None:
        # Edges to things outside the universe (library code, imports, other
        # binaries) are not blockers -- they will never be documented here, and
        # waiting on them would stall every function that touches the CRT.
        keep = set(universe)
        nodes = keep
        pending = {n: {c for c in (callees or {}).get(n, set()) if c in keep}
                   for n in keep}
    else:
        pending = {n: set((callees or {}).get(n, set())) for n in nodes}

    done: Set[str] = set()
    order: List[str] = []
    while True:
        ready = sorted(n for n in nodes
                       if n not in done and not (pending[n] - done))
        if not ready:
            break
        order.extend(ready)
        done.update(ready)
    remaining = sorted(n for n in nodes if n not in done)
    order.extend(remaining)         # cycles, in a stated deterministic order
    return order


def unresolved_callees(address: str, callees: Dict[str, Set[str]],
                       documented: Set[str],
                       universe: Optional[Sequence[str]] = None) -> Set[str]:
    """In-universe callees of `address` that are not yet documented.

    The signal a selector needs to answer "is this function's evidence ready?",
    and the signal an abstention rule needs to say "this cannot be named yet,
    and here is precisely what is missing".
    """
    cs = set((callees or {}).get(address, set()))
    if universe is not None:
        cs &= set(universe)
    return cs - set(documented or set())

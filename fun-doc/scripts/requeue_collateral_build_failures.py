#!/usr/bin/env python3
r"""Re-queue functions retired by a build failure that was not theirs.

Sibling of requeue_bad_target_failures.py, different axis. That one repairs
rows whose ADDRESS was wrong (module relocation). This one repairs rows whose
BUILD was broken by somebody else's candidate.

THE BUG
-------
Every candidates/*.cpp links into ONE provider DLL. A draft that references an
undefined symbol (LNK2019/LNK2001) or redefines one (LNK2005) fails the link
for EVERY other candidate in that build. `build_provider_attributed` heals the
shapes it can attribute -- compile errors naming `candidates\X.cpp`, and
duplicate symbols -- but an unresolved-external names only the .vcxproj, so it
matched no attributor and fell through to a blanket `build_provider` verdict.

`live_prove_failed` is TERMINAL. So whichever function happened to be proving
when someone else's draft broke the link was permanently retired, with its own
reimpl compiled fine and never executed once.

Measured 2026-07-31 across 523 live_prove_failed rows:

    126  unresolved symbol referenced in ANOTHER function   <- collateral
     24  duplicate symbol                                   <- collateral
     37  unresolved symbol referenced in the function ITSELF <- genuinely its own
     58  compile error                                       <- genuinely its own

traced to just 35 distinct offending candidates (top 15 = 67% of references).

The pipeline fix is `_find_unresolved_symbol_offender` (attribute + quarantine
the offender, heal, retry) plus `_prove_failure_is_environmental` treating an
attributed-collateral build stage as non-terminal. This script repairs the DATA
the bug already produced.

WHAT COUNTS AS COLLATERAL
-------------------------
The evidence is in the linker message itself, and it is decisive rather than
circumstantial -- no time-window heuristics are needed here (unlike the
relocation repair, where "relocated now" says nothing about a past verdict):

    error LNK2019: unresolved external symbol S referenced in function F

If F is NOT the function under test, this row's candidate is not what failed to
link. That is a fact about the recorded message, not an inference about the
world when it was recorded.

Deliberately NOT re-queued:
  * F == the function under test    -- its own draft calls something undefined.
  * `error C####` compile errors    -- its own draft does not compile.
  * mismatch / marshal_fault        -- both sides ran; a real verdict.
  * rows with no parseable referrer -- unattributable, so left alone.

Re-queued rows go to `oracle_unavailable`, the same non-terminal status every
other environmental failure uses; select_port_candidates re-admits them the
moment FUNDOC_LIVE_PROVE is on.

USAGE
    python fun-doc/scripts/requeue_collateral_build_failures.py            # dry run
    python fun-doc/scripts/requeue_collateral_build_failures.py --apply
    python fun-doc/scripts/requeue_collateral_build_failures.py --program D2Client.dll
"""
from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

_FUNDOC = Path(__file__).resolve().parent.parent
if str(_FUNDOC) not in sys.path:
    sys.path.insert(0, str(_FUNDOC))

_UNRESOLVED = re.compile(
    r"error LNK(?:2019|2001):\s*unresolved external symbol\s+(\S+)"
    r"(?:\s+referenced in function\s+(\"[^\"]+\"|\S+))?")
_DUP = re.compile(r"(\w+)\.obj\s*:\s*error LNK2005:\s*(\S+)\s+already defined in\s+(\w+)\.obj")
_COMPILE_ERR = re.compile(r"error C\d+")


def _undecorate(sym: str) -> str:
    """MSVC symbol -> plain name. Mirrors port_live_prove._undecorate.

    Note the leading `@` for FASTCALL (`@Foo@4`): stripping only `_` leaves
    `split("@")[0]` returning the empty string, which then sorts ahead of every
    real candidate name. 34 of 125 collateral rows blamed a nameless offender
    before this was fixed.
    """
    s = (sym or "").strip().strip('"')
    if s.startswith("?"):
        m = re.match(r"\?([A-Za-z_]\w*)@", s)
        return m.group(1) if m else s
    if "(" in s:
        m = re.search(r"([A-Za-z_]\w*)\s*\(", s)
        return m.group(1) if m else s
    return s.lstrip("_@").split("@")[0]


def classify(name: str, detail: str):
    """(is_collateral, offender_or_None, reason)."""
    d = detail or ""
    if _COMPILE_ERR.search(d):
        return False, None, "own draft: compile error"
    refs = _UNRESOLVED.findall(d)
    if refs:
        # Count, don't just collect: pick the most-referenced offender rather
        # than the alphabetically-first one. `port_last_result` is truncated to
        # 500 chars, so a tail-truncated referrer ("@L") can appear alongside
        # the real one and must not win.
        referrers = collections.Counter(
            u for u in (_undecorate(rf) for _, rf in refs if rf) if u)
        if not referrers:
            return False, None, "unresolved symbol, no referrer recorded"
        if name in referrers:
            return False, None, f"own draft: references undefined symbol from {name}"
        offender = referrers.most_common(1)[0][0]
        return True, offender, f"link broken by {offender}, not {name}"
    dups = _DUP.findall(d)
    if dups:
        dup_stem, symbol, orig_stem = dups[0]
        if name in (dup_stem, orig_stem):
            return False, None, f"own draft: duplicate symbol {symbol}"
        return True, dup_stem, f"duplicate symbol {symbol} between {dup_stem}/{orig_stem}"
    return False, None, "no attributable link error"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="write the changes (default is a dry run)")
    ap.add_argument("--program", help="restrict to one binary (name or full path)")
    ap.add_argument("--limit", type=int, default=0, help="cap rows processed (0 = all)")
    args = ap.parse_args()

    from fun_doc import _get_storage_repo, update_function_state
    from sqlalchemy import select

    repo = _get_storage_repo()
    if repo is None:
        print("storage backend unavailable", file=sys.stderr)
        return 1
    c = repo.t_workflow.c
    q = select(c.name, c.address, c.program_path, c.port_last_result,
               c.port_failure_stage, c.port_attempts).where(
        c.port_status == "live_prove_failed")
    if args.program:
        q = q.where(c.program_path.like(f"%{args.program}"))
    with repo.engine.connect() as conn:
        rows = list(conn.execute(q))

    hits, skipped = [], collections.Counter()
    for name, addr, prog, detail, stage, attempts in rows:
        collateral, offender, reason = classify(name, detail)
        if collateral:
            hits.append((name, addr, prog, offender, reason, stage))
        else:
            skipped[reason.split(":")[0]] += 1

    if args.limit:
        hits = hits[: args.limit]

    print(f"scanned {len(rows)} live_prove_failed row(s)\n")
    print(f"COLLATERAL (re-queue): {len(hits)}")
    by_offender = collections.Counter(o for _, _, _, o, _, _ in hits)
    for off, n in by_offender.most_common(15):
        print(f"    {n:>4}  victims of {off}")
    if len(by_offender) > 15:
        print(f"    ... and {len(by_offender) - 15} more offending candidate(s)")
    print(f"\n  distinct offenders: {len(by_offender)}")
    print("\nNOT re-queued:")
    for k, n in skipped.most_common():
        print(f"    {n:>4}  {k}")

    if not args.apply:
        print("\nDRY RUN -- re-run with --apply to write.")
        if hits:
            print("\nfirst 10 that would be re-queued:")
            for name, addr, prog, off, reason, _ in hits[:10]:
                print(f"    {name} ({Path(prog).name}) -- {reason}")
        return 0

    ok = 0
    for name, addr, prog, offender, reason, stage in hits:
        key = f"{prog}::{addr}"
        try:
            update_function_state(key, {
                "port_status": "oracle_unavailable",
                "port_failure_stage": stage or "build_provider",
                "port_last_result": (
                    f"re-queued: shared provider link was broken by {offender}, not by "
                    f"{name} -- this function's reimpl compiled and never executed"),
            })
            ok += 1
        except Exception as e:  # noqa: BLE001
            print(f"  FAILED {name}: {e}", file=sys.stderr)
    print(f"\nre-queued {ok}/{len(hits)} row(s) to oracle_unavailable "
          f"(non-terminal; re-admitted when the oracle is up)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

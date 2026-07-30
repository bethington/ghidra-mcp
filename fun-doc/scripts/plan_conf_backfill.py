#!/usr/bin/env python3
"""Plan (and later apply) the CONF_* rung backfill from fun-doc SQL state.

Context: the CONF_* tag ladder and fun-doc's `port_status` are two state
machines that were never connected -- `port_status` is written by the workers
on every transition, while the CONF_ rung is written only by
`port_live_prove.record_proof()`, which the main worker path never calls
(fun_doc.py ends at port_status="proven_live_pending_review" and stops). The
result: D2Client.dll carries 0 CONF_ tags across 5,739 functions while SQL
holds 35 static-harness passes for it, and CONF_DRAFT/CONF_VECTORS have zero
writers anywhere in the codebase.

This script computes the one-shot backfill that closes that gap, per
CONFORMANCE_TAXONOMY_V2.md. It is READ-ONLY by default and emits a diff-able
report so the plan can be eyeballed before ~1,900 tag writes hit Ghidra.

Usage:
    python -m scripts.plan_conf_backfill                      (dry-run; prints a summary)
    python -m scripts.plan_conf_backfill --report out.json    (full per-function plan)
    python -m scripts.plan_conf_backfill --apply --limit 1    (trial a single write)
    python -m scripts.plan_conf_backfill --apply              (the real backfill)

Always dry-run first. --apply writes ~2,400 function tags plus a reason record
per CONF_BLOCKED function, then save_program's each binary. It does NOT check
in to the shared Ghidra Server -- the programs are exclusively checked out, so
the working copy is authoritative until you choose to check in.

Safety rules encoded here:
  * PROMOTE-ONLY. The backfill never lowers an existing rung. D2Common has 33
    CONF_BATTLETESTED functions whose port_status is still
    "proven_live_pending_review" -- naively mapping that to CONF_LIVE would
    demote 33 proven functions. Those land in the `skipped_demotion` bucket.
  * OUT-OF-SCOPE EXCLUSION. LIB_CRT / LIB_MSVC_EH / LIB_MSVC / LIB_SECURITY /
    THUNK / STUB / EXTERNAL functions never enter the ladder at all -- not even
    CONF_BLOCKED. They are excluded from the denominator (taxonomy v2 "Scope").
  * ADDRESS-RANGE QUARANTINE. A row whose address falls outside its claimed
    program's image range is the fingerprint of the wrong-binary default fixed
    2026-07-27 (a hardcoded program="D2Common.dll" sent every non-D2Common
    proof's tag to the wrong binary). Those are quarantined, never tagged --
    backfilling one would launder a bug into a durable claim.
  * OPEN PROGRAMS ONLY. Tags on closed programs aren't queryable; BH.dll and
    D2Game.dll have port_status rows but are not currently open, so they are
    reported as unreachable rather than silently dropped.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sqlite3
import sys
from pathlib import Path

import requests

GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")
STATE_DB = Path(__file__).resolve().parent.parent / "state.db"
D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
PROVEN_REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"

# The ladder, the port_status mapping and decide() are single-sourced in
# fun-doc/conf_ladder.py so this bulk backfill and fun_doc.py's live hook cannot
# drift. sys.path juggling: fun-doc/ isn't a package, and this script runs as
# `python -m scripts.plan_conf_backfill` from inside fun-doc/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from conf_ladder import (  # noqa: E402
    ALL_CONF_TAGS, CONF_BLOCKED, CONF_LADDER, CONF_PROPERTY_MAP, LEGACY_TOP,
    OUT_OF_SCOPE_TAGS, PORT_STATUS_NO_RUNG, PORT_STATUS_TO_BLOCKED_REASON,
    PORT_STATUS_TO_RUNG, TAG_COMMENTS, decide, rung_strength,
)

# Back-compat alias: the planner's tests and older call sites used _rung_strength.
_rung_strength = rung_strength


def _get(endpoint, params=None, timeout=30):
    r = requests.get(f"{GHIDRA_HTTP}/{endpoint.lstrip('/')}", params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _tagged_addresses(program, tag):
    """Every address carrying `tag` in `program`. Pages -- the 1,000 default
    limit silently truncates DOC_DRAFT (2,278 in D2Common) and the COMPLETE_*
    tags, which would make an absent tag look like an untagged function."""
    out = {}
    offset, page = 0, 1000
    while True:
        try:
            data = _get("search_functions_by_tag",
                        {"tag": tag, "program": program, "limit": page, "offset": offset})
        except requests.HTTPError:
            return out
        fns = data.get("functions") or []
        for f in fns:
            out[str(f.get("address", "")).lower().lstrip("0x").rjust(8, "0")] = f.get("name")
        total = data.get("total", len(fns))
        offset += page
        if offset >= total or not fns:
            return out


def _open_programs():
    """name -> (image_base, image_base + memory_size). The image range is the
    only trustworthy discriminator for wrong-binary rows: proven_functions.jsonl's
    own `program` field came from the same defaulted argument that caused the bug."""
    data = _get("list_open_programs")
    progs = data.get("programs") if isinstance(data, dict) else None
    if progs is None and isinstance(data, dict) and "result" in data:
        progs = json.loads(data["result"]).get("programs", [])
    ranges = {}
    for p in progs or []:
        base = int(str(p.get("image_base", "0")), 16)
        ranges[p["name"]] = (base, base + int(p.get("memory_size") or 0))
    return ranges


def _registry_misattributions():
    """address -> claimed program, for every proven_functions.jsonl row whose
    `program` disagrees with the address's real owning image.

    This is the durable fingerprint of the wrong-binary default fixed
    2026-07-27: record_proof defaulted program="D2Common.dll", so a D2Client
    proof wrote its tag into D2Common (where the address resolves to no
    function, so the write failed silently) AND mirrored a row claiming
    D2Common into the registry. The SQL row for such a function is correctly
    attributed, which is exactly why a naive backfill would promote it -- the
    underlying PROOF was executed under a mis-set program argument and has
    never been reconciled, so it must be re-proven, not tagged.
    """
    if not PROVEN_REGISTRY.exists():
        return {}
    ranges = _open_programs()
    bad = {}
    for line in PROVEN_REGISTRY.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            a = int(str(row["address"]), 16)
        except (ValueError, KeyError, json.JSONDecodeError):
            continue
        claimed = row.get("program")
        owner = next((n for n, (lo, hi) in ranges.items() if lo <= a < hi), None)
        if owner and claimed and owner != claimed:
            key = f"{a:08x}"
            bad[key] = claimed
    return bad


def _sql_rows():
    if not STATE_DB.exists():
        sys.exit(f"state.db not found at {STATE_DB}")
    con = sqlite3.connect(f"file:{STATE_DB}?mode=ro", uri=True)
    q = ("select binary_name, address, name, port_status from functions_workflow "
         "where port_status is not null and port_status != ''")
    return con.execute(q).fetchall()


def build_plan():
    ranges = _open_programs()
    rows = _sql_rows()
    misattributed = _registry_misattributions()

    by_prog = collections.defaultdict(list)
    for binary, addr, name, status in rows:
        by_prog[binary].append((addr, name, status))

    plan = {
        "promote": [],            # (program, addr, name, current, proposed, reason)
        "skipped_demotion": [],
        "skipped_no_rung": [],
        "skipped_out_of_scope": [],
        "stale_sql_proven": [],   # already proven in Ghidra; SQL still says blocked
        "quarantined": [],
        "unreachable_programs": {},
        "already_correct": 0,
    }

    for program, entries in sorted(by_prog.items()):
        if program not in ranges:
            plan["unreachable_programs"][program] = len(entries)
            continue

        lo, hi = ranges[program]
        current = {}
        for tag in ALL_CONF_TAGS:
            for a, _n in _tagged_addresses(program, tag).items():
                current[a] = tag
        out_of_scope_addrs = set()
        for tag in OUT_OF_SCOPE_TAGS:
            out_of_scope_addrs |= set(_tagged_addresses(program, tag).keys())

        for addr, name, status in entries:
            key = str(addr).lower().lstrip("0x").rjust(8, "0")
            try:
                a_int = int(key, 16)
            except ValueError:
                plan["quarantined"].append((program, addr, name, status, "unparseable address"))
                continue
            if not (lo <= a_int < hi):
                plan["quarantined"].append(
                    (program, addr, name, status, f"outside {program} image range"))
                continue
            if key in misattributed:
                plan["quarantined"].append(
                    (program, addr, name, status,
                     f"proof recorded under program={misattributed[key]!r} "
                     f"(wrong-binary default) -- re-prove, do not tag"))
                continue
            if key in out_of_scope_addrs:
                plan["skipped_out_of_scope"].append((program, addr, name, status))
                continue

            cur = current.get(key)
            bucket, proposed, reason = decide(status, cur, out_of_scope=False)

            if bucket == "already_correct":
                plan["already_correct"] += 1
            elif bucket == "promote":
                plan["promote"].append((program, addr, name, cur or "none", proposed, reason))
            elif bucket == "skipped_demotion":
                plan["skipped_demotion"].append((program, addr, name, status, cur, proposed))
            elif bucket == "stale_sql_proven":
                plan["stale_sql_proven"].append((program, addr, name, status, cur))
            elif bucket == "skipped_no_rung":
                plan["skipped_no_rung"].append(
                    (program, addr, name, status + (f" {reason}" if reason else "")))

    return plan


_SESSION = requests.Session()


def _post(endpoint, body=None, program=None, timeout=30):
    """POST with `program` as a QUERY param, never in the body.

    @Param(value="program") defaults to ParamSource.QUERY, so a body-sourced
    program is silently ignored -- the write then lands on whatever program
    happens to be ACTIVE. That is the same class of bug as the wrong-binary
    default: it fails silently and produces a durable, wrong result.
    """
    params = {"program": program} if program else None
    r = _SESSION.post(f"{GHIDRA_HTTP}/{endpoint.lstrip('/')}",
                      json=body or {}, params=params, timeout=timeout)
    try:
        return r.json()
    except ValueError:
        return {"error": f"non-JSON ({r.status_code}): {r.text[:200]}"}


def _ok(resp):
    return bool(resp.get("success")) or resp.get("status") == "success"


def ensure_definitions(program):
    """Create/refresh the tag definitions and the Conf property map. Idempotent."""
    for tag, comment in TAG_COMMENTS.items():
        _post("/create_function_tag", {"name": tag, "comment": comment}, program=program)
        # create is a no-op when the tag exists (D2Client already has a
        # comment-less CONF_DRAFT), so always set the comment explicitly.
        # param is `name`, not `tag` -- a wrong key here fails SILENTLY (the
        # endpoint returns an error the caller never sees), which is exactly how
        # D2Client's pre-existing CONF_DRAFT stayed comment-less.
        r = _post("/set_function_tag_comment", {"name": tag, "comment": comment},
                  program=program)
        if not _ok(r):
            print(f"  [WARN] tag comment not set for {tag} on {program}: {str(r)[:160]}")
    _post("/create_property_map",
          {"name": CONF_PROPERTY_MAP, "type": "string"}, program=program)


def apply_plan(plan, limit=None):
    """Write the promotions. Loud on every failure -- a silently-swallowed
    write-back is how both the wrong-binary default and a 5-day property-write
    outage went unnoticed."""
    promos = plan["promote"]
    if limit:
        promos = promos[:limit]

    by_prog = collections.defaultdict(list)
    for row in promos:
        by_prog[row[0]].append(row)

    failures, tagged, propped = [], 0, 0
    for program, rows in sorted(by_prog.items()):
        print(f"\n[{program}] ensuring tag definitions + Conf property map ...")
        ensure_definitions(program)
        print(f"[{program}] writing {len(rows)} rungs ...")
        for i, (_p, addr, name, cur, rung, reason) in enumerate(rows, 1):
            if cur != "none":
                failures.append((program, addr, name, f"expected cur=none, saw {cur} -- skipped"))
                continue
            a = f"0x{str(addr).lstrip('0x')}"
            resp = _post("/add_function_tag", {"function": a, "tags": rung}, program=program)
            if not _ok(resp):
                failures.append((program, addr, name, f"tag {rung}: {str(resp)[:160]}"))
                continue
            tagged += 1
            if rung == CONF_BLOCKED and reason:
                rec = json.dumps({"conf": CONF_BLOCKED, "reason": reason},
                                 separators=(",", ":"))
                pr = _post("/set_property",
                           {"map": CONF_PROPERTY_MAP, "address": a, "value": rec},
                           program=program)
                if _ok(pr):
                    propped += 1
                else:
                    failures.append((program, addr, name, f"reason: {str(pr)[:160]}"))
            if i % 250 == 0:
                print(f"    {i}/{len(rows)} ...")
        print(f"[{program}] saving ...")
        try:
            s = _SESSION.get(f"{GHIDRA_HTTP}/save_program",
                             params={"program": program}, timeout=180)
            print(f"[{program}] save_program -> {s.status_code} {s.text[:120]}")
        except requests.RequestException as e:
            failures.append((program, "-", "-", f"save_program: {e}"))

    print(f"\nAPPLIED: {tagged} tags, {propped} CONF_BLOCKED reason records")
    if failures:
        print(f"\nFAILURES ({len(failures)}):")
        for f in failures[:40]:
            print("  ", f)
        if len(failures) > 40:
            print(f"   ... and {len(failures) - 40} more")
    else:
        print("No failures.")
    print("\nNOT checked in to the shared server. The programs are exclusively "
          "checked out, so the working copy is authoritative until you check in.")
    return failures


def fix_stale_sql(plan, dry_run=True):
    """Correct SQL rows that have fallen behind Ghidra.

    A function proven via the live/shadow path gets its CONF_ rung written to
    Ghidra by the promoter, but nothing writes that outcome back to
    `port_status` -- so 23 D2Common functions read CONF_LIVE/CONF_BATTLETESTED
    in Ghidra while SQL still calls them `stateful_skip`. That is not a bug in
    either store; it is a missing edge between them, and it recurs on every
    shadow promotion, which is why this is a mode rather than a one-shot.

    Ghidra is the source of truth, so SQL is what moves.
    """
    import conf_ladder
    rows = plan["stale_sql_proven"]
    if not rows:
        print("\nNo stale SQL rows.")
        return 0

    print(f"\n{'DRY-RUN: would correct' if dry_run else 'CORRECTING'} "
          f"{len(rows)} stale SQL row(s):")
    fun_doc = None
    if not dry_run:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import fun_doc  # noqa: F811 - deferred so a dry-run needs no SQLAlchemy
    fixed = 0
    for program, addr, name, status, held in rows:
        want = conf_ladder.RUNG_TO_PORT_STATUS.get(held)
        if not want:
            print(f"  SKIP {program} 0x{addr} {name}: no port_status for rung {held}")
            continue
        print(f"  {program} 0x{addr} {name or '?':<38} "
              f"{status} -> {want}  (Ghidra holds {held})")
        if dry_run:
            continue
        fun_doc.update_function_state(f"/Mods/PD2-S12/{program}::{addr}", {
            "program": f"/Mods/PD2-S12/{program}",
            "address": addr,
            "port_status": want,
            "port_last_result": f"corrected from {status}; Ghidra holds {held}",
        })
        fixed += 1
    return fixed


def main():
    ap = argparse.ArgumentParser(description="Plan/apply the CONF_* rung backfill.")
    ap.add_argument("--report", help="write the full per-function plan as JSON")
    ap.add_argument("--apply", action="store_true", help="WRITE the promotions to Ghidra")
    ap.add_argument("--ensure-definitions", metavar="PROGRAM", nargs="+",
                    help="register/refresh the CONF_ tag definitions + Conf property map "
                         "on these programs and exit (needed when a new rung is added but "
                         "there are no promotions to carry it in)")
    ap.add_argument("--limit", type=int, help="with --apply, write only the first N (trial)")
    ap.add_argument("--fix-stale", action="store_true",
                    help="correct SQL port_status rows that have fallen behind Ghidra "
                         "(dry-run unless combined with --apply)")
    args = ap.parse_args()

    if args.ensure_definitions:
        for program in args.ensure_definitions:
            print(f"[{program}] registering CONF_ tag definitions + Conf property map ...")
            ensure_definitions(program)
            s = _SESSION.get(f"{GHIDRA_HTTP}/save_program",
                             params={"program": program}, timeout=180)
            print(f"[{program}] save_program -> {s.status_code}")
        return

    plan = build_plan()

    print("=" * 72)
    print("CONF_* BACKFILL PLAN (read-only -- nothing has been written)")
    print("=" * 72)

    promo = collections.Counter((p, cur, new) for p, _a, _n, cur, new, _r in plan["promote"])
    print(f"\nPROMOTIONS ({len(plan['promote'])} functions)")
    for (prog, cur, new), n in sorted(promo.items()):
        print(f"  {prog:<28} {cur:<18} -> {new:<18} {n:>5}")

    blocked = collections.Counter(
        (p, r) for p, _a, _n, _c, new, r in plan["promote"] if new == CONF_BLOCKED)
    if blocked:
        print("\n  CONF_BLOCKED reasons:")
        for (prog, reason), n in sorted(blocked.items()):
            print(f"    {prog:<28} {reason:<20} {n:>5}")

    print(f"\nSKIPPED -- would demote ({len(plan['skipped_demotion'])})")
    for (prog, cur, new), n in sorted(collections.Counter(
            (p, c, nw) for p, _a, _n, _s, c, nw in plan["skipped_demotion"]).items()):
        print(f"  {prog:<28} keeps {cur:<18} (SQL implies {new}) {n:>5}")

    print(f"\nSTALE SQL -- proven in Ghidra, port_status still says blocked "
          f"({len(plan['stale_sql_proven'])})")
    for (prog, cur), n in sorted(collections.Counter(
            (p, c) for p, _a, _n, _s, c in plan["stale_sql_proven"]).items()):
        print(f"  {prog:<28} holds {cur:<20} {n:>5}  (SQL row needs correcting)")

    print(f"\nSKIPPED -- out of scope (lib/thunk/stub): {len(plan['skipped_out_of_scope'])}")
    print(f"SKIPPED -- transient failure, no rung:    {len(plan['skipped_no_rung'])}")
    print(f"ALREADY CORRECT:                          {plan['already_correct']}")

    print(f"\nQUARANTINED ({len(plan['quarantined'])}) -- wrong-binary fingerprint, never tag:")
    for prog, addr, name, status, why in plan["quarantined"]:
        print(f"  {prog} 0x{addr} {name or '?'} [{status}] -- {why}")

    if plan["unreachable_programs"]:
        print("\nUNREACHABLE (program not open in Ghidra -- cannot tag):")
        for prog, n in sorted(plan["unreachable_programs"].items()):
            print(f"  {prog:<28} {n:>5} rows")

    if args.report:
        Path(args.report).write_text(json.dumps(plan, indent=2), encoding="utf-8")
        print(f"\nfull plan -> {args.report}")

    if args.fix_stale:
        n = fix_stale_sql(plan, dry_run=not args.apply)
        if not args.apply:
            print("\n(dry-run -- add --apply to write)")
        else:
            print(f"\ncorrected {n} row(s)")
        return

    if args.apply:
        n = args.limit or len(plan["promote"])
        print(f"\n{'=' * 72}\nAPPLYING {n} promotion(s) to Ghidra\n{'=' * 72}")
        apply_plan(plan, limit=args.limit)


if __name__ == "__main__":
    main()

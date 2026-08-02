"""Cross-version documentation disagreement harvester.

THE FREE FALSIFIER: two functions with the SAME normalized instruction hash
are the same code, so if two versions carry DIFFERENT human-assigned names, at
least one of them is wrong — no model, no oracle, no game process required.
This is the inverse of cross-version hash propagation, and it matters for the
same reason propagation does: a wrong name replicates to every binary with a
matching hash (the measured PD2_EXT.dll case: 25 CRT functions wearing
gameplay prefixes, spread corpus-wide).

HASH DISCIPLINE — three different function hashes exist in this repo and they
are NOT interchangeable:
  1. /get_function_hash + /get_bulk_function_hashes -> computeNormalizedFunctionHash
     (mnemonic + normalized operands: internal refs -> REL+off, externals ->
     CALL_EXT, small scalars kept). THIS SCRIPT USES ONLY THIS ONE.
  2. DocumentationHashService.computeOpcodeHash (mnemonic + raw operand-type
     ints) — the re-kb archive payload's `opcode_hash`.
  3. ghidra_scripts/Propagate_CrossVersionHash.java's hash (mnemonic + operand
     count only).
Mixing them silently produces zero matches; comparing groups built from
different hashes produces nonsense.

FINDINGS ARE TIER-2 (review), on EVERY disagreeing side — the harvester knows
the names differ, not which one is right; a human (or a seeded audit pass)
picks the winner from the group listing in the report. Accordingly:

  * report-first, dry-run default; --apply writes
  * SQL: the finding is APPENDED to falsify_findings (existing findings from
    other check lanes are kept; a stale cross_version finding is replaced).
    falsify_status is NOT touched — a tier-2 disagreement is not a verdict,
    and overwriting a worker's 'contradicted' with anything would erase a
    real counterexample.
  * Ghidra: an idempotent [AUDIT falsify:cross_version_disagreement] plate
    note on each side (falsify.flag_finding). No DOC_REFUTED — tier 2.

Skips: auto-names (bulk filter=documented), functions under MIN_INSTRUCTIONS
(tiny bodies hash-collide meaninglessly), LIB_*-tagged functions (identical
CRT correctly shares a name; the MISnamed case is doc_lint's
library_domain_prefix check), and propagation-suffix artifacts (`Foo` vs
`Foo_2` is the propagator's collision fallback, not a human disagreement).

Usage:
    python -m scripts.cross_version_disagreement --folders /Vanilla/1.09d /Vanilla/1.13c --json report.json
    python -m scripts.cross_version_disagreement --all-folders --json report.json
    python -m scripts.cross_version_disagreement --all-folders --apply
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

_FUNDOC_DIR = Path(__file__).resolve().parent.parent
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

import falsify  # noqa: E402

MIN_INSTRUCTIONS = 5
PAGE = 2000
CHECK_ID = "cross_version_disagreement"

# The propagator's name-conflict fallback appends a numeric suffix; `Foo` vs
# `Foo_2` is that artifact, not a human disagreement.
_PROPAGATION_SUFFIX_RE = re.compile(r"_\d+$")


def canonical_name(name: str) -> str:
    return _PROPAGATION_SUFFIX_RE.sub("", name or "")


# --------------------------------------------------------------- pure -------

def group_rows(rows_by_program: dict, lib_names_by_program: dict = None) -> dict:
    """hash -> [(program, address, name)] for rows worth comparing."""
    lib_names_by_program = lib_names_by_program or {}
    groups = defaultdict(list)
    for program, rows in rows_by_program.items():
        lib = set(lib_names_by_program.get(program) or ())
        for r in rows:
            name = r.get("name") or ""
            h = r.get("hash") or ""
            if not h or not name or name in lib:
                continue
            if (r.get("instruction_count") or 0) < MIN_INSTRUCTIONS:
                continue
            groups[h].append((program, str(r.get("address") or ""), name))
    return dict(groups)


def find_disagreements(groups: dict) -> list:
    """Groups where >=2 distinct canonical names exist across programs.
    Returns [{hash, names: {canonical: count}, members: [...]}] sorted by
    group size, largest first."""
    out = []
    for h, members in groups.items():
        if len(members) < 2:
            continue
        canon = Counter(canonical_name(n) for _, _, n in members)
        if len(canon) < 2:
            continue
        out.append({
            "hash": h,
            "names": dict(canon.most_common()),
            "members": [{"program": p, "address": a, "name": n}
                        for p, a, n in sorted(members)],
        })
    out.sort(key=lambda g: -len(g["members"]))
    return out


def finding_for_member(member: dict, group: dict):
    """The tier-2 Finding stamped on ONE side of a disagreement — the claim is
    its own name; the evidence is what every other version calls the same code."""
    others = Counter()
    for m in group["members"]:
        if m["program"] == member["program"] and m["address"] == member["address"]:
            continue
        others[canonical_name(m["name"])] += 1
    other_desc = ", ".join(f"{n} (x{c})" for n, c in others.most_common(4))
    return falsify.Finding(
        check_id=CHECK_ID, tier=falsify.TIER_REVIEW,
        program=member["program"], address=member["address"],
        function=member["name"],
        claim=f"name '{member['name']}' for this code",
        evidence=f"byte-identical code (normalized hash {group['hash'][:12]}...) "
                 f"is named {other_desc} in other versions -- at most one "
                 f"name is right",
        detail={"hash": group["hash"], "names": group["names"],
                "member_count": len(group["members"])})


def merge_finding_into_row(existing_findings, finding_dict):
    """Append/refresh the cross_version finding in a row's findings blob,
    preserving every other check's findings. Pure."""
    kept = [f for f in (existing_findings or [])
            if not (isinstance(f, dict) and f.get("check_id") == CHECK_ID)]
    return kept + [finding_dict]


# ---------------------------------------------------------------- I/O -------

def fetch_hashes(program: str) -> list:
    """All documented functions' normalized hashes for one program (paged)."""
    rows, offset = [], 0
    while True:
        resp = falsify._get("/get_bulk_function_hashes", program=program,
                            filter="documented", offset=offset, limit=PAGE)
        if not isinstance(resp, dict) or resp.get("error"):
            raise RuntimeError(f"bulk hashes failed for {program}: {resp}")
        batch = resp.get("functions") or []
        rows.extend(batch)
        offset += len(batch)
        if len(batch) < PAGE or offset >= (resp.get("total_matching") or 0):
            break
    return rows


def lib_tagged(program: str) -> list:
    try:
        import doc_lint
        return doc_lint.lib_tagged_names(program)
    except Exception as e:  # noqa: BLE001
        print(f"  !! LIB tags unavailable for {program}: {e}", file=sys.stderr)
        return []


def apply_findings(disagreements: list, checked_at) -> dict:
    """--apply: SQL findings append + tier-2 plate notes. Never touches
    falsify_status (tier-2 is not a verdict)."""
    from storage import make_engine, resolve_config
    from storage.repository import Repository

    cfg = resolve_config()
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)
    date = checked_at.date().isoformat()
    counters = {"sql_updated": 0, "sql_upserted": 0,
                "flagged": 0, "already_flagged": 0, "flag_errors": 0}
    try:
        for g in disagreements:
            for m in g["members"]:
                f = finding_for_member(m, g)
                row = repo.get_function(m["program"], m["address"])
                if row is not None:
                    merged = merge_finding_into_row(
                        row.get("falsify_findings"), f.to_dict())
                    repo.update_function_fields(
                        m["program"], m["address"], falsify_findings=merged)
                    counters["sql_updated"] += 1
                else:
                    repo.upsert_function({
                        "program_path": m["program"],
                        "binary_name": m["program"].rsplit("/", 1)[-1],
                        "address": m["address"],
                        "name": m["name"],
                        "falsify_findings": [f.to_dict()],
                    })
                    counters["sql_upserted"] += 1
                st = falsify.flag_finding(m["program"], m["address"], f, date=date)
                key = {"flagged": "flagged",
                       "already-flagged": "already_flagged"}.get(st, "flag_errors")
                counters[key] += 1
            time.sleep(0.1)
    finally:
        engine.dispose()
    return counters


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--all-folders", action="store_true")
    g.add_argument("--folders", nargs="+", help="specific project folders")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--apply", action="store_true",
                    help="append tier-2 findings to SQL + plate notes "
                         "(default: dry-run report only)")
    global MIN_INSTRUCTIONS
    ap.add_argument("--min-instructions", type=int, default=MIN_INSTRUCTIONS)
    args = ap.parse_args()
    MIN_INSTRUCTIONS = args.min_instructions

    if args.folders:
        programs = []
        for folder in args.folders:
            programs.extend(falsify.list_programs(folder))
    else:
        from falsify_sweep import all_programs
        programs = all_programs()

    mode = "APPLY" if args.apply else "dry-run"
    print(f"# {mode}: hashing {len(programs)} program(s) "
          f"(normalized hash — see module docstring)", file=sys.stderr)

    rows_by_program, lib_by_program = {}, {}
    for p in programs:
        try:
            rows_by_program[p] = fetch_hashes(p)
            lib_by_program[p] = lib_tagged(p)
            print(f"  {p:44} {len(rows_by_program[p]):6} documented",
                  file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print(f"  !! {p}: {e}", file=sys.stderr)

    groups = group_rows(rows_by_program, lib_by_program)
    disagreements = find_disagreements(groups)

    total_members = sum(len(g["members"]) for g in disagreements)
    print(f"\n=== {len(disagreements)} disagreement group(s), "
          f"{total_members} function(s) involved ===")
    for g in disagreements[:20]:
        names = ", ".join(f"{n} (x{c})" for n, c in g["names"].items())
        print(f"\n  hash {g['hash'][:16]}...  x{len(g['members'])}: {names}")
        for m in g["members"][:6]:
            print(f"    {m['program'].rsplit('/', 1)[-1]:20} {m['address']:>10}  {m['name']}")
        if len(g["members"]) > 6:
            print(f"    ... and {len(g['members']) - 6} more")
    if len(disagreements) > 20:
        print(f"\n  ... and {len(disagreements) - 20} more groups (see --json)")

    applied = None
    if args.apply and disagreements:
        print("\n# applying findings ...", file=sys.stderr)
        applied = apply_findings(disagreements, datetime.now(timezone.utc))
        print(f"  {applied}", file=sys.stderr)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "mode": mode,
                "scanned_programs": programs,
                "min_instructions": MIN_INSTRUCTIONS,
                "group_count": len(disagreements),
                "function_count": total_members,
                "applied": applied,
                "disagreements": disagreements,
            }, fh, indent=2)
        print(f"\nwrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

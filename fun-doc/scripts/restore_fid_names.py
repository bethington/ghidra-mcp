"""Restore canonical Function ID names that a documentation pass overwrote.

Ghidra's Function ID analyzer identifies statically-linked library functions and
records each match as an Analysis bookmark. The bookmark SURVIVES a later
rename, so when a documentation pass renamed `_vsprintf` to
`DATATBLS_PrintFormattedString`, the truth was not destroyed -- only overridden.
This script reads it back and puts it right.

It consumes `doc_lint.py --json` output and acts on tier-0 findings only, i.e.
the ones where FID supplied the real name. Tiers 1 and 2 know a function is
library code but not what it is called, so there is nothing to restore there.

WHY THIS MATTERS MORE THAN TIDINESS
-----------------------------------
A wrong name on statically-linked CRT is not a cosmetic problem, because
cross-version hash propagation copies names to every binary with a matching
function hash -- and CRT is byte-identical everywhere. One bad name reaches the
whole corpus. Measured here: `___acrt_locale_free_numeric` had become
`DATATBLS_FreeUnitResourceArray`, a name asserting D2 units and resource arrays
that appear nowhere in that function, in a binary (BH.dll) that carries no
`LIB_*` tags at all and so was invisible to every other check.

SAFETY
------
- Dry run by default; `--apply` performs writes.
- Single-match FID hits are restored by default. Multiple-match hits are
  ambiguous BETWEEN LIBRARY FUNCTIONS (never between library and game code), so
  they are still wrong today; include them with `--include-multiple`.
- Every change is journalled to a reversal file, so the whole run can be undone.
- `program` is always sent as a QUERY parameter. POST endpoints resolve it from
  the query string, and a body-only `program` silently retargets the write at
  whatever program happens to be active.

USAGE
    python restore_fid_names.py --report C:\\tmp\\doc_lint_fid.json
    python restore_fid_names.py --report ... --apply
    python restore_fid_names.py --undo C:\\tmp\\fid_restore_journal.json --apply
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter

GHIDRA = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")


def _post(path: str, program: str, payload: dict) -> dict:
    # program MUST ride in the query string -- see module docstring.
    url = f"{GHIDRA}{path}?" + urllib.parse.urlencode({"program": program})
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


def load_targets(report_path: str, include_multiple: bool) -> list:
    with open(report_path, encoding="utf-8") as fh:
        rep = json.load(fh)
    out = []
    for d in rep.get("defects", []):
        if d.get("tier") != 0 or not d.get("fid_name"):
            continue
        if d.get("fid_multiple") and not include_multiple:
            continue
        out.append(d)
    return out


def restore(targets: list, apply: bool, journal_path: str) -> int:
    journal, failures = [], []
    by_prog = Counter(t["program"].rsplit("/", 1)[-1] for t in targets)

    print(f"{'BINARY':<24}{'ADDRESS':>10}  {'CURRENT NAME':<38} -> CANONICAL")
    print("-" * 108)

    # Grouped per program, and SAVED before moving on. A shared-server project
    # tolerates only a handful of programs open at once (20+ has crashed
    # Ghidra), and a modified program cannot be evicted without losing the
    # edit -- so finishing and saving one binary at a time keeps exactly one
    # dirty program in flight instead of 21.
    grouped: dict = {}
    for t in targets:
        grouped.setdefault(t["program"], []).append(t)

    for program in sorted(grouped):
        binary = program.rsplit("/", 1)[-1]
        touched = False
        for t in sorted(grouped[program], key=lambda x: x["name"]):
            flag = " [multi]" if t.get("fid_multiple") else ""
            print(f"{binary:<24}{t['address']:>10}  "
                  f"{t['name']:<38} -> {t['fid_name']}{flag}")
            if not apply:
                continue
            try:
                res = _post("/rename_function", program,
                            {"old_name": t["address"], "new_name": t["fid_name"]})
                ok = str(res.get("status", "")).lower() == "success" or res.get("success")
                if not ok and "already exists at this address" in str(res):
                    # Not a real conflict: FID's own label is still sitting on
                    # the address as an ANALYSIS symbol, it just is not primary.
                    # The rename is blocked by the very evidence we are
                    # restoring. Drop the duplicate label, then take the name.
                    _post("/delete_label", program,
                          {"address": t["address"], "name": t["fid_name"]})
                    res = _post("/rename_function", program,
                                {"old_name": t["address"],
                                 "new_name": t["fid_name"]})
                    ok = (str(res.get("status", "")).lower() == "success"
                          or res.get("success"))
                if ok:
                    journal.append({"program": program, "address": t["address"],
                                    "from": t["name"], "to": t["fid_name"]})
                    # Library classification, so the selector stops queueing it.
                    _post("/add_function_tag", program,
                          {"function": t["address"], "tags": "LIB_CRT"})
                    touched = True
                else:
                    failures.append((binary, t["address"], t["name"], str(res)[:160]))
            except Exception as e:  # noqa: BLE001
                failures.append((binary, t["address"], t["name"], repr(e)[:160]))
        if apply and touched:
            try:
                _post("/save_program", program, {})
                print(f"    -- saved {binary}")
            except Exception as e:  # noqa: BLE001
                failures.append((binary, "-", "save_program", repr(e)[:160]))

    print(f"\n{len(targets)} candidate(s) across {len(by_prog)} binary/binaries")
    for b, n in by_prog.most_common():
        print(f"    {b:<24}{n}")

    if not apply:
        print("\nDRY RUN -- nothing written. Re-run with --apply.")
        return 0

    if journal:
        with open(journal_path, "w", encoding="utf-8") as fh:
            json.dump(journal, fh, indent=2)
        print(f"\nrenamed {len(journal)}; reversal journal -> {journal_path}")
    if failures:
        print(f"\n{len(failures)} FAILED:")
        for b, a, n, err in failures:
            print(f"    {b:<22}{a:>10}  {n}  :: {err}")
    return 1 if failures else 0


def undo(journal_path: str, apply: bool) -> int:
    with open(journal_path, encoding="utf-8") as fh:
        journal = json.load(fh)
    print(f"reverting {len(journal)} rename(s)")
    for j in journal:
        print(f"  {j['program'].rsplit('/',1)[-1]:<22}{j['address']:>10}  "
              f"{j['to']} -> {j['from']}")
        if apply:
            _post("/rename_function", j["program"],
                  {"old_name": j["address"], "new_name": j["from"]})
    if not apply:
        print("\nDRY RUN -- nothing written.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", help="doc_lint --json output")
    ap.add_argument("--undo", help="reversal journal to replay backwards")
    ap.add_argument("--apply", action="store_true", help="actually write")
    ap.add_argument("--include-multiple", action="store_true",
                    help="also restore FID multiple-match hits")
    ap.add_argument("--journal",
                    default=os.path.join(os.environ.get("TEMP", "."),
                                         "fid_restore_journal.json"))
    args = ap.parse_args()

    if args.undo:
        return undo(args.undo, args.apply)
    if not args.report:
        ap.error("--report or --undo is required")
    targets = load_targets(args.report, args.include_multiple)
    if not targets:
        print("no tier-0 findings to restore")
        return 0
    return restore(targets, args.apply, args.journal)


if __name__ == "__main__":
    raise SystemExit(main())

"""Corpus sweep: find authored functions the library detector wrongly retired.

Report-first with a dry-run default, like `audit_evicted_globals.py` and
`falsify_sweep.py` before it -- read the JSON, then `--apply`.

THE BUG THIS SWEEPS UP (fixed 2026-08-06, but the damage is already on disk)

Two defects in `library_code_detector`, both found by documenting a binary whose
ORIGINAL SOURCE we have (SGD2FreeRes-GDI.dll) and scoring every verdict against
it. `library_code` makes the selector skip a function PERMANENTLY, so each false
positive is authored code deleted from the workload for good.

    PROSE READ AS CODE   The body searched for callee evidence is
                         `/decompile_function` output, and that output carries
                         the COMMENTS -- the plate and every inline comment a
                         previous documentation pass wrote. `d2::CelFile_Api::
                         GetCel`, three authored lines wrapping a delegate, was
                         classified `hard_callee:_CxxThrowException` when the
                         only occurrences of that string were an inline comment
                         and the detector's own plate. The code never mentions
                         it.

    SELF-CONFIRMATION    The stamped plate embeds the reason string verbatim
                         ("matched signals: hard_callee:_CxxThrowException"), so
                         the next run re-derived the verdict from its own
                         output -- and `--scan --refresh`, the documented escape
                         hatch, re-reads that same plate. The false positive
                         could not be cleared by the one mechanism offered for
                         clearing it.

    OVER-STRONG SIGNALS  `_invoke_watson` (0.68 precision) and `_Xout_of_range`
                         (0.50) were HARD evidence. Neither is CRT-only: MSVC
                         emits `_invoke_watson` into ordinary functions via /GS
                         and secure-CRT validation, and `_Xout_of_range` arrives
                         inlined with `std::vector::at`. Demoted to SOFT.

Whole-binary effect of the fixes, with STL as the positive control so a detector
that simply stopped claiming things could not pass:

    before   false positives 17/377 (4.5%)   recall 63/285 (22.1%)
    after    false positives  0/377 (0.0%)   recall 28/285 ( 9.8%)

WHAT IT RE-EVALUATES

ONLY rows whose recorded `library_code_reasons` are HEURISTIC. A verdict from an
exact lane -- a durable `LIB_*` Ghidra tag, a byte match, FID, BSim -- is not
this detector's to overturn, and re-deciding one from a heuristic re-read is the
same mistake in the other direction. `backfill_library_code.py` refuses to clear
for exactly this reason; the difference here is that the recorded reason names
the retracted signal, so the evidence for clearing is explicit rather than
absent.

WHAT IT WRITES (only with --apply)

    SQL      clears `library_code` and replaces `library_code_reasons` with a
             note naming this recalibration, so the row's history stays legible.
    Ghidra   removes the auto-stamped library plate, and ONLY when the plate is
             still that exact generated text. A plate a human or a worker wrote
             is never touched -- and leaving the generated one behind would
             leave false documentation on an authored function.

USAGE

    python fun-doc/scripts/audit_library_misclassification.py
    python fun-doc/scripts/audit_library_misclassification.py --binary D2Client.dll
    python fun-doc/scripts/audit_library_misclassification.py --apply
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import date

_HERE = os.path.dirname(os.path.abspath(__file__))
_FUNDOC = os.path.dirname(_HERE)
if _FUNDOC not in sys.path:
    sys.path.insert(0, _FUNDOC)

import library_code_detector as lcd  # noqa: E402

GHIDRA = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")

# Reasons produced by the EXACT lanes. A row carrying any of these was not
# decided by the heuristic detector and is out of scope, whatever else it says.
_EXACT_MARKERS = (
    "LIB_* Ghidra tag",
    "retag:",
    "via fid:",
    "via bsim:",
    "via bytes:",
    "pset harness",
)

# The first line of LIBRARY_PLATE_TEMPLATE. Used to recognise a plate this
# detector generated, so a hand-written one is never removed.
_PLATE_MARKER = "auto-classified by fun-doc library detector"


def _get(path: str, **params):
    url = f"{GHIDRA}{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
    try:
        with urllib.request.urlopen(url, timeout=180) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _post(path: str, body: dict, program: str):
    url = f"{GHIDRA}{path}?" + urllib.parse.urlencode({"program": program})
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception as exc:
        return {"error": str(exc)}


def is_heuristic(reasons_raw) -> bool:
    """True when the verdict came from this detector and nothing stronger."""
    if not reasons_raw:
        return False
    text = reasons_raw if isinstance(reasons_raw, str) else json.dumps(reasons_raw)
    return not any(m in text for m in _EXACT_MARKERS)


def reevaluate(program: str, address: str) -> dict | None:
    """Re-run the CALIBRATED detector against the function's current state.

    Returns None when the function cannot be read -- an unreadable decompile
    says nothing about the classification, and clearing on it would be the same
    "cannot tell treated as passed" error this codebase rejects everywhere else.
    """
    d = _get("/decompile_function", address=address, program=program)
    if not isinstance(d, dict):
        return None
    body = d.get("decompiled") or d.get("code") or ""
    if isinstance(body, dict):
        body = body.get("decompiled") or body.get("code") or ""
    if not body:
        return None
    name = d.get("name") or ""
    cal = _get("/get_function_callees", address=address, program=program)
    callees = []
    if isinstance(cal, dict):
        items = cal.get("result", cal)
        if isinstance(items, dict):
            items = items.get("callees") or items.get("items") or []
        for c in items or []:
            callees.append(c.get("name") if isinstance(c, dict) else str(c))
    res = lcd.detect_library_code(name, body, [c for c in callees if c])
    return {"still_library": res.is_library, "reasons": res.reasons,
            "name": name, "plate_is_generated": _PLATE_MARKER in body}


def clear_plate(program: str, address: str) -> str:
    """Remove the generated plate. Never called for a plate we did not write."""
    r = _post("/batch_set_comments", {"address": address, "plate_comment": " "}, program)
    return "ok" if not (isinstance(r, dict) and r.get("error")) else str(r.get("error"))[:120]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", help="restrict to one binary_name")
    ap.add_argument("--limit", type=int, default=0, help="cap rows examined (0 = all)")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--out", default="library_misclassification.json")
    ap.add_argument("--apply", action="store_true",
                    help="clear the flag and the generated plate for confirmed rows")
    args = ap.parse_args()

    from storage import make_engine, resolve_config
    from sqlalchemy import text

    eng = make_engine(resolve_config())
    sql = ("SELECT program_path, binary_name, address, name, library_code_reasons "
           "FROM functions_workflow WHERE library_code=1")
    params = {}
    if args.binary:
        sql += " AND binary_name = :b"
        params["b"] = args.binary
    with eng.connect() as c:
        rows = c.execute(text(sql), params).fetchall()

    candidates = [r for r in rows if is_heuristic(r[4])]
    if args.limit:
        candidates = candidates[:args.limit]
    print(f"{len(rows):,} rows with library_code=1; "
          f"{len(candidates):,} decided by the heuristic detector (in scope)")
    if not candidates:
        return 0

    findings, unreadable = [], 0

    def work(r):
        prog, binname, addr, nm, reasons = r
        out = reevaluate(prog, addr if str(addr).startswith("0x") else f"0x{addr}")
        return r, out

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for i, (r, out) in enumerate(ex.map(work, candidates), 1):
            if out is None:
                unreadable += 1
            elif not out["still_library"]:
                findings.append({
                    "program": r[0], "binary": r[1], "address": str(r[2]),
                    "sql_name": r[3], "ghidra_name": out["name"],
                    "old_reasons": r[4],
                    "plate_is_generated": out["plate_is_generated"],
                })
            if i % 200 == 0:
                print(f"  ...{i}/{len(candidates)}  no longer library: {len(findings)}",
                      flush=True)

    print(f"\nexamined {len(candidates):,}  unreadable {unreadable:,} "
          f"(left alone -- cannot tell is not cleared)")
    print(f"NO LONGER CLASSIFIED AS LIBRARY: {len(findings):,}")
    by_bin = {}
    for f in findings:
        by_bin[f["binary"]] = by_bin.get(f["binary"], 0) + 1
    for b, n in sorted(by_bin.items(), key=lambda kv: -kv[1])[:15]:
        print(f"   {n:>5,}  {b}")

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=1)
    print(f"\nwrote {args.out}")

    if not args.apply:
        print("DRY RUN -- nothing written. Review the JSON, then re-run with --apply.")
        return 0

    note = json.dumps([f"cleared {date.today().isoformat()}: detector recalibration "
                       f"(comment-matching + _invoke_watson/_Xout_of_range demoted)"])
    plates = 0
    with eng.begin() as c:
        for f in findings:
            c.execute(text("UPDATE functions_workflow SET library_code=0, "
                           "library_code_reasons=:n WHERE program_path=:p AND address=:a"),
                      {"n": note, "p": f["program"], "a": f["address"]})
    for f in findings:
        if f["plate_is_generated"]:
            a = f["address"] if str(f["address"]).startswith("0x") else f"0x{f['address']}"
            r = clear_plate(f["program"], a)
            if r == "ok":
                plates += 1
            else:
                print(f"  ! plate clear failed {f['binary']} {a}: {r}", flush=True)
    print(f"APPLIED: {len(findings):,} rows re-opened, {plates:,} generated plates removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

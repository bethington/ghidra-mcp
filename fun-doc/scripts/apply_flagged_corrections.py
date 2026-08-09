"""Apply the corrected plates from correct_flagged_comments.py's review file to Ghidra.

WHY
---
correct_flagged_comments.py is deliberately report-first: it never writes to
Ghidra. This is the explicit, separate apply step -- run only after a human
has reviewed the review JSON (see that script's docstring for the full
D2Game.dll contamination background).

WHAT IT DOES
------------
For each item in one or more --input review files with verdict == "inaccurate":
  1. Extract the CORRECTED_PLATE text out of the raw provider_response via a
     deterministic regex (the template is `CORRECTED_PLATE:\\n<text>`,
     optionally wrapped in a ``` code fence). This is plain text processing --
     no LLM call -- because the plate text was ALREADY generated and already
     reviewed; re-generating it here would risk drifting from what was
     actually checked.
  2. For the (expected to be rare) items where that extraction fails or comes
     back empty/"N/A", fall back to a single small MiniMax cleanup call that
     is scoped ONLY to reformatting the existing response -- not to
     re-deriving the answer from scratch.
  3. POST the resulting plate text to /batch_set_comments for that address.

Skips verdict == "accurate" (nothing to change) and "cannot_determine"
(needs a human judgement call, not a mechanical apply).

Multiple --input files are merged by address, later files winning -- this is
how a single re-run of a previously "unparsed"/"provider_failure" item gets
folded back in without re-running the whole batch.

USAGE
-----
    python fun-doc/scripts/apply_flagged_corrections.py \\
        --input d2game_corrections_full.json --input d2game_unparsed_rerun.json \\
        --program "/Vanilla/1.00/D2Game.dll" --dry-run     # preview, no writes
    python fun-doc/scripts/apply_flagged_corrections.py \\
        --input d2game_corrections_full.json --input d2game_unparsed_rerun.json \\
        --program "/Vanilla/1.00/D2Game.dll"                # actually writes
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

_FUNDOC_DIR = Path(__file__).resolve().parent.parent
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))

GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")

CORRECTED_PLATE_RE = re.compile(r"CORRECTED[_\s]?PLATE\s*:\s*\n?(.*)", re.IGNORECASE | re.DOTALL)
FENCE_RE = re.compile(r"^```[a-zA-Z]*\s*\n(.*?)\n?```\s*$", re.DOTALL)


def extract_corrected_plate(provider_response: str):
    if not provider_response:
        return None
    m = CORRECTED_PLATE_RE.search(provider_response)
    if not m:
        return None
    body = m.group(1).strip()
    fence_m = FENCE_RE.match(body)
    if fence_m:
        body = fence_m.group(1).strip()
    if not body or body.upper() in {"N/A", "NONE", "(NONE)"}:
        return None
    return body


def _post_json(url: str, payload: dict, timeout: int = 60):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except (OSError, ValueError) as exc:
        return {"success": False, "error": str(exc)}


def apply_plate(program: str, address: str, plate_text: str, dry_run: bool):
    # `program` MUST be a URL query param, not a JSON body field -- @Param(value="program")
    # defaults to ParamSource.QUERY (see CLAUDE.md "Code Conventions"). Putting it in the body
    # leaves the server unable to resolve a program for the dry-run rollback wrapper, which
    # then silently falls through to a REAL write even with dry_run=true in the body
    # (see reference_dry_run_silently_writes.md -- confirmed live 2026-08-09, this exact shape).
    url = f"{GHIDRA_HTTP}/batch_set_comments?program=" + urllib.parse.quote(program, safe="")
    payload = {"address": address, "plate_comment": plate_text, "dry_run": dry_run}
    return _post_json(url, payload)


CLEANUP_PROMPT_TEMPLATE = """The text below is a raw response from a previous documentation-verification pass. \
It should contain a corrected Ghidra plate comment (a one-line summary, then Algorithm/Parameters/Returns \
sections), possibly preceded by VERDICT/REASONING lines or wrapped in a markdown code fence.

Extract ONLY the corrected plate comment text -- no VERDICT/REASONING preamble, no markdown code fences, no \
commentary of your own. If the raw text does not actually contain a usable corrected plate (e.g. it just says \
N/A, or it's truncated garbage), respond with exactly: NONE

RAW RESPONSE:
{raw}
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", action="append", required=True, help="Review JSON from correct_flagged_comments.py (repeatable; later files win on address conflicts)")
    ap.add_argument("--program", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--cleanup-provider", default="minimax")
    ap.add_argument("--output", default=None)
    args = ap.parse_args(argv)

    merged: dict[str, dict] = {}
    for path in args.input:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for r in data["results"]:
            merged[str(r["address"]).lower().replace("0x", "")] = r

    items = list(merged.values())
    to_apply = [r for r in items if r.get("verdict") == "inaccurate"]
    skipped_accurate = sum(1 for r in items if r.get("verdict") == "accurate")
    skipped_other = [r for r in items if r.get("verdict") not in ("inaccurate", "accurate")]

    print(f"[apply] program={args.program}  dry_run={args.dry_run}  "
          f"to_apply={len(to_apply)}  skipped_accurate={skipped_accurate}  skipped_other={len(skipped_other)}")
    for r in skipped_other:
        print(f"    skip (verdict={r.get('verdict')})  0x{r['address']}  {r.get('name')}")

    needs_cleanup = []
    for r in to_apply:
        plate = extract_corrected_plate(r.get("provider_response", ""))
        r["_extracted_plate"] = plate
        if plate is None:
            needs_cleanup.append(r)

    if needs_cleanup:
        print(f"[apply] {len(needs_cleanup)} item(s) need MiniMax cleanup pass (regex extraction failed)")
        import fun_doc
        model = fun_doc.DEFAULT_PROVIDER_MODELS.get(args.cleanup_provider, {}).get("FIX")
        for r in needs_cleanup:
            prompt = CLEANUP_PROMPT_TEMPLATE.format(raw=r.get("provider_response", ""))
            text, meta = fun_doc._invoke_provider_direct(prompt, model=model, provider=args.cleanup_provider, use_tools=False)
            cleaned = (text or "").strip()
            if not cleaned or cleaned.upper() == "NONE":
                print(f"    cleanup FAILED  0x{r['address']}  {r.get('name')}  -- no usable plate, will skip")
                r["_extracted_plate"] = None
            else:
                print(f"    cleanup ok  0x{r['address']}  {r.get('name')}")
                r["_extracted_plate"] = cleaned

    final_apply = [r for r in to_apply if r.get("_extracted_plate")]
    unrecoverable = [r for r in to_apply if not r.get("_extracted_plate")]

    print(f"[apply] {len(final_apply)} plate(s) ready to write, {len(unrecoverable)} unrecoverable")

    report = []
    ok_count = 0
    for i, r in enumerate(final_apply, 1):
        addr = r["address"]
        resp = apply_plate(args.program, addr, r["_extracted_plate"], args.dry_run)
        success = bool(resp.get("success"))
        if success:
            ok_count += 1
        else:
            print(f"    [{i}/{len(final_apply)}] FAILED 0x{addr}  {r.get('name')}  -> {resp}")
        report.append({
            "address": addr, "name": r.get("name"), "success": success,
            "response": resp, "plate_written": r["_extracted_plate"],
        })

    print(f"\n[apply] wrote {ok_count}/{len(final_apply)} plate(s) successfully"
          f"{' (DRY RUN -- nothing actually persisted)' if args.dry_run else ''}")

    out_path = Path(args.output) if args.output else (
        _FUNDOC_DIR / "logs" / f"comment_apply_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}Z.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "program": args.program, "dry_run": args.dry_run,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "applied": report,
        "unrecoverable": [{"address": r["address"], "name": r.get("name")} for r in unrecoverable],
        "skipped_other": [{"address": r["address"], "name": r.get("name"), "verdict": r.get("verdict")} for r in skipped_other],
    }, indent=2), encoding="utf-8")
    print(f"[apply] wrote report to {out_path}")
    return 0 if ok_count == len(final_apply) else 1


if __name__ == "__main__":
    raise SystemExit(main())

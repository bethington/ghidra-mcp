"""Verify and correct plate comments on a specific, pre-flagged list of functions.

WHY
---
A manual audit of /Vanilla/1.00/D2Game.dll found its documentation contaminated
in ways analyze_function_completeness cannot see: some plates cite hex addresses
outside the program's own 0x10000000-based image (leftover text from a different,
0x6fc20000-based 1.13c build), some carry an RVA/ordinal stamp that doesn't match
the address it's attached to, and at least two carry a Storm.dll-range ordinal
number on a D2Game function -- documentation written for a different module
entirely. A wrong-but-well-formed plate scores fine on completeness (it has a
name-ish structure), so the normal selector never re-visits it -- the same
falsifiability blind spot this project's own falsify.py exists to address, just
for a defect class falsify.py's mechanical checks don't cover.

/Vanilla/1.00/D2Game.dll has ZERO rows in fun-doc's tracked state (the corpus is
entirely /Mods/PD2-S12/*) -- this is a one-off research binary, not part of the
documentation corpus, so the standard requeue-into-priority-queue pattern
(scripts/requeue_bad_target_failures.py) does not apply: there is nothing to
requeue. This script is deliberately standalone: it calls fun_doc's own
_invoke_provider_direct (same provider plumbing, retry/watchdog handling, and
MINIMAX_API_KEY resolution the live dashboard workers use) but never touches
fun_doc's SQL state, priority queue, or selector.

WHAT IT DOES
------------
For each flagged (address, evidence) pair in the input JSON:
  1. Read the function's current comment via /batch_get_comments (or /get_comment)
  2. Decompile the function via /decompile_function
  3. Ask the configured provider to verify the existing plate against the
     decompiled body, given the specific defect evidence, and either confirm it
     or propose a corrected Algorithm/Parameters/Returns plate
  4. Record the verdict + proposal to a review file

NEVER WRITES TO GHIDRA. This is a report-first tool, same posture as
audit_evicted_globals.py and falsify_sweep.py -- it produces a review artifact
for a human (or a separate, explicit apply step) to act on, not an autonomous
corrector.

USAGE
-----
    python fun-doc/scripts/correct_flagged_comments.py --input flagged.json \
        --program "/Vanilla/1.00/D2Game.dll"                     # writes review file
    python fun-doc/scripts/correct_flagged_comments.py --input flagged.json \
        --program "/Vanilla/1.00/D2Game.dll" --limit 1 --address 10005090  # single-item smoke test

Input JSON shape: a list of objects, each with at least "address" (hex string,
no 0x prefix) and "evidence" (free text describing why it was flagged). "name"
and "defect_types" are optional and carried through to the review file.
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


def _get_json(url: str, timeout: int = 60):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            body = json.loads(resp.read().decode("utf-8", "replace"))
    except (OSError, ValueError) as exc:
        print(f"  [http] GET failed: {url}  ({exc})", file=sys.stderr)
        return None
    # 7.0.0 envelope: {"result": "<json string>"}
    if isinstance(body, dict) and isinstance(body.get("result"), str):
        try:
            return json.loads(body["result"])
        except ValueError:
            return body
    return body


def fetch_comment(program: str, address: str):
    url = (f"{GHIDRA_HTTP}/get_comment?program=" + urllib.parse.quote(program, safe="")
           + "&address=" + urllib.parse.quote(address, safe=""))
    return _get_json(url) or {}


def fetch_decompiled(program: str, address: str):
    url = (f"{GHIDRA_HTTP}/decompile_function?program=" + urllib.parse.quote(program, safe="")
           + "&address=" + urllib.parse.quote(address, safe=""))
    data = _get_json(url) or {}
    return data.get("decompiled") or data.get("error") or "(no decompiled output)"


PROMPT_TEMPLATE = """You are verifying reverse-engineering documentation on a genuine Blizzard \
Diablo II v1.00 binary ({program}, ImageBase 0x10000000, MSVC6). This exact function was \
flagged by a mechanical audit as SUSPECT -- its existing plate comment may describe different \
code entirely (possible causes: leftover documentation from an unrelated, later 0x6fc20000-based \
build of this same module; a copy-pasted snippet from a wholly different module like Storm.dll; \
or an RVA/ordinal stamp that doesn't match this address).

WHY THIS FUNCTION WAS FLAGGED:
{evidence}

EXISTING (SUSPECT) DOCUMENTATION:
{existing_comment}

ACTUAL DECOMPILED BODY AT {address}:
{decompiled}

TASK
Read the decompiled body carefully. Determine whether the existing documentation accurately \
describes what THIS CODE actually does.

- If the existing documentation IS accurate for this body (the flag was a false positive, e.g. a \
coincidental hex constant that happens to fall outside the normal range but is legitimately part \
of this function's own logic), say so explicitly and explain why in one sentence.
- If it is NOT accurate, write a corrected plate comment following this project's convention: a \
one-line summary, then "Algorithm:" (numbered steps grounded ONLY in what the decompiled body \
actually does), "Parameters:", and "Returns:". Do not invent behavior the code doesn't show. If \
you cannot determine what the function does with confidence, say so explicitly instead of guessing \
-- do not produce a plausible-sounding but unsupported plate.

Respond in exactly this format:
VERDICT: <accurate | inaccurate | cannot_determine>
REASONING: <one to three sentences>
CORRECTED_PLATE:
<the corrected plate text, or "N/A" if VERDICT is accurate or cannot_determine>
"""


def build_prompt(program, address, evidence, existing_comment, decompiled):
    existing = existing_comment.get("plate") or existing_comment.get("comment") or "(no plate comment found)"
    return PROMPT_TEMPLATE.format(
        program=program, evidence=evidence, existing_comment=existing,
        address=address, decompiled=decompiled,
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, help="JSON file: list of {address, evidence, ...}")
    ap.add_argument("--program", required=True, help="Ghidra program path, e.g. /Vanilla/1.00/D2Game.dll")
    ap.add_argument("--provider", default="minimax")
    ap.add_argument("--model", default=None, help="Defaults to the provider's FIX-tier model")
    ap.add_argument("--limit", type=int, default=None, help="Process only the first N items")
    ap.add_argument("--address", action="append", default=[],
                    help="Process only this address (repeatable); default is all items in --input")
    ap.add_argument("--output", default=None,
                    help="Review file path (default: fun-doc/logs/comment_corrections_<ts>.json)")
    args = ap.parse_args(argv)

    import fun_doc  # deferred: only needed once we're actually calling a provider

    model = args.model or fun_doc.DEFAULT_PROVIDER_MODELS.get(args.provider, {}).get("FIX")
    if not model:
        print(f"[correct] no default model for provider={args.provider}; pass --model", file=sys.stderr)
        return 2

    items = json.loads(Path(args.input).read_text(encoding="utf-8"))
    if args.address:
        wanted = {a.lower().replace("0x", "") for a in args.address}
        items = [it for it in items if str(it.get("address", "")).lower().replace("0x", "") in wanted]
    if args.limit:
        items = items[: args.limit]

    print(f"[correct] program={args.program}  provider={args.provider}  model={model}  items={len(items)}")

    results = []
    for i, item in enumerate(items, 1):
        address = str(item["address"]).lower().replace("0x", "")
        evidence = item.get("evidence", "(no evidence text provided)")
        name = item.get("name") or "(unknown)"
        print(f"[correct] {i}/{len(items)}  0x{address}  {name}  ...", flush=True)

        existing_comment = fetch_comment(args.program, address)
        decompiled = fetch_decompiled(args.program, address)
        prompt = build_prompt(args.program, address, evidence, existing_comment, decompiled)

        text, meta = fun_doc._invoke_provider_direct(
            prompt, model=model, provider=args.provider, use_tools=False,
        )

        if text is None:
            print(f"    -> PROVIDER FAILURE: {meta.get('provider_error', meta)}")
            results.append({
                "address": address, "name": name, "evidence": evidence,
                "verdict": "provider_failure", "raw_meta": meta,
            })
            continue

        # Search anywhere in the text, not just at a line start: streaming/capture
        # artifacts have been observed clipping the first few characters of the
        # response (e.g. "VERDICT:" arriving as "ICT:"), which a strict
        # line.startswith check misses even though the rest of the response --
        # including a perfectly good CORRECTED_PLATE -- is intact.
        verdict = "unparsed"
        m = re.search(r"(?:VERDICT|ERDICT|RDICT|DICT|ICT)\s*:\s*(\w+)", text, re.IGNORECASE)
        if m:
            verdict = m.group(1).strip().lower()
        print(f"    -> {verdict}")

        results.append({
            "address": address,
            "name": name,
            "defect_types": item.get("defect_types"),
            "evidence": evidence,
            "existing_plate": existing_comment.get("plate"),
            "verdict": verdict,
            "provider_response": text,
        })

    out_path = Path(args.output) if args.output else (
        _FUNDOC_DIR / "logs" / f"comment_corrections_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}Z.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "program": args.program, "provider": args.provider, "model": model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }, indent=2), encoding="utf-8")

    by_verdict = {}
    for r in results:
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
    print(f"\n[correct] wrote {len(results)} result(s) to {out_path}")
    for v, n in sorted(by_verdict.items(), key=lambda x: -x[1]):
        print(f"    {n:>4}  {v}")
    print("\n[correct] REVIEW FILE ONLY -- nothing was written to Ghidra. "
          "Review the output, then apply corrections manually (set_comment/batch_set_comments) "
          "for whatever you confirm.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

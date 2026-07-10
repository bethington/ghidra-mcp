"""batch_assess.py -- run a backlog of functions through the WHOLE prove_doc workflow
(live-prove -> gate -> canonical-name -> DOC rung) and emit a performance scorecard.

This is the batch harness for assessing the unified pipeline at scale: it loops
prove_doc() over conformance/profiler/hot_backlog.json, CHECKPOINTS after every function
(so a mid-batch game/oracle crash loses nothing), and prints a scorecard partitioning
outcomes by result + how far each function got through the pipeline stages.

    python batch_assess.py                 # run the whole backlog
    python batch_assess.py --count 4       # first N only (smaller wave)
    python batch_assess.py --scorecard     # re-print scorecard from the last run, no proving

Honest by construction: failures are DATA (they show where the pipeline stops), not hidden.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import traceback
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
D2MOO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
BACKLOG = D2MOO / "conformance" / "profiler" / "hot_backlog.json"
OUT = D2MOO / "conformance" / "profiler" / f"batch_assess_results.json"


def _stage_reached(summary: dict) -> str:
    """Coarse 'how far did it get' bucket from the stages present."""
    st = summary.get("stages", {})
    if summary.get("result", "").startswith("EXCEPTION"):
        return "exception"
    if st.get("prove") not in ("proven_live_pending_review", "(skipped -- gate-only re-run)"):
        return "prove_failed"
    if "canonical_name" in st:
        cn = st["canonical_name"]
        if isinstance(cn, dict) and cn.get("applied"):
            return "canonical_named"
    if "gate" in st:
        return "gated"
    return "proven_only"


def run(count: int | None) -> list:
    os.environ.setdefault("FUNDOC_LIVE_PROVE", "1")
    os.environ.setdefault("FUNDOC_DOC_TAGS", "1")      # stamp the DOC_ maturity rung
    import prove_doc as pd
    rows = json.loads(BACKLOG.read_text(encoding="utf-8")).get("backlog", [])
    if count:
        rows = rows[:count]
    results = []
    for i, r in enumerate(rows):
        name, addr = r["name"], r["address"]
        print(f"\n===== [{i+1}/{len(rows)}] {name} {addr} ({r.get('hits','?')} hits) =====",
              flush=True)
        t0 = datetime.now()
        try:
            s = pd.prove_doc(addr, name)
        except Exception as e:
            s = {"name": name, "address": addr, "result": f"EXCEPTION: {e}",
                 "trace": traceback.format_exc()[-600:], "stages": {}}
        s["_secs"] = round((datetime.now() - t0).total_seconds(), 1)
        s["_hits"] = r.get("hits")
        s["_reached"] = _stage_reached(s)
        results.append(s)
        OUT.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")   # checkpoint
        print(f"  -> {s.get('result')}  [{s['_reached']}]  ({s['_secs']}s)", flush=True)
    return results


def scorecard(results: list) -> None:
    n = len(results)
    reached = collections.Counter(s.get("_reached") for s in results)
    total_s = sum(s.get("_secs", 0) for s in results)
    print("\n" + "=" * 72)
    print(f"BATCH SCORECARD -- {n} functions, {total_s/60:.1f} min total "
          f"({total_s/max(n,1):.0f}s avg)")
    print("=" * 72)
    print("\nHOW FAR THROUGH THE PIPELINE:")
    order = ["canonical_named", "proven_only", "gated", "prove_failed", "exception"]
    for k in order:
        if reached.get(k):
            print(f"  {k:<18} {reached[k]}")
    for k, v in reached.items():
        if k not in order:
            print(f"  {k:<18} {v}")
    proven = [s for s in results if s.get("_reached") not in ("prove_failed", "exception")]
    named = [s for s in results if s.get("_reached") == "canonical_named"]
    print(f"\nPROVED (whole workflow ran): {len(proven)}/{n}")
    print(f"CANONICAL-NAMED live:        {len(named)}/{n}")
    print("\nPER-FUNCTION:")
    for s in results:
        cn = s.get("stages", {}).get("canonical_name", {})
        nm = (f"  -> {cn['to']}" if isinstance(cn, dict) and cn.get("applied")
              else (f"  (name: {cn.get('unresolved','')[:40]})" if isinstance(cn, dict)
                    and cn.get("unresolved") else ""))
        print(f"  {s['name']:<34} {s.get('_reached',''):<16} {str(s.get('result',''))[:46]}{nm}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--count", type=int, default=None)
    ap.add_argument("--scorecard", action="store_true",
                    help="re-print scorecard from the last results file, no proving")
    args = ap.parse_args()
    if args.scorecard:
        results = json.loads(OUT.read_text(encoding="utf-8"))
    else:
        results = run(args.count)
    scorecard(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

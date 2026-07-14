"""Supervised parallel-set harness (2026-07-14, user-directed throughput redesign).

ONE SET per run: draft N functions IN PARALLEL (minimax, the bottleneck), then
batch-build the provider ONCE and prove each SERIALLY through the single oracle.
Emits a review report (JSON + human) so the orchestrating agent can decide,
per failure, script-fix vs. intelligence-escalate.

Draft workers reuse the FULL pipeline (process_port_candidate under
FUNDOC_DRAFT_ONLY=1) -- every capability, guard, and route applies; they just
stop before build/prove. So a function only drafts if the pipeline decided to
prove it (stateful/hazard/abort still skip/defer in-worker).

Usage:  python pset.py --count 10        # pull next N from the getter_queue
        python pset.py --names A,B,C
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

FUNDOC = r"C:\Users\benam\source\mcp\ghidra-mcp\fun-doc"
sys.path.insert(0, FUNDOC)
PROGRAM = "/Mods/PD2-S12/D2Common.dll"
HERE = Path(__file__).parent
STATE = HERE / "loop_state.json"
DRAFTMETA = Path(r"C:\Users\benam\source\cpp\D2MOO\conformance\reimpl_provider\draftmeta")
REG = Path(r"C:\Users\benam\source\cpp\D2MOO\conformance\proven_functions.jsonl")

# one-function draft worker: run the real pipeline, draft-only
_DRAFT_SNIPPET = (
    "import os,sys; sys.path.insert(0,r'%s');"
    "os.environ['FUNDOC_DRAFT_ONLY']='1'; os.environ['FUNDOC_LIVE_PROVE']='1';"
    "os.environ['FUNDOC_DOC_TAGS']='1'; os.environ['FUNDOC_SHADOW_PROMOTE']='1';"
    "os.environ.setdefault('FUNDOC_ADVERSARIAL_VET','0');"
    "import fun_doc;"
    "r=fun_doc.process_port_candidate('%s', sys.argv[1], sys.argv[2],"
    " provider=fun_doc.AI_PROVIDER, model=None, worker_id='pset_draft');"
    "print('DRAFT_RESULT:'+str(r))"
) % (FUNDOC, PROGRAM)


def pick_batch(count, names):
    s = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}
    if names:
        # look up addresses from the getter_queue / triage pool
        idx = {}
        for e in s.get("getter_queue", []):
            idx[e["name"]] = e["address"]
        return [{"name": n, "address": idx.get(n, "")} for n in names]
    gq = s.get("getter_queue", [])
    batch = gq[:count]
    s["getter_queue"] = gq[count:]
    STATE.write_text(json.dumps(s, indent=1) + "\n", encoding="utf-8")
    return batch


def draft_parallel(batch):
    if DRAFTMETA.exists():
        for f in DRAFTMETA.glob("*.json"):
            f.unlink()
    env = dict(os.environ)
    procs = []
    for e in batch:
        # process_port_candidate prepends "0x"; the getter_queue stores addrs WITH
        # "0x". Strip it so we don't pass 0x0x... (-> decompile fail -> unknown_skip).
        addr = str(e["address"]).lower().replace("0x", "")
        p = subprocess.Popen(
            [sys.executable, "-c", _DRAFT_SNIPPET, addr, e["name"]],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        procs.append((e, p))
    outcomes = {}
    for e, p in procs:
        out, _ = p.communicate()
        line = next((l for l in (out or "").splitlines() if l.startswith("DRAFT_RESULT:")), "")
        outcomes[e["name"]] = line.replace("DRAFT_RESULT:", "").strip() or "no-result"
    return outcomes


def prove_serial(draft_outcomes):
    import port_live_prove as plp
    metas = []
    for f in sorted(DRAFTMETA.glob("*.json")):
        try:
            metas.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    results = {}
    for i, m in enumerate(metas):
        build = (i == 0)   # first prove builds+reloads the whole candidates dir
        try:
            if m.get("prove_kind") == "handle":
                res = plp.run_handle_prove(m["reimpl"], m["name"], m["address"],
                                           m["layout"], m["input_sets"], build=build)
            else:
                res = plp.run_live_prove(m["reimpl"], m["name"], m["address"],
                                         m["layout"], m["input_sets"], build=build,
                                         abort_class=m.get("abort_class", False))
            results[m["name"]] = {
                "ok": bool(res.get("ok")), "passed": res.get("passed"),
                "total": res.get("total"), "stage": res.get("failure_stage"),
                "detail": (res.get("failure_detail") or "")[:160]}
        except Exception as ex:
            results[m["name"]] = {"ok": False, "stage": "exception", "detail": str(ex)[:160]}
        # oracle-death guard between proves
        if not plp.check_oracle_alive():
            results["_HALT"] = f"oracle died after {m['name']}"
            break
    return results, [m["name"] for m in metas]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--names")
    a = ap.parse_args()
    batch = pick_batch(a.count, [n.strip() for n in a.names.split(",")] if a.names else None)
    print(f"=== SET: {len(batch)} fns ===", flush=True)

    t0 = time.time()
    drafts = draft_parallel(batch)
    t_draft = time.time() - t0
    drafted = [n for n, r in drafts.items() if r == "drafted"]
    print(f"[draft] {len(drafted)}/{len(batch)} drafted in {t_draft:.0f}s (parallel); "
          f"non-drafted: {[(n, r) for n, r in drafts.items() if r != 'drafted']}", flush=True)

    t1 = time.time()
    proven_map, order = prove_serial(drafts)
    t_prove = time.time() - t1

    proven = [n for n, r in proven_map.items() if isinstance(r, dict) and r.get("ok")]
    failed = {n: r for n, r in proven_map.items() if isinstance(r, dict) and not r.get("ok")}
    report = {
        "set_size": len(batch), "drafted": len(drafted),
        "draft_secs": round(t_draft), "prove_secs": round(t_prove),
        "proven": proven, "failed": failed,
        "non_drafted": {n: r for n, r in drafts.items() if r != "drafted"},
        "halt": proven_map.get("_HALT"),
    }
    (HERE / "pset_report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"\n=== REPORT ===")
    print(f"proven {len(proven)}/{len(batch)} | draft {t_draft:.0f}s parallel, prove {t_prove:.0f}s serial")
    print(f"PROVEN: {proven}")
    for n, r in failed.items():
        print(f"  FAIL {r.get('stage'):<18} {n}  {r.get('detail','')[:80]}")
    for n, r in report["non_drafted"].items():
        print(f"  SKIP {r:<22} {n}")
    if report["halt"]:
        print(f"  !! HALT: {report['halt']}")


if __name__ == "__main__":
    raise SystemExit(main())

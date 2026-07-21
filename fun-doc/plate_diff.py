"""plate_diff.py -- dry-run plate workflow report (READ-ONLY).

For a stratified sample of documented functions and globals, it regenerates the harness-owned
scaffold (without writing anything) and compares it to the CURRENT plate, producing an evidence
report an AI can read to judge how well the documentation workflow is actually working -- for
functions and globals separately. Four dimensions per item:

  * fidelity      -- would converting this plate to the scaffold lose any existing prose?
  * empirical_gaps-- which derivable fields the current plate LACKS (params, Source, Set/Read by)
  * quality       -- markdown outliers, placeholder/echo descriptions, non-canonical param types
  * deductions    -- the completeness deductions this item currently carries

Output: a readable aggregate + notable-findings report to stdout, and the full per-item records
to a JSON file. NO grades/thresholds are baked in -- the AI reading the evidence forms the verdict.
NOTHING is written back to Ghidra; this is a dry run.

Usage:
    python plate_diff.py [--count N] [--tag DOC_VERIFIED] [--binary <program>] [--json <path>]
"""
from __future__ import annotations

import argparse
import json
import os
import re

import plate_scaffold as ps
import d2moo_types

PROGRAM = os.environ.get("FUNDOC_GHIDRA_PROGRAM", "/Mods/PD2-S12/D2Common.dll")
_FN_TIERS = ("DOC_VERIFIED", "DOC_REVIEWED", "DOC_DRAFT")
_STOP = set("the a an of to for and or is are in on at by with from as it this that value pointer".split())
_MD = re.compile(r"(^|\n)\s*#{1,4}\s|\n\s*\|[^\n]*\|\s*\n|\*\*[A-Za-z][^*]*:\*\*")


def _words(s):
    return {w for w in re.findall(r"[A-Za-z_]\w{2,}", (s or "").lower()) if w not in _STOP}


def _content_in(body, target, thresh=0.7):
    """True if >= thresh of body's significant words appear in target (prose-retention proxy)."""
    bw = _words(body)
    if not bw:
        return True
    return len(bw & _words(target)) / len(bw) >= thresh


# ---- per-item analysis -----------------------------------------------------------------------
def analyze_function(addr, program):
    a = addr if str(addr).startswith("0x") else "0x" + str(addr)
    cur = ps._get("/get_comment", address=a, program=program)
    orig = cur.get("plate") if isinstance(cur, dict) else None
    params, rt, fname = ps._fetch_signature(a, program)
    regen = ps.scaffold_for(a, program)
    po, pr = ps.parse_function_plate(orig or ""), ps.parse_function_plate(regen)

    lost = []
    for sec, body in po["sections"].items():
        if sec in ("Parameters", "Returns", "Source") or not body.strip():
            continue
        if not _content_in(body, regen):
            lost.append(f"section '{sec}'")
    for pn, d in po["params"].items():
        # content-based: the description may have re-attached to a differently-named live param
        # (positional fallback, e.g. pUnit -> param_1), so check the prose survives ANYWHERE.
        # Strip a storage annotation first -- the harness RELOCATES it to the canonical position,
        # so those words aren't "lost", they moved.
        d = ps._STORAGE_TAIL.sub("", d or "").strip()
        if d and not _content_in(d, regen):
            lost.append(f"param '{pn}' description")
    if po.get("summary") and not _content_in(po["summary"], regen):
        lost.append("summary")

    gaps = []
    if params and not po["sections"].get("Parameters"):
        gaps.append("no Parameters section")
    missing = [p["name"] for p in params if p["name"] and p["name"] not in po["params"]]
    if missing:
        gaps.append(f"{len(missing)} live param(s) not documented: {', '.join(missing[:4])}")
    if rt and rt != "void" and not po["sections"].get("Returns"):
        gaps.append("no Returns section")
    if not any("source" in s.lower() for s in po["sections"]) and "source:" not in (orig or "").lower():
        gaps.append("no Source line")

    quality = []
    if orig and _MD.search(orig):
        quality.append("markdown-outlier format")
    noncanon = []
    for p in params:
        t = (p.get("type") or "")
        v = d2moo_types.validate_type(t)
        if ("void" in t and "*" in t) or v["verdict"] == "UNKNOWN":
            noncanon.append(f"{p['name']}:{t}")
    if noncanon:
        quality.append(f"{len(noncanon)} non-canonical param type(s): {', '.join(noncanon[:3])}")
    ph = [i for i in ps.unfilled_slots(orig or "") if "placeholder" in i or "echo" in i]
    if ph:
        quality.append(f"{len(ph)} placeholder/echo description(s)")

    ded = _deductions(a, program)
    return {"kind": "function", "address": a, "name": fname, "has_plate": bool(orig),
            "fidelity": {"lossless": not lost, "lost": lost},
            "empirical_gaps": gaps, "quality": quality, "deductions": ded,
            "params_live": len(params)}


def analyze_global(addr, program):
    a = addr if str(addr).startswith("0x") else "0x" + str(addr)
    cur = ps._get("/get_comment", address=a, program=program)
    orig = cur.get("plate") if isinstance(cur, dict) else None
    name, gtype, size, writers, readers = ps._fetch_global(a, program)
    regen = ps.global_scaffold_for(a, program)
    po = ps.parse_global_plate(orig or "")

    lost = []
    for sec, body in po["sections"].items():
        if sec in ("Set By", "Read By") or not body.strip():
            continue
        if not _content_in(body, regen):
            lost.append(f"section '{sec}'")
    if po.get("summary") and not _content_in(po["summary"], regen):
        lost.append("summary")

    low = (orig or "").lower()
    gaps = []
    if writers and "set by" not in low:
        gaps.append(f"{len(writers)} writer(s) not attributed (no 'Set by')")
    if readers and "read by" not in low and "used by" not in low:
        gaps.append(f"{len(readers)} reader site(s) not attributed (no 'Read by')")
    if "type:" not in low and gtype:
        gaps.append("no Type/identity line")

    quality = []
    if orig and _MD.search(orig):
        quality.append("markdown-outlier format")
    v = d2moo_types.validate_type(gtype or "")
    if v["verdict"] in ("INVALID", "UNREFINED", "UNKNOWN") and gtype and "*" not in (gtype or ""):
        quality.append(f"non-canonical type: {gtype} ({v['verdict']})")
    if orig and len(orig.split()) < 6:
        quality.append("very short / thin plate")

    return {"kind": "global", "address": a, "name": name, "has_plate": bool(orig),
            "type": gtype, "writers": len(writers), "readers": len(readers),
            "fidelity": {"lossless": not lost, "lost": lost},
            "empirical_gaps": gaps, "quality": quality, "deductions": []}


def _deductions(addr, program):
    try:
        r = ps._get("/analyze_function_completeness", function_address=addr, program=program)
        if isinstance(r, str):
            r = json.loads(r)
        return sorted({d.get("category") for d in (r.get("deduction_breakdown") or []) if d.get("category")})
    except Exception:
        return []


# ---- sampling --------------------------------------------------------------------------------
def _fn_sample(program, count, tag):
    tiers = [tag] if tag else _FN_TIERS
    out = []
    for t in tiers:
        try:
            r = ps._get("/search_functions_by_tag", tag=t, program=program)
            fns = (r.get("functions") or []) if isinstance(r, dict) else []
        except Exception:
            fns = []
        out += [("0x" + str(f["address"]).lstrip("0x"), t) for f in fns[:count]]
    return out


def _glob_sample(program, count):
    """Documented globals: addresses in the Doc property map."""
    out = []
    try:
        r = ps._get("/list_properties", map="Doc", program=program, limit=100000)
        ents = (r.get("entries") or r.get("properties") or []) if isinstance(r, dict) else []
        for e in ents[:count * 2]:
            a = e.get("address")
            if a:
                out.append("0x" + str(a).lower().lstrip("0x"))
    except Exception:
        pass
    return out[:count]


# ---- aggregate + render ----------------------------------------------------------------------
def _agg(records):
    n = len(records)
    if not n:
        return {"n": 0}
    lossless = sum(1 for r in records if r["fidelity"]["lossless"])
    with_gaps = sum(1 for r in records if r["empirical_gaps"])
    with_qual = sum(1 for r in records if r["quality"])
    ded_hist, gap_hist, qual_hist = {}, {}, {}
    for r in records:
        for d in r.get("deductions", []):
            ded_hist[d] = ded_hist.get(d, 0) + 1
        for g in r["empirical_gaps"]:
            k = re.sub(r"\d+", "N", g.split(":")[0]).strip()
            gap_hist[k] = gap_hist.get(k, 0) + 1
        for q in r["quality"]:
            k = re.sub(r"\d+", "N", q.split(":")[0]).strip()
            qual_hist[k] = qual_hist.get(k, 0) + 1
    return {"n": n, "lossless": lossless, "lost_prose": n - lossless,
            "with_empirical_gaps": with_gaps, "with_quality_issues": with_qual,
            "gap_histogram": dict(sorted(gap_hist.items(), key=lambda x: -x[1])),
            "quality_histogram": dict(sorted(qual_hist.items(), key=lambda x: -x[1])),
            "deduction_histogram": dict(sorted(ded_hist.items(), key=lambda x: -x[1]))}


def _pct(a, b):
    return f"{100*a//b}%" if b else "-"


def render(fn_records, glob_records, fa, ga):
    L = ["=" * 70, "PLATE WORKFLOW REPORT (dry run, read-only) -- evidence for AI assessment", "=" * 70]
    for label, recs, ag in (("FUNCTIONS", fn_records, fa), ("GLOBALS", glob_records, ga)):
        L.append("")
        L.append(f"== {label} (n={ag.get('n',0)}) ==")
        if not ag.get("n"):
            L.append("  (none sampled)")
            continue
        n = ag["n"]
        L.append(f"  conversion fidelity : {ag['lossless']}/{n} lossless ({_pct(ag['lossless'],n)}), "
                 f"{ag['lost_prose']} would lose prose")
        L.append(f"  empirical gaps      : {ag['with_empirical_gaps']}/{n} items have missing derivable fields")
        for k, c in ag["gap_histogram"].items():
            L.append(f"      - {k}: {c}")
        L.append(f"  description quality : {ag['with_quality_issues']}/{n} items have quality issues")
        for k, c in ag["quality_histogram"].items():
            L.append(f"      - {k}: {c}")
        if ag.get("deduction_histogram"):
            L.append("  completeness deductions present:")
            for k, c in ag["deduction_histogram"].items():
                L.append(f"      - {k}: {c}")
    # notable per-item findings: one concrete example per issue type
    L += ["", "== NOTABLE ITEMS (concrete examples) =="]
    seen = set()
    for r in fn_records + glob_records:
        for issue in (["LOST-PROSE: " + ", ".join(r["fidelity"]["lost"])] if r["fidelity"]["lost"] else []) \
                + ["GAP: " + g for g in r["empirical_gaps"]] + ["QUALITY: " + q for q in r["quality"]]:
            key = issue.split(":")[0] + issue.split(":")[1][:18]
            if key in seen:
                continue
            seen.add(key)
            L.append(f"  [{r['kind']}] {r.get('name') or r['address']} @ {r['address']}")
            L.append(f"      {issue}")
    return "\n".join(L)


def run(program=None, count=15, tag=None, json_path=None):
    program = program or PROGRAM
    fn_records, glob_records = [], []
    for addr, tier in _fn_sample(program, count, tag):
        try:
            rec = analyze_function(addr, program)
            rec["tier"] = tier
            fn_records.append(rec)
        except Exception as e:
            fn_records.append({"kind": "function", "address": addr, "error": str(e),
                               "fidelity": {"lossless": True, "lost": []}, "empirical_gaps": [], "quality": []})
    if not tag:  # globals sampled only when not narrowing to a function tag
        for addr in _glob_sample(program, count + 5):
            try:
                glob_records.append(analyze_global(addr, program))
            except Exception as e:
                glob_records.append({"kind": "global", "address": addr, "error": str(e),
                                     "fidelity": {"lossless": True, "lost": []}, "empirical_gaps": [], "quality": []})
    fa, ga = _agg(fn_records), _agg(glob_records)
    report = render(fn_records, glob_records, fa, ga)
    print(report)
    path = json_path or os.path.join(os.environ.get("TEMP", "."), "plate_diff_report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"program": program, "functions": fn_records, "globals": glob_records,
                   "aggregate": {"functions": fa, "globals": ga}}, f, indent=2)
    print(f"\nfull per-item records -> {path}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--count", type=int, default=15, help="items per function tier / globals (default 15)")
    ap.add_argument("--tag", help="narrow to one function DOC tag (skips globals)")
    ap.add_argument("--binary", default=None, help="program path")
    ap.add_argument("--json", default=None, help="where to write the full JSON")
    args = ap.parse_args()
    return run(program=args.binary, count=args.count, tag=args.tag, json_path=args.json)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""conformance_dashboard.py -- the Ghidra-native READ LAYER for the confidence dashboard.

Per the nailed-down design, Ghidra is the source of truth AND the dashboard's read-model,
read LIVE (no cache DB). This module pulls everything the dashboard needs directly:

  summary()          -> the `Conformance.summary` program OPTION -- one call: rung counts,
                        vetted, in_scope, totals. The dashboard headline + matrix marginals.
  matrix()           -> the DOC_ x CONF_ joint, computed from tag SETS (a handful of
                        search_functions_by_tag calls -- cheap set math, no per-fn scan).
  intake()           -> never-evaluated count (in_scope minus everything tagged).
  function_detail()  -> one function's drawer: rung tags + the `Conf` property (proof
                        detail) + signature/decompile for the side-by-side code.

Runnable standalone to dump/verify the data against a live Ghidra:
  python conformance_dashboard.py            # summary + matrix + intake
  python conformance_dashboard.py --fn 0x6fd681f0   # one function's drawer data
"""
from __future__ import annotations
import argparse
import json
import os
import urllib.request
from urllib.parse import urlencode

GHIDRA = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")
PROGRAM = os.environ.get("FUNDOC_GHIDRA_PROGRAM", "/Mods/PD2-S12/D2Common.dll")

CONF_RUNGS = ["CONF_REGRESSION", "CONF_BATTLETESTED", "CONF_LIVE", "CONF_VECTORS", "CONF_DRAFT"]  # best->worst
DOC_RUNGS = ["DOC_VERIFIED", "DOC_REVIEWED", "DOC_DRAFT"]                                        # best->worst
OPT_GROUP, OPT_NAME = "Program Information", "Conformance.summary"


def _get(path: str, **params):
    url = f"{GHIDRA}{path}" + ("?" + urlencode(params) if params else "")
    with urllib.request.urlopen(url, timeout=60) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw   # text endpoints (decompile, list_functions)


def _tag_addrs(tag: str, program: str = None) -> set[str]:
    """Set of function addresses carrying `tag` (one search, not per-function)."""
    try:
        r = _get("/search_functions_by_tag", tag=tag, program=program or PROGRAM)
    except OSError:
        return set()
    return {"0x" + str(f.get("address", "")).lower() for f in (r.get("functions") or [])}


def summary(program: str = None) -> dict:
    """The one-call dashboard rollup from the program option (written per batch by the
    sync tool). Falls back to {} if Ghidra/the option is unavailable."""
    try:
        opts = _get("/get_program_options", group=OPT_GROUP, program=program or PROGRAM).get("options", [])
        raw = next((o["value"] for o in opts if o.get("name") == OPT_NAME), None)
        return json.loads(raw) if raw else {}
    except (OSError, json.JSONDecodeError, KeyError):
        return {}


def matrix(program: str = None) -> dict:
    """The DOC_ x CONF_ joint counts, plus marginals and the never-evaluated cell.
    Rows = CONF (best->worst then none); cols = DOC (none->best). Cheap set math."""
    conf_sets = {r: _tag_addrs(r, program) for r in CONF_RUNGS}
    doc_sets = {r: _tag_addrs(r, program) for r in DOC_RUNGS}
    conf_tagged = set().union(*conf_sets.values()) if conf_sets else set()
    doc_tagged = set().union(*doc_sets.values()) if doc_sets else set()

    def conf_of(a):  # a function has at most one rung (mutual exclusivity, now enforced)
        return next((r for r in CONF_RUNGS if a in conf_sets[r]), "none")

    def doc_of(a):
        return next((r for r in DOC_RUNGS if a in doc_sets[r]), "none")

    rows = ["CONF_REGRESSION", "CONF_BATTLETESTED", "CONF_LIVE", "CONF_VECTORS", "none"]
    cols = ["none", "DOC_DRAFT", "DOC_REVIEWED", "DOC_VERIFIED"]
    cell = {rk: {ck: 0 for ck in cols} for rk in rows}
    for a in conf_tagged | doc_tagged:
        cell[conf_of(a)][doc_of(a)] += 1

    s = summary(program)
    in_scope = s.get("in_scope")
    evaluated = len(conf_tagged | doc_tagged)
    if in_scope is not None:                       # the none/none cell = never-evaluated
        cell["none"]["none"] = max(0, in_scope - evaluated)
    return {"rows": rows, "cols": cols, "cell": cell,
            "in_scope": in_scope, "evaluated": evaluated,
            "excluded_lib": s.get("excluded_lib")}


def intake(program: str = None) -> dict:
    """The intake lane: never-evaluated (in-scope, no tag) and the excluded library set."""
    s = summary(program)
    m = matrix(program)
    return {"untriaged": m["cell"]["none"]["none"], "in_scope": s.get("in_scope"),
            "excluded_lib": s.get("excluded_lib"), "total_all": s.get("total_all")}


def inventory(search: str = "", limit: int = 100, program: str = None) -> dict:
    """Searchable Function Inventory: in-scope functions matching `search` (name substring),
    each with its DOC_/CONF_ rung. Computed from tag sets + a name filter over the defined
    function list, so a search returns fast without per-function calls."""
    program = program or PROGRAM
    conf_sets = {r: _tag_addrs(r, program) for r in CONF_RUNGS}
    doc_sets = {r: _tag_addrs(r, program) for r in DOC_RUNGS}
    lib = set().union(*(_tag_addrs(t, program) for t in
                        ("LIB_CRT", "LIB_MSVC_EH", "LIB_SECURITY", "LIB_MATH", "LIB_MSVC", "LIB_UNKNOWN")))
    txt = _get("/list_functions", program=program, limit=6000)
    import re
    line = re.compile(r"^(?P<name>\S.*?)\s+at\s+(?P<addr>[0-9a-fA-F]+)\s*$")
    s = search.lower()
    rows, total = [], 0
    seen = set()
    for ln in (txt if isinstance(txt, str) else "").splitlines():
        m = line.match(ln.strip())
        if not m:
            continue
        a = "0x" + m.group("addr").lower()
        name = m.group("name")
        if a in seen or a in lib:          # dedup + exclude library (out of scope)
            continue
        seen.add(a)
        if s and s not in name.lower():
            continue
        total += 1
        if len(rows) < limit:
            conf = next((r for r in CONF_RUNGS if a in conf_sets[r]), "none")
            doc = next((r for r in DOC_RUNGS if a in doc_sets[r]), "none")
            rows.append({"name": name, "address": a, "doc": doc, "conf": conf})
    rows.sort(key=lambda r: (r["conf"] == "none", r["name"].lower()))
    return {"rows": rows, "total": total, "shown": len(rows)}


def function_detail(addr: str, program: str = None) -> dict:
    """One function's drawer data: rung tags, the Conf proof record, and the signature
    for the side-by-side code view."""
    program = program or PROGRAM
    addr = addr if str(addr).startswith("0x") else "0x" + str(addr)
    out = {"address": addr, "doc": "none", "conf": "none", "scope": None, "proof": None,
           "name": None, "signature": None}
    try:
        tg = _get("/get_function_tags", function=addr, program=program)
        out["name"] = tg.get("function")
        for t in tg.get("tags", []):
            n = t.get("name", "")
            if n in CONF_RUNGS:
                out["conf"] = n
            elif n in DOC_RUNGS:
                out["doc"] = n
            elif n.startswith("LIB_"):
                out["scope"] = n
    except OSError:
        pass
    try:
        p = _get("/get_property", map="Conf", address=addr, program=program)
        if p.get("value"):
            out["proof"] = json.loads(p["value"])
    except (OSError, json.JSONDecodeError):
        pass
    try:
        sig = _get("/get_function_signature", function=addr, program=program)
        out["signature"] = sig.get("signature") if isinstance(sig, dict) else None
    except OSError:
        pass
    return out


def list_binaries() -> dict:
    """The folder + binary options for the header selectors, so the dashboard is
    focused on ONE binary at a time (its per-program tags/maps/rollup). Sourced from
    Ghidra's OPEN programs; the currently-active one is flagged."""
    out = {"binaries": [], "active": PROGRAM}
    try:
        r = _get("/list_open_programs")
        progs = r.get("programs") or r.get("open_programs") or []
        for p in progs:
            path = p.get("path") or p.get("program") or (p if isinstance(p, str) else None)
            if not path:
                continue
            folder, _, name = str(path).rpartition("/")
            out["binaries"].append({"path": path, "name": name or path, "folder": folder or "/"})
    except OSError:
        pass
    if not out["binaries"]:                # fall back to the current program
        folder, _, name = PROGRAM.rpartition("/")
        out["binaries"] = [{"path": PROGRAM, "name": name, "folder": folder or "/"}]
    return out


def _main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fn", help="print one function's drawer data (address)")
    args = ap.parse_args()
    if args.fn:
        print(json.dumps(function_detail(args.fn), indent=2))
        return 0
    print("SUMMARY:", json.dumps(summary()))
    print("\nINTAKE:", json.dumps(intake()))
    m = matrix()
    print(f"\nMATRIX (in_scope={m['in_scope']}, evaluated={m['evaluated']}):")
    print(f"  {'':16}" + "".join(f"{c:>13}" for c in m["cols"]))
    for rk in m["rows"]:
        print(f"  {rk:16}" + "".join(f"{m['cell'][rk][ck]:>13}" for ck in m["cols"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

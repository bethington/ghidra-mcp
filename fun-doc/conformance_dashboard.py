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
# tags that drop a function OUT of the "real game work" scope: library + trivial dispositions.
LIB_TAGS = ("LIB_CRT", "LIB_MSVC_EH", "LIB_SECURITY", "LIB_MATH", "LIB_MSVC", "LIB_UNKNOWN")
EXCLUDE_TAGS = LIB_TAGS + ("STUB", "THUNK", "EXTERNAL")
OPT_GROUP, OPT_NAME = "Program Information", "Conformance.summary"


import time as _time


def _get(path: str, **params):
    """GET with a couple of retries -- Ghidra's HTTP bridge can transiently hiccup
    (5xx/reset) when a worker is hammering it; a bare failure here would 500 the
    dashboard endpoint and make the UI fall back to stale sample data."""
    url = f"{GHIDRA}{path}" + ("?" + urlencode(params) if params else "")
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                raw = r.read().decode("utf-8", "replace")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw   # text endpoints (decompile, list_functions)
        except Exception as e:   # URLError, HTTPError, timeout, reset
            last = e
            if attempt < 2:
                _time.sleep(0.3 * (attempt + 1))
    raise last


def _post(path: str, data: dict) -> dict:
    req = urllib.request.Request(f"{GHIDRA}{path}", data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _norm(a) -> str:
    """Normalize an address to '0x' + lowercase hex (tag search returns bare hex)."""
    a = str(a).lower()
    return a if a.startswith("0x") else "0x" + a


def _tag_named(tag: str, program: str = None) -> dict:
    """{address -> name} for functions carrying `tag`."""
    try:
        r = _get("/search_functions_by_tag", tag=tag, program=program or PROGRAM)
    except OSError:
        return {}
    return {_norm(f.get("address", "")): f.get("name") for f in (r.get("functions") or [])}


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

    # every CONF rung is a row (incl. CONF_DRAFT) so the dashboard bars can show the full
    # ladder; every DOC rung is a column. `none` = no rung on that axis.
    rows = ["CONF_REGRESSION", "CONF_BATTLETESTED", "CONF_LIVE", "CONF_VECTORS", "CONF_DRAFT", "none"]
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


def inventory(search: str = "", limit: int = 6000, program: str = None) -> dict:
    """Searchable Function Inventory: the COMPLETE list of in-scope functions matching `search`
    (name substring), each with its DOC_/CONF_ rung. Library functions (LIB_-tagged) are
    excluded. Computed from tag sets + a name filter over the defined function list. Rows are
    sorted (un-proven first, then by name) BEFORE the limit is applied, so the cap keeps the
    most-relevant rows rather than an arbitrary address-ordered slice."""
    program = program or PROGRAM
    conf_sets = {r: _tag_addrs(r, program) for r in CONF_RUNGS}
    doc_sets = {r: _tag_addrs(r, program) for r in DOC_RUNGS}
    lib = set().union(*(_tag_addrs(t, program) for t in EXCLUDE_TAGS))
    txt = _get("/list_functions", program=program, limit=100000)
    import re
    line = re.compile(r"^(?P<name>\S.*?)\s+at\s+(?P<addr>[0-9a-fA-F]+)\s*$")
    s = search.lower()
    rows = []
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
        conf = next((r for r in CONF_RUNGS if a in conf_sets[r]), "none")
        doc = next((r for r in DOC_RUNGS if a in doc_sets[r]), "none")
        rows.append({"name": name, "address": a, "doc": doc, "conf": conf})
    total = len(rows)
    rows.sort(key=lambda r: (r["conf"] == "none", r["name"].lower()))
    return {"rows": rows[:limit], "total": total, "shown": min(len(rows), limit)}


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


import re as _re

# A global counts toward "typing groundwork" once it carries a real (non-primitive) type.
# This is NOT a doc rung -- it's the interim signal shown while the DOC_ rung pass is pending.
_GLOB_PRIM = _re.compile(
    r"^(undefined\d*|dword|word|byte|qword|void\s*\*?\d*|u?int\d*|u?char|u?short|u?long|"
    r"bool|float|double|pointer|code|undefined)\s*$", _re.I)
_GLOB_LINE = _re.compile(
    r"^(?P<name>\S+)\s+@\s+(?P<addr>[0-9a-fA-F]+)\s+\[[^\]]*\]\s+\((?P<type>[^)]*)\)"
    r"(?:\s+xrefs=(?P<xrefs>\d+))?")
_IMG_LO, _IMG_HI = 0x6f000000, 0x70000000  # DLL mapped range; excludes TIB/PEB/stack labels
# Globals carry the SAME doc rungs as functions, but stored in a per-address property map
# ("Doc") rather than Ghidra function-tags (which are function-scoped and can't attach to data).
GLOB_DOC_MAP = "Doc"


def _global_rows(program: str) -> list[dict]:
    """In-scope image globals for a program: {addr, name, type, typed}. Parsed from the
    free list_globals text (one call, no per-global fanout). Excludes out-of-image OS
    labels (TIB/PEB) and Ordinal_ export aliases."""
    txt = _get("/list_globals", program=program, limit=100000)
    rows = []
    for ln in (txt if isinstance(txt, str) else "").splitlines():
        m = _GLOB_LINE.match(ln.strip())
        if not m:
            continue
        a = int(m.group("addr"), 16)
        if not (_IMG_LO <= a < _IMG_HI):
            continue
        name = m.group("name")
        if name.startswith("Ordinal_"):
            continue
        t = m.group("type").strip()
        rows.append({"addr": "0x%08x" % a, "name": name, "type": t,
                     "typed": not bool(_GLOB_PRIM.match(t)),
                     "xrefs": int(m.group("xrefs") or 0)})
    return rows


def _doc_map_rungs(program: str) -> dict:
    """{address -> DOC_ rung} from the `Doc` property map (globals' doc rungs). Empty until
    a globals-doc pass writes them -- the honest 'not yet documented' state."""
    out = {}
    try:
        r = _get("/list_properties", map=GLOB_DOC_MAP, program=program)
        # the endpoint returns the list under "entries" (not "properties")
        for p in (r.get("entries") or r.get("properties") or []):
            a = p.get("address")
            v = p.get("value")
            if a and v in DOC_RUNGS:
                out["0x" + str(a).lower().lstrip("0x").rjust(8, "0")] = v
    except (OSError, AttributeError):
        pass
    return out


def _in_scope_fn(program: str, s: dict) -> int | None:
    """In-scope function count: from the summary option if present, else defined-minus-LIB_."""
    if s.get("in_scope") is not None:
        return s["in_scope"]
    txt = _get("/list_functions", program=program, limit=100000)
    line = _re.compile(r"\bat\s+([0-9a-fA-F]+)\s*$")
    defined = {line.search(l.strip()).group(1).lower() for l in
               (txt if isinstance(txt, str) else "").splitlines() if line.search(l.strip())}
    lib = set()
    for t in EXCLUDE_TAGS:
        lib |= {a.lstrip("0x") for a in _tag_addrs(t, program)}
    return len(defined - lib) if defined else None


def _bar(scope, rung_order, rung_sets, addr_pool):
    """Assemble one segmented bar: per-rung counts (over addr_pool), done, remaining."""
    rungs = {r: sum(1 for a in addr_pool if a in rung_sets[r]) for r in rung_order}
    done = sum(rungs.values())
    rem = max(0, scope - done) if scope is not None else None
    return {"scope": scope, "rungs": rungs, "done": done, "remaining": rem}


def globals_inventory(search: str = "", limit: int = 100, program: str = None) -> dict:
    """Searchable Globals Inventory (sibling of the function inventory): in-scope image
    globals matching `search`, each with its type, typed-groundwork flag, and DOC rung
    (from the `Doc` property map -- 'none' until the globals-doc pass runs). Untyped/
    undocumented globals sort first (most work), then by name."""
    program = program or PROGRAM
    doc = _doc_map_rungs(program)
    allrows = _global_rows(program)

    # whole-program summary (feeds the top Globals-Documentation bar; NOT affected by search)
    scope = len(allrows)
    typed = sum(1 for g in allrows if g["typed"])
    rungs = {r: 0 for r in DOC_RUNGS}
    for g in allrows:
        dv = doc.get(g["addr"], "none")
        if dv in rungs:
            rungs[dv] += 1
    done = sum(rungs.values())
    summ = {"scope": scope, "typed": typed,
            "typed_pct": round(typed / scope * 100, 1) if scope else 0,
            "rungs": rungs, "done": done, "remaining": max(0, scope - done)}

    s = search.lower()
    rows = [{"name": g["name"], "address": g["addr"], "type": g["type"],
             "typed": g["typed"], "doc": doc.get(g["addr"], "none")}
            for g in allrows if not s or s in g["name"].lower()]
    total = len(rows)
    rows.sort(key=lambda r: (r["doc"] != "none", r["typed"], r["name"].lower()))
    return {"rows": rows[:limit], "total": total, "shown": min(len(rows), limit), "summary": summ}


# ---- Recommended next: 1 auto "closest to advancing" pick per entity + user pins ----
PIN_GROUP, PIN_NAME = "Program Information", "Recommended.pins"


def get_pins(program: str = None) -> list:
    """User-pinned recommended items for a binary: list of {kind, address, name}."""
    program = program or PROGRAM
    try:
        opts = _get("/get_program_options", group=PIN_GROUP, program=program).get("options", [])
        raw = next((o["value"] for o in opts if o.get("name") == PIN_NAME), None)
        return json.loads(raw) if raw else []
    except (OSError, json.JSONDecodeError, KeyError):
        return []


def set_pins(program: str, pins: list) -> None:
    _post("/set_program_option", {"group": PIN_GROUP, "name": PIN_NAME,
                                  "value": json.dumps(pins), "program": program})
    try:
        _post("/save_program", {"program": program})
    except OSError:
        pass


def add_pin(kind: str, address: str, name: str = None, program: str = None) -> list:
    program = program or PROGRAM
    address = _norm(address)
    pins = get_pins(program)
    if not any(p["kind"] == kind and _norm(p["address"]) == address for p in pins):
        pins.append({"kind": kind, "address": address, "name": name})
        set_pins(program, pins)
    return pins


def remove_pin(kind: str, address: str, program: str = None) -> list:
    program = program or PROGRAM
    address = _norm(address)
    pins = [p for p in get_pins(program)
            if not (p["kind"] == kind and _norm(p["address"]) == address)]
    set_pins(program, pins)
    return pins


def _pretty(rung: str) -> str:
    return (rung or "").replace("CONF_", "").replace("DOC_", "")


def _fn_status(addr, conf_named, doc_named):
    c = conf_named.get(addr)
    d = doc_named.get(addr)
    return {"conf": c[1] if c else "none", "doc": d[1] if d else "none",
            "name": (c or d or (None,))[0]}


def recommended_next(program: str = None) -> dict:
    """One auto 'closest to advancing' pick for functions and for globals, plus the user's
    pinned items (resolved to current status). Functions: proven-but-undocumented -> document
    (else documented-but-unproven -> prove). Globals: typed-but-undocumented -> document
    (else untyped -> type & document). Impact (xrefs) breaks global ties."""
    program = program or PROGRAM

    # function tag maps: addr -> (name, rung)
    conf_named = {}
    for r in CONF_RUNGS:
        for a, n in _tag_named(r, program).items():
            conf_named.setdefault(a, (n, r))
    doc_named = {}
    for r in DOC_RUNGS:
        for a, n in _tag_named(r, program).items():
            doc_named.setdefault(a, (n, r))
    conf_a, doc_a = set(conf_named), set(doc_named)
    corder = {r: i for i, r in enumerate(CONF_RUNGS)}   # REGRESSION=0 (best) first
    dorder = {r: i for i, r in enumerate(DOC_RUNGS)}

    fn_auto = None
    t1 = [(a, conf_named[a][0], conf_named[a][1]) for a in conf_a - doc_a]
    if t1:
        t1.sort(key=lambda x: (corder.get(x[2], 9), (x[1] or "").lower()))
        a, n, rung = t1[0]
        fn_auto = {"kind": "fn", "address": a, "name": n, "action": "document",
                   "conf": rung, "doc": "none",
                   "reason": f"proven ({_pretty(rung)}) but undocumented → document"}
    else:
        t2 = [(a, doc_named[a][0], doc_named[a][1]) for a in doc_a - conf_a]
        if t2:
            t2.sort(key=lambda x: (dorder.get(x[2], 9), (x[1] or "").lower()))
            a, n, rung = t2[0]
            fn_auto = {"kind": "fn", "address": a, "name": n, "action": "prove",
                       "conf": "none", "doc": rung,
                       "reason": f"documented ({_pretty(rung)}) but unproven → prove"}

    # globals
    grows = _global_rows(program)
    gmap = {g["addr"]: g for g in grows}
    gdoc = _doc_map_rungs(program)
    glob_auto = None
    gt1 = sorted([g for g in grows if g["typed"] and gdoc.get(g["addr"], "none") == "none"],
                 key=lambda g: -g.get("xrefs", 0))
    if gt1:
        g = gt1[0]
        glob_auto = {"kind": "glob", "address": g["addr"], "name": g["name"], "action": "document",
                     "type": g["type"], "doc": "none",
                     "reason": f"typed ({g['type']}), {g.get('xrefs', 0)} xrefs → document"}
    else:
        gt2 = sorted([g for g in grows if not g["typed"] and gdoc.get(g["addr"], "none") == "none"],
                     key=lambda g: -g.get("xrefs", 0))
        if gt2:
            g = gt2[0]
            glob_auto = {"kind": "glob", "address": g["addr"], "name": g["name"], "action": "type",
                         "type": g["type"], "doc": "none",
                         "reason": f"untyped, {g.get('xrefs', 0)} xrefs → type & document"}

    # resolve user pins to current status
    pins = get_pins(program)
    fn_pins, glob_pins = [], []
    for p in pins:
        a = _norm(p["address"])
        if p["kind"] == "fn":
            st = _fn_status(a, conf_named, doc_named)
            fn_pins.append({"kind": "fn", "address": a, "name": p.get("name") or st["name"],
                            "conf": st["conf"], "doc": st["doc"], "pinned": True})
        else:
            g = gmap.get(a, {})
            glob_pins.append({"kind": "glob", "address": a, "name": p.get("name") or g.get("name"),
                              "type": g.get("type"), "doc": gdoc.get(a, "none"), "pinned": True})

    return {"functions": {"auto": fn_auto, "pins": fn_pins},
            "globals": {"auto": glob_auto, "pins": glob_pins}}


def binaries_progress() -> dict:
    """Per-binary progress for the picker panel: three segmented bars (Fn Doc, Fn Conf,
    Glob Doc) each with in-scope denominator, rung segment counts, and remaining work.
    Cards sorted most-remaining-first so the binary needing the most work floats to top."""
    cards = []
    for b in list_binaries()["binaries"]:
        prog = b["path"]
        s = summary(prog)
        fn_scope = _in_scope_fn(prog, s)
        doc_sets = {r: _tag_addrs(r, prog) for r in DOC_RUNGS}
        conf_sets = {r: _tag_addrs(r, prog) for r in CONF_RUNGS}
        fn_pool = set().union(*doc_sets.values(), *conf_sets.values())
        fn_doc = _bar(fn_scope, DOC_RUNGS, doc_sets, set().union(*doc_sets.values()))
        fn_conf = _bar(fn_scope, [r for r in CONF_RUNGS if r != "CONF_DRAFT"] + ["CONF_DRAFT"],
                       conf_sets, set().union(*conf_sets.values()))

        grows = _global_rows(prog)
        g_scope = len(grows)
        g_typed = sum(1 for g in grows if g["typed"])
        g_doc = _doc_map_rungs(prog)
        g_rungs = {r: sum(1 for v in g_doc.values() if v == r) for r in DOC_RUNGS}
        g_done = sum(g_rungs.values())
        glob_doc = {"scope": g_scope, "rungs": g_rungs, "done": g_done,
                    "remaining": max(0, g_scope - g_done), "typed": g_typed,
                    "typed_pct": round(g_typed / g_scope * 100, 1) if g_scope else 0}

        rem_total = sum(x for x in (fn_doc["remaining"], fn_conf["remaining"],
                                    glob_doc["remaining"]) if x is not None)
        cards.append({"path": prog, "name": b["name"], "folder": b["folder"],
                      "fn_scope": fn_scope, "fn_doc": fn_doc, "fn_conf": fn_conf,
                      "glob_doc": glob_doc, "remaining_total": rem_total})
    cards.sort(key=lambda c: -c["remaining_total"])
    return {"binaries": cards, "active": PROGRAM,
            "doc_rungs": DOC_RUNGS, "conf_rungs": CONF_RUNGS}


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

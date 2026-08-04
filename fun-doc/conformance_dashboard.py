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
import re as _re
import urllib.request
from urllib.parse import urlencode, quote

import d2moo_types   # placeholder-type vocabulary; import is lazy (load() reads no files)

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


def _envelope_items(resp, key: str) -> list:
    """Items out of a 7.0.0 list-shaped response: {"<key>": [...], "count", "total"}.

    Mirrors `fun_doc._envelope_items`. This module read `/list_globals`,
    `/list_segments` and `/list_functions` as newline text until 7.0.0 reshaped
    them into JSON records; the `isinstance(txt, str) else ""` fallbacks then
    parsed an empty string and every globals/functions read silently returned
    ZERO rows -- the dashboard rendered 0/0 while the underlying property maps
    held 17k entries. Returns [] for an unexpected shape so callers keep their
    existing "no data -> fall back" behavior instead of raising.
    """
    if isinstance(resp, dict):
        items = resp.get(key)
        if isinstance(items, list):
            return items
    if isinstance(resp, str):          # pre-7.0.0 plugin still on the wire
        return [ln for ln in resp.splitlines() if ln.strip()]
    return []


def _norm(a) -> str:
    """Normalize an address to '0x' + lowercase hex (tag search returns bare hex)."""
    a = str(a).lower()
    return a if a.startswith("0x") else "0x" + a


def _tag_named(tag: str, program: str = None) -> dict:
    """{address -> name} for functions carrying `tag`."""
    try:
        # limit high: the endpoint defaults to 1000, which silently caps the
        # completeness/doc bars on large binaries (D2Client has >1000 in a band).
        r = _get("/search_functions_by_tag", tag=tag, program=program or PROGRAM, limit=100000)
    except OSError:
        return {}
    return {_norm(f.get("address", "")): f.get("name") for f in (r.get("functions") or [])}


def _tag_addrs(tag: str, program: str = None) -> set[str]:
    """Set of function addresses carrying `tag` (one search, not per-function)."""
    try:
        # limit high (endpoint default 1000 undercounts big-binary bands)
        r = _get("/search_functions_by_tag", tag=tag, program=program or PROGRAM, limit=100000)
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
    Rows = CONF (best->worst then none); cols = DOC (none->best). Cheap set math.

    Library/stub functions are subtracted, exactly as `bands()` does, because
    the dashboard divides these counts by `in_scope` -- which already excludes
    them. Without the subtraction the numerator covers a WIDER population than
    the denominator and the bars read over 100%: measured 105.3% on D2Common
    and 172.6% on PD2_EXT before this, with the leading `untagged`/`none`
    segment clamped to zero so the bar looked merely full instead of wrong."""
    excl = set().union(*(_tag_addrs(t, program) for t in EXCLUDE_TAGS))
    conf_sets = {r: _tag_addrs(r, program) - excl for r in CONF_RUNGS}
    doc_sets = {r: _tag_addrs(r, program) - excl for r in DOC_RUNGS}
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
    if in_scope is None:
        # Same fallback as bands(): the summary option is only written by the
        # sync tool / doc worker. When it's absent — e.g. a binary that never
        # went through conformance intake, like D2Client — compute in-scope as
        # defined-minus-library so the doc/conformance bars have a real
        # denominator. Without this the frontend divides thousands of tagged
        # functions by the `|| 1` fallback and renders e.g. 326700%.
        in_scope = _in_scope_fn(program, s)
    if in_scope is not None:                       # the none/none cell = never-evaluated
        cell["none"]["none"] = max(0, in_scope - evaluated)
    return {"rows": rows, "cols": cols, "cell": cell,
            "in_scope": in_scope, "evaluated": evaluated,
            "excluded_lib": s.get("excluded_lib")}


BAND_TAGS = ["COMPLETE_80", "COMPLETE_90", "COMPLETE_95", "COMPLETE_100"]


def bands(program: str = None) -> dict:
    """Completeness band counts (COMPLETE_80/90/95/100 — exclusive, score-derived).
    Library/stub functions are excluded so counts line up with in_scope.
    `untagged` = in-scope functions below 80 or not yet swept."""
    excl = set().union(*(_tag_addrs(t, program) for t in EXCLUDE_TAGS))
    sets = {t: _tag_addrs(t, program) - excl for t in BAND_TAGS}
    counts = {t: len(a) for t, a in sets.items()}
    tagged = len(set().union(*sets.values())) if sets else 0
    s = summary(program)
    in_scope = s.get("in_scope")
    if in_scope is None:
        # The summary option is only written by the doc worker; after an
        # assess-only pass it's absent, which makes the completeness bar bail
        # (renderBandBar returns on in_scope==null). Fall back to the computed
        # defined-minus-LIB_ count, same as binaries_progress does.
        in_scope = _in_scope_fn(program, s)
    return {"bands": counts, "tagged": tagged, "in_scope": in_scope,
            "untagged": max(0, (in_scope or 0) - tagged)}


def intake(program: str = None) -> dict:
    """The intake lane: never-evaluated (in-scope, no tag) and the excluded library set."""
    s = summary(program)
    m = matrix(program)
    # Prefer the matrix's in_scope: it already applied the defined-minus-library
    # fallback when the summary option is absent, so the "X / Y in scope" header
    # isn't blank for a binary that never went through conformance intake.
    return {"untriaged": m["cell"]["none"]["none"], "in_scope": m.get("in_scope"),
            "excluded_lib": s.get("excluded_lib"), "total_all": s.get("total_all")}


_FN_LINE = _re.compile(r"^(?P<name>\S.*?)\s+at\s+(?P<addr>[0-9a-fA-F]+)\s*$")


def _function_rows(program: str) -> list:
    """[(0xaddr, name)] for every defined function. Handles the 7.0.0 record shape
    ({"functions": [{"name","address"}]}) and the pre-7.0.0 "<name> at <addr>" text.

    Address format matches `_tag_addrs` -- '0x' + bare lowercase hex, NOT zero-padded --
    so the two can be set-compared directly."""
    txt = _get("/list_functions", program=program, limit=100000)
    out = []
    for f in _envelope_items(txt, "functions"):
        if isinstance(f, dict):
            a, n = f.get("address"), f.get("name")
            if a and n:
                out.append(("0x" + str(a).lower().replace("0x", ""), n))
            continue
        m = _FN_LINE.match(str(f).strip())
        if m:
            out.append(("0x" + m.group("addr").lower(), m.group("name")))
    return out


def inventory(search: str = "", limit: int = 6000, program: str = None,
              include_library: bool = False) -> dict:
    """Searchable Function Inventory: the COMPLETE list of in-scope functions matching `search`
    (name substring), each with its DOC_/CONF_ rung. Library functions (LIB_-tagged) are
    excluded. Computed from tag sets + a name filter over the defined function list. Rows are
    sorted (un-proven first, then by name) BEFORE the limit is applied, so the cap keeps the
    most-relevant rows rather than an arbitrary address-ordered slice.

    `include_library=True` is the operator's "show library code" toggle. It adds the excluded
    rows back with `library` set to the tag that excluded them, so the view is auditable --
    you can see WHY something is out of scope, not just that it is. `library_total` is
    reported either way, so the caller can render "191 in scope (272 library hidden)" without
    a second request; a hidden count that is invisible is how the operator ends up believing
    a binary is smaller than it is."""
    program = program or PROGRAM
    conf_sets = {r: _tag_addrs(r, program) for r in CONF_RUNGS}
    doc_sets = {r: _tag_addrs(r, program) for r in DOC_RUNGS}
    # Keep per-tag sets rather than one union: the toggled-in row carries the
    # tag that excluded it, which is the auditable part.
    lib_by_tag = {t: _tag_addrs(t, program) for t in EXCLUDE_TAGS}
    lib = set().union(*lib_by_tag.values()) if lib_by_tag else set()
    s = search.lower()
    rows = []
    seen = set()
    lib_total = 0
    for a, name in _function_rows(program):
        if a in seen:                      # dedup: one row per address
            continue
        seen.add(a)
        is_lib = a in lib
        if is_lib:
            lib_total += 1
            if not include_library:
                continue
        if s and s not in name.lower():
            continue
        conf = next((r for r in CONF_RUNGS if a in conf_sets[r]), "none")
        doc = next((r for r in DOC_RUNGS if a in doc_sets[r]), "none")
        row = {"name": name, "address": a, "doc": doc, "conf": conf}
        if is_lib:
            row["library"] = next((t for t in EXCLUDE_TAGS if a in lib_by_tag[t]),
                                  "LIB")
        rows.append(row)
    total = len(rows)
    # Library rows sort last even when shown: the toggle is for inspection, and
    # burying the actual work under 272 CRT rows would defeat the inventory.
    rows.sort(key=lambda r: (bool(r.get("library")), r["conf"] == "none",
                             r["name"].lower()))
    return {"rows": rows[:limit], "total": total, "shown": min(len(rows), limit),
            "library_total": lib_total, "include_library": bool(include_library)}


from pathlib import Path as _Path

# ENDPOINT CONTRACT -- everything the dashboard read layer and the conformance
# write-backs (record_proof, sync_conformance_to_ghidra) call on the plugin. Exists
# because 11 property/option endpoints silently vanished in a jar swap (2026-07-15)
# and every best-effort caller swallowed the 404s for days: 404 = contract violation.
_CONTRACT_REQUIRED = [
    ("GET", "/check_connection"), ("GET", "/list_functions"),
    ("GET", "/get_function_tags"), ("GET", "/decompile_function"),
    ("GET", "/get_function_signature"), ("GET", "/search_functions_by_tag"),
    ("GET", "/list_bookmarks"),
    ("POST", "/set_bookmark"), ("POST", "/delete_bookmark"),
    ("POST", "/add_function_tag"), ("POST", "/remove_function_tag"),
    ("POST", "/rename_function"), ("POST", "/save_program"),
]
# the property-map/program-option store: expected ABSENT until the ghidra-mcp branch
# feat/program-options-property-map-tools is merged + deployed
_CONTRACT_OPTIONAL = [
    ("GET", "/get_property"), ("GET", "/list_properties"), ("GET", "/get_program_options"),
    ("POST", "/set_property"), ("POST", "/create_property_map"), ("POST", "/set_program_option"),
]


def endpoint_contract() -> dict:
    """Probe the deployed plugin for every endpoint we depend on. A 404 means the
    endpoint does not exist (deployment/contract error -- loud); any other status
    (200/400/500) means it is present; connection failure means Ghidra is down."""
    import urllib.error

    def probe(method: str, path: str) -> str:
        req = urllib.request.Request(f"{GHIDRA}{path}", method=method,
                                     data=b"{}" if method == "POST" else None,
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10)
            return "present"
        except urllib.error.HTTPError as e:
            return "missing" if e.code == 404 else "present"
        except OSError:
            return "unreachable"

    out = {"missing": [], "optional_missing": [], "unreachable": False}
    for method, path in _CONTRACT_REQUIRED:
        s = probe(method, path)
        if s == "unreachable":
            out["unreachable"] = True
            break
        if s == "missing":
            out["missing"].append(path)
    if not out["unreachable"]:
        out["optional_missing"] = [p for m, p in _CONTRACT_OPTIONAL if probe(m, p) == "missing"]
    out["ok"] = not out["missing"] and not out["unreachable"]
    return out


# Where the proven D2MOO reimplementations live. The Conf proof record stores a relative
# path like "candidates/SEED_GetRandomNumber.cpp"; the code itself is read from here.
REIMPL_DIR = os.environ.get(
    "CONF_REIMPL_DIR",
    str(_Path(__file__).resolve().parents[3] / "cpp" / "D2MOO" / "conformance" / "reimpl_provider"))


def _extract_function_block(text: str, name: str) -> str | None:
    """Pull one function definition (leading comment block + brace-matched body) out of a
    multi-function provider source. Definition = a non-indented, non-comment line containing
    `name(` -- calls are indented in these files, so this doesn't match call sites."""
    lines = text.splitlines()
    def_re = _re.compile(r"^[A-Za-z_(][^;]*\b" + _re.escape(name) + r"\s*\(")
    for i, ln in enumerate(lines):
        if not def_re.match(ln) or ln.lstrip().startswith(("//", "*", "/*")):
            continue
        # walk back over the contiguous comment block (and the D2MOO_REIMPL_EXPORT marker)
        start = i
        while start > 0:
            prev = lines[start - 1].strip()
            if prev.startswith(("//", "/*", "*", "\\")) or prev.endswith("*/"):
                start -= 1
            else:
                break
        # walk forward brace-matching the body
        depth, opened, end = 0, False, i
        for j in range(i, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            opened = opened or "{" in lines[j]
            if opened and depth == 0:
                end = j
                break
        else:
            return None
        return "\n".join(lines[start:end + 1])
    return None


def _find_reimpl_by_name(names: list[str]) -> tuple[str, str] | None:
    """Fallback for proofs whose `reimpl` path is stale or was never a per-function file:
    the coord family lives in coord_provider.cpp, early batches share multi-function
    candidates (unit_field_getters.cpp, batch_shakeout.cpp), and the name-audit renamed
    some candidate files after the proof record was written. Scans provider sources for
    the function definition by name; returns (relpath, code) or None."""
    root = _Path(REIMPL_DIR)
    if not root.is_dir():
        return None
    sources = sorted(root.glob("*.cpp")) + sorted((root / "candidates").glob("*.cpp"))
    for name in names:
        if not name:
            continue
        for fp in sources:
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if name not in text:
                continue
            block = _extract_function_block(text, name)
            if block:
                rel = fp.relative_to(root).as_posix()
                return rel, f"// [resolved by name from {rel}]\n{block}"
    return None


def function_detail(addr: str, program: str = None) -> dict:
    """One function's drawer data: rung tags, the Conf proof record, the signature, the
    ORIGINAL decompiled code from Ghidra, and the D2MOO EQUIVALENT reimpl code (read from the
    file the proof points at) so the side-by-side code view is populated."""
    program = program or PROGRAM
    addr = addr if str(addr).startswith("0x") else "0x" + str(addr)
    out = {"address": addr, "doc": "none", "conf": "none", "scope": None, "proof": None,
           "name": None, "signature": None, "decompile": None, "reimpl_code": None, "reimpl_path": None}
    try:
        tg = _get("/get_function_tags", function=addr, program=program)
        out["name"] = tg.get("function")
        for t in tg.get("tags", []):
            n = t.get("name", "")
            if n in CONF_RUNGS:
                out["conf"] = n
            elif n in DOC_RUNGS:
                out["doc"] = n
            elif n.startswith("LIB_") or n in ("STUB", "THUNK", "EXTERNAL"):
                out["scope"] = n
    except OSError:
        pass
    try:
        p = _get("/get_property", map="Conf", address=addr, program=program)
        if p.get("value"):
            out["proof"] = json.loads(p["value"])
    except (OSError, json.JSONDecodeError):
        pass
    if out["proof"] is None:
        # the deployed plugin has no property-map endpoints (that code lives on the
        # unshipped ghidra-mcp branch feat/program-options-property-map-tools) -- the
        # proof record is stored in the function's CONFORMANCE bookmark instead
        try:
            r = _get("/list_bookmarks", category="CONFORMANCE", program=program)
            want = addr.lower().replace("0x", "")
            for b in (r.get("bookmarks") or r.get("entries") or []):
                if str(b.get("address", "")).lower().replace("0x", "") == want:
                    out["proof"] = json.loads(b.get("comment") or "")
                    break
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
    try:
        sig = _get("/get_function_signature", function=addr, program=program)
        out["signature"] = sig.get("signature") if isinstance(sig, dict) else None
    except OSError:
        pass
    # ORIGINAL: the live Ghidra decompilation (text endpoint -> raw string)
    try:
        dec = _get("/decompile_function", address=addr, program=program)
        if isinstance(dec, dict):
            dec = dec.get("decompiled") or dec.get("result")
        out["decompile"] = dec if isinstance(dec, str) and dec.strip() else None
    except OSError:
        pass
    # EQUIVALENT: the proven D2MOO reimpl, read from the file the proof references
    rel = (out.get("proof") or {}).get("reimpl")
    if rel:
        out["reimpl_path"] = rel
        try:
            fp = _Path(REIMPL_DIR) / rel
            if fp.exists():
                text = fp.read_text(encoding="utf-8", errors="replace")
                out["reimpl_code"] = text
                # shared multi-function file (coord_provider, early batch candidates):
                # show just the proven function, not every function in the file
                if _Path(rel).stem != (out.get("name") or ""):
                    for n in ((out.get("proof") or {}).get("name"), out.get("name")):
                        block = _extract_function_block(text, n) if n else None
                        if block:
                            out["reimpl_code"] = f"// [from {rel}]\n{block}"
                            break
        except OSError:
            pass
    if out["reimpl_code"] is None:
        # stale/absent reimpl path (coord family, multi-function candidates, name-audit
        # renames) -- resolve by function name instead so proven code is always shown
        names = [(out.get("proof") or {}).get("name"), out.get("name")]
        if rel:
            names.append(_Path(rel).stem)
        found = _find_reimpl_by_name([n for n in dict.fromkeys(names) if n])
        if found:
            out["reimpl_path"], out["reimpl_code"] = found
    return out


def list_binaries() -> dict:
    """The folder + binary options for the header selectors, so the dashboard is
    focused on ONE binary at a time (its per-program tags/maps/rollup).

    Sourced from the UNION of Ghidra's OPEN programs and the version-control
    CHECKED-OUT work set: a binary that's checked out but not currently open is
    still fully queryable by path (assess/doc workers target it fine), so it must
    stay pickable — otherwise the picker silently drops most of the project the
    moment those programs aren't held open. Deduped by path; active is flagged."""
    out = {"binaries": [], "active": PROGRAM}
    seen = set()

    def _add(path):
        if not path or path in seen:
            return
        seen.add(path)
        folder, _, name = str(path).rpartition("/")
        out["binaries"].append({"path": path, "name": name or path, "folder": folder or "/"})

    try:
        r = _get("/list_open_programs")
        for p in (r.get("programs") or r.get("open_programs") or []):
            _add(p.get("path") or p.get("program") or (p if isinstance(p, str) else None))
    except OSError:
        pass
    # Checked-out work set — queryable even when not open. Optional: absent on
    # non-versioned/local projects, in which case open programs are the whole set.
    try:
        r = _get("/server/checkouts")
        for c in (r.get("checkouts") or []):
            _add(c.get("path"))
    except OSError:
        pass

    if not out["binaries"]:                # fall back to the current program
        folder, _, name = PROGRAM.rpartition("/")
        out["binaries"] = [{"path": PROGRAM, "name": name, "folder": folder or "/"}]
    out["binaries"].sort(key=lambda b: (b["folder"], b["name"].lower()))
    return out


# Does a global carry a real type? ONE definition, shared with the scorer.
#
# This used to be a much stricter `_GLOB_PRIM` regex that also rejected int/dword/
# word/byte, and it fed a "typed groundwork" underlay on the Globals bar. The Java
# scorer's type axis (DataTypeService.auditGlobalAt -> hasPlaceholderType) only
# rejects placeholders, so the same global was simultaneously "untyped" on the bar
# and worth a full 20/20 type points to the band -- which is how the bar could read
# 96% documented against 51% typed. The underlay is gone; this test now matches the
# scorer exactly and is used only for inventory styling and work prioritization.
#
# 2026-08-03: the `pointer` family joined the placeholder set on BOTH sides at once
# (NamingConventions.isPlaceholderTypeName / d2moo_types.PLACEHOLDERS). It has to be
# all three or none -- when Java alone rejected `undefined*` and Python's validator
# also rejected bare `pointer`, a `pointer *` global audited perfectly clean while
# the types bar counted it untyped, so the bar demanded a globals worker that
# structurally could not change its own count.
#
# This delegates to d2moo_types rather than re-encoding the set in a regex: the
# decoration strip (`pointer *`, `undefined4[8]`) is the same problem d2moo_types._base
# already solves, and a second copy is exactly how the two sides drifted apart before.
def _glob_is_untyped(type_str: str) -> bool:
    """True when the global carries no real type -- empty, or a Ghidra placeholder
    (`undefined*`, `code`, bare `pointer`/`pointer32`/`pointer64`), with pointer/array
    decoration stripped. Mirrors NamingConventions.isPlaceholderTypeName on the Java
    side; both must move together."""
    base = d2moo_types._base(type_str)
    return not base or base in d2moo_types.PLACEHOLDERS
_GLOB_LINE = _re.compile(
    r"^(?P<name>\S+)\s+@\s+(?P<addr>[0-9a-fA-F]+)\s+\[[^\]]*\]\s+\((?P<type>[^)]*)\)"
    r"(?:\s+xrefs=(?P<xrefs>\d+))?")
_IMG_LO, _IMG_HI = 0x6f000000, 0x70000000  # legacy fallback (base D2 DLL map)
_SEG_RANGE = _re.compile(r":\s*([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)\s*$")


def _image_range(program: str):
    """(lo, hi_exclusive) for the program's own image, from /list_segments, so the
    globals bar/inventory work at any base address (mod DLLs, exes, third-party
    libs) instead of only the D2 0x6f window. Returns None on failure (callers
    fall back to _IMG_LO/_IMG_HI)."""
    try:
        txt = _get("/list_segments", program=program)
    except OSError:
        return None
    ranges = []
    for seg in _envelope_items(txt, "segments"):
        if isinstance(seg, dict):
            try:
                ranges.append((int(seg["start"], 16), int(seg["end"], 16)))
            except (KeyError, TypeError, ValueError):
                continue
            continue
        m = _SEG_RANGE.search(str(seg).strip())     # legacy text row
        if m:
            ranges.append((int(m.group(1), 16), int(m.group(2), 16)))
    if not ranges:
        return None
    base = min(s for s, _ in ranges)
    window = 0x08000000  # 128MB span from base; drops OS overlay blocks
    ends = [e for s, e in ranges if base <= s < base + window]
    if not ends:
        return None
    return base, max(ends) + 1
# Globals do NOT carry the function DOC_ ladder.
#
# They used to: the `Doc` property map held DOC_DRAFT/DOC_REVIEWED/DOC_VERIFIED,
# copied from the function rungs. Only DOC_DRAFT ever got written, by the assess
# pass, and it was written on any global whose score crossed Target and then never
# re-examined -- so it behaved as an "assess visited this" watermark, not a quality
# signal (2,142 of D2Common's 2,231 globals carried it). DOC_REVIEWED and
# DOC_VERIFIED had no producer anywhere in the codebase and read zero on every
# binary, forever; there is no proof pipeline for a data address, so DOC_VERIFIED
# had no reachable definition at all.
#
# Globals now have two independent signals:
#   COMPLETENESS -- the `Complete` band map, machine-scored, live, demotes on
#                   re-score. This is the Globals progress bar.
#   TRUST        -- the `Doc` map, reduced to the single value REVIEWED, set by the
#                   globals audit pass or by hand from the inventory row. Absent
#                   means "not vetted", which is the honest default.
GLOB_DOC_MAP = "Doc"
GLOB_REVIEWED = "REVIEWED"


def _scope_excluded_globals(program: str) -> set[str]:
    """Data addresses triage marked as library data (`Scope` property) -- excluded from the
    Globals Inventory and denominators, mirroring LIB_ function exclusion."""
    out = set()
    try:
        r = _get("/list_properties", map="Scope", program=program, limit=100000)
        for p in ((r or {}).get("entries") or (r or {}).get("properties") or []):
            a, v = p.get("address"), p.get("value")
            if a and v:
                out.add("0x" + str(a).lower().lstrip("0x").rjust(8, "0"))
    except (OSError, AttributeError):
        pass
    return out


def _scope_excluded_tags(program: str) -> dict[str, str]:
    """{addr -> the tag that excluded it} from the `Scope` map.

    Sibling of `_scope_excluded_globals` rather than a change to it: that one returns a set
    and both the route-contract test and the completeness tests patch it as a set. Only the
    "show library code" toggle needs the values, so only the toggle pays for the call."""
    out: dict[str, str] = {}
    try:
        r = _get("/list_properties", map="Scope", program=program, limit=100000)
        for p in ((r or {}).get("entries") or (r or {}).get("properties") or []):
            a, v = p.get("address"), p.get("value")
            if a and v:
                out["0x" + str(a).lower().lstrip("0x").rjust(8, "0")] = str(v)
    except (OSError, AttributeError):
        pass
    return out


def _global_rows(program: str, include_library: bool = False) -> list[dict]:
    """In-scope image globals for a program: {addr, name, type, typed, xrefs, aliases}.
    Parsed from list_globals (one call, no per-global fanout). Excludes out-of-image OS
    labels (TIB/PEB), Ordinal_ export aliases, and triage-marked library data (Scope).

    `include_library=True` adds the Scope-excluded globals back with `library` set, for the
    operator's "show library code" toggle. It mirrors the function inventory's toggle so the
    two halves of the same question never disagree about what is in scope -- two views of
    "the globals in this binary" with different denominators is the exact bug class the
    shadowed-globals endpoint was built to expose.

    ONE ROW PER ADDRESS. Ghidra allows many symbols on one data address, and
    /list_globals emits a line for each: D2Client has 3,405 symbol lines over 3,223
    distinct addresses, with up to SEVEN labels on a single address (0x6fbcb9a0 is
    g_nScreenShiftX / g_nPanelBaseX / g_nScreenCenterX / ...). Both the `Complete`
    and `Doc` property maps are keyed by ADDRESS, so counting symbol lines inflates
    the scope while the band counts stay per-address -- which made the inventory
    report 3,398 scored against glob_bands' 3,219 for the same binary. Extra labels
    are kept in `aliases` so nothing is hidden, just not double-counted."""
    img_lo, img_hi = _image_range(program) or (_IMG_LO, _IMG_HI)
    txt = _get("/list_globals", program=program, limit=100000)
    excluded = _scope_excluded_globals(program)
    excluded_tag = _scope_excluded_tags(program) if include_library else {}
    by_addr = {}
    for ln in _envelope_items(txt, "globals"):
        m = _GLOB_LINE.match(str(ln).strip())
        if not m:
            continue
        a = int(m.group("addr"), 16)
        if not (img_lo <= a < img_hi):
            continue
        name = m.group("name")
        key = "0x%08x" % a
        if name.startswith("Ordinal_"):
            continue
        is_lib = key in excluded
        if is_lib and not include_library:
            continue
        prev = by_addr.get(key)
        if prev is not None:
            prev["aliases"].append(name)     # secondary label, same address
            continue
        t = m.group("type").strip()
        row = {"addr": key, "name": name, "type": t,
               "typed": not _glob_is_untyped(t),
               "xrefs": int(m.group("xrefs") or 0), "aliases": []}
        if is_lib:
            row["library"] = excluded_tag.get(key) or "LIB"
        by_addr[key] = row
    return list(by_addr.values())


GLOB_COMPLETE_MAP = "Complete"


def _prop_map(program: str, name: str, allowed=None, img=None) -> dict:
    """{normalized 0xaddr -> value} for one property map, restricted to the program's
    OWN image when `img` is given.

    The image filter is not cosmetic. A survey of all 32 project binaries found 4,848
    of 17,442 `Doc` entries sitting at addresses outside the program that holds them --
    D2CMP.dll held 4,049 entries of which only 307 were its own, the rest D2Client and
    rebased-module addresses. Those are writes that leaked to whatever program was
    active, the known hazard of `/set_property`'s QUERY-sourced `program` param. Every
    consumer must filter or it double-counts other binaries' work as its own.
    """
    out = {}
    try:
        r = _get("/list_properties", map=name, program=program, limit=100000)
        for p in ((r or {}).get("entries") or (r or {}).get("properties") or []):
            a, v = p.get("address"), p.get("value")
            if not a or (allowed is not None and v not in allowed):
                continue
            try:
                n = int(str(a).lower().replace("0x", ""), 16)
            except ValueError:
                continue
            if img and not (img[0] <= n < img[1]):
                continue
            out["0x%08x" % n] = v
    except (OSError, AttributeError):
        pass
    return out


def _review_flags(program: str, img=None) -> set:
    """Addresses carrying the REVIEWED trust bit in the `Doc` map. A set, not a
    ladder -- see the GLOB_DOC_MAP note above."""
    return set(_prop_map(program, GLOB_DOC_MAP, {GLOB_REVIEWED}, img))


def _complete_map_bands(program: str, img=None) -> dict:
    """{address -> COMPLETE_<band>} from the `Complete` property map (globals'
    completeness bands -- the data-address analog of a function's COMPLETE_* tag).
    Unlike the retired DOC rung this tracks LIVE completeness: it is rewritten on
    every worker touch and cleared when a re-score drops below 80."""
    return _prop_map(program, GLOB_COMPLETE_MAP, set(BAND_TAGS), img)


def glob_bands(program: str = None) -> dict:
    """Global-variable completeness band counts (COMPLETE_80/90/95/100) from the
    `Complete` property map, with the in-scope globals denominator. The data-address
    analog of bands(), and now the ONLY Globals progress bar. `untagged` = in-scope
    globals below 80 or not yet scored."""
    program = program or PROGRAM
    img = _image_range(program) or (_IMG_LO, _IMG_HI)
    m = _complete_map_bands(program, img)
    # Count bands against the ACTUAL in-scope rows, not raw map size: the map can
    # hold entries for addresses that are no longer in-scope (triaged into `Scope`,
    # or a label that went away), and `tagged` must agree with what the inventory
    # shows or the two Globals views disagree on the same binary.
    rows = _global_rows(program)
    scope = len(rows)
    counts = {t: 0 for t in BAND_TAGS}
    for g in rows:
        v = m.get(g["addr"])
        if v in counts:
            counts[v] += 1
    tagged = sum(counts.values())
    reviewed = _review_flags(program, img)
    return {"bands": counts, "tagged": tagged, "in_scope": scope,
            "untagged": max(0, scope - tagged),
            "reviewed": sum(1 for g in rows if g["addr"] in reviewed)}


def _in_scope_fn(program: str, s: dict) -> int | None:
    """In-scope function count: from the summary option if present, else defined-minus-LIB_."""
    if s.get("in_scope") is not None:
        return s["in_scope"]
    # both sides are '0x' + bare lowercase hex, so they compare directly (the old
    # code hand-stripped prefixes with lstrip("0x"), which also eats leading zeros)
    defined = {a for a, _ in _function_rows(program)}
    lib = set()
    for t in EXCLUDE_TAGS:
        lib |= _tag_addrs(t, program)
    return len(defined - lib) if defined else None


def _bar(scope, rung_order, rung_sets, addr_pool):
    """Assemble one segmented bar: per-rung counts (over addr_pool), done, remaining."""
    rungs = {r: sum(1 for a in addr_pool if a in rung_sets[r]) for r in rung_order}
    done = sum(rungs.values())
    rem = max(0, scope - done) if scope is not None else None
    return {"scope": scope, "rungs": rungs, "done": done, "remaining": rem}


def globals_inventory(search: str = "", limit: int = 100, program: str = None,
                      include_library: bool = False) -> dict:
    """Searchable Globals Inventory (sibling of the function inventory): in-scope image
    globals matching `search`, each with its type, completeness band, and REVIEWED bit.

    Sorted worst-first so the top of the list is the work: unscored before banded,
    lower band before higher, untyped before typed, then by name. The `summary`
    block is whole-program (NOT filtered by `search`) and feeds the single Globals
    bar -- band distribution plus a reviewed count.

    `include_library=True` is the same toggle the function inventory carries. `library_total`
    is reported either way so the caller can say how many are hidden without a second call."""
    program = program or PROGRAM
    img = _image_range(program) or (_IMG_LO, _IMG_HI)
    bandmap = _complete_map_bands(program, img)
    reviewed = _review_flags(program, img)
    allrows = _global_rows(program, include_library=include_library)
    lib_total = (sum(1 for g in allrows if g.get("library")) if include_library
                 else len(_scope_excluded_globals(program)))

    scope = len(allrows)
    counts = {t: 0 for t in BAND_TAGS}
    for g in allrows:
        b = bandmap.get(g["addr"])
        if b in counts:
            counts[b] += 1
    scored = sum(counts.values())
    summ = {"scope": scope, "bands": counts, "scored": scored,
            "unscored": max(0, scope - scored),
            "reviewed": sum(1 for g in allrows if g["addr"] in reviewed),
            "complete_pct": round(counts["COMPLETE_100"] / scope * 100, 1) if scope else 0}

    # worst band first: unscored (rank 0) then COMPLETE_80..100 (ranks 1..4)
    rank = {None: 0, "COMPLETE_80": 1, "COMPLETE_90": 2, "COMPLETE_95": 3, "COMPLETE_100": 4}
    s = search.lower()
    rows = [{"name": g["name"], "address": g["addr"], "type": g["type"],
             "typed": g["typed"], "xrefs": g.get("xrefs", 0),
             "band": bandmap.get(g["addr"]), "reviewed": g["addr"] in reviewed,
             **({"library": g["library"]} if g.get("library") else {})}
            for g in allrows if not s or s in g["name"].lower()]
    total = len(rows)
    # Library rows sort last even when shown -- same rule as the function inventory.
    rows.sort(key=lambda r: (bool(r.get("library")), rank.get(r["band"], 0),
                             r["typed"], r["name"].lower()))
    return {"rows": rows[:limit], "total": total, "shown": min(len(rows), limit),
            "summary": summ, "library_total": lib_total,
            "include_library": bool(include_library)}


def set_global_reviewed(address: str, reviewed: bool, program: str = None) -> dict:
    """Manual override for the trust bit: set or clear REVIEWED on one global.

    The audit pass is the bulk producer; this is the "I looked at it myself" path
    from the inventory row. Writes `program` in the QUERY string -- /set_property
    and /remove_property resolve `program` from the query, so a body-only program
    silently targets the ACTIVE program instead. That exact mistake is what put
    4,848 foreign addresses into these maps."""
    program = program or PROGRAM
    address = "0x%08x" % int(str(address).lower().replace("0x", ""), 16)
    q = "?program=" + quote(program, safe="")
    if reviewed:
        body = {"map": GLOB_DOC_MAP, "address": address, "value": GLOB_REVIEWED,
                "program": program}
        r = _post("/set_property" + q, body)
        if isinstance(r, dict) and not r.get("success") and "No property map" in str(r):
            _post("/create_property_map" + q,
                  {"name": GLOB_DOC_MAP, "type": "string", "program": program})
            r = _post("/set_property" + q, body)
    else:
        r = _post("/remove_property" + q,
                  {"map": GLOB_DOC_MAP, "address": address, "program": program})
    try:
        _post("/save_program" + q, {})
    except OSError:
        pass
    return {"address": address, "reviewed": bool(reviewed), "program": program, "result": r}


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


# ---- canonical D2MOO type vocabulary: is it loaded into this binary's type manager? ----
# (d2moo_types is imported at module top -- _glob_is_untyped needs it too.)

_TYPES_CACHE = {}   # program -> status (session cache; the check runs once per binary per session)


def types_status(program: str = None, force: bool = False) -> dict:
    """Lightweight 'are the canonical types loaded & current?' check for one binary: reads the
    unified-types program-option marker (Fortification base + D2MOO backfill) and compares it to
    the expected unified marker. Cached per program until a load or an explicit force (the
    once-per-session cadence)."""
    import unify_types
    program = program or PROGRAM
    if not force and program in _TYPES_CACHE:
        return _TYPES_CACHE[program]
    try:
        expected = unify_types.unified_marker()
    except Exception:
        expected = None
    current = None
    try:
        opts = _get("/get_program_options", group=unify_types.MARKER_GROUP,
                    program=program).get("options", [])
        current = next((o["value"] for o in opts if o.get("name") == unify_types.MARKER_OPTION), None)
    except (OSError, KeyError, AttributeError):
        pass
    loaded = bool(current)
    count = None
    if expected and expected.count(":") >= 1:
        try:
            count = int(expected.split(":")[1])
        except ValueError:
            pass
    res = {"program": program, "loaded": loaded, "current": current, "expected": expected,
           "stale": loaded and expected is not None and current != expected, "count": count}
    _TYPES_CACHE[program] = res
    return res


def types_cache_clear(program: str = None) -> None:
    _TYPES_CACHE.pop(program, None) if program else _TYPES_CACHE.clear()


def types_mark_loaded(program: str = None) -> dict:
    """Stamp the version marker after a successful load and refresh the cached status.
    NOTE: these POST endpoints read `program` from the QUERY string (not the body), so it must
    go in the path -- a body-only program silently targets the active program instead."""
    import unify_types
    program = program or PROGRAM
    q = "?program=" + quote(program, safe="")
    _post("/set_program_option" + q, {"group": unify_types.MARKER_GROUP,
                                      "name": unify_types.MARKER_OPTION,
                                      "value": unify_types.unified_marker()})
    try:
        _post("/save_program" + q, {})
    except OSError:
        pass
    return types_status(program, force=True)


_NATIVE_CACHE = {}   # program -> native-type-usage status (globals canary; session-cached)


def native_types_status(program: str = None, force: bool = False) -> dict:
    """Cheap 'is this binary using native (non-canonical) types?' canary: scans in-image GLOBALS
    (one list_globals call) and counts UNREFINED (dword/byte/uint -> normalizable) and INVALID
    (placeholder: undefined*/code/bare pointer -> untyped) via validate_type. A trigger for the
    Normalize bar; the full globals+locals+fields fix runs on demand. Cached per binary per session.

    Also returns `invalid_addresses` -- the actual 0x-prefixed addresses behind the INVALID
    count, so the bar's button can dispatch a globals worker AT THEM (target_addresses) instead
    of turning it loose on the whole binary in arbitrary enumeration order. The bar names a
    number; the action it offers should act on the things counted, not on their neighbours.
    `invalid_types` is the distinct placeholder spellings found, so the bar can say `undefined`
    vs `pointer *` truthfully rather than hardcoding "(undefined*)".

    Counts are per ADDRESS, not per list_globals line. Two labels on one address (Ghidra keeps
    every alias: `g_abCharClassFlags` and `g_p_char_class_flags` both sit on 0x100120a0) are one
    global and one unit of work. Counting lines made `invalid` disagree with the length of
    `invalid_addresses` -- 29 vs 16 on D2sound.dll -- so the bar overstated the backlog and the
    targeted run's `count` would not have matched the number the bar showed. `_global_rows` and
    `glob_bands` have always been per-address; this now matches them."""
    program = program or PROGRAM
    if not force and program in _NATIVE_CACHE:
        return _NATIVE_CACHE[program]
    unref = inval = total = 0
    invalid_addresses = []
    invalid_types = {}
    seen = set()
    try:
        img_lo, img_hi = _image_range(program) or (_IMG_LO, _IMG_HI)
        txt = _get("/list_globals", program=program, limit=100000)
        for ln in _envelope_items(txt, "globals"):
            m = _GLOB_LINE.match(str(ln).strip())
            if not m:
                continue
            a = int(m.group("addr"), 16)
            if not (img_lo <= a < img_hi) or m.group("name").startswith("Ordinal_"):
                continue
            addr = "0x%08x" % a
            if addr in seen:                 # alias label on an address already counted
                continue
            seen.add(addr)
            total += 1
            v = d2moo_types.validate_type(m.group("type")).get("verdict")
            if v == "UNREFINED":
                unref += 1
            elif v == "INVALID":
                inval += 1
                invalid_addresses.append(addr)
                spelling = (m.group("type") or "").strip() or "(none)"
                invalid_types[spelling] = invalid_types.get(spelling, 0) + 1
    except OSError:
        pass
    res = {"program": program, "unrefined": unref, "invalid": inval, "native": unref + inval,
           "globals_scanned": total, "scope": "globals",
           "invalid_addresses": invalid_addresses,
           "invalid_types": dict(sorted(invalid_types.items(), key=lambda kv: -kv[1]))}
    _NATIVE_CACHE[program] = res
    return res


def native_cache_clear(program: str = None) -> None:
    _NATIVE_CACHE.pop(program, None) if program else _NATIVE_CACHE.clear()


_SHADOW_CACHE = {}   # program -> shadowed-globals status (session-cached)


def shadowed_globals(program: str = None, force: bool = False, limit: int = 5000) -> dict:
    """Globals with no type of their own because a larger unit starting earlier
    covers them — the population `/list_globals` structurally cannot show.

    This is the ONE dashboard read that cannot be derived from the inventory:
    `/list_globals` resolves the CONTAINING data unit, so a shadowed global
    reports its eater's type and renders as perfectly typed. Measured across
    the PD2-S12 corpus on 2026-08-03: 540 shadowed globals, 539 of them
    invisible to every existing dashboard view, each one hard-capped at 79 by
    the untyped ceiling and so unable to band COMPLETE_80+ no matter what else
    is done to it. A number nobody can see is a number nobody fixes.

    One bulk call per binary (`/list_shadowed_globals`), not one audit per
    global — the corpus has 17,773 globals and the per-address route would be
    17,773 HTTP round-trips per refresh.

    `top_containers` is the actionable half: the damage is concentrated, and
    10 containers covered 32% of the corpus total, so the panel can point at
    the handful of decisions that matter instead of a flat list of 540."""
    program = program or PROGRAM
    if not force and program in _SHADOW_CACHE:
        return _SHADOW_CACHE[program]
    rows, err = [], None
    try:
        txt = _get("/list_shadowed_globals", program=program, limit=limit)
        for item in _envelope_items(txt, "shadowed"):
            if isinstance(item, dict):
                rows.append(item)
    except OSError as e:
        # Degrade to a reported error, never a 500 and never a silent 0 — a
        # zero here reads as "clean", which is exactly the false reassurance
        # this panel exists to remove.
        err = f"{type(e).__name__}: {e}"
    by_container = {}
    for r in rows:
        c = r.get("container") or {}
        key = c.get("address")
        if not key:
            continue
        slot = by_container.setdefault(key, {"address": key, "name": c.get("name"),
                                             "type": c.get("type"), "victims": 0})
        slot["victims"] += 1
    top = sorted(by_container.values(), key=lambda d: -d["victims"])[:10]
    res = {"program": program, "shadowed": len(rows), "containers": len(by_container),
           "top_containers": top, "items": rows[:200], "error": err}
    if err is None:
        _SHADOW_CACHE[program] = res
    return res


def shadow_cache_clear(program: str = None) -> None:
    _SHADOW_CACHE.pop(program, None) if program else _SHADOW_CACHE.clear()


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

    # globals -- "closest to advancing" is now band-driven, not rung-driven:
    # a typed global that has never scored is the cheapest real progress, then
    # anything sitting below COMPLETE_100, then untyped high-impact globals.
    gimg = _image_range(program) or (_IMG_LO, _IMG_HI)
    grows = _global_rows(program)
    gmap = {g["addr"]: g for g in grows}
    gband = _complete_map_bands(program, gimg)
    greviewed = _review_flags(program, gimg)
    glob_auto = None

    def _impact(g):
        return -g.get("xrefs", 0)

    unscored_typed = sorted([g for g in grows if g["typed"] and not gband.get(g["addr"])], key=_impact)
    partial = sorted([g for g in grows
                      if gband.get(g["addr"]) and gband[g["addr"]] != "COMPLETE_100"], key=_impact)
    untyped = sorted([g for g in grows if not g["typed"]], key=_impact)
    if unscored_typed:
        g = unscored_typed[0]
        glob_auto = {"kind": "glob", "address": g["addr"], "name": g["name"], "action": "document",
                     "type": g["type"], "band": None,
                     "reason": f"typed ({g['type']}), {g.get('xrefs', 0)} xrefs, never scored → document"}
    elif partial:
        g = partial[0]
        b = gband[g["addr"]].replace("COMPLETE_", "")
        glob_auto = {"kind": "glob", "address": g["addr"], "name": g["name"], "action": "document",
                     "type": g["type"], "band": gband[g["addr"]],
                     "reason": f"at {b}, {g.get('xrefs', 0)} xrefs → finish to 100"}
    elif untyped:
        g = untyped[0]
        glob_auto = {"kind": "glob", "address": g["addr"], "name": g["name"], "action": "type",
                     "type": g["type"], "band": None,
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
                              "type": g.get("type"), "band": gband.get(a),
                              "reviewed": a in greviewed, "pinned": True})

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

        # Globals: band distribution, image-filtered. The old version counted the
        # WHOLE Doc map with no image filter, so a program holding another binary's
        # leaked entries (D2CMP.dll: 4,049 entries, 307 its own) reported those as
        # its own completed work.
        gimg = _image_range(prog) or (_IMG_LO, _IMG_HI)
        grows = _global_rows(prog)
        g_scope = len(grows)
        gband = _complete_map_bands(prog, gimg)
        g_bands = {t: 0 for t in BAND_TAGS}
        for g in grows:
            b_ = gband.get(g["addr"])
            if b_ in g_bands:
                g_bands[b_] += 1
        g_scored = sum(g_bands.values())
        glob = {"scope": g_scope, "bands": g_bands, "scored": g_scored,
                "unscored": max(0, g_scope - g_scored),
                "reviewed": len(_review_flags(prog, gimg)),
                "remaining": max(0, g_scope - g_bands["COMPLETE_100"])}

        rem_total = sum(x for x in (fn_doc["remaining"], fn_conf["remaining"],
                                    glob["remaining"]) if x is not None)
        cards.append({"path": prog, "name": b["name"], "folder": b["folder"],
                      "fn_scope": fn_scope, "fn_doc": fn_doc, "fn_conf": fn_conf,
                      "glob": glob, "remaining_total": rem_total})
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

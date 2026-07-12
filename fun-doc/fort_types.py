"""fort_types.py -- load Fortification's PD2 runtime structs into Ghidra as a COMPLEMENTARY
reference to the D2MOO canonical set.

Fortification (C:\\...\\Fortification\\D2Structs.h) targets Project Diablo 2 -- exactly what the
conformance oracle proves against -- so its runtime-struct layouts (UnitAny, Room1, ItemData, ...)
are the PD2-native reference. They use community names (no D2 prefix), so they load ALONGSIDE the
D2MOO `D2*Strc` types without collision, giving Ghidra both vocabularies.

Reuses d2moo_types' emit machinery (forward-decls + topological order + sanitize) on the UTF-16
D2Structs.h, plus a few external shims. Verified: parses clean via the CParser.

Usage:
    python fort_types.py --status [--program P]
    python fort_types.py --load   [--program P]     # one program
    python fort_types.py --load-all                 # every open PD2 game binary
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import d2moo_types as dt

GHIDRA = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")
FORT_H = Path(os.environ.get(
    "FORTIFICATION_STRUCTS",
    r"C:\Users\benam\source\cpp\Fortification\Fortification\D2Structs.h"))
MARKER_GROUP, MARKER_OPTION = "Program Information", "PD2.forttypes.version"
# externals D2Structs.h references but that live in other Fortification headers / Windows
_SHIMS = ("typedef char CHAR;\ntypedef void VOID;\ntypedef unsigned long long ULONGLONG;\n"
          "typedef struct { int _opaque; } MonsterStats;\n")
_DIR_CACHE = None


def _fort_dir() -> Path:
    """A temp include/ dir holding D2Structs.h as UTF-8, so d2moo_types' dir-based emit works."""
    global _DIR_CACHE
    if _DIR_CACHE is None:
        tmp = Path(tempfile.mkdtemp(prefix="forttypes_")) / "include"
        tmp.mkdir()
        (tmp / "D2Structs.h").write_text(FORT_H.read_text(encoding="utf-16"), encoding="utf-8")
        _DIR_CACHE = tmp.parent
    return _DIR_CACHE


def emit_fort_header():
    header, stats = dt.emit_header(_fort_dir())
    header = header.replace("#pragma pack(push, 1)", "#pragma pack(push, 1)\n" + _SHIMS, 1)
    return header, stats


def version_marker() -> str:
    v = dt.load(_fort_dir())
    names = sorted(set(v["structs"]) | set(v["enums"]) | set(v["unions"]))
    h = hashlib.sha1("\n".join(names).encode("utf-8")).hexdigest()[:8]
    return f"fort1:{len(names)}:{h}"


def _post(path, body, program):
    url = f"{GHIDRA}{path}?program=" + urllib.parse.quote(program, safe="")
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _get(path, **params):
    url = f"{GHIDRA}{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
    with urllib.request.urlopen(url, timeout=60) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def status(program):
    try:
        opts = _get("/get_program_options", group=MARKER_GROUP, program=program).get("options", [])
        cur = next((o["value"] for o in opts if o.get("name") == MARKER_OPTION), None)
    except Exception:
        cur = None
    return {"program": program, "loaded": bool(cur), "current": cur, "expected": version_marker()}


def load_into(program, header=None, marker=None):
    header = header or emit_fort_header()[0]
    marker = marker or version_marker()
    res = _post("/import_data_types", {"source": header}, program)
    added = res.get("types_added", 0)
    if res.get("parse_succeeded") or added > 0:
        _post("/set_program_option", {"group": MARKER_GROUP, "name": MARKER_OPTION, "value": marker}, program)
        try:
            _post("/save_program", {}, program)
        except Exception:
            pass
        return {"program": program, "ok": True, "added": added, "status": res.get("status")}
    return {"program": program, "ok": False, "error": res.get("error"), "status": res.get("status")}


def _open_programs():
    d = _get("/list_open_programs")
    progs = d if isinstance(d, list) else d.get("programs", d.get("open_programs", []))
    out = []
    for p in progs:
        s = p if isinstance(p, str) else (p.get("path") or p.get("name"))
        if s and s.startswith("/Mods/") and s.endswith(".dll"):
            out.append(s)
    return sorted(set(out))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--load", action="store_true")
    ap.add_argument("--load-all", action="store_true")
    ap.add_argument("--program", default="/Mods/PD2-S12/D2Common.dll")
    args = ap.parse_args()
    if args.status:
        print(json.dumps(status(args.program), indent=2)); return 0
    if args.load:
        print(json.dumps(load_into(args.program), indent=2)); return 0
    if args.load_all:
        header, stats = emit_fort_header()
        marker = version_marker()
        print(f"Fortification PD2 header: {stats['total']} defs, {stats['bytes']//1024} KB, marker {marker}\n")
        for p in _open_programs():
            r = load_into(p, header, marker)
            print(f"  {os.path.basename(p):16} " + ("+%d types, marked" % r["added"] if r["ok"]
                                                     else "FAILED: %s" % (r.get("error") or r.get("status"))))
        return 0
    ap.error("pick --status / --load / --load-all")


if __name__ == "__main__":
    raise SystemExit(main())

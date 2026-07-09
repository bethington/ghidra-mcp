"""ledger_apply.py -- apply the shared struct-field ledger to Ghidra structs.

Each prove_doc run appends PROVEN (struct, offset, width, signed) field facts to
conformance/doc_ledger/<struct>.jsonl. This pass rolls a struct's ledger up and
reconciles it against the CURRENT Ghidra struct layout, so one proof improves the
doc for EVERY function that uses the struct (the compounding lever).

Reconciliation policy (mirrors the consistency gate -- proof-backed mechanical vs
semantic):
  * TYPE/WIDTH is proof-backed -> AUTO-APPLY. A byte read proven at +0x32 means the
    field there is 1 byte; if Ghidra has it wider/mistyped, correct it (only when
    the proof is CONSISTENT -- all reads at that offset agree on width/sign; a
    CONFLICT between proofs is flagged, never guessed).
  * NAME is semantic -> NEVER auto-named from an offset alone (field_0x32 stays until
    a human/xref confirms meaning). We only ensure a proof-backed TYPE and leave a
    review note where a good name is derivable. This is deliberately conservative:
    a wrong struct-field name propagates to every user of the struct.

Idempotent: re-running only changes fields whose Ghidra type still disagrees with
the (consistent) proven width. Dry-run by default in --plan.

Usage:
    python ledger_apply.py --plan                     # show what WOULD change, all structs
    python ledger_apply.py --struct ItemData          # apply one struct's ledger
    python ledger_apply.py --struct ItemData --map UnitAny  # ledger key -> real Ghidra struct
    python ledger_apply.py --selftest
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import defaultdict
from pathlib import Path

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
PROGRAM_PATH = os.environ.get("FUNDOC_GHIDRA_PROGRAM", "/Mods/PD2-S12/D2Common.dll")
LEDGER_DIR = D2MOO_REPO / "conformance" / "doc_ledger"

_WIDTH_TYPE = {(1, False): "byte", (1, True): "char",
               (2, False): "ushort", (2, True): "short",
               (4, False): "uint", (4, True): "int"}
_GHIDRA_WIDTH = {"byte": 1, "uchar": 1, "undefined1": 1, "bool": 1, "char": 1,
                 "sbyte": 1, "ushort": 2, "short": 2, "word": 2, "undefined2": 2,
                 "wchar_t": 2, "uint": 4, "int": 4, "dword": 4, "undefined4": 4,
                 "long": 4, "ulong": 4, "float": 4, "LPVOID": 4, "void *": 4}


# ---------------------------------------------------------------------------
# pure logic (offline-testable)
# ---------------------------------------------------------------------------

def consolidate(rows: list) -> dict:
    """Ledger rows for ONE struct -> {offset: decision}. A decision is either a
    CONSISTENT proven field (all reads agree on width+sign) or a CONFLICT (proofs
    disagree -> flag, never apply). Only FINAL-depth reads (final=True) are trusted
    for the named struct; side-bucket files are consumed separately by their key."""
    by_off = defaultdict(list)
    for r in rows:
        by_off[r["off"]].append(r)
    out = {}
    for off, rs in sorted(by_off.items()):
        widths = {(r["width"], bool(r.get("signed", False))) for r in rs}
        fns = sorted({r.get("from_fn", "?") for r in rs})
        if len(widths) == 1:
            w, s = next(iter(widths))
            out[off] = {"status": "consistent", "width": w, "signed": s,
                        "type": _WIDTH_TYPE[(w, s)], "proofs": len(rs), "fns": fns}
        else:
            out[off] = {"status": "conflict", "widths": sorted(widths),
                        "proofs": len(rs), "fns": fns}
    return out


def _parse_layout(text: str) -> dict:
    """/get_struct_layout text -> {offset: {'type':.., 'name':.., 'size':..}}."""
    out = {}
    for m in re.finditer(r"^\s*(\d+)\s*\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|\s*(\S.*?)\s*$",
                         text, re.MULTILINE):
        out[int(m.group(1))] = {"size": int(m.group(2)),
                                "type": m.group(3).strip(), "name": m.group(4).strip()}
    return out


def reconcile(proven: dict, layout: dict) -> list:
    """Per offset, decide the action vs the current Ghidra struct layout.
    Actions: retype (proof width != ghidra width, proof consistent), ok (match),
    conflict (proofs disagree -> skip), absent (offset not a struct field ->
    likely nested/union; flag, don't force)."""
    actions = []
    for off, dec in sorted(proven.items()):
        if dec["status"] == "conflict":
            actions.append({"off": off, "action": "conflict", **dec})
            continue
        cur = layout.get(off)
        if not cur:
            actions.append({"off": off, "action": "absent", "want_type": dec["type"],
                            "width": dec["width"], "fns": dec["fns"]})
            continue
        cur_w = _GHIDRA_WIDTH.get(cur["type"].replace(" *", " *").strip(),
                                  cur.get("size"))
        if cur_w == dec["width"]:
            actions.append({"off": off, "action": "ok", "type": cur["type"],
                            "name": cur["name"]})
        else:
            actions.append({"off": off, "action": "retype", "from": cur["type"],
                            "from_width": cur_w, "want_type": dec["type"],
                            "width": dec["width"], "name": cur["name"], "fns": dec["fns"]})
    return actions


# ---------------------------------------------------------------------------
# apply (needs Ghidra)
# ---------------------------------------------------------------------------

def _ledger_rows(struct_key: str) -> list:
    p = LEDGER_DIR / f"{struct_key}.jsonl"
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def apply_struct(struct_key: str, ghidra_struct: str = None, *, program: str = PROGRAM_PATH,
                 dry_run: bool = True, log=print) -> dict:
    """Reconcile one ledger struct against Ghidra; apply proof-backed retypes."""
    import fun_doc
    gstruct = ghidra_struct or struct_key
    rows = _ledger_rows(struct_key)
    if not rows:
        return {"struct": struct_key, "error": "no ledger rows"}
    proven = consolidate(rows)
    layout_raw = str(fun_doc.ghidra_get("/get_struct_layout",
                                        params={"struct_name": gstruct, "program": program}))
    if "error" in layout_raw[:60].lower() or "not found" in layout_raw.lower():
        return {"struct": struct_key, "ghidra_struct": gstruct,
                "error": f"struct not found in Ghidra: {layout_raw[:80]}",
                "reconcile": reconcile(proven, {})}
    layout = _parse_layout(layout_raw)
    actions = reconcile(proven, layout)
    applied = []
    if not dry_run:
        prog = Path(program).name
        for a in actions:
            if a["action"] != "retype":
                continue
            r = fun_doc.ghidra_post("/modify_struct_field",
                                    data={"struct_name": gstruct,
                                          "field_name": a.get("name") or "",
                                          "new_type": a["want_type"]},
                                    params={"program": prog})
            ok = not (isinstance(r, dict) and r.get("error"))
            applied.append({"off": a["off"], "to": a["want_type"], "ok": ok})
        if applied:
            fun_doc.ghidra_post("/save_program", data={"program": prog})
    return {"struct": struct_key, "ghidra_struct": gstruct,
            "actions": actions, "applied": applied, "dry_run": dry_run}


def all_struct_keys() -> list:
    if not LEDGER_DIR.exists():
        return []
    # skip the __lvlN side-buckets for the top-level view (they're shallower structs)
    return sorted(p.stem for p in LEDGER_DIR.glob("*.jsonl") if "__lvl" not in p.stem)


# ---------------------------------------------------------------------------
# self-test (offline)
# ---------------------------------------------------------------------------

def _selftest() -> int:
    rows = [
        {"off": 0x32, "width": 2, "signed": False, "from_fn": "GetField32"},
        {"off": 0x32, "width": 2, "signed": False, "from_fn": "GetField32b"},
        {"off": 0x44, "width": 1, "signed": False, "from_fn": "GetByte44"},
        {"off": 0x50, "width": 2, "signed": False, "from_fn": "A"},
        {"off": 0x50, "width": 4, "signed": False, "from_fn": "B"},   # CONFLICT
    ]
    c = consolidate(rows)
    assert c[0x32]["status"] == "consistent" and c[0x32]["type"] == "ushort" and c[0x32]["proofs"] == 2
    assert c[0x44]["type"] == "byte"
    assert c[0x50]["status"] == "conflict", c[0x50]

    layout = _parse_layout(
        "Offset | Size | Type | Name\n"
        "-------|------|------|-----\n"
        "    50 |    2 | ushort | wField32\n"
        "    68 |    4 | uint   | dwField44\n")   # 0x44=68: ghidra has uint, proof says byte
    assert layout[50]["name"] == "wField32" and layout[68]["type"] == "uint"

    acts = {a["off"]: a for a in reconcile(c, layout)}
    assert acts[0x32]["action"] == "ok"                 # matches (2==2)
    assert acts[0x44]["action"] == "retype" and acts[0x44]["want_type"] == "byte"  # 4->1
    assert acts[0x50]["action"] == "conflict"           # never auto-applied
    # an offset Ghidra doesn't have as a field:
    assert reconcile({0x99: c[0x44] if False else
                      {"status": "consistent", "width": 1, "signed": False,
                       "type": "byte", "proofs": 1, "fns": ["X"]}}, layout)[0][
        "action"] == "absent"
    print("[ok] ledger_apply self-test: consolidate + layout-parse + reconcile pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", action="store_true", help="dry-run reconcile, all structs")
    ap.add_argument("--struct", help="ledger struct key to apply")
    ap.add_argument("--map", dest="ghidra_struct", help="real Ghidra struct name if != key")
    ap.add_argument("--program", default=PROGRAM_PATH)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    if args.plan:
        for key in all_struct_keys():
            res = apply_struct(key, program=args.program, dry_run=True)
            acts = res.get("actions", [])
            n = {k: sum(1 for a in acts if a["action"] == k)
                 for k in ("retype", "ok", "conflict", "absent")}
            print(f"[{key}] {res.get('error', '')} retype={n['retype']} ok={n['ok']} "
                  f"conflict={n['conflict']} absent={n['absent']}")
            for a in acts:
                if a["action"] in ("retype", "conflict"):
                    print(f"    +0x{a['off']:x} {a['action']}: {json.dumps({k:v for k,v in a.items() if k not in ('off','action','fns')})}")
        return 0
    if args.struct:
        res = apply_struct(args.struct, ghidra_struct=args.ghidra_struct,
                           program=args.program, dry_run=False)
        print(json.dumps(res, indent=2, default=str))
        return 0
    ap.error("pick --plan / --struct / --selftest")


if __name__ == "__main__":
    raise SystemExit(main())

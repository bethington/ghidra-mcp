"""recanonicalize.py -- replace offset-derived function names with REAL D2MOO field names.

Iterates the proven registry, finds functions whose name is offset-derived
(GetItemTypeField10, Field104, Short0x10...), resolves the REAL field from the D2MOO
struct headers (d2moo_names.canonicalize, via the proven candidate's stride/offset), and
renames the function + stamps a provenance plate + updates the registry. Offset names are
kept only where D2MOO genuinely has no field there (honest last resort, flagged).

    python recanonicalize.py --plan            # dry-run: what resolves, what doesn't
    python recanonicalize.py --apply           # rename in Ghidra + update registry
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
from pathlib import Path

D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
PROGRAM = os.environ.get("FUNDOC_GHIDRA_PROGRAM", "/Mods/PD2-S12/D2Common.dll")
REGISTRY = D2MOO_REPO / "conformance" / "proven_functions.jsonl"
CANDIDATES = D2MOO_REPO / "conformance" / "reimpl_provider" / "candidates"


def _rows():
    return [json.loads(l) for l in REGISTRY.read_text(encoding="utf-8").splitlines() if l.strip()]


def plan() -> dict:
    import d2moo_names as dn
    seen, buckets = set(), {"resolved": [], "no_field": [], "no_struct": [], "no_candidate": []}
    for r in _rows():
        name, addr = r.get("name"), r.get("address")
        if not name or name in seen or not dn.is_offset_name(name):
            continue
        seen.add(name)
        cand = CANDIDATES / f"{name}.cpp"
        if not cand.exists():
            buckets["no_candidate"].append((name, addr))
            continue
        c = dn.canonicalize(name, cand.read_text(encoding="utf-8"))
        if c.get("ok"):
            buckets["resolved"].append((name, addr, c["proposed_name"], c["reason"]))
        elif c.get("struct"):
            buckets["no_field"].append((name, addr, c["reason"]))
        else:
            buckets["no_struct"].append((name, addr, c.get("reason")))
    return buckets


def _rewrite_plate_body(text: str, c: dict, dn) -> tuple:
    """Rewrite stale offset-derived field references in an EXISTING plate body to the
    canonical names, so the whole plate is self-consistent (not just a truth-note prepended
    on top of stale prose). Two safe, structural substitutions only -- descriptive prose is
    left alone unless it is an exact stale token:
      1. Ghidra field placeholder  `field_0x45` / `bField45` -> the real field (`nInvPage`).
      2. Wrong union-member stem    `PlayerData` -> the member this getter uses (`ItemData`),
         which fixes the identifier (pPlayerData), the type (PlayerData*) and PascalCase prose
         in one pass; plus the spaced lowercase form ("player data" -> "item data").
    Only the LIVING documentation prose is rewritten; dated `[...]` stamp paragraphs (the
    [CORRECTED]/[AUDIT]/[CONFORMANCE]/[D2MOO-DERIVED NAME] history log) are left verbatim so
    the audit trail stays honest. Returns (new_text, [edit-descriptions])."""
    off, field, edits = c.get("read_off"), c.get("field"), []
    if off is None or not field:
        return text, edits
    tok = re.compile(rf"\b[bwdn]?[Ff]ield_?(?:0x)?0*{off:x}\b")
    member = c.get("member")
    correct = member[1:] if member and member.startswith("p") else None   # pItemData->ItemData
    correct_spaced = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", correct).lower() if correct else None
    wrong_members = ([m for m in dn.unit_union_member_names()
                      if m.endswith("Data") and m.startswith("p") and m != member]
                     if correct else [])
    tally = {}

    def _sub(para: str) -> str:
        para, n = tok.subn(field, para)                        # field_0x45 -> nInvPage
        if n:
            tally[f"field_0x{off:x} -> {field}"] = tally.get(f"field_0x{off:x} -> {field}", 0) + n
        for wrong in wrong_members:
            stem = wrong[1:]                                   # PlayerData
            para, na = re.subn(re.escape(wrong), member, para)        # pPlayerData -> pItemData
            para, nb = re.subn(rf"(?<![A-Za-z]){stem}", correct, para)  # PlayerData* -> ItemData*
            if na + nb:
                tally[f"{stem} -> {correct}"] = tally.get(f"{stem} -> {correct}", 0) + na + nb
            spaced = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", stem).lower()   # "player data"
            para, nc = re.subn(re.escape(spaced), correct_spaced, para, flags=re.I)
            if nc:
                k = f'"{spaced}" -> {correct_spaced}'
                tally[k] = tally.get(k, 0) + nc
        return para

    # rewrite paragraph-by-paragraph, skipping dated [...] stamp paragraphs (the history log)
    paras = text.split("\n\n")
    out = [p if p.lstrip().startswith("[") else _sub(p) for p in paras]
    edits = [f"{k} ({v}x)" for k, v in tally.items()]
    return "\n\n".join(out), edits


def rewrite_plates(program: str = PROGRAM, do_apply: bool = False) -> dict:
    """Second pass over already-renamed functions: make each plate BODY canonical, not just
    its header note. Preview by default; --apply writes + saves."""
    import d2moo_names as dn
    import fun_doc
    prog = Path(program).name
    touched = []
    for r in _rows():
        if not r.get("_prev_name"):
            continue                                           # only functions we canonicalized
        name, addr = r.get("name"), r.get("address")
        cand = CANDIDATES / f"{r['_prev_name']}.cpp"
        if not cand.exists():
            continue
        c = dn.canonicalize(name, cand.read_text(encoding="utf-8"))
        if not c.get("ok"):
            continue
        cur = fun_doc.ghidra_get("/get_plate_comment", params={"address": addr, "program": program})
        cur_txt = cur.get("comment", "") if isinstance(cur, dict) else str(cur)
        new_txt, edits = _rewrite_plate_body(cur_txt, c, dn)
        if not edits or new_txt == cur_txt:
            continue
        touched.append((name, edits))
        if do_apply:
            fun_doc.ghidra_post("/set_plate_comment",
                                data={"address": addr, "comment": new_txt},
                                params={"program": program})
    if do_apply and touched:
        fun_doc.ghidra_post("/save_program", data={"program": prog})
    return {"touched": touched}


def apply(program: str = PROGRAM) -> dict:
    import d2moo_names as dn
    import fun_doc
    prog = Path(program).name
    b = plan()
    applied, renames = [], {}
    stamp = datetime.date.today().isoformat()
    for name, addr, proposed, reason in b["resolved"]:
        r = fun_doc.ghidra_post("/rename_function_by_address",
                                data={"function_address": addr, "new_name": proposed},
                                params={"program": prog})
        ok = not (isinstance(r, dict) and r.get("error")) and "success" in str(r).lower()
        if ok:
            cur = fun_doc.ghidra_get("/get_plate_comment", params={"address": addr, "program": program})
            cur_txt = cur.get("comment", "") if isinstance(cur, dict) else str(cur)
            note = (f"[D2MOO-DERIVED NAME {stamp}] was '{name}' (offset-derived transcription); "
                    f"real field per D2MOO reimplementation: {reason}. Community-canonical.")
            if "[D2MOO-DERIVED NAME" not in cur_txt:
                fun_doc.ghidra_post("/set_plate_comment",
                                    data={"address": addr, "comment": (note + "\n\n" + cur_txt).strip()},
                                    params={"program": program})
            applied.append((name, proposed))
            renames[name] = proposed
    # stamp a REVIEW note on SUSPECT cases (D2MOO field disagrees with the getter's use --
    # keep the honest offset name, but flag the discrepancy for a human to resolve).
    for name, addr, reason in b["no_field"]:
        if "SUSPECT" not in str(reason):
            continue
        cur = fun_doc.ghidra_get("/get_plate_comment", params={"address": addr, "program": program})
        cur_txt = cur.get("comment", "") if isinstance(cur, dict) else str(cur)
        if "[D2MOO REVIEW" not in cur_txt:
            fun_doc.ghidra_post("/set_plate_comment",
                                data={"address": addr, "comment":
                                      (f"[D2MOO REVIEW {stamp}] {reason}\n\n" + cur_txt).strip()},
                                params={"program": program})
            applied.append((name, "(review-flagged, not renamed)"))
    if applied:
        fun_doc.ghidra_post("/save_program", data={"program": prog})
        # update registry names (name is a key for downstream tooling)
        rows = _rows()
        for row in rows:
            if row.get("name") in renames:
                row["_prev_name"] = row["name"]
                row["name"] = renames[row["name"]]
        REGISTRY.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return {"applied": applied, "plan": {k: len(v) for k, v in b.items()}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--rewrite-plates", action="store_true",
                    help="second pass: make already-renamed functions' plate BODIES canonical "
                         "(field_0x45->nInvPage, PlayerData->ItemData). Preview unless --apply.")
    ap.add_argument("--program", default=PROGRAM)
    args = ap.parse_args()
    if args.rewrite_plates:
        out = rewrite_plates(program=args.program, do_apply=args.apply)
        verb = "REWROTE" if args.apply else "would rewrite"
        print(f"{verb} plate bodies for {len(out['touched'])} functions"
              f"{'' if args.apply else ' (preview -- add --apply to write)'}:")
        for name, edits in out["touched"]:
            print(f"  {name}")
            for e in edits:
                print(f"       {e}")
        return 0
    if args.apply:
        out = apply(program=args.program)
        print(f"RENAMED {len(out['applied'])} functions; plan counts: {out['plan']}")
        for old, new in out["applied"]:
            print(f"  {old}  ->  {new}")
        return 0
    b = plan()
    print(f"offset-named proven functions: resolved={len(b['resolved'])} "
          f"no_field={len(b['no_field'])} no_struct={len(b['no_struct'])} "
          f"no_candidate={len(b['no_candidate'])}")
    print("\n-- RESOLVED (would rename) --")
    for name, addr, proposed, reason in b["resolved"]:
        print(f"  {name:<34} -> {proposed:<38} [{reason}]")
    if b["no_field"]:
        print("\n-- struct found, NO D2MOO field at offset (offset name is honest) --")
        for name, addr, reason in b["no_field"]:
            print(f"  {name:<34} {reason}")
    if b["no_struct"]:
        print("\n-- struct NOT identified (needs chain/context) --")
        for name, addr, reason in b["no_struct"][:20]:
            print(f"  {name:<34} {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

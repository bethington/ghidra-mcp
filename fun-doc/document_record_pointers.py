#!/usr/bin/env python3
"""
Phase 2 / Form C — pointer-to-record-array globals.

A `g_p*` global whose callers compute `i * STRIDE + (int)g` is a POINTER to an
array of fixed-size records. Deterministically recover STRIDE, give the pointer
a concrete record type (reuse an existing struct of that size, else create a
sized placeholder `<Base>Record`), and type the global `<Record> *`.

That typing is the enabler: once Ghidra knows the element size, re-decompiling
renders `g[i].field_0xNN`, which is what field recovery (the next step) reads.
This tool does the reliable, deterministic part (stride + record type); field
population is reported but left to the model-assisted refinement pass.

Usage:
  python document_record_pointers.py --name g_pCompositTextData          # dry
  python document_record_pointers.py --name g_pCompositTextData --apply
"""
import argparse, json, re
import requests

GHIDRA = "http://127.0.0.1:8089"
PROGRAM = "/Mods/PD2-S12/D2Common.dll"

def gget(path, **p):
    p.setdefault("program", PROGRAM)
    r = requests.get(f"{GHIDRA}{path}", params=p, timeout=60); r.raise_for_status()
    try: return r.json()
    except ValueError: return r.text

def gpost(path, **b):
    prog = b.pop("program", PROGRAM)
    r = requests.post(f"{GHIDRA}{path}", params={"program": prog}, json=b, timeout=60)
    r.raise_for_status()
    try: return r.json()
    except ValueError: return r.text

def num(s):
    return int(s, 16) if s.lower().startswith("0x") else int(s)

def recover_stride(decomp, gname):
    """`i * STRIDE + (int)g` / `(int)g + i*STRIDE` / `g + i*STRIDE` -> STRIDE votes."""
    votes = {}
    pats = [
        r"\w+\s*\*\s*(0x[0-9a-fA-F]+|\d+)\s*\+\s*\(int\)\s*" + re.escape(gname),
        r"\(int\)\s*" + re.escape(gname) + r"\s*\+\s*\w+\s*\*\s*(0x[0-9a-fA-F]+|\d+)",
        re.escape(gname) + r"\s*\+\s*\w+\s*\*\s*(0x[0-9a-fA-F]+|\d+)",
        r"\w+\s*\*\s*(0x[0-9a-fA-F]+|\d+)\s*\+\s*" + re.escape(gname),
    ]
    for p in pats:
        for m in re.finditer(p, decomp):
            s = num(m.group(1))
            if 2 <= s <= 0x4000:
                votes[s] = votes.get(s, 0) + 1
    return votes

def recover_direct_fields(decomp, gname, stride):
    """Best-effort: `*(T *)(i*STRIDE + (int)g + OFF)` -> {off: type}. Usually empty
    (fields go through a local), but capture any that ARE direct."""
    fields = {}
    pat = (r"\*\(\s*([A-Za-z_][\w \*]*?)\s*\)\s*\([^()]*?"
           + re.escape(gname) + r"[^()]*?\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
    for m in re.finditer(pat, decomp):
        off = num(m.group(2))
        if off < stride:
            fields[off] = m.group(1).strip()
    return fields

def existing_struct_of_size(size, hint):
    """Find an existing struct of exactly `size` bytes whose name matches hint."""
    res = gget("/search_data_types", pattern=hint)
    if not isinstance(res, str): return None
    for line in res.splitlines():
        m = re.match(r"(\S+)\s*\|\s*Size:\s*(\d+)", line)
        if m and int(m.group(2)) == size and "*" not in m.group(1) and "[" not in m.group(1):
            return m.group(1)
    return None

def struct_named(base):
    """Return (name, size) of an existing STRUCT exactly named `base`, else None."""
    res = gget("/search_data_types", pattern=base)
    if not isinstance(res, str): return None
    for line in res.splitlines():
        m = re.match(r"(\S+)\s*\|\s*Size:\s*(\d+)", line)
        if m and m.group(1) == base and int(m.group(2)) > 1:
            return base, int(m.group(2))
    return None

def process(gname, addr, decomp, apply):
    """Returns a one-line result string. Types g as a record pointer when a
    reliable record type is found (direct stride, or a canonical *Txt struct)."""
    votes = recover_stride(decomp, gname)
    base = re.sub(r"^g_p(fn)?", "", gname)
    rec_type, why = None, None
    if votes:
        stride = max(votes, key=votes.get)
        hint = base.split("Data")[0].split("Table")[0].split("Lookup")[0]
        ex = existing_struct_of_size(stride, hint)
        rec_type = ex or (hint + "Record")
        why = f"stride={stride}({'reuse '+ex if ex else 'new'})"
    else:
        # name-match: g_p<Name>Txt -> existing <Name>Txt struct (data-table convention)
        if base.endswith("Txt"):
            sm = struct_named(base)
            if sm:
                rec_type, why = sm[0], f"name-match {sm[0]}({sm[1]}B)"
    if not rec_type:
        return f"  {gname:36} SKIP (no reliable record type)"
    if not apply:
        return f"  {gname:36} -> {rec_type} *   [{why}]  (dry)"
    # create the placeholder struct only if it doesn't already exist (needs a size)
    if not struct_named(rec_type):
        if not votes:
            return f"  {gname:36} SKIP (no size to create {rec_type})"
        gpost("/create_struct", name=rec_type,
              fields=json.dumps([{"name": "data", "type": f"byte[{max(votes, key=votes.get)}]"}]),
              replace_placeholder=True)
    res = gpost("/apply_data_type", address=addr, type_name=f"{rec_type} *",
                clear_existing=True, strict_mode="warn")
    ok = not (isinstance(res, dict) and res.get("error"))
    return f"  {gname:36} -> {rec_type} *   [{why}]  {'OK' if ok else res.get('error')[:40]}"

def run_batch(apply, limit):
    txt = gget("/list_globals", limit=20000, filter="all", type_filter="all")
    cands = []
    for m in re.finditer(r"(g_p[A-Za-z0-9_]+)\s+@\s+([0-9a-fA-F]{5,})\s+\[[^\]]*\]\s+\((void \*|undefined)\)", txt):
        cands.append((m.group(1), "0x" + m.group(2)))
    if limit: cands = cands[:limit]
    print(f"[batch] {len(cands)} g_p* void*/undefined candidates  (apply={apply})")
    anchored = skipped = 0
    for gname, addr in cands:
        xr = gget("/get_xrefs_to", address=addr)
        callers = re.findall(r"From\s+([0-9a-fA-F]{5,})", xr if isinstance(xr, str) else "")[:3]
        decomp = ""
        for c in dict.fromkeys(callers):
            d = gget("/decompile_function", address="0x" + c)
            dc = (d.get("decompilation") or "") if isinstance(d, dict) else (d or "")
            decomp += "\n" + dc
        line = process(gname, addr, decomp, apply)
        if "SKIP" in line: skipped += 1
        else:
            anchored += 1; print(line)
    print(f"[batch] anchored={anchored}  skipped={skipped}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name"); ap.add_argument("--address")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--batch", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    if args.batch:
        run_batch(args.apply, args.limit)
        return

    addr = args.address
    if args.name and not addr:
        txt = gget("/list_globals", limit=20000, name_substring=args.name)
        m = re.search(r"@\s+([0-9a-fA-F]{5,})", txt if isinstance(txt, str) else "")
        addr = "0x" + m.group(1) if m else None
    if not addr: print("not found"); return
    if not addr.startswith("0x"): addr = "0x" + addr

    ag = gget("/audit_global", address=addr)
    gname = ag.get("name"); plate = ag.get("plate_comment") or ""
    print(f"[rec] {gname} @ {addr}  type={ag.get('type')!r}")

    xr = gget("/get_xrefs_to", address=addr)
    callers = re.findall(r"From\s+([0-9a-fA-F]{5,})", xr if isinstance(xr, str) else "")
    decomp = ""
    for c in dict.fromkeys(callers):
        d = gget("/decompile_function", address="0x" + c)
        dc = (d.get("decompilation") or "") if isinstance(d, dict) else (d or "")
        decomp += "\n" + dc

    votes = recover_stride(decomp, gname)
    if not votes:
        print("[rec] no `i*STRIDE + g` record-array access — not a Form C pointer. SKIP.")
        return
    stride = max(votes, key=votes.get)
    print(f"[rec] RECORD STRIDE = {stride} bytes (0x{stride:x})  votes={votes}")

    fields = recover_direct_fields(decomp, gname, stride)
    print(f"[rec] directly-recoverable fields: {len(fields)} "
          f"{ {hex(o): t for o,t in sorted(fields.items())} if fields else '(fields go through a local -> need the type+re-decompile refinement pass)'}")

    # choose the record type: reuse existing struct of this size, else placeholder
    hint = re.sub(r"^g_p", "", gname).split("Data")[0].split("Table")[0]
    existing = existing_struct_of_size(stride, hint)
    if existing:
        rec_type = existing
        print(f"[rec] reuse existing struct: {existing} (size {stride})")
    else:
        rec_type = hint + "Record"
        print(f"[rec] would CREATE placeholder struct {rec_type} (size {stride}, "
              f"field_0: byte[{stride}])")

    print(f"[rec] would type {gname} as `{rec_type} *`")

    if not args.apply:
        print("[rec] DRY RUN — re-run with --apply to create/apply.")
        return

    if not existing:
        pre = [{"name": f"field_0x{o:x}", "type": t} for o, t in sorted(fields.items())]
        if not pre:
            pre = [{"name": "data", "type": f"byte[{stride}]"}]
        r = gpost("/create_struct", name=rec_type, fields=json.dumps(pre),
                  replace_placeholder=True)
        print(f"[rec] create_struct {rec_type} -> {r if not isinstance(r,dict) else r.get('error') or 'OK'}")
    res = gpost("/apply_data_type", address=addr, type_name=f"{rec_type} *",
                clear_existing=True, strict_mode="warn")
    print(f"[rec] apply `{rec_type} *` -> {res if not isinstance(res,dict) else res.get('error') or 'OK'}")

if __name__ == "__main__":
    main()

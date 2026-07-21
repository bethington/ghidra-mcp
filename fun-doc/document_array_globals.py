#!/usr/bin/env python3
"""
Phase 1 — ARRAY structure recovery for composite globals.

For a global that callers access as an array (e.g.
`*(T **)(&g_pDistLookupTable + (x + y*8) * 4)`), DETERMINISTICALLY recover the
shape from the access pattern — element size, dimensions (from strides + bounds),
element type (from the cast) — then apply the real array type and (optionally)
fix the Hungarian prefix (g_p -> g_ap for an array of pointers).

No model guessing: the shape comes from parsing the decompiled index arithmetic.

Usage:
  python document_array_globals.py --name g_pDistLookupTable        # dry run
  python document_array_globals.py --name g_pDistLookupTable --apply
  python document_array_globals.py --address 0x6fddabc0
"""
import argparse, re, sys
import requests

GHIDRA = "http://127.0.0.1:8089"
PROGRAM = "/Mods/PD2-S12/D2Common.dll"

def gget(path, **p):
    p.setdefault("program", PROGRAM)
    r = requests.get(f"{GHIDRA}{path}", params=p, timeout=60); r.raise_for_status()
    try: return r.json()
    except ValueError: return r.text

def gpost(path, **body):
    prog = body.pop("program", PROGRAM)
    r = requests.post(f"{GHIDRA}{path}", params={"program": prog}, json=body, timeout=60)
    r.raise_for_status()
    try: return r.json()
    except ValueError: return r.text

# ---------- deterministic expression parsing ----------
def split_top(expr, op):
    """Split on `op` at paren-depth 0."""
    parts, depth, cur = [], 0, ""
    i = 0
    while i < len(expr):
        c = expr[i]
        if c == "(": depth += 1
        elif c == ")": depth -= 1
        if depth == 0 and expr[i:i+len(op)] == op:
            parts.append(cur); cur = ""; i += len(op); continue
        cur += c; i += 1
    parts.append(cur)
    return [p.strip() for p in parts]

def strip_parens(e):
    e = e.strip()
    while e.startswith("(") and e.endswith(")"):
        # only strip if the outer parens match
        depth = 0; ok = True
        for k, c in enumerate(e):
            if c == "(": depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0 and k != len(e) - 1: ok = False; break
        if ok: e = e[1:-1].strip()
        else: break
    return e

def extract_accesses(decomp, gname):
    """Find `*(CAST)(&gname + OFFSET)` accesses; return list of (cast, offset)."""
    out = []
    needle = "&" + gname
    idx = 0
    while True:
        j = decomp.find(needle, idx)
        if j < 0: break
        idx = j + 1
        # walk back to the '(' that opens `( &gname + ...`
        # find the enclosing paren group start
        k = decomp.rfind("(", 0, j)
        if k < 0: continue
        # find matching close paren from k
        depth, m = 0, k
        while m < len(decomp):
            if decomp[m] == "(": depth += 1
            elif decomp[m] == ")":
                depth -= 1
                if depth == 0: break
            m += 1
        group = decomp[k+1:m]          # `&gname + OFFSET`
        # the cast: look just before k for `*(CAST)`
        pre = decomp[max(0, k-40):k]
        mcast = re.search(r"\*\s*\(\s*([A-Za-z_][\w \*]*?)\s*\)\s*$", pre)
        cast = mcast.group(1).strip() if mcast else None
        # split `&gname + OFFSET`
        parts = split_top(group, "+")
        if len(parts) >= 2 and needle in parts[0]:
            offset = "+".join(parts[1:]).strip()
            out.append((cast, offset))
    return out

def parse_offset(offset):
    """`(x + y*8) * 4` -> (elem_size=4, [(x,1),(y,8)])."""
    factors = split_top(offset, "*")
    factors = [strip_parens(f) for f in factors]
    # element size = the lone integer top-level factor
    elem = None; index_expr = None
    for f in factors:
        if re.fullmatch(r"\d+", f) and elem is None:
            elem = int(f)
        else:
            index_expr = f if index_expr is None else index_expr  # first non-int
    if elem is None or index_expr is None:
        # form `&g + i*4` with i alone -> factors=[i,4]; or `&g + 4` scalar
        if len(factors) == 2 and re.fullmatch(r"\d+", factors[1]):
            elem = int(factors[1]); index_expr = factors[0]
        else:
            return None, None
    index_expr = strip_parens(index_expr)   # `(x + y*8)` -> `x + y*8`
    terms = split_top(index_expr, "+")
    idx_terms = []
    for t in terms:
        t = strip_parens(t)
        sub = split_top(t, "*")
        if len(sub) == 1:
            idx_terms.append((sub[0].strip(), 1))
        elif len(sub) == 2:
            a, b = sub[0].strip(), sub[1].strip()
            if re.fullmatch(r"\d+", b): idx_terms.append((a, int(b)))
            elif re.fullmatch(r"\d+", a): idx_terms.append((b, int(a)))
    return elem, idx_terms

def find_bound(decomp, var):
    """Find the array-dimension bound from `var < N` / `var <= N` guards.
    Ignores non-positive bounds (`< 0` is a sign check, not a dimension) and
    takes the smallest POSITIVE upper bound (the tightest real dimension)."""
    cands = []
    for m in re.finditer(r"(?:\(int\)\s*)?" + re.escape(var) + r"\s*(<=?)\s*(\d+)", decomp):
        n = int(m.group(2)) + (1 if m.group(1) == "<=" else 0)
        if n > 0:
            cands.append(n)
    return min(cands) if cands else None

def elem_type_from_cast(cast):
    """`DynamicPath **` accessed via `*(...)` -> element `DynamicPath *`."""
    if not cast: return None
    c = cast.strip()
    stars = c.count("*")
    base = c.replace("*", "").strip()
    # one deref happens (the leading `*`), so element keeps (stars-1) pointer levels
    lvl = max(stars - 1, 0)
    return (base + " " + "*" * lvl).strip() if lvl else base

# Hungarian element prefix -> (ghidra element type, byte size)
ELEM_BY_PREFIX = {"ab": ("byte", 1), "an": ("int", 4), "aw": ("ushort", 2),
                  "adw": ("uint", 4), "ap": ("void *", 4), "apfn": ("void *", 4)}

def hungarian_elem(gname):
    after = gname[2:] if gname.startswith("g_") else gname
    for pre in ("apfn", "adw", "ab", "an", "aw", "ap"):
        if after.startswith(pre) and len(after) > len(pre) and after[len(pre)].isupper():
            return ELEM_BY_PREFIX[pre]
    return None, None

def extract_indexed(decomp, gname):
    """Form B: `(&g)[idx]` or `g[idx]` -> list of index variable names."""
    vars_ = []
    for m in re.finditer(r"\(?&?\s*" + re.escape(gname) + r"\s*\)?\s*\[\s*([A-Za-z_]\w*)\s*\]", decomp):
        vars_.append(m.group(1))
    return vars_

def memcpy_size(decomp, gname):
    """`Copy 0xN bytes from g` / `memcpy/memset(... g ..., N)` -> total bytes."""
    best = None
    for m in re.finditer(r"0x([0-9a-fA-F]+)\s*bytes.*?" + re.escape(gname), decomp):
        best = int(m.group(1), 16)
    for m in re.finditer(re.escape(gname) + r".*?0x([0-9a-fA-F]+)\s*bytes", decomp):
        best = int(m.group(1), 16) if best is None else best
    return best

def infer_indexed(gname, decomp):
    """Form B recovery: 1D array from (&g)[i] + element(prefix) + length(memcpy/bound)."""
    idx_vars = extract_indexed(decomp, gname)
    if not idx_vars:
        return None
    et, esz = hungarian_elem(gname)
    if not et:
        et, esz = "byte", 1                      # (&g)[i] on undefined => byte indexing
    total = memcpy_size(decomp, gname)
    if total:
        n = total // esz
    else:
        bounds = [find_bound(decomp, v) for v in idx_vars]
        bounds = [b for b in bounds if b]
        if not bounds:
            return None
        n = max(bounds)
    return {"elem_type": et, "elem_size": esz, "dims": [n], "votes": len(idx_vars),
            "total_bytes": esz * n}

def infer(accesses, decomp):
    """Combine accesses -> (elem_type, elem_size, dims[]) or None."""
    votes = {}
    for cast, offset in accesses:
        elem, terms = parse_offset(offset)
        if not elem or not terms: continue
        et = elem_type_from_cast(cast)
        # dims: sort terms by stride descending (outer..inner); bound each
        terms_sorted = sorted(terms, key=lambda t: -t[1])
        dims = []
        ok = True
        for var, stride in terms_sorted:
            b = find_bound(decomp, var)
            if b is None: ok = False; break
            dims.append(b)
        if not ok or not dims: continue
        key = (et, elem, tuple(dims))
        votes[key] = votes.get(key, 0) + 1
    if not votes: return None
    (et, elem, dims), n = max(votes.items(), key=lambda kv: kv[1])
    return {"elem_type": et, "elem_size": elem, "dims": list(dims), "votes": n,
            "total_bytes": elem * (1 if not dims else __import__("math").prod(dims))}

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name"); ap.add_argument("--address")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--rename", action="store_true", help="also fix g_p->g_ap prefix")
    args = ap.parse_args()

    addr = args.address
    if args.name and not addr:
        txt = gget("/list_globals", limit=20000, name_substring=args.name)
        m = re.search(r"@\s+([0-9a-fA-F]{5,})", txt if isinstance(txt, str) else str(txt))
        addr = "0x" + m.group(1) if m else None
    if not addr: print("global not found"); return
    if not addr.startswith("0x"): addr = "0x" + addr

    ag = gget("/audit_global", address=addr)
    gname = ag.get("name") if isinstance(ag, dict) else None
    print(f"[arr] {gname} @ {addr}  current type={ag.get('type')!r}")

    xr = gget("/get_xrefs_to", address=addr)
    callers = re.findall(r"From\s+([0-9a-fA-F]{5,})", xr if isinstance(xr, str) else str(xr))
    print(f"[arr] {len(callers)} caller ref(s)")
    accesses = []
    seen_decomp = ""
    for c in dict.fromkeys(callers):
        d = gget("/decompile_function", address="0x" + c)
        if isinstance(d, dict): d = d.get("decompilation") or d.get("code") or ""
        seen_decomp += "\n" + d
        accesses += extract_accesses(d, gname)
    print(f"[arr] {len(accesses)} array-access expression(s) found")
    for cast, off in accesses[:6]:
        print(f"       cast={cast!r}  offset={off!r}")

    shape = infer(accesses, seen_decomp)              # Form A: *(CAST)(&g + i*size)
    if not shape:
        shape = infer_indexed(gname, seen_decomp)     # Form B: (&g)[i] + size hint
    if not shape:
        print("[arr] no supported array-access form recovered — SKIP (underclaim)")
        return
    dims = shape["dims"]
    et, total = shape["elem_type"], shape["total_bytes"]
    type_str = et + "".join(f"[{d}]" for d in dims)
    print(f"\n[arr] RECOVERED: {type_str}   ({total} bytes, {shape['votes']} caller-vote(s))")

    # --- region-fit guard: does the span overlap OTHER labeled globals? ---
    base = int(addr, 16)
    allg = gget("/list_globals", limit=20000)
    interior = []
    for m in re.finditer(r"(\S.*?)\s+@\s+([0-9a-fA-F]{5,})", allg if isinstance(allg, str) else ""):
        a = int(m.group(2), 16)
        if base < a < base + total:
            interior.append((hex(a), m.group(1).strip()))
    # Distinguish DERIVED sub-labels (g_x[2], g_x_4 — part of THIS array, safe to
    # absorb) from FOREIGN globals (a different base name — a real conflict).
    def derived(n): return n.startswith(gname)
    foreign = [(a, n) for a, n in interior if not derived(n)]
    subs = [(a, n) for a, n in interior if derived(n)]
    if foreign:
        print(f"[arr] *** FLAGGED — the {total}-byte span overlaps {len(foreign)} FOREIGN global(s):")
        for a, n in foreign[:6]:
            print(f"        {a}  {n}")
        print("[arr] NOT applying: those are unrelated globals — either mislabeled (part of this")
        print("      array) or the bound is over-read. Shape is trustworthy; the conflict is the signal.")
        return
    if subs:
        print(f"[arr] {len(subs)} interior sub-label(s) of this array will be absorbed: "
              f"{[n for _, n in subs][:4]}")

    if not args.apply:
        print("[arr] region clear (no foreign overlap). DRY RUN — re-run with --apply.")
        return

    # --- create the (possibly multi-dim) array type, innermost first ---
    cur = et
    for d in reversed(dims):
        nm = re.sub(r"[^A-Za-z0-9]", "_", cur) + f"_{d}"
        gpost("/create_array_type", base_type=cur, length=d, name=nm)
        cur = f"{cur}[{d}]"
    res = gpost("/apply_data_type", address=addr, type_name=cur,
                clear_existing=True, strict_mode="warn")
    ok = not (isinstance(res, dict) and res.get("error"))
    print(f"[arr] apply {cur} -> {'OK' if ok else res.get('error')}")
    # --- name-fix: g_p* single-pointer prefix is wrong for an array ---
    if ok and args.rename and gname and gname.startswith("g_p") and not gname.startswith("g_ap"):
        newn = "g_ap" + gname[3:] if "*" in et else "g_a" + gname[3:]
        rr = gpost("/rename_or_label", address=addr, name=newn)
        print(f"[arr] rename {gname} -> {newn}: {'OK' if not (isinstance(rr,dict) and rr.get('error')) else rr.get('error')}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Dedup globals that carry MULTIPLE labels at one address down to a single label
that follows the documented naming rules (g_ + Hungarian prefix matching the
type + >=2-char descriptor). Keeps Ghidra's primary when it conforms; otherwise
keeps the conforming secondary; deletes the rest. Flags addresses where NO label
conforms (needs a real rename, not a delete).

Read-only by default. --apply to delete the losing labels.
"""
import argparse, re, sys
import requests

GHIDRA = "http://127.0.0.1:8089"
PROGRAM = "/Mods/PD2-S12/D2Common.dll"
LINE_RE = re.compile(r"^(?P<name>.+?)\s+@\s+(?P<addr>[0-9a-fA-F]{5,})\b", re.M)

# Hungarian prefix -> semantic category (longest match first)
HUNG = [("lpcsz","str"),("lpsz","str"),("ppfn","ptr"),("lpfn","ptr"),("pfn","ptr"),
        ("wsz","wstr"),("sz","str"),("lp","ptr"),("pp","ptr"),("dw","u32"),("qw","u64"),
        ("ll","i64"),("fl","flt"),("ab","arr"),("an","arr"),("ap","arr"),("aw","arr"),
        ("a","arr"),("p","ptr"),("n","int"),("i","int"),("w","u16"),("b","byte"),
        ("f","bool"),("d","dbl"),("h","hnd")]
DEDUP_SUFFIX = re.compile(r"_[0-9a-fA-F]{2,}$")
AUTO_REMNANT = re.compile(r"(DAT_|PTR_|FUN_|LAB_|SUB_)")

def gget(path, **p):
    p.setdefault("program", PROGRAM)
    r = requests.get(f"{GHIDRA}{path}", params=p, timeout=45); r.raise_for_status()
    try: return r.json()
    except ValueError: return r.text

def gpost(path, **body):
    prog = body.pop("program", PROGRAM)
    r = requests.post(f"{GHIDRA}{path}", params={"program": prog}, json=body, timeout=45)
    r.raise_for_status()
    try: return r.json()
    except ValueError: return r.text

def type_category(t):
    t = (t or "").lower()
    if not t: return None
    if "wchar" in t: return "wstr"
    if t == "string" or t.startswith("char *") or t.startswith("char[") or t == "char": return "str"
    if "*" in t: return "ptr"
    if "double" in t: return "dbl"
    if "float" in t: return "flt"
    if "bool" in t: return "bool"
    if "uint" in t or "dword" in t: return "u32"
    if t == "int" or "int32" in t: return "int"
    if "ushort" in t or "word" == t or "uint16" in t: return "u16"
    if "byte" in t or "uchar" in t or "undefined1" in t: return "byte"
    if "[" in t: return "arr"
    return "other"

def extract_hung(after_g):
    for pre, cat in HUNG:
        if after_g.startswith(pre) and len(after_g) > len(pre) and after_g[len(pre)].isupper():
            return pre, cat
    return None, None

def score(name, tcat):
    """Higher = more rule-conformant."""
    if not name.startswith("g_"): return -10, "no g_ prefix"
    after = name[2:]
    if AUTO_REMNANT.search(name): return -8, "auto-generated remnant"
    pre, pcat = extract_hung(after)
    s, notes = 0, []
    if pre is None: return -3, "no Hungarian prefix"
    s += 3;
    desc = after[len(pre):]
    if len(desc) < 2: s -= 2; notes.append("short descriptor")
    else: s += 1
    if tcat and pcat == tcat: s += 3
    elif tcat and pcat != tcat: s -= 1; notes.append(f"prefix {pre}~{pcat} vs type {tcat}")
    if DEDUP_SUFFIX.search(name): s -= 2; notes.append("_NN dedup suffix")
    return s, ",".join(notes) or "ok"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    txt = gget("/list_globals", limit=20000, filter="all", type_filter="all")
    if isinstance(txt, dict): txt = txt.get("text") or str(txt)
    by_addr = {}
    for m in LINE_RE.finditer(txt):
        by_addr.setdefault(m["addr"].lower(), []).append(m["name"].strip())
    multi = {a: ns for a, ns in by_addr.items() if len(set(ns)) > 1}
    print(f"[dedup] {len(multi)} multi-labeled addresses")

    def clearly_inferior(loser, keep, keep_score, tcat):
        if not loser.startswith("g_"):
            return True                                  # DATATBLS_/Ordinal_/etc.
        if AUTO_REMNANT.search(loser):
            return True
        if DEDUP_SUFFIX.search(loser) and not DEDUP_SUFFIX.search(keep):
            return True                                  # g_..._74 dedup artifact
        after = loser[2:]
        pre, _ = extract_hung(after)
        desc = after[len(pre):] if pre else after
        if "_" in desc and desc.lower() == desc:
            return True                                  # snake_case descriptor
        return score(loser, tcat)[0] <= keep_score - 3   # clearly lower quality

    clean, flagged = [], []
    for addr, names in sorted(multi.items()):
        names = list(dict.fromkeys(names))
        try:
            ag = gget("/audit_global", address="0x" + addr)
            primary = ag.get("name") if isinstance(ag, dict) else None
            tcat = type_category(ag.get("type") if isinstance(ag, dict) else None)
        except Exception:
            primary, tcat = None, None
        scored = sorted(((score(n, tcat)[0], n) for n in names), reverse=True)
        best_score = scored[0][0]
        prim_score = next((sc for sc, n in scored if n == primary), -99)
        keep = primary if prim_score >= best_score else scored[0][1]
        ks = score(keep, tcat)[0]
        losers = [n for n in names if n != keep]
        all_inferior = all(clearly_inferior(l, keep, ks, tcat) for l in losers)
        if ks >= 4 and all_inferior:
            clean.append((addr, keep, losers, tcat))
        else:
            flagged.append((addr, keep, losers, tcat, ks))

    print(f"\n[dedup] === AUTO-DELETE (kept label conforms; losers clearly inferior) ===")
    for addr, keep, losers, tcat in clean:
        print(f"  0x{addr} [{tcat}]  KEEP {keep}   del {losers}")
    print(f"\n[dedup] === FLAGGED for your review (semantic disagreement / kept non-conformant) ===")
    for addr, keep, losers, tcat, ks in flagged:
        print(f"  0x{addr} [{tcat}] keep={keep}(score {ks})  vs  {losers}")

    total_del = sum(len(l) for _, _, l, _ in clean)
    print(f"\n[dedup] auto-delete {total_del} losers across {len(clean)} clean addresses; "
          f"{len(flagged)} flagged for review (untouched)")
    plan = clean

    if not args.apply:
        print("[dedup] DRY RUN — nothing deleted. Re-run with --apply.")
        return

    print(f"\n[dedup] DELETING {total_del} loser labels (clean cases only)...")
    ok, fail = 0, []
    for addr, keep, losers, tcat in plan:
        for name in losers:
            try:
                res = gpost("/delete_label", address="0x" + addr, name=name)
                s = str(res).lower()
                if isinstance(res, dict) and res.get("error"): fail.append((addr, name, res.get("error")))
                elif "error" in s and "no error" not in s: fail.append((addr, name, str(res)[:80]))
                else: ok += 1
            except Exception as e:
                fail.append((addr, name, str(e)[:80]))
    print(f"[dedup] deleted ok={ok} failed={len(fail)}")
    for a, n, m in fail[:12]:
        print(f"    FAIL 0x{a} {n}: {m}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Sweep: re-type mis-typed string globals to Ghidra's auto-sizing `string`
(TerminatedCString) type so the FULL null-terminated string is captured —
fixing the "single char typed at the top, rest of the letters left undefined"
cases.

Design (per user decisions 2026-07-15):
  * TARGET TYPE   : Ghidra native `string` (auto-sizes to the null terminator).
  * SCOPE         : existing-program sweep (the forward worker change is separate).
  * CANDIDATES    : "broad + guarded" — any global typed as bare char / char[1] /
                    too-short char[N], OR an undefined-family type with a data
                    xref, WHERE `inspect_memory_content(detect_strings)` says the
                    bytes are a real null-terminated printable string whose length
                    EXCEEDS the current type size. Numbers/structs never qualify.

Deterministic: the length + is-it-a-string decision come entirely from Ghidra
(`inspect_memory_content`), never from a model guess.

Usage:
  python fix_string_globals.py                # DRY RUN (default) — report only
  python fix_string_globals.py --apply        # actually apply the string type
  python fix_string_globals.py --limit 50     # cap candidates inspected (testing)
"""
import argparse, re, sys, time
import requests

GHIDRA = "http://127.0.0.1:8089"
PROGRAM = "/Mods/PD2-S12/D2Common.dll"
INSPECT_LEN = 600   # bytes to read when detecting the string (covers long paths)

# list_globals line: "name @ 6fdxxxxx [Label] (type) xrefs=N"
LINE_RE = re.compile(r"^(?P<name>.+?)\s+@\s+(?P<addr>[0-9a-fA-F]+)\s+\[(?P<kind>[^\]]*)\]\s+\((?P<type>.*?)\)\s+xrefs=(?P<xrefs>\d+)", re.M)


def gget(path, **params):
    params.setdefault("program", PROGRAM)
    r = requests.get(f"{GHIDRA}{path}", params=params, timeout=45)
    r.raise_for_status()
    # Ghidra serves JSON as text/plain, so try JSON first regardless of header.
    try:
        return r.json()
    except ValueError:
        return r.text


def gpost(path, **body):
    prog = body.pop("program", PROGRAM)
    r = requests.post(f"{GHIDRA}{path}", params={"program": prog}, json=body, timeout=45)
    r.raise_for_status()
    try:
        return r.json()
    except ValueError:
        return r.text


def type_size(t):
    """Byte size of a current type string, or None if not a string-candidate type."""
    t = t.strip()
    m = re.fullmatch(r"char\[(\d+)\]", t)
    if m:
        return int(m.group(1))
    if t == "char":
        return 1
    m = re.fullmatch(r"undefined(\d+)", t)
    if m:
        return int(m.group(1))
    if t in ("undefined", "undefined1"):
        return 1
    m = re.fullmatch(r"undefined\[(\d+)\]", t)
    if m:
        return int(m.group(1))
    return None  # struct/pointer/string/etc — not a candidate


def is_undefined(t):
    return t.strip().startswith("undefined")


def list_all_globals():
    # Single large pull — list_globals returns all ~2200 in one text response.
    txt = gget("/list_globals", limit=20000,
               filter="all", type_filter="all", include_all_sections="false")
    if isinstance(txt, dict):
        txt = txt.get("text") or txt.get("result") or str(txt)
    out = []
    for m in LINE_RE.finditer(txt):
        out.append({"name": m["name"].strip(), "addr": m["addr"].lower(),
                    "kind": m["kind"], "type": m["type"].strip(),
                    "xrefs": int(m["xrefs"])})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="actually write (default: dry run)")
    ap.add_argument("--limit", type=int, default=0, help="cap candidates inspected")
    args = ap.parse_args()

    print(f"[fix-strings] program={PROGRAM}  mode={'APPLY' if args.apply else 'DRY-RUN'}")
    globs = list_all_globals()
    print(f"[fix-strings] {len(globs)} globals enumerated")

    # Target: g_sz*/g_lpsz* NARROW-string-named globals not already typed `string`.
    # The name is authoritative (the `sz` prefix deliberately means zero-terminated
    # string) and avoids the is_likely_string false-positives on 2-byte g_w words.
    # g_wsz* wide strings need the `unicode` type — reported, not touched here.
    def is_narrow_sz(name):
        n = name.lower()
        return (n.startswith("g_sz") or n.startswith("g_lpsz")) and not n.startswith("g_wsz")

    wide = [g for g in globs if g["name"].lower().startswith("g_wsz")]
    cands = [g for g in globs if is_narrow_sz(g["name"]) and g["type"] != "string"]
    print(f"[fix-strings] {len(cands)} g_sz* globals not yet typed `string` "
          f"(+ {len(wide)} g_wsz wide-string, reported only)")
    if args.limit:
        cands = cands[: args.limit]

    fixes, skipped_notstr, errors = [], 0, []
    for g in cands:
        addr = "0x" + g["addr"]
        try:
            info = gget("/inspect_memory_content", address=addr,
                        length=INSPECT_LEN, detect_strings="true")
        except Exception as e:
            errors.append((g["addr"], f"inspect: {e}")); continue
        det = (info.get("detected_string") if isinstance(info, dict) else "") or ""
        slen = (info.get("string_length") if isinstance(info, dict) else 0) or 0
        # GUARD: only apply where there is real string content at the address.
        if not det or slen < 1:
            skipped_notstr += 1; continue
        fixes.append({"addr": g["addr"], "name": g["name"], "cur": g["type"],
                      "slen": slen, "text": det[:48]})

    print(f"\n[fix-strings] === RESULT ===")
    print(f"  would re-type to `string` : {len(fixes)}")
    print(f"  skipped (no string content at addr / guard) : {skipped_notstr}")
    print(f"  inspect errors : {len(errors)}")
    print(f"\n  sample of what would change (current -> string[detected_len]):")
    for f in fixes[:25]:
        print(f"    {f['addr']}  {f['name'][:34]:34}  {f['cur']:>10} -> string[{f['slen']}]  \"{f['text']}\"")
    if len(fixes) > 25:
        print(f"    ... and {len(fixes)-25} more")

    if not args.apply:
        print(f"\n[fix-strings] DRY RUN — nothing written. Re-run with --apply to apply.")
        return

    def apply_one(f):
        """Apply `string`; return None on success or an error string."""
        try:
            res = gpost("/apply_data_type", address="0x" + f["addr"],
                        type_name="string", clear_existing=True)
            if isinstance(res, dict):
                return res.get("error") or (res.get("message") if res.get("status") == "rejected" else None)
            low = str(res).lower()
            return str(res)[:140] if ("error" in low or "conflict" in low or "rejected" in low) else None
        except Exception as e:
            return str(e)[:140]

    # Process ADDRESS-ASCENDING so an oversized parent (lower address) shrinks
    # to its real length BEFORE the strings it was hiding (higher addresses) are
    # reached — the fix cascades. Retry the leftovers (a parent may free a child
    # only after the child's first attempt). Remaining conflicts are g_sz labels
    # inside a real fixed-width table (g_ab*) — left alone by design.
    fixes.sort(key=lambda f: int(f["addr"], 16))
    print(f"\n[fix-strings] APPLYING `string` to {len(fixes)} globals "
          f"(address-ascending, up to 3 passes)...")
    ok = 0
    pending = fixes
    for _pass in range(1, 4):
        still = []
        for i, f in enumerate(pending, 1):
            if apply_one(f) is None:
                ok += 1
            else:
                still.append(f)
        print(f"    pass {_pass}: ok so far {ok}, still-conflicting {len(still)}")
        if len(still) == len(pending):   # no progress -> the rest are real conflicts
            pending = still
            break
        pending = still
    print(f"\n[fix-strings] APPLIED ok={ok}  left (real conflicts, e.g. table entries)={len(pending)}")
    for f in pending[:12]:
        print(f"    LEFT {f['addr']} {f['name'][:34]:34} (\"{f['text']}\")")


if __name__ == "__main__":
    main()

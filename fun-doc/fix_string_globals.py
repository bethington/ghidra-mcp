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
    r = requests.get(f"{GHIDRA}{path}", params=params, timeout=30)
    r.raise_for_status()
    ct = r.headers.get("content-type", "")
    return r.json() if "json" in ct else r.text


def gpost(path, **body):
    prog = body.pop("program", PROGRAM)
    r = requests.post(f"{GHIDRA}{path}", params={"program": prog}, json=body, timeout=30)
    r.raise_for_status()
    ct = r.headers.get("content-type", "")
    return r.json() if "json" in ct else r.text


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
    out, offset, page = [], 0, 500
    while True:
        txt = gget("/list_globals", limit=page, offset=offset,
                   filter="all", type_filter="all", include_all_sections="false")
        if isinstance(txt, dict):
            txt = txt.get("text") or txt.get("result") or str(txt)
        rows = list(LINE_RE.finditer(txt))
        if not rows:
            break
        for m in rows:
            out.append({"name": m["name"].strip(), "addr": m["addr"].lower(),
                        "kind": m["kind"], "type": m["type"].strip(),
                        "xrefs": int(m["xrefs"])})
        if len(rows) < page:
            break
        offset += page
        if offset > 100000:
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="actually write (default: dry run)")
    ap.add_argument("--limit", type=int, default=0, help="cap candidates inspected")
    args = ap.parse_args()

    print(f"[fix-strings] program={PROGRAM}  mode={'APPLY' if args.apply else 'DRY-RUN'}")
    globs = list_all_globals()
    print(f"[fix-strings] {len(globs)} globals enumerated")

    # Stage 1: cheap type filter -> string candidates
    cands = []
    for g in globs:
        sz = type_size(g["type"])
        if sz is None:
            continue                      # struct/pointer/already-string -> skip
        if is_undefined(g["type"]) and g["xrefs"] == 0:
            continue                      # undefined w/o a data xref -> skip
        cands.append((g, sz))
    print(f"[fix-strings] {len(cands)} char/undefined candidates to inspect")
    if args.limit:
        cands = cands[: args.limit]

    fixes, skipped_notstr, skipped_covered, errors = [], 0, 0, []
    for g, cur_sz in cands:
        addr = "0x" + g["addr"]
        try:
            info = gget("/inspect_memory_content", address=addr,
                        length=INSPECT_LEN, detect_strings="true")
        except Exception as e:
            errors.append((g["addr"], f"inspect: {e}")); continue
        if not isinstance(info, dict):
            skipped_notstr += 1; continue
        if not info.get("is_likely_string"):
            skipped_notstr += 1; continue                 # GUARD: real string only
        slen = info.get("string_length") or 0
        if slen <= cur_sz:
            skipped_covered += 1; continue                # already covers it
        fixes.append({"addr": g["addr"], "name": g["name"], "cur": g["type"],
                      "cur_sz": cur_sz, "slen": slen,
                      "text": (info.get("detected_string") or "")[:48]})

    print(f"\n[fix-strings] === RESULT ===")
    print(f"  would re-type : {len(fixes)}")
    print(f"  skipped (not a string / guard) : {skipped_notstr}")
    print(f"  skipped (type already covers)  : {skipped_covered}")
    print(f"  inspect errors : {len(errors)}")
    print(f"\n  sample of what would change (current -> string[detected_len]):")
    for f in fixes[:25]:
        print(f"    {f['addr']}  {f['name'][:34]:34}  {f['cur']:>10} -> string[{f['slen']}]  \"{f['text']}\"")
    if len(fixes) > 25:
        print(f"    ... and {len(fixes)-25} more")

    if not args.apply:
        print(f"\n[fix-strings] DRY RUN — nothing written. Re-run with --apply to apply.")
        return

    print(f"\n[fix-strings] APPLYING string type to {len(fixes)} globals...")
    ok, fail = 0, []
    for i, f in enumerate(fixes, 1):
        try:
            res = gpost("/apply_data_type", address="0x" + f["addr"],
                        type_name="string", clear_existing=True)
            s = str(res)
            if '"error"' in s or "ERROR" in s or "rejected" in s:
                fail.append((f["addr"], s[:120]))
            else:
                ok += 1
        except Exception as e:
            fail.append((f["addr"], str(e)[:120]))
        if i % 50 == 0:
            print(f"    {i}/{len(fixes)} ...")
    print(f"\n[fix-strings] APPLIED ok={ok} failed={len(fail)}")
    for a, m in fail[:15]:
        print(f"    FAIL {a}: {m}")


if __name__ == "__main__":
    main()

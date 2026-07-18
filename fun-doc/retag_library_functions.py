#!/usr/bin/env python3
"""
Re-tag CRT/library functions that ESCAPED the name-based detector (usually
because a doc pass renamed them to readable names before they were tagged).

Signals (conservative, name-independent where possible):
  A. name-propagation — a name that carries a LIB_* tag at ANY address is that
     same CRT function everywhere; tag all its untagged copies. (Strongest.)
  B. extended CRT-name patterns the detector misses (___sbh_, __freefls, etc.).

GUARD: never touch a function with a game-subsystem prefix (GAME_/MISSILE_/...) —
those are real game code; mistagging them would silently exclude them from docs.

Writes BOTH the durable Ghidra LIB_CRT tag AND the library_code state flag (the
selector reads the flag; the assess pass reads the tag).

  python retag_library_functions.py            # DRY RUN (report only)
  python retag_library_functions.py --apply
"""
import argparse, json, re, urllib.request
import fun_doc

GH = "http://127.0.0.1:8089"
PROGRAM = "/Mods/PD2-S12/D2Common.dll"
LIB_TAGS = ("LIB_CRT", "LIB_MSVC_EH", "LIB_SECURITY", "LIB_MATH", "LIB_MSVC", "LIB_UNKNOWN")

# Core D2 re-implementation binaries the doc/fix workers actually target. The
# same statically-linked CRT is duplicated into each, so a CRT name tagged in
# ONE binary is the same CRT function in all of them (cross-binary propagation).
# Third-party DLLs (glide3x/libcrypto/BH/ddraw/…) are deliberately excluded.
CORE_BINARIES = ["D2Common.dll", "D2Game.dll", "D2Client.dll", "D2Win.dll",
                 "D2Lang.dll", "D2Net.dll", "D2CMP.dll", "D2Launch.dll",
                 "D2Multi.dll", "D2sound.dll", "D2gfx.dll", "Fog.dll", "Storm.dll"]

# Game-subsystem prefixes — NEVER library. Anything starting with these is skipped.
GAME_PREFIXES = ("GAME_", "MISSILE_", "SKILLS_", "SKILL_", "CLIENT_", "ROOM_", "PRESET_",
                 "DATATBLS_", "DATATBL_", "ANIM_", "UNIT_", "PATH_", "ITEMS_", "ITEM_",
                 "INV_", "INVENTORY_", "STAT_", "STATS_", "DRLG_", "MONSTER_", "QUEST_",
                 "DUNGEON_", "TREASURE_", "OBJECT_", "STORE_", "PARTY_", "NPC_", "AI_",
                 "COLLISION_", "SEED_", "PLAYER_", "COF_", "TXT_", "STRING_", "GFX_")

# Extended CRT-internal name patterns the detector doesn't cover.
CRT_NAME_RE = re.compile(
    r"^(___?sbh_|__freefls|__mbctype|__mtinit|__crt|__initp|__set_|_setmbcp|"
    r"__lc_|___lc_|__updatetlocinfo|__getptd|_ioinit|_freefls|__dllonexit|"
    r"__onexit|_setmode|_isctype|_ismbb|__addl|__shift|__aulldiv|__aullrem|"
    r"__ftol|__ftol2|_chkstk|__alloca|__CIpow|__CIsqrt|__CIlog|__CIexp)",
    re.IGNORECASE)

def prog_path(binary):
    return f"/Mods/PD2-S12/{binary}"

def gget(path, program, **p):
    p["program"] = program
    q = "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in p.items())
    r = urllib.request.urlopen(f"{GH}{path}?{q}", timeout=25).read().decode()
    try: return json.loads(r)
    except ValueError: return r

def gpost(path, program, body):
    req = urllib.request.Request(f"{GH}{path}?program={urllib.request.quote(program)}",
        data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    r = urllib.request.urlopen(req, timeout=25).read().decode()
    try: return json.loads(r)
    except ValueError: return r

def tagged_addrs_and_names(program):
    """(addr set '0x..', name set) of LIB_*-tagged functions in `program`."""
    addrs, names = set(), set()
    for t in LIB_TAGS:
        d = gget("/search_functions_by_tag", program, tag=t)
        for f in (d.get("functions") or []) if isinstance(d, dict) else []:
            a = "0x" + str(f.get("address", "")).lower().lstrip("0x")
            addrs.add(a)
            if f.get("name"): names.add(f["name"])
    return addrs, names

def game_prefixed(name):
    return any(name.startswith(p) for p in GAME_PREFIXES)

def scan_binary(binary, prop_names, st, apply):
    """Return (candidates, per_addr_tagged) for one binary. candidates =
    [(addr, name, reason, key)] using ONLY the two safe signals."""
    program = prog_path(binary)
    tagged_addrs, _ = tagged_addrs_and_names(program)
    cands = []
    for key, f in st["functions"].items():
        if not key.startswith(program + "::"):
            continue
        name = f.get("name") or ""
        addr = "0x" + key.split("::")[1].lstrip("0x")
        if addr in tagged_addrs:
            continue                      # already tagged
        if not name or game_prefixed(name):
            continue                      # game code or unnamed -> never
        reason = None
        if name in prop_names:
            reason = "name-propagation (LIB_* elsewhere)"
        elif CRT_NAME_RE.match(name):
            reason = "CRT-name pattern"
        if reason:
            cands.append((addr, name, reason, key))
    seen = set()
    cands = [c for c in cands if not (c[0] in seen or seen.add(c[0]))]
    return cands, len(tagged_addrs)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--binaries", default=None,
                    help="comma-list; default = core reimpl set")
    args = ap.parse_args()
    binaries = args.binaries.split(",") if args.binaries else CORE_BINARIES

    # Build the cross-binary propagation name-set: any name LIB_*-tagged in ANY
    # core binary is the same CRT function everywhere.
    prop_names = set()
    for b in binaries:
        _, names = tagged_addrs_and_names(prog_path(b))
        prop_names |= names
    print(f"[retag] cross-binary propagation set: {len(prop_names)} distinct CRT names")

    st = fun_doc.load_state()
    grand, borderline_all = [], []
    for b in binaries:
        cands, already = scan_binary(b, prop_names, st, args.apply)
        by = {}
        for _, _, r, _ in cands: by[r] = by.get(r, 0) + 1
        print(f"\n[{b}] already-tagged={already}  new candidates={len(cands)}  {by}")
        for a, n, r, _ in cands[:12]:
            print(f"    {a}  {n[:38]:38} {r}")
        if len(cands) > 12:
            print(f"    ... and {len(cands)-12} more")
        bl = [(a, n) for a, n, _, _ in cands if len(n) <= 4 or n.startswith("FUN_")]
        if bl:
            borderline_all += [(b, a, n) for a, n in bl]
        grand += [(b,) + c for c in cands]

    print(f"\n[retag] GRAND TOTAL new candidates across {len(binaries)} binaries: {len(grand)}")
    if borderline_all:
        print(f"  BORDERLINE (review — short/FUN_ names): {borderline_all[:20]}")

    if not args.apply:
        print(f"\n[retag] DRY RUN — nothing written. Re-run with --apply.")
        return

    print(f"\n[retag] APPLYING LIB_CRT tag + library_code=True to {len(grand)}...")
    # Group by binary and SAVE each program before moving to the next: the plugin
    # holds tag writes in memory and discards them for a program once it switches
    # to another, so a per-binary save_program is required for the writes to stick.
    from collections import defaultdict
    by_bin = defaultdict(list)
    for b, a, n, r, key in grand:
        by_bin[b].append((a, n, r, key))
    ok, fail, by_bin_ok = 0, [], {}
    for b, items in by_bin.items():
        prog = prog_path(b)
        b_ok = 0
        for a, n, r, key in items:
            try:
                res = gpost("/add_function_tag", prog, {"function": a, "tags": "LIB_CRT"})
                good = isinstance(res, dict) and res.get("status") == "success" and (
                    "LIB_CRT" in (res.get("added") or []) or
                    "LIB_CRT" in (res.get("already_present") or []))
                if not good:
                    fail.append((b, a, str(res)[:60])); continue
                st["functions"][key]["library_code"] = True
                st["functions"][key]["library_code_reasons"] = [f"retag: {r}"]
                ok += 1; b_ok += 1
            except Exception as e:
                fail.append((b, a, str(e)[:50]))
        # persist this program's tag writes before switching away from it
        try:
            sres = gpost("/save_program", prog, {})
            saved = not (isinstance(sres, dict) and sres.get("error"))
        except Exception as e:
            saved = False; sres = str(e)[:60]
        by_bin_ok[b] = f"{b_ok}{'' if saved else ' (SAVE FAILED: %s)' % sres}"
    fun_doc.save_state(st)
    print(f"[retag] tagged ok={ok} failed={len(fail)}")
    for b, v in by_bin_ok.items():
        print(f"    {b}: {v}")
    for b, a, m in fail[:12]:
        print(f"    FAIL {b} {a}: {m}")

if __name__ == "__main__":
    main()

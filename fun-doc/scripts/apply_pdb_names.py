"""Transfer function names from an authoritative PDB into a live program.

Several binaries in the corpus are open-source components whose PUBLISHED build
is byte-identical to the one shipped, and whose PDB is therefore obtainable.
That is not similarity matching -- it is the actual symbol table, so it beats
every heuristic in this repo by construction.

The route is indirect on purpose. Applying a PDB needs a Ghidra script, and
script execution over MCP is gated behind GHIDRA_MCP_ALLOW_SCRIPTS, which would
mean restarting a live Ghidra. Instead:

    1. import the binary + its PDB into a THROWAWAY headless project, where
       Ghidra's own PDB analyzer applies it (see ApplyPdbToProgram.java, which
       also verifies the PDB GUID against the binary and dumps address -> name)
    2. carry the names across with this script, over the ordinary MCP endpoints

TRUST GATE: only run this against a PDB whose GUID matches the binary's own
CodeView record AND whose published DLL is byte-identical (md5) to the shipped
one. A PDB from a different build produces confidently wrong names at every
address, which is far worse than none. ApplyPdbToProgram prints the GUID; check
it before trusting the dump.

Names are applied ONLY over Ghidra defaults (FUN_/SUB_/thunk_FUN_). Anything
already documented is reported, never overwritten -- same rule as crt_sweep.

    python fun-doc/scripts/apply_pdb_names.py --program /Mods/PD2-S12/libcrypto-1_1.dll \
        --dump C:\\tmp\\pdbapply.log --tag LIB_OPENSSL
    ... --apply
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from collections import Counter

GHIDRA_URL = os.environ.get("GHIDRA_URL", "http://127.0.0.1:8089").rstrip("/")
DEFAULT_NAME = re.compile(r"^(FUN_|SUB_|LAB_|thunk_FUN_)")
# `PDBNAME<TAB>address<TAB>name`, possibly wrapped in headless log decoration.
DUMP_LINE = re.compile(r"PDBNAME\t([0-9A-Fa-f]+)\t(.+?)\s*(?:\(GhidraScript\))?\s*$")


def _get(path: str, **params) -> dict:
    url = f"{GHIDRA_URL}{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=180) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _post(path: str, program: str, body: dict) -> dict:
    url = f"{GHIDRA_URL}{path}?" + urllib.parse.urlencode({"program": program})
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


def _ok(res: dict) -> bool:
    return bool(res.get("success")
                or str(res.get("status", "")).lower() == "success")


def parse_dump(path: str) -> dict:
    out = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = DUMP_LINE.search(line)
            if m:
                out[m.group(1).lower().lstrip("0").rjust(8, "0")] = m.group(2)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--program", required=True)
    ap.add_argument("--dump", required=True,
                    help="headless log containing PDBNAME lines")
    ap.add_argument("--tag", default=None,
                    help="function tag to attach (e.g. LIB_OPENSSL), so the "
                         "fun-doc selector stops queueing this code")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)

    names = parse_dump(args.dump)
    if not names:
        print(f"no PDBNAME lines in {args.dump}")
        return 2
    print(f"{len(names)} names from the PDB dump")

    live = _get("/list_functions", program=args.program,
                limit=200000).get("functions", [])
    print(f"{len(live)} functions in {args.program}")

    buckets = Counter()
    todo = []
    for f in live:
        addr = str(f["address"]).lower().lstrip("0").rjust(8, "0")
        cur = f.get("name") or ""
        want = names.get(addr)
        if not want:
            buckets["no_pdb_symbol"] += 1
            continue
        if cur == want:
            buckets["already_correct"] += 1
            continue
        if DEFAULT_NAME.match(cur):
            buckets["will_rename"] += 1
            todo.append((addr, cur, want))
        else:
            buckets["documented_preserved"] += 1

    for k in ("already_correct", "will_rename", "documented_preserved",
              "no_pdb_symbol"):
        print(f"  {k:22} {buckets[k]:7}")

    if not args.apply:
        print("\nDRY RUN -- nothing written. Re-run with --apply.")
        for a, cur, want in todo[:15]:
            print(f"    {a}  {cur:26} -> {want}")
        return 0

    renamed = tagged = failed = 0
    for i, (addr, cur, want) in enumerate(todo, 1):
        # strict_mode=false on purpose. NamingConventions enforces OUR authored
        # standard -- PascalCase, a leading verb, a minimum length -- and it is
        # right to. But these names are not ours to style: they are the
        # upstream project's own symbols, and they are ground truth. Strict
        # mode rejected 66 real OpenSSL names on the first pass, including
        # X448, X25519, CMAC_Final and OPENSSL_Uplink, for "missing_specifier".
        res = _post("/rename_function", args.program,
                    {"old_name": addr, "new_name": want, "strict_mode": False})
        if not _ok(res) and "already exists at this address" in str(res):
            _post("/delete_label", args.program,
                  {"address": addr, "name": want})
            res = _post("/rename_function", args.program,
                        {"old_name": addr, "new_name": want,
                         "strict_mode": False})
        if _ok(res):
            renamed += 1
        else:
            failed += 1
            if failed <= 10:
                print(f"    ! rename failed {addr} -> {want}: {str(res)[:120]}")
        if args.tag:
            if _ok(_post("/add_function_tag", args.program,
                         {"function": addr, "tags": args.tag})):
                tagged += 1
        if i % 500 == 0:
            print(f"    ... {i}/{len(todo)}", flush=True)

    print(f"\nrenamed {renamed}, tagged {tagged}, failed {failed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

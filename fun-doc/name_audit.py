"""Duplicate-function-name audit — code-shape based, per the 2026-07-14 rule:
Ghidra names are provisional; ordinal/address comments in D2MOO headers are
unverifiable for PD2. The ONLY trustworthy discriminator is the code itself
(disassembly / decompile) compared against D2MOO implementation bodies.

Phase 1 (this tool):
  * enumerate duplicate-name sets in a binary (from the fun-doc DB),
  * disassemble every member and normalize (strip addresses/branch targets),
  * classify each set: IDENTICAL bodies (benign — same code may honestly share
    a name) vs DIFFERING bodies (>=1 member is misnamed by construction),
  * write a JSON report for the differing sets with each member's disasm
    fingerprint, ready for D2MOO body matching (manual or doc-lane).

Usage (from fun-doc/, venv):
  python name_audit.py                # report to name_audit_report.json
  python name_audit.py --name X       # audit a single name set
"""
import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fun_doc import ghidra_get  # noqa: E402

DB = str(Path(__file__).parent / "state.db")
PROG = "/Mods/PD2-S12/D2Common.dll"
BINARY = "D2Common.dll"
REPORT = Path(__file__).parent / "name_audit_report.json"

_ADDR_RE = re.compile(r"\b(?:0x)?6f[0-9a-f]{6}\b", re.I)
_HEXOFF_RE = re.compile(r"^\s*[0-9a-f]{8}:\s*", re.I | re.M)


def normalized_disasm(address):
    d = ghidra_get("/disassemble_function",
                   params={"address": f"0x{address.lstrip('0x')}", "program": PROG})
    text = str(d or "")
    if not text or "error" in text[:60].lower():
        return None
    text = _HEXOFF_RE.sub("", text)          # strip per-line addresses
    text = _ADDR_RE.sub("<ADDR>", text)      # neutralize absolute addresses
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def dup_sets(name_filter=None):
    db = sqlite3.connect(DB, timeout=30)
    db.row_factory = sqlite3.Row
    q = ("SELECT name, GROUP_CONCAT(address) AS addrs FROM functions_workflow "
         "WHERE binary_name=? AND name IS NOT NULL "
         "AND (library_code IS NULL OR library_code=0) "
         "GROUP BY name HAVING COUNT(*) > 1")
    rows = db.execute(q, (BINARY,)).fetchall()
    out = {}
    for r in rows:
        if name_filter and r["name"] != name_filter:
            continue
        out[r["name"]] = sorted(set(r["addrs"].split(",")))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", help="audit only this function name")
    args = ap.parse_args()

    sets = dup_sets(args.name)
    print(f"duplicate-name sets: {len(sets)}")
    report = {"identical": {}, "differing": {}, "fetch_failed": {}}

    for name, addrs in sorted(sets.items()):
        bodies = {}
        for a in addrs:
            nd = normalized_disasm(a)
            if nd is None:
                report["fetch_failed"].setdefault(name, []).append(a)
                continue
            bodies[a] = nd
        if len(bodies) < 2:
            continue
        unique = {}
        for a, b in bodies.items():
            unique.setdefault(b, []).append(a)
        if len(unique) == 1:
            report["identical"][name] = addrs
            print(f"  IDENTICAL {len(addrs)}x {name}")
        else:
            groups = [{"addresses": v, "disasm": k} for k, v in unique.items()]
            report["differing"][name] = groups
            print(f"  DIFFERING {len(addrs)}x {name} -> {len(unique)} distinct bodies")

    REPORT.write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"\nidentical sets: {len(report['identical'])}  "
          f"differing sets: {len(report['differing'])}  "
          f"fetch failures: {len(report['fetch_failed'])}")
    print(f"report: {REPORT}")


if __name__ == "__main__":
    main()

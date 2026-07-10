#!/usr/bin/env python3
"""Regenerate conformance_protected.json from live Ghidra function tags.

conformance_protected.json has, since it was created, carried a note saying
it's "regenerated from Ghidra tags via scripts/gen_conformance_protected.py
(or the in-scan ingest once landed)" -- but that script never existed until
now. Until this script, the file was maintained by hand.

Source of truth: the four OpenD2 conformance lifecycle tags applied to
Ghidra functions (see OpenD2/docs/EMULATION_CONFORMANCE_PLAN.md Sec 13):
    ANALYZED_RUNTIME | ORACLE | PORTED | PROVEN
Queried live via ghidra-mcp's /search_functions_by_tag endpoint, across
every currently-OPEN program (tags on closed programs aren't queryable --
the MCP plugin only sees the live Program objects Ghidra has open).

Usage:
    python -m scripts.gen_conformance_protected --dry-run   (default; prints a diff)
    python -m scripts.gen_conformance_protected --apply     (writes the file)

Always dry-run first -- if Ghidra doesn't have all the usual PD2-S12
programs open, a --apply would shrink the protected set and silently
un-protect functions the auto-doc worker must never touch.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

import requests

GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "conformance_protected.json"

CONFORMANCE_TAGS = ["ANALYZED_RUNTIME", "ORACLE", "PORTED", "PROVEN"]

# Default scope: the conformance tags are an OpenD2/PD2-S12 concept only --
# every existing conformance_protected.json key lives under this prefix.
# Scanning it (not "every open program") matters for two reasons: (1)
# correctness -- instance_info's `open` flag does NOT mean "queryable via
# /search_functions_by_tag" (confirmed live: D2Game.dll reports open=false
# yet resolves fine and returns real tagged functions -- filtering on
# `open` silently dropped it), so path-prefix is the right scope signal,
# not the open flag; (2) a live instance can have 100+ programs loaded
# across multiple projects/versions -- scanning all of them (4 tag queries
# apiece) is slow and pointless outside the PD2-S12 oracle set.
DEFAULT_PROGRAM_PREFIX = "/Mods/PD2-S12/"


def _get(endpoint, params=None, timeout=15):
    r = requests.get(f"{GHIDRA_HTTP}/{endpoint.lstrip('/')}", params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _matching_programs(prefix):
    """[(name, path), ...] for every program whose path starts with `prefix`
    -- NOT filtered by instance_info's `open` flag (see DEFAULT_PROGRAM_PREFIX
    docstring for why that flag is the wrong signal here)."""
    info = _get("/mcp/instance_info")
    return [
        (p["name"], p["path"])
        for p in info.get("programs", [])
        if p.get("path", "").startswith(prefix)
    ]


def build_protected_keys(prefix=DEFAULT_PROGRAM_PREFIX):
    """Query every program under `prefix` for each conformance tag. Returns
    {key: [tags...]} where key = "<program_path>::<address_no_0x_lowercase>",
    matching fun_doc.load_conformance_protected's expected format."""
    protected: dict[str, list[str]] = {}
    programs = _matching_programs(prefix)
    if not programs:
        print(f"WARNING: no programs found under prefix {prefix!r}", file=sys.stderr)

    for name, path in programs:
        for tag in CONFORMANCE_TAGS:
            try:
                result = _get("/search_functions_by_tag", params={"tag": tag, "program": path, "limit": 1000})
            except requests.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 400:
                    continue  # tag not defined on this program -- normal, not an error
                print(f"  WARNING: {path} tag={tag}: {exc}", file=sys.stderr)
                continue
            except requests.RequestException as exc:
                print(f"  WARNING: {path} tag={tag}: {exc}", file=sys.stderr)
                continue

            for fn in result.get("functions", []):
                addr = str(fn.get("address", "")).lower()
                if addr.startswith("0x"):
                    addr = addr[2:]
                key = f"{path}::{addr}"
                protected.setdefault(key, [])
                if tag not in protected[key]:
                    protected[key].append(tag)

    return protected


def load_existing():
    if not OUTPUT_PATH.exists():
        return {}
    try:
        return json.loads(OUTPUT_PATH.read_text(encoding="utf-8")).get("protected_keys", {})
    except (json.JSONDecodeError, OSError):
        return {}


def diff_summary(old, new):
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(k for k in (set(new) & set(old)) if sorted(new[k]) != sorted(old[k]))
    return added, removed, changed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="Write conformance_protected.json (default: dry-run only)")
    parser.add_argument(
        "--program-prefix", default=DEFAULT_PROGRAM_PREFIX,
        help=f"Only scan programs whose path starts with this (default: {DEFAULT_PROGRAM_PREFIX!r}). "
             "Widen only if conformance tags start getting applied outside PD2-S12.",
    )
    args = parser.parse_args(argv)

    old = load_existing()
    new = build_protected_keys(prefix=args.program_prefix)
    added, removed, changed = diff_summary(old, new)

    programs = _matching_programs(args.program_prefix)
    print(f"Scanned {len(programs)} program(s) under {args.program_prefix!r} for tags: {', '.join(CONFORMANCE_TAGS)}")
    print(f"Current file: {len(old)} protected key(s). Live scan: {len(new)} protected key(s).")
    if added:
        print(f"\n+{len(added)} newly protected:")
        for k in added[:20]:
            print(f"    + {k}  {new[k]}")
        if len(added) > 20:
            print(f"    ... and {len(added) - 20} more")
    if removed:
        print(f"\n-{len(removed)} no longer tagged (would be UN-protected on --apply):")
        for k in removed[:20]:
            print(f"    - {k}  {old[k]}")
        if len(removed) > 20:
            print(f"    ... and {len(removed) - 20} more")
    if changed:
        print(f"\n~{len(changed)} tag set changed:")
        for k in changed[:20]:
            print(f"    ~ {k}  {old[k]} -> {new[k]}")

    if not (added or removed or changed):
        print("\nNo changes.")

    if not args.apply:
        print("\nDry run only -- pass --apply to write conformance_protected.json.")
        if removed:
            print(
                "NOTE: this scan removed protected keys. If any open program is missing "
                "(Ghidra not fully loaded, a program not opened), --apply would silently "
                "un-protect real PROVEN/PORTED functions. Verify all expected programs are "
                "open before applying."
            )
        return 0

    payload = {
        "generated": date.today().isoformat(),
        "note": (
            "Functions carrying an OpenD2 conformance tag in Ghidra (ANALYZED_RUNTIME / "
            "ORACLE / PORTED / PROVEN). These are hand-verified against the live PD2-S12 "
            "process and/or ported to the OpenD2 clone; they are EXCLUDED from the auto-doc "
            "selector so a cheap worker cannot overwrite a runtime-verified plate. Keys are "
            "fun-doc function keys: '<program_path>::<address>'. Regenerated from live Ghidra "
            "tags via scripts/gen_conformance_protected.py --apply. Pinning a function in the "
            "dashboard bypasses this protection for a deliberate re-document."
        ),
        "protected_keys": dict(sorted(new.items())),
    }
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {OUTPUT_PATH} ({len(new)} protected keys).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

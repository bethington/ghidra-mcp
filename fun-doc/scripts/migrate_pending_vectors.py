"""Migrate vectors/_pending/*.json to the binary-namespaced filename scheme.

WHY
---
`write_pending_vectors` keyed its staging file on the function name alone
until 2026-07-30, so DIFFERENT binaries' same-named functions merged into one
file. Running Prove workers on several binaries concurrently made this visible
fast: `shutdown_stub_no_op.json` accumulated 101 vectors from FIVE binaries
(D2Common, Bnclient, Fog, Storm, D2CMP), all under one `fn: "ShutdownStubNoOp"`
key. Stub/CRT names (ShutdownStubNoOp, strcoll, NoOp, UnwindExceptionFrame,
StubReturnZero) recur across nearly every D2 DLL, so this was not exotic.

Those are distinct compiled functions that merely share a name. Merging their
golden values is how false divergences get manufactured.

WHAT IT DOES
------------
Splits every `_pending/<system>.json` into `_pending/<module>_<system>.json`,
attributing each vector by the source binary recorded in its own `note` field
("PD2-S12; src /Mods/PD2-S12/Fog.dll 0x6ff51020"). Module names are normalized
to the path stem, so `/Mods/PD2-S12/D2Common.dll` and a bare `D2Common.dll`
(both spellings exist in the corpus) collapse to `D2Common`.

Vectors whose note has no parseable `src` are NEVER dropped -- they go to
`<system>_unattributed.json` for a human to place.

Originals are MOVED to `_pending/_premigration/`, not deleted.

Idempotent: a file already named `<module>_<system>.json` whose contents all
attribute to `<module>` is left alone.

USAGE
-----
    python fun-doc/scripts/migrate_pending_vectors.py            # dry run
    python fun-doc/scripts/migrate_pending_vectors.py --apply

Run it with the Prove workers STOPPED. A running worker holds the pre-fix
module in memory and will still append un-namespaced, racing the migration.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

OPEND2_REPO = Path(os.environ.get("FUNDOC_OPEND2_REPO", r"C:\Users\benam\source\cpp\OpenD2"))
PENDING_DIR = OPEND2_REPO / "Tools" / "d2conform" / "vectors" / "_pending"
ARCHIVE_DIR = PENDING_DIR / "_premigration"

_SRC_RE = re.compile(r"src\s+(\S+)")
UNATTRIBUTED = "_unattributed"


def module_of(entry):
    """Source-binary stem for one vector entry, or None if unattributable."""
    if not isinstance(entry, dict):
        return None
    m = _SRC_RE.search(entry.get("note", "") or "")
    if not m:
        return None
    # /Mods/PD2-S12/D2Common.dll -> D2Common ; D2Common.dll -> D2Common
    return Path(m.group(1).replace("\\", "/")).stem or None


def plan_file(path):
    """Return (groups, error). groups maps module -> [entries]."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return None, f"unreadable: {e}"
    if not isinstance(data, list):
        return None, "not a JSON list"
    groups = collections.OrderedDict()
    for entry in data:
        mod = module_of(entry) or UNATTRIBUTED
        groups.setdefault(mod, []).append(entry)
    return groups, None


def is_already_migrated(stem, groups):
    """True when the file is already `<module>_<system>` and holds only that
    module's vectors -- re-running must not produce `Fog_Fog_shutdown...`."""
    if len(groups) != 1:
        return False
    only = next(iter(groups))
    return only != UNATTRIBUTED and stem.startswith(f"{only}_")


def target_stem(stem, module):
    if module == UNATTRIBUTED:
        return f"{stem}_unattributed"
    return f"{module}_{stem}"


def merge_into(path, entries, apply):
    """Append entries to path, preserving anything already there."""
    existing = []
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except (json.JSONDecodeError, OSError):
            existing = []
    merged = existing + entries
    if apply:
        path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    return len(existing), len(merged)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="perform the migration (default is a dry run)")
    ap.add_argument("--pending-dir", default=str(PENDING_DIR),
                    help="override the _pending directory (for tests)")
    args = ap.parse_args(argv)

    pending = Path(args.pending_dir)
    archive = pending / "_premigration"
    if not pending.is_dir():
        print(f"ERROR: no such directory: {pending}", file=sys.stderr)
        return 2

    files = sorted(p for p in pending.glob("*.json") if p.is_file())
    print(f"{'APPLY' if args.apply else 'DRY RUN'} -- {len(files)} file(s) in {pending}\n")

    split = already = unattributed = errors = 0
    total_written = 0
    for path in files:
        stem = path.stem
        groups, err = plan_file(path)
        if err:
            print(f"  !! {path.name}: {err}")
            errors += 1
            continue
        if is_already_migrated(stem, groups):
            already += 1
            continue
        if len(groups) == 1 and next(iter(groups)) == UNATTRIBUTED:
            # e.g. the hand-authored treasureclass.json precedent: no `src`
            # note to attribute by, so there is nothing to namespace it with.
            print(f"  ?? {path.name}: no entry carries a parseable `src` -- left in place")
            unattributed += 1
            continue

        multi = len(groups) > 1
        print(f"  {'SPLIT' if multi else 'RENAME'} {path.name} ({sum(len(v) for v in groups.values())} entries)")
        for module, entries in groups.items():
            tstem = target_stem(stem, module)
            tpath = pending / f"{tstem}.json"
            had, now = merge_into(tpath, entries, args.apply)
            note = f" (merged into {had} existing)" if had else ""
            print(f"      -> {tpath.name}: {len(entries)} entries{note}")
            total_written += len(entries)
        if args.apply:
            archive.mkdir(parents=True, exist_ok=True)
            path.replace(archive / path.name)
        else:
            print(f"      -> archive {path.name} to {archive.name}/")
        split += 1

    print(f"\nmigrated={split} already-namespaced={already} "
          f"unattributed-left-in-place={unattributed} errors={errors} "
          f"vectors-rewritten={total_written}")
    if not args.apply:
        print("\n(dry run -- nothing written; re-run with --apply)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

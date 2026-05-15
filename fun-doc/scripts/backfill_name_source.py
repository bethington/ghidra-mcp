#!/usr/bin/env python3
"""Retroactively mark `functions_workflow` rows with their name provenance.

The v5.10 schema adds three columns to `functions_workflow`:

    * name_source         TEXT  'scan' | 'manual' | 'propagation' | 'pdb' | 'archive'
    * name_source_binary  TEXT   the binary the propagated name came from
    * name_confidence     REAL   0.0-1.0, archive/BSim-gate signal

Existing rows ship with `name_source = 'scan'` (the schema default).
This script paints `name_source = 'propagation'` (or any other value)
onto rows whose `name` matches a pattern — the natural way to mark
cross-version propagated names retroactively without rerunning the
propagator.

Typical use
-----------

The dominant propagation artifact is D2-style module prefixes applied
to MSVC CRT/STL/iostream code (see issue #204 for the quantified
~10M-token impact on BH.dll). Mark them in one shot:

    python -m scripts.backfill_name_source \
        --program /Vanilla/1.13d/BH.dll \
        --name-pattern '^(DATATBLS|ROOM|CLIENT|NET|GAME)_' \
        --name-source propagation \
        --source-binary /Vanilla/1.13d/D2Common.dll

Always dry-run first:

    python -m scripts.backfill_name_source --program ... --dry-run

The dry-run prints the count + a 10-row sample so you can sanity-check
the regex catches what you meant. Add `--apply` to commit the writes.

Programmatic use
----------------

If you have a JSON file of `[{"program": ..., "address": ...}, ...]`
records (e.g. exported from a propagation script's per-target log),
feed it via `--from-json`:

    python -m scripts.backfill_name_source \
        --from-json /tmp/propagated_in_session_X.json \
        --name-source propagation \
        --source-binary /Vanilla/1.13d/D2Common.dll \
        --apply

Either ``--name-pattern`` or ``--from-json`` is required; ``--apply``
is required to write. Without ``--apply`` the script is read-only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable

# Resolve the fun-doc/ root so `from storage import ...` works regardless
# of how the script is invoked (python -m scripts.backfill_name_source,
# python fun-doc/scripts/backfill_name_source.py, etc.).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from storage import make_repository, resolve_config  # noqa: E402


_VALID_SOURCES = {"scan", "manual", "propagation", "pdb", "archive"}


def _candidate_rows(
    repo,
    *,
    program: str | None,
    pattern: re.Pattern[str] | None,
    addresses: set[str] | None,
) -> Iterable[dict]:
    """Yield workflow rows that match the selection criteria.

    Streams via `list_functions(program_path=...)`; on programs with
    100k+ functions this iterates rather than buffering.
    """
    rows = repo.list_functions(program_path=program) if program else repo.list_functions()
    for row in rows:
        if pattern is not None:
            name = row.get("name") or ""
            if not pattern.search(name):
                continue
        if addresses is not None:
            if row.get("address") not in addresses:
                continue
        yield row


def _load_from_json(path: Path) -> tuple[str | None, set[str]]:
    """Parse the --from-json file. Returns (program, address-set).

    File shape: ``[{"program": ..., "address": ...}, ...]``. If every
    entry shares the same program, returns it as the first element so
    we can use the indexed list_functions path; otherwise returns None
    and the caller falls back to the whole-table scan.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise SystemExit(f"--from-json: expected a list, got {type(raw).__name__}")
    programs: set[str] = set()
    addresses: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise SystemExit(f"--from-json: every entry must be an object, got {entry!r}")
        addr = entry.get("address")
        prog = entry.get("program")
        if not addr:
            raise SystemExit(f"--from-json: entry missing 'address': {entry!r}")
        addresses.add(str(addr))
        if prog:
            programs.add(str(prog))
    program = programs.pop() if len(programs) == 1 else None
    return program, addresses


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Retroactively mark name_source on functions_workflow rows",
    )
    p.add_argument(
        "--program",
        help="Limit to a single program_path (e.g. /Vanilla/1.13d/BH.dll). "
        "Required unless --from-json supplies a single-program manifest.",
    )
    p.add_argument(
        "--name-pattern",
        help="Regex matched against the function's current name (re.search semantics). "
        "Use this for retroactive cross-version propagation marking — e.g. "
        "'^(DATATBLS|ROOM|CLIENT|NET|GAME)_' to mark every D2-prefixed name.",
    )
    p.add_argument(
        "--from-json",
        type=Path,
        help="JSON file with [{program, address}, ...] entries. Mutually exclusive "
        "with --name-pattern.",
    )
    p.add_argument(
        "--name-source",
        default="propagation",
        choices=sorted(_VALID_SOURCES),
        help="Value to write into name_source. Default: propagation.",
    )
    p.add_argument(
        "--source-binary",
        help="Set name_source_binary to this value (the binary the propagated name "
        "came from). Required when --name-source=propagation, ignored otherwise.",
    )
    p.add_argument(
        "--confidence",
        type=float,
        help="Optional name_confidence (0.0-1.0). Leave unset to keep null "
        "(treated as untrusted by the selector).",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help="Write the updates. Without --apply, the script is read-only.",
    )
    p.add_argument(
        "--sample",
        type=int,
        default=10,
        help="In dry-run mode, print N example rows (default: 10).",
    )
    args = p.parse_args(argv)

    if not args.name_pattern and not args.from_json:
        p.error("one of --name-pattern or --from-json is required")
    if args.name_pattern and args.from_json:
        p.error("--name-pattern and --from-json are mutually exclusive")
    if args.confidence is not None and not (0.0 <= args.confidence <= 1.0):
        p.error("--confidence must be between 0.0 and 1.0")
    if args.name_source == "propagation" and not args.source_binary:
        p.error("--source-binary is required when --name-source=propagation")

    pattern = re.compile(args.name_pattern) if args.name_pattern else None
    addresses: set[str] | None = None
    program = args.program
    if args.from_json:
        json_program, addresses = _load_from_json(args.from_json)
        if json_program and not program:
            program = json_program

    repo = make_repository(resolve_config(None))
    repo.bootstrap_schema()

    rows = list(_candidate_rows(repo, program=program, pattern=pattern, addresses=addresses))
    if not rows:
        print("No rows matched the selection criteria.")
        return 0

    fields = {"name_source": args.name_source}
    if args.source_binary:
        fields["name_source_binary"] = args.source_binary
    if args.confidence is not None:
        fields["name_confidence"] = args.confidence

    print(f"Matched {len(rows)} row(s).")
    print(f"Would set: {fields}")
    print()
    for row in rows[: args.sample]:
        print(
            f"  {row.get('binary_name', '?'):>20}  "
            f"{row.get('address', '?'):>10}  "
            f"{row.get('name', '?')}"
        )
    if len(rows) > args.sample:
        print(f"  ... ({len(rows) - args.sample} more)")

    if not args.apply:
        print("\nDry-run. Re-run with --apply to commit.")
        return 0

    updated = 0
    for row in rows:
        ok = repo.update_function_fields(
            program_path=row["program_path"],
            address=row["address"],
            **fields,
        )
        if ok:
            updated += 1
    print(f"\nWrote {updated} row(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

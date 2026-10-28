"""Every tool the 7.0.0 migration guide removes must map to one that shipped.

7.0.0 is a **clean break**: the old tools are deleted and there are no
backward-compatibility aliases, so the migration guide is the only thing a user
has to get from an old call site to a new one. That makes two failure modes
expensive and invisible:

- A removed tool with **no successor named** is a capability the release
  silently dropped while claiming it did not.
- A removed tool whose named successor **is not in the shipped catalog** sends
  the reader to a 404. The guide was written against the catalog as it stood
  mid-consolidation; nothing re-checked it afterwards, and two endpoints were
  added to the catalog after it was written.

This file reads the guide itself -- not a restatement of it -- and checks both
directions against ``tests/endpoints.json``.

**The parser is the risk, so it is guarded.** A markdown parser that quietly
stops matching would turn this into a test that passes by finding nothing,
which is worse than no test at all. ``MINIMUM_REMOVALS`` and
``MINIMUM_SURVIVORS`` are floors: if the guide is reformatted such that the
parser sees fewer pairs than the consolidation actually performed, the test
fails and says so rather than reporting a vacuous pass.

Runs offline: no Ghidra, no network, no git history (CI checks out shallow).
"""

from __future__ import annotations

import io
import json
import re
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
GUIDE = PROJECT_ROOT / "docs" / "project-management" / "MIGRATION_7.0.0_TOOL_CONSOLIDATION.md"
CATALOG = PROJECT_ROOT / "tests" / "endpoints.json"

#: The consolidation removed 23 tools and introduced 2 new survivor names.
#: Measured against the catalog at the last pre-consolidation commit (272
#: endpoints) versus the shipped one (253): 272 - 23 + 2 = 251, then
#: `/list_shadowed_globals` and `/batch_get_comments` landed later in the same
#: cycle for 253. These floors exist so a parser that stops matching fails
#: loudly instead of passing vacuously.
MINIMUM_REMOVALS = 23
MINIMUM_SURVIVORS = 15

#: An identifier in the guide, with any call signature stripped:
#: ``set_plate_comment(address, comment)`` -> ``set_plate_comment``.
_IDENT = re.compile(r"`(?:~~)?([a-z_][a-z0-9_]*)(?:\([^`]*\))?(?:~~)?`")
_STRUCK = re.compile(r"~~`?([a-z_][a-z0-9_]*)`?~~")


def _catalog_tool_names() -> set[str]:
    """Tool names in the shipped catalog.

    A route's tool name is its path with the leading slash dropped and any
    remaining separators flattened, so ``/mcp/health`` is reachable as both
    ``mcp/health`` and ``mcp_health`` -- the guide spells it the second way.
    """
    catalog = json.loads(io.open(CATALOG, encoding="utf-8").read())
    names: set[str] = set()
    for entry in catalog["endpoints"]:
        bare = entry["path"].lstrip("/")
        names.add(bare)
        names.add(bare.replace("/", "_"))
    return names


class _Removal:
    """One `removed -> survivor` claim, with where in the guide it was made."""

    def __init__(self, removed: str, survivor: str | None, line_no: int, raw: str):
        self.removed = removed
        self.survivor = survivor
        self.line_no = line_no
        self.raw = raw.strip()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{self.removed} -> {self.survivor} @ line {self.line_no}>"


def parse_guide() -> tuple[list[_Removal], list[_Removal]]:
    """``(removals, kept)`` parsed out of the migration guide.

    Two shapes carry the contract:

    1. **Tables** whose header row's first cell is ``REMOVE``. First cell is the
       removed tool, second is the survivor. A row whose removed cell is struck
       through (``~~mcp_health~~``) is an explicit **KEPT** decision, not a
       removal, and is returned separately so it can be checked differently.
    2. **Tier-3 prose**, where a ``### <survivor>`` heading is followed by a
       line beginning ``Unifies`` that lists what it absorbed.
    """
    removals: list[_Removal] = []
    kept: list[_Removal] = []

    lines = io.open(GUIDE, encoding="utf-8").read().splitlines()
    in_removal_table = False
    heading: str | None = None

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()

        if stripped.startswith("### "):
            heading = stripped[4:].split("(")[0].strip().strip("`")
            in_removal_table = False
            continue

        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            first = cells[0] if cells else ""
            # Header row of a removal table.
            if first.upper() == "REMOVE":
                in_removal_table = True
                continue
            # Separator row.
            if set(first) <= set("-: "):
                continue
            if not in_removal_table or len(cells) < 2:
                continue

            struck = _STRUCK.search(cells[0])
            removed_names = _IDENT.findall(cells[0])
            if struck:
                kept.append(_Removal(struck.group(1), None, line_no, stripped))
                continue
            if not removed_names:
                continue
            survivor_names = _IDENT.findall(cells[1])
            survivor = survivor_names[0] if survivor_names else None
            for name in removed_names[:1]:
                removals.append(_Removal(name, survivor, line_no, stripped))
            continue

        in_removal_table = False

        if stripped.startswith("Unifies ") and heading:
            for name in _IDENT.findall(stripped):
                removals.append(_Removal(name, heading, line_no, stripped))

    return removals, kept


REMOVALS, KEPT = parse_guide()
CATALOG_NAMES = _catalog_tool_names()


class TestGuideParserSeesTheWholeContract(unittest.TestCase):
    """Guard the parser before trusting anything it produced."""

    def test_guide_exists(self):
        self.assertTrue(
            GUIDE.is_file(),
            f"{GUIDE} is missing. 7.0.0 is a clean break with no aliases, so "
            f"this file is the only migration path a user has.",
        )

    def test_enough_removals_were_parsed(self):
        self.assertGreaterEqual(
            len(REMOVALS),
            MINIMUM_REMOVALS,
            f"Parsed only {len(REMOVALS)} removals from the migration guide, "
            f"but the consolidation removed {MINIMUM_REMOVALS} tools. Either "
            f"the guide was reformatted and parse_guide() no longer sees its "
            f"tables, or rows were deleted. A parser that matches nothing "
            f"makes this whole file a vacuous pass, which is the failure this "
            f"assertion exists to prevent.\nParsed: "
            f"{sorted(r.removed for r in REMOVALS)}",
        )

    def test_enough_survivors_were_parsed(self):
        survivors = {r.survivor for r in REMOVALS if r.survivor}
        self.assertGreaterEqual(
            len(survivors),
            MINIMUM_SURVIVORS,
            f"Parsed only {len(survivors)} distinct survivors: "
            f"{sorted(survivors)}",
        )

    def test_no_removal_is_parsed_twice_with_different_survivors(self):
        by_name: dict[str, set[str | None]] = {}
        for r in REMOVALS:
            by_name.setdefault(r.removed, set()).add(r.survivor)
        conflicting = {k: sorted(map(str, v)) for k, v in by_name.items() if len(v) > 1}
        self.assertEqual(
            conflicting,
            {},
            f"The guide names two different survivors for the same removed "
            f"tool: {conflicting}. A reader cannot act on that.",
        )


class TestEveryRemovedToolHasALivingSuccessor(unittest.TestCase):
    """The two directions that matter to someone migrating a call site."""

    def test_every_removal_names_a_survivor(self):
        orphans = [
            f"{r.removed} (line {r.line_no}): {r.raw[:110]}"
            for r in REMOVALS
            if not r.survivor
        ]
        self.assertEqual(
            orphans,
            [],
            "Removed with no successor named. Either the capability was "
            "genuinely dropped -- which 7.0.0 claims it was not, and which "
            "belongs in the CHANGELOG as a removal -- or the row is a "
            "documentation error:\n  " + "\n  ".join(orphans),
        )

    def test_every_survivor_is_in_the_shipped_catalog(self):
        missing = sorted(
            {
                f"{r.survivor}  (successor of {r.removed}, line {r.line_no})"
                for r in REMOVALS
                if r.survivor and r.survivor not in CATALOG_NAMES
            }
        )
        self.assertEqual(
            missing,
            [],
            "The guide points at a successor that is not in "
            "tests/endpoints.json. Anyone following this row lands on a 404:"
            "\n  " + "\n  ".join(missing),
        )

    def test_every_removed_tool_is_actually_gone(self):
        """A 'removed' tool still in the catalog means the guide is wrong.

        Cheap to check and it closes the other half: a guide that tells people
        to rewrite a call site that did not need rewriting costs them exactly
        as much as one that misses a rewrite.
        """
        still_present = sorted(
            {
                f"{r.removed} (line {r.line_no})"
                for r in REMOVALS
                if r.removed in CATALOG_NAMES
            }
        )
        self.assertEqual(
            still_present,
            [],
            "Documented as REMOVED but still in tests/endpoints.json:\n  "
            + "\n  ".join(still_present),
        )


class TestExplicitlyKeptRowsAreStillKept(unittest.TestCase):
    """A struck-out row is a decision, and decisions can go stale too.

    ``mcp_health`` was proposed for removal as a duplicate of
    ``/check_connection`` and then explicitly kept: the two answer different
    questions, and `/mcp/health` has real consumers. The row records that. If
    the endpoint later disappears, the row becomes a lie about why -- so the
    row is checked, not just read.
    """

    def test_kept_rows_were_parsed(self):
        self.assertTrue(
            KEPT,
            "No struck-out KEPT row found in the migration guide. There was "
            "one (mcp_health); if it was deleted, delete this test with it.",
        )

    def test_kept_tools_are_in_the_catalog(self):
        missing = [k.removed for k in KEPT if k.removed not in CATALOG_NAMES]
        self.assertEqual(
            missing,
            [],
            f"The guide says these were explicitly KEPT, but they are not in "
            f"tests/endpoints.json: {missing}",
        )

    def test_kept_rows_say_kept(self):
        """The strike-through alone is ambiguous; the row must say why."""
        for k in KEPT:
            self.assertIn(
                "KEPT",
                k.raw.upper(),
                f"Line {k.line_no} strikes out {k.removed} without saying it "
                f"was kept. A strike-through on its own reads as 'removed':"
                f"\n  {k.raw[:160]}",
            )


if __name__ == "__main__":
    unittest.main()

"""Every tool removed since 6.0.0 must be named in the 7.0.0 migration guide.

The guide is what a 6.0.0 user reads to rewrite their calls. Before this test
existed it covered the first consolidation pass and nothing after it: three
later passes removed 38 more tools -- ``decompile_function``,
``list_functions``, ``search_functions``, ``get_version`` and ``health`` among
them, the most-called tools in the catalog -- and the guide named none of
them. A PR description even said "the migration guide and CHANGELOG list each
one". Nothing compared the guide with the catalog, so the gap was invisible
until someone diffed them by hand on the way to rc.2.

The baseline is a frozen fixture, not ``git show v6.0.0:...``, because CI
clones are shallow and carry no tags; a test that skips when the tag is
missing is a test that never runs where it matters.

A tool counts as named when its path appears in backticks in the guide,
either as the route (``list_exports``, ``project/info``) or as the bridge tool
name with ``/`` replaced by ``_`` (``debugger_step_into``), followed by a
closing backtick or an opening parenthesis.

Runs offline: no Ghidra, no network, no build.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
GUIDE = PROJECT_ROOT / "docs" / "project-management" / "MIGRATION_7.0.0_TOOL_CONSOLIDATION.md"
BASELINE = PROJECT_ROOT / "tests" / "unit" / "fixtures" / "catalog_v6.0.0_paths.json"
CATALOG = PROJECT_ROOT / "tests" / "endpoints.json"


def _catalog_paths() -> set[str]:
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    entries = data["endpoints"] if isinstance(data, dict) else data
    return {e["path"].lstrip("/") for e in entries}


def _baseline_paths() -> list[str]:
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    return [p.lstrip("/") for p in data["paths"]]


def _named(guide: str, path: str) -> bool:
    for spelling in {path, path.replace("/", "_")}:
        if re.search(r"`/?" + re.escape(spelling) + r"[`(]", guide):
            return True
    return False


class MigrationGuideCoverageTest(unittest.TestCase):
    def test_baseline_is_the_frozen_6_0_0_catalog(self):
        data = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertEqual(data["tag"], "v6.0.0")
        self.assertEqual(data["count"], len(data["paths"]))
        self.assertEqual(data["count"], 272, "the 6.0.0 catalog had 272 tools; the fixture must not be edited")

    def test_every_removed_tool_is_named_in_the_guide(self):
        guide = GUIDE.read_text(encoding="utf-8")
        current = _catalog_paths()
        removed = [p for p in _baseline_paths() if p not in current]
        self.assertGreater(len(removed), 0, "nothing removed since 6.0.0 -- the baseline or catalog failed to load")
        missing = [p for p in removed if not _named(guide, p)]
        self.assertEqual(
            missing,
            [],
            f"{len(missing)} tool(s) removed since 6.0.0 have no row in {GUIDE.name}. "
            "Add each to a REMOVE | SURVIVOR | Transform table so a 6.0.0 user can migrate.",
        )

    def test_guide_states_the_shipped_count(self):
        guide = GUIDE.read_text(encoding="utf-8")
        m = re.search(r"shipped catalog is \*\*(\d+)\*\*", guide)
        self.assertIsNotNone(m, "the guide's 'shipped catalog is **N**' sentence was reworded; update this pattern")
        self.assertEqual(int(m.group(1)), len(_catalog_paths()))


if __name__ == "__main__":
    unittest.main()

"""Every route the release-regression tier calls must exist in the catalog.

``deploy --test release`` is the gate a release cannot publish without, and it
is driven by two things: the benchmark fixture's YAML baselines
(``tests/fixtures/benchmark/regression/*.yaml``) and the request helpers in
``tools/setup/ghidra.py``. When the 7.0.0 consolidation removed
``list_functions``, ``search_functions``, ``decompile_function``,
``get_function_callees`` and the eight ``list_*`` inventories, both kept
calling them: nine fixture assertions and four helper calls named routes the
server no longer registers. Nothing runs that tier in CI -- it needs a live
Ghidra GUI -- so the first sign would have been a red gate on release day,
reading like a server regression instead of a stale test.

This checks the names offline against ``tests/endpoints.json``. It does not
check response shapes; that still needs the live tier.

Runs offline: no Ghidra, no network, no build.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REGRESSION_DIR = PROJECT_ROOT / "tests" / "fixtures" / "benchmark" / "regression"
GHIDRA_PY = PROJECT_ROOT / "tools" / "setup" / "ghidra.py"
CATALOG = PROJECT_ROOT / "tests" / "endpoints.json"

# Routes the helpers call that are served by the HTTP server itself rather than
# registered as catalog tools.
SERVER_ROUTES = {"mcp/schema", "mcp/instance_info"}


def _bridge_static_tools() -> set[str]:
    """Bridge-side tools (check_tools, load_tool_group, ...): real tools, not HTTP routes."""
    import sys
    sys.path.insert(0, str(PROJECT_ROOT / "python"))
    from bridge_mcp_ghidra.config import STATIC_TOOL_NAMES
    return set(STATIC_TOOL_NAMES)


def _catalog() -> set[str]:
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    entries = data["endpoints"] if isinstance(data, dict) else data
    return {e["path"].lstrip("/") for e in entries}


def _yaml_endpoints() -> list[tuple[str, str, str]]:
    found = []
    for path in sorted(REGRESSION_DIR.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for section in ("endpoint_smoke", "skipped"):
            for entry in doc.get(section) or []:
                found.append((path.name, section, str(entry["endpoint"]).lstrip("/")))
    return found


def _helper_routes() -> list[tuple[int, str]]:
    """Route literals passed to the request helpers in tools/setup/ghidra.py."""
    text = GHIDRA_PY.read_text(encoding="utf-8")
    routes = []
    call = re.compile(r'_(?:mcp_request|bench_get|ensure_mcp_ok)\([^)]*?"(/[a-z0-9_/]+)"', re.S)
    tuple_form = re.compile(r'\(\s*"(/[a-z0-9_/]+)"\s*,\s*\{')
    for rx in (call, tuple_form):
        for m in rx.finditer(text):
            routes.append((text.count("\n", 0, m.start()) + 1, m.group(1).lstrip("/")))
    return routes


class RegressionEndpointsExistTest(unittest.TestCase):
    def test_fixture_endpoints_are_in_the_catalog(self):
        catalog = _catalog()
        entries = _yaml_endpoints()
        self.assertGreater(len(entries), 20, "found too few fixture entries -- did the YAML layout change?")
        known = catalog | SERVER_ROUTES | _bridge_static_tools()
        missing = [f"{f} [{s}] /{e}" for f, s, e in entries if e not in known]
        self.assertEqual(missing, [], "fixture names routes the server no longer registers")

    def test_helper_routes_are_in_the_catalog(self):
        catalog = _catalog()
        routes = _helper_routes()
        self.assertGreater(len(routes), 5, "found too few helper calls -- did the call pattern change?")
        missing = [f"ghidra.py:{line} /{r}" for line, r in routes if r not in catalog and r not in SERVER_ROUTES]
        self.assertEqual(missing, [], "tools/setup/ghidra.py calls routes the server no longer registers")

    def test_required_tool_sets_are_in_the_catalog(self):
        import importlib
        ghidra = importlib.import_module("tools.setup.ghidra")
        catalog = _catalog()
        for name in ("SMOKE_REQUIRED_TOOLS", "RELEASE_CONTRACT_TOOLS"):
            tools = getattr(ghidra, name)
            missing = sorted(t for t in tools if t.lstrip("/") not in catalog)
            self.assertEqual(missing, [], f"{name} requires tools the catalog does not have")


if __name__ == "__main__":
    unittest.main()

"""Render the README's API Reference section from tests/endpoints.json.

The endpoint catalog is the single source of truth for the MCP tool inventory.
This module renders the tool listing between the BEGIN/END markers in
README.md so the section can be regenerated instead of hand-edited:

    python -m tools.gen_readme_api_reference           # check (exit 1 on drift)
    python -m tools.gen_readme_api_reference --write   # rewrite README section

tests/unit/test_project_consistency.py calls render_api_reference() and fails
when the README drifts from the catalog, so `@McpTool` additions that pass
EndpointsJsonParityTest also force a README refresh.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENDPOINTS_JSON = PROJECT_ROOT / "tests" / "endpoints.json"
README = PROJECT_ROOT / "README.md"

BEGIN_MARKER = "<!-- BEGIN GENERATED API REFERENCE (tools/gen_readme_api_reference.py) -->"
END_MARKER = "<!-- END GENERATED API REFERENCE -->"

# Catalog category -> (README heading, blurb). Order here is presentation order;
# categories missing from this map are appended alphabetically with a generic
# heading so new catalog categories can never be silently dropped.
CATEGORY_SECTIONS: dict[str, tuple[str, str]] = {
    "program": ("Program & Session Management", ""),
    "project": ("Project Organization", ""),
    "headless": (
        "Headless Project & Program Lifecycle",
        "Available on the standalone headless server (`GhidraMCPHeadlessServer`).",
    ),
    "listing": ("Listing & Enumeration", ""),
    "getter": ("Context & Lookups", ""),
    "search": ("Search", ""),
    "decompile": ("Decompilation & Disassembly", ""),
    "function": ("Function Tags, Variables & Attributes", ""),
    "xref": ("Cross-References", ""),
    "datatype": ("Data Types & Structures", ""),
    "rename": ("Renaming & Labels", ""),
    "comment": ("Comments & Bookmarks", ""),
    "analysis": ("Analysis", ""),
    "documentation": ("Cross-Binary Documentation & Archive", ""),
    "utility": ("Utility & Documentation Transfer", ""),
    "emulation": ("Emulation", ""),
    "script": ("Scripting", ""),
    "server": ("Ghidra Server & Version Control", ""),
    "debugger": (
        "Debugger (Ghidra TraceRmi — GUI only)",
        "On Windows hosts where the bridge's WinDbg debugger proxy is active"
        " (`GHIDRA_DEBUGGER_URL`), colliding names get a `_2` suffix"
        " (e.g. `debugger_status_2`).",
    ),
    "system": ("System", ""),
}

# Bridge-level static tools (python/bridge_mcp_ghidra/static_tools.py) are not
# endpoint-backed, so they are not in the catalog; descriptions live here.
# config.MANAGEMENT_TOOL_NAMES is cross-checked at render time so a new static
# tool cannot be silently omitted.
STATIC_TOOL_DESCRIPTIONS: dict[str, str] = {
    "list_instances": "Discover running Ghidra MCP instances (UDS + TCP port scan)",
    "connect_instance": "Connect the bridge to a specific Ghidra instance",
    "list_tool_groups": "List tool groups and their load state",
    "load_tool_group": "Register a tool group's dynamic tools with the MCP client",
    "unload_tool_group": "Unregister a tool group's dynamic tools",
    "check_tools": "Report which tools are currently registered and callable",
    "search_tools": "Search the full tool catalog by keyword",
    "import_file": "Import a binary from disk into the current project and open it",
}


def _tool_name(path: str) -> str:
    """Mirror the bridge's sanitize_tool_name for catalog paths (`/a/b` -> `a_b`)."""
    return re.sub(r"[^a-z0-9_]", "_", path.lstrip("/").lower())


def _first_sentence(description: str) -> str:
    sentence = description.split(". ")[0].strip()
    return sentence.rstrip(".")


def render_api_reference(endpoints_json: Path = ENDPOINTS_JSON) -> str:
    """Render the generated portion of the README API Reference section."""
    catalog = json.loads(endpoints_json.read_text(encoding="utf-8"))
    endpoints = catalog["endpoints"]
    total = catalog["total_endpoints"]

    by_category: dict[str, list[dict]] = {}
    for endpoint in endpoints:
        by_category.setdefault(endpoint["category"], []).append(endpoint)

    ordered = [cat for cat in CATEGORY_SECTIONS if cat in by_category]
    ordered += sorted(set(by_category) - set(CATEGORY_SECTIONS))

    try:
        sys.path.insert(0, str(PROJECT_ROOT / "python"))
        from bridge_mcp_ghidra.config import MANAGEMENT_TOOL_NAMES
    finally:
        sys.path.pop(0)
    static_names = sorted(MANAGEMENT_TOOL_NAMES)

    lines = [
        BEGIN_MARKER,
        "",
        f"{total} MCP tools backed by HTTP endpoints, grouped by catalog category. "
        "Generated from [tests/endpoints.json](tests/endpoints.json) by "
        "`python -m tools.gen_readme_api_reference --write`; the live schema at "
        "`/mcp/schema` is authoritative at runtime. Usage patterns: "
        "[docs/prompts/TOOL_USAGE_GUIDE.md](docs/prompts/TOOL_USAGE_GUIDE.md).",
    ]

    for category in ordered:
        heading, blurb = CATEGORY_SECTIONS.get(
            category, (f"{category.title()} (uncategorized)", "")
        )
        lines += ["", f"### {heading}", ""]
        if blurb:
            lines += [blurb, ""]
        for endpoint in sorted(by_category[category], key=lambda e: _tool_name(e["path"])):
            lines.append(
                f"- `{_tool_name(endpoint['path'])}` - {_first_sentence(endpoint['description'])}"
            )

    lines += [
        "",
        "### Bridge Static Tools",
        "",
        "Defined in the Python bridge itself (instance discovery, tool-group "
        "management); always available even before a Ghidra connection. The "
        "bridge also proxies 22 `debugger_*` WinDbg tools when "
        "`GHIDRA_DEBUGGER_URL` points at the standalone debugger server.",
        "",
    ]
    for name in static_names:
        lines.append(f"- `{name}` - {STATIC_TOOL_DESCRIPTIONS.get(name, name)}")

    lines += ["", END_MARKER]
    return "\n".join(lines)


def readme_section(readme_text: str) -> str:
    """Extract the currently committed generated block from README text."""
    match = re.search(
        re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER), readme_text, re.S
    )
    if not match:
        raise ValueError(f"README.md is missing the {BEGIN_MARKER} block")
    return match.group(0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="rewrite the README section in place"
    )
    args = parser.parse_args(argv)

    rendered = render_api_reference()
    readme_text = README.read_text(encoding="utf-8")
    current = readme_section(readme_text)

    if current == rendered:
        print("README API Reference is up to date.")
        return 0
    if args.write:
        # newline="\n": README.md is committed with LF; the platform default
        # would rewrite the whole file as CRLF on Windows.
        README.write_text(
            readme_text.replace(current, rendered), encoding="utf-8", newline="\n"
        )
        print("README API Reference regenerated.")
        return 0
    print(
        "README API Reference is stale. Run:\n"
        "  python -m tools.gen_readme_api_reference --write"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

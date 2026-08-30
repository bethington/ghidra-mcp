"""Audit ``tests/endpoints.json`` categories against the ``@McpTool`` annotations.

The catalog at ``tests/endpoints.json`` records a ``category`` per endpoint, and
CLAUDE.md points at it as the authoritative tool inventory. But the category the
bridge *actually* groups by comes from ``/mcp/schema``, which the running plugin
generates from the annotations — never from the catalog. Nothing compared the
two, so they were free to disagree, and they did.

This script reproduces the runtime category resolution by reading the Java
sources directly (no Maven, no Ghidra, no JVM), so the drift is measurable from
a clean checkout::

    python -m tools.audit_endpoint_categories            # human-readable report
    python -m tools.audit_endpoint_categories --json     # machine-readable
    python -m tools.audit_endpoint_categories --quiet    # exit code only

Exit code is 0 when catalog and annotations agree, 1 when they drift.

Resolution rule mirrored from ``AnnotationScanner.scanService``::

    category = @McpTool.category            if non-empty
             = @McpToolGroup.value          if the class carries one
             = simpleName.toLowerCase().replaceAll("service$", "")

Only classes that ``ServerManager`` actually hands to the scanner count as
scanned; a class carrying ``@McpTool`` methods that nobody registers is reported
separately as unscanned rather than silently folded into the totals.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# Services handed to AnnotationScanner. Mirrors GhidraMCPPlugin's scanner
# construction plus the headless server's, i.e. the same union the offline
# ServiceFactory.buildAllServices() builds; kept as simple class names so a newly
# registered service shows up as a diff in one obvious place.
SCANNED_SERVICES = (
    "ListingService",
    "FunctionService",
    "CommentService",
    "SymbolLabelService",
    "XrefCallGraphService",
    "DataTypeService",
    "AnalysisService",
    "DocumentationHashService",
    "MalwareSecurityService",
    "ProgramScriptService",
    "EmulationService",
    "HeadlessManagementService",
    "DebuggerService",
    "PromptPolicyService",
)

# Hand-registered routes get their descriptors from ManualToolDescriptors, which
# is published in /mcp/schema alongside the scanned ones. Its categories are
# therefore just as real at runtime as any @McpToolGroup value.
_MANUAL_ADD_RE = re.compile(
    r'add\(m,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"',
)

_TOOL_GROUP_RE = re.compile(
    r"@McpToolGroup\s*\(\s*(?:value\s*=\s*)?\"([^\"]*)\"",
)

# @McpTool(...) up to the closing paren of the annotation. Annotation bodies here
# never contain a nested paren outside a string literal, so a non-greedy scan to
# the first ')' that is not inside a quoted string is sufficient and exact.
_TOOL_START_RE = re.compile(r"@McpTool\s*\(")

_PATH_RE = re.compile(r"\bpath\s*=\s*\"([^\"]*)\"")
_METHOD_RE = re.compile(r"\bmethod\s*=\s*\"([^\"]*)\"")
_CATEGORY_RE = re.compile(r"\bcategory\s*=\s*\"([^\"]*)\"")


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _strip_line_comments(text: str) -> str:
    """Blank out comment lines so a documented annotation is not scanned.

    Covers ``//`` and javadoc continuation lines (``*``). The latter matters:
    ``McpTool.java``'s own javadoc contains a worked ``@McpTool(path =
    "/list_methods", ...)`` example that would otherwise be counted as a real
    endpoint. Real annotations never have a line beginning with ``*``.
    """
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*"):
            out.append("")
        else:
            out.append(line)
    return "\n".join(out)


def _annotation_body(text: str, open_paren: int) -> tuple[str, int]:
    """Return the text inside the annotation's parens and the index past them."""
    depth = 0
    i = open_paren
    in_str = False
    escaped = False
    while i < len(text):
        ch = text[i]
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i], i + 1
        i += 1
    raise ValueError("unterminated @McpTool annotation")


def _default_category(simple_name: str) -> str:
    """Java's ``simpleName.toLowerCase().replaceAll("service$", "")``."""
    return re.sub(r"service$", "", simple_name.lower())


def scan_annotations(src_root: Path) -> tuple[dict[str, dict], list[dict]]:
    """Scan Java sources for ``@McpTool`` endpoints.

    Returns ``(scanned_by_path, unscanned)`` where ``scanned_by_path`` covers the
    services the plugin registers and ``unscanned`` lists annotated endpoints in
    classes nobody hands to the scanner.
    """
    scanned: dict[str, dict] = {}
    unscanned: list[dict] = []

    for java in sorted(src_root.rglob("*.java")):
        raw = java.read_text(encoding="utf-8")
        if "@McpTool(" not in raw:
            continue
        text = _strip_line_comments(raw)
        simple_name = java.stem
        group = _TOOL_GROUP_RE.search(text)
        group_category = group.group(1) if group else _default_category(simple_name)

        pos = 0
        while True:
            m = _TOOL_START_RE.search(text, pos)
            if m is None:
                break
            body, pos = _annotation_body(text, m.end() - 1)
            path_m = _PATH_RE.search(body)
            if path_m is None:
                # @McpTool with no path= is the annotation's own javadoc example.
                continue
            cat_m = _CATEGORY_RE.search(body)
            explicit = cat_m.group(1) if cat_m else ""
            method_m = _METHOD_RE.search(body)
            entry = {
                "path": path_m.group(1),
                "method": method_m.group(1) if method_m else "GET",
                "category": explicit if explicit else group_category,
                "explicit_category": explicit,
                "group_category": group_category,
                "source": java.as_posix(),
                "class": simple_name,
            }
            if simple_name in SCANNED_SERVICES:
                scanned[entry["path"]] = entry
            else:
                unscanned.append(entry)
    return scanned, unscanned


def scan_manual_descriptors(src_root: Path) -> dict[str, str]:
    """Path -> category for every hand-registered route in ManualToolDescriptors."""
    java = src_root / "core" / "ManualToolDescriptors.java"
    if not java.exists():
        return {}
    text = _strip_line_comments(java.read_text(encoding="utf-8"))
    return {m.group(1): m.group(3) for m in _MANUAL_ADD_RE.finditer(text)}


def load_catalog(catalog_path: Path) -> dict[str, dict]:
    data = json.loads(catalog_path.read_text(encoding="utf-8"))
    return {e["path"]: e for e in data["endpoints"]}


def audit(repo: Path | None = None) -> dict:
    repo = repo or _repo_root()
    src_root = repo / "src" / "main" / "java" / "com" / "xebyte"
    scanned, unscanned = scan_annotations(src_root)
    manual = scan_manual_descriptors(src_root)
    catalog = load_catalog(repo / "tests" / "endpoints.json")

    # Every group name /mcp/schema can actually emit.
    runtime_groups = {a["category"] for a in scanned.values()} | set(manual.values())

    drift = []
    for path, ann in sorted(scanned.items()):
        cat_entry = catalog.get(path)
        if cat_entry is None:
            continue  # presence is EndpointsJsonParityTest's job
        catalog_cat = cat_entry.get("category", "")
        if catalog_cat != ann["category"]:
            drift.append(
                {
                    "path": path,
                    "catalog": catalog_cat,
                    "annotation": ann["category"],
                    "explicit_category": ann["explicit_category"],
                    "group_category": ann["group_category"],
                    "class": ann["class"],
                    # Does the catalog's category even name a loadable group?
                    "catalog_group_exists": catalog_cat in runtime_groups,
                }
            )

    manual_drift = []
    for path, cat in sorted(manual.items()):
        entry = catalog.get(path)
        if entry is not None and entry.get("category", "") != cat:
            manual_drift.append(
                {"path": path, "catalog": entry.get("category", ""), "manual": cat}
            )

    hand_registered = sorted(set(catalog) - set(scanned))
    catalog_only_groups = sorted(
        {e.get("category", "") for e in catalog.values()} - runtime_groups
    )
    return {
        "scanned_endpoints": len(scanned),
        "catalog_endpoints": len(catalog),
        "manual_descriptors": len(manual),
        "hand_registered_only": hand_registered,
        "unscanned_annotated": unscanned,
        "runtime_groups": sorted(runtime_groups),
        "catalog_only_groups": catalog_only_groups,
        "drift_count": len(drift),
        "drift": drift,
        "manual_drift": manual_drift,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="emit the raw audit as JSON")
    ap.add_argument("--quiet", action="store_true", help="exit code only, no output")
    args = ap.parse_args(argv)

    result = audit()

    if args.json:
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif not args.quiet:
        print(f"annotation-scanned endpoints  : {result['scanned_endpoints']}")
        print(f"manual (hand-registered) descs: {result['manual_descriptors']}")
        print(f"catalog entries               : {result['catalog_endpoints']}")
        print(f"annotated but never scanned   : {len(result['unscanned_annotated'])}")
        for e in result["unscanned_annotated"]:
            print(f"    {e['path']}  ({e['class']}, category={e['category']!r})")
        print(f"\nruntime tool groups ({len(result['runtime_groups'])}): "
              f"{', '.join(result['runtime_groups'])}")
        if result["catalog_only_groups"]:
            print("catalog categories that name NO runtime group: "
                  f"{', '.join(result['catalog_only_groups'])}")
        print()
        print(f"CATEGORY DRIFT (scanned): {result['drift_count']}")
        if result["drift"]:
            pairs = Counter((d["catalog"], d["annotation"]) for d in result["drift"])
            print("\n  by (catalog -> annotation):")
            for (cat, ann), n in pairs.most_common():
                print(f"    {n:>4}  {cat or '<empty>'} -> {ann}")
            print("\n  per endpoint:")
            for d in result["drift"]:
                origin = "explicit" if d["explicit_category"] else "group"
                exists = "" if d["catalog_group_exists"] else "  [no such group]"
                print(
                    f"    {d['path']:<44} catalog={d['catalog']:<14}"
                    f" annotation={d['annotation']:<12} ({origin}, {d['class']}){exists}"
                )
        if result["manual_drift"]:
            print(f"\nCATEGORY DRIFT (hand-registered): {len(result['manual_drift'])}")
            for d in result["manual_drift"]:
                print(f"    {d['path']:<44} catalog={d['catalog']:<14} manual={d['manual']}")

    return 1 if (result["drift_count"] or result["manual_drift"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Guidance strings must only reference things that actually exist.

The Java services embed operator/model-facing guidance in their responses:
`recommendations`, `remediation_actions`, and error-message "try this instead"
hints. Those strings name MCP tools and documentation files. Nothing typechecks
them, so they rot silently -- and when they rot, a model following them calls a
tool that 404s or opens a doc that isn't there.

This is not hypothetical. Found live on 2026-07-25 by hand-testing through MCP:

  * `get_disassembly()`                        -- never a registered tool
                                                  (the tool is disassemble_function)
  * `run_script()`                             -- route deleted in 6.0.0 as an
                                                  ungated code-exec hole
  * `FUNCTION_DOC_WORKFLOW_V4.md`   x6         -- repo ships V5
  * `PLATE_COMMENT_FORMAT_GUIDE.md` x2         -- real file is
                                                  docs/PLATE_COMMENT_BEST_PRACTICES.md

Offline tier: reads tests/endpoints.json + the repo tree. No Ghidra required.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
JAVA_ROOT = REPO_ROOT / "src" / "main" / "java"
CATALOG = REPO_ROOT / "tests" / "endpoints.json"

# Bridge-side static tools: real callable tools, but not in the Java catalog.
STATIC_TOOLS = {
    "list_instances", "connect_instance", "list_tool_groups", "load_tool_group",
    "unload_tool_group", "check_tools", "search_tools", "import_file",
}

# `name()` inside a string literal that is Java API or prose, not a tool call.
# Kept explicit rather than heuristic so a genuinely missing tool can't hide
# behind a loose pattern.
NOT_TOOL_CALLS = {
    # java.lang / collections / streams
    "length", "stream", "count", "start", "value", "error", "trace", "toString",
    "hashCode", "equals", "clone", "close", "flush", "size", "isEmpty", "keySet",
    "values", "entrySet", "iterator", "build", "run", "call", "apply", "accept",
    # annotation accessors (McpTool / Param / McpToolGroup)
    "description", "method", "category", "required", "display", "describe",
    "aliases", "defaultValue", "paramType", "source",
    # Ghidra / domain API referenced in prose
    "checkin", "checkout", "undoCheckout", "getEntryPoint", "getName",
}

TOOL_CALL_RE = re.compile(r"\b([a-z][a-z0-9_]{3,})\(\)")
# Only .md paths; source-file references (.cpp/.java) are examples, not repo files.
DOC_RE = re.compile(r"\b((?:docs/)?[A-Za-z0-9_./-]*[A-Z][A-Z0-9_]{3,}[A-Za-z0-9_./-]*\.md)\b")


def _string_literals(line: str) -> str:
    """Concatenated contents of double-quoted literals on a line."""
    return " ".join(re.findall(r'"((?:[^"\\]|\\.)*)"', line))


def _java_files() -> list[Path]:
    return sorted(JAVA_ROOT.rglob("*.java"))


@pytest.fixture(scope="module")
def known_tools() -> set[str]:
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    endpoints = data["endpoints"] if isinstance(data, dict) else data
    names: set[str] = set()
    for e in endpoints:
        path = e["path"].lstrip("/")
        names.add(path)
        names.add(path.replace("/", "_"))
    return names | STATIC_TOOLS


def test_guidance_strings_reference_only_real_tools(known_tools):
    """A `some_tool()` mention inside a Java string must be a registered tool."""
    offenders: list[str] = []
    for f in _java_files():
        rel = f.relative_to(REPO_ROOT).as_posix()
        for lineno, line in enumerate(f.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            literal = _string_literals(line)
            if not literal:
                continue
            for m in TOOL_CALL_RE.finditer(literal):
                name = m.group(1)
                if name in NOT_TOOL_CALLS or name in known_tools:
                    continue
                # Heuristic guard: only flag snake_case, which is how tools are
                # named. camelCase in prose is a Java method.
                if "_" not in name:
                    continue
                offenders.append(f"  {rel}:{lineno}  references {name}() -- not a registered tool")

    assert not offenders, (
        "Java guidance strings name tools that do not exist. A model following "
        "this guidance will call a tool that 404s.\n" + "\n".join(sorted(set(offenders)))
    )


def test_guidance_strings_reference_only_real_docs():
    """A doc filename mentioned in guidance must exist somewhere in the repo."""
    on_disk = {p.name for p in REPO_ROOT.rglob("*.md")}
    offenders: list[str] = []
    for f in _java_files():
        rel = f.relative_to(REPO_ROOT).as_posix()
        for lineno, line in enumerate(f.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            literal = _string_literals(line)
            if not literal:
                continue
            for m in DOC_RE.finditer(literal):
                ref = m.group(1)
                if Path(ref).name in on_disk:
                    continue
                offenders.append(f"  {rel}:{lineno}  references {ref} -- no such file in the repo")

    assert not offenders, (
        "Java guidance strings point at documentation that does not exist.\n"
        + "\n".join(sorted(set(offenders)))
    )


def test_remediation_action_tools_are_real(known_tools):
    """`"tool", "<name>"` pairs in remediation_actions must be real tools.

    These are the machine-readable half of the guidance -- a model reads
    `action.tool` and calls it directly, so a stale name here is worse than
    stale prose.
    """
    pair_re = re.compile(r'"tool",\s*"([a-z][a-z0-9_]*)"')
    # "none" is a deliberate sentinel: the deduction is structural, no tool
    # applies, estimated_gain is 0. Not a stale reference.
    sentinels = {"none"}
    offenders: list[str] = []
    for f in _java_files():
        rel = f.relative_to(REPO_ROOT).as_posix()
        for lineno, line in enumerate(f.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            for m in pair_re.finditer(line):
                name = m.group(1)
                if name not in known_tools and name not in sentinels:
                    offenders.append(f"  {rel}:{lineno}  remediation_action tool={name} -- not registered")

    assert not offenders, (
        "remediation_actions advertise tools that do not exist.\n" + "\n".join(sorted(set(offenders)))
    )

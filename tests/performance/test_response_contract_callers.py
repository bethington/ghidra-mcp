"""Callers of reshaped endpoints must unwrap the response, not str() it.

The 6.0.0 response contract turned text-returning tools into JSON records. Every
consumer that regexed the old text has to go through a helper
(`fun_doc.decompiled_text` / `disasm_text` / `_envelope_items`) instead.

This test exists because grepping for call sites by hand missed 14 of them in
fun_doc.py alone -- including the port worker's own decompile, which then failed
184 live runs with "'dict' object has no attribute 'startswith'" before anyone
noticed. A grep is not a guarantee; this is.

Offline: pure source inspection, no Ghidra required.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FUN_DOC = REPO_ROOT / "fun-doc"

# Endpoints whose response shape changed, mapped to markers that prove the call
# site unwraps the record. Both the named helpers and the equivalent inline
# forms count -- the point is "does this consumer handle a dict", not "did it
# use my preferred helper". What must NOT appear is a bare str()/regex over the
# response with no unwrap at all.
RESHAPED = {
    "decompile_function": ("decompiled_text", '"decompiled"'),
    "disassemble_function": ("disasm_text", "disasm_lines", '"instructions"'),
    "get_function_by_address": ("_envelope_items", '.get("name")', "func_resp.get"),
    "list_segments": ("_envelope_items", "_segments_text", '"segments"'),
    "list_globals": ("_envelope_items", "_globals_text", '"globals"'),
    "list_exports": ("_envelope_items", '"exports"'),
    "get_metadata": ("_envelope_items", ".get("),
}

# How far after the call site to look for the unwrap. Generous on purpose: a
# false negative here is a production break, a false positive is a code comment.
WINDOW = 10

# Modules that legitimately pass responses through without interpreting them.
EXEMPT = {
    "conformance_dashboard.py",   # contract-probe list: endpoint names only
    "submission_api.py",          # forwards raw payloads to an external caller
}


def _python_sources() -> list[Path]:
    return [
        p for p in FUN_DOC.rglob("*.py")
        if p.name not in EXEMPT and "benchmark/fixtures" not in p.as_posix()
    ]


@pytest.mark.parametrize("endpoint,helpers", sorted(RESHAPED.items()))
def test_reshaped_endpoint_consumers_unwrap(endpoint: str, helpers: tuple[str, ...]):
    offenders: list[str] = []
    call_re = re.compile(rf'["\']/{re.escape(endpoint)}["\']')

    for path in _python_sources():
        lines = path.read_text(encoding="utf-8", errors="ignore").split("\n")
        for i, line in enumerate(lines):
            if not call_re.search(line):
                continue
            # A mention inside a comment or docstring is not a call site.
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            window = "\n".join(lines[max(0, i - 3):i + WINDOW])
            if any(h in window for h in helpers):
                continue
            # str(resp) on a reshaped response is the specific bug: it stringifies
            # a dict instead of failing loudly.
            offenders.append(
                f"  {path.relative_to(REPO_ROOT).as_posix()}:{i + 1}  "
                f"{stripped[:88]}"
            )

    assert not offenders, (
        f"/{endpoint} changed shape in 6.0.0; these call sites do not unwrap it "
        f"with one of {list(helpers)}.\n"
        "A dict reaching text-parsing code fails at runtime, not at import "
        "time -- see docs/project-management/MCP_RESPONSE_CONTRACT.md.\n"
        + "\n".join(offenders)
    )


def test_helpers_exist():
    """The helpers this test recommends must actually be exported."""
    source = (FUN_DOC / "fun_doc.py").read_text(encoding="utf-8", errors="ignore")
    for helper in ("def decompiled_text", "def disasm_text", "def disasm_lines",
                   "def _envelope_items"):
        assert helper in source, f"fun_doc.py is missing {helper}"

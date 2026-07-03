"""
conformance_workbench.py -- implementation-coverage + side-by-side data for the
fun-doc dashboard.

Ties each PD2-S12 Ghidra function to its equivalent OpenD2 implementation so the
dashboard can show original ASSEMBLY, decompiled PSEUDOCODE, and the live ported
C++ side by side, and report how much of each binary is actually IMPLEMENTED
(not merely documented).

Link source of truth = the OpenD2 repo itself. Ported symbols carry a marker:
    // @PD2S12 <Module>!<Symbol> @ 0x<ghidra_address>  (conformance: <STATE>)
(see Shared/D2Seed.hpp). Ghidra carries the reverse @OPEND2 marker + the
PORTED / PROVEN function tags. build_index() greps the OpenD2 tree for @PD2S12,
so the coverage index is always in sync with the committed code.
"""
import os
import re
from pathlib import Path

OPEND2_REPO = Path(os.environ.get("FUNDOC_OPEND2_REPO", r"C:\Users\benam\source\cpp\OpenD2"))
GHIDRA_HTTP = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8089").rstrip("/")

_MARKER_RE = re.compile(
    r"@PD2S12\s+(?P<module>\w+)!(?P<symbol>\w+)\s*@\s*(?P<addr>0x[0-9a-fA-F]+)"
    r"(?:.*?conformance:\s*(?P<state>\w+))?"
)
_SRC_GLOBS = (
    "Shared/**/*.hpp", "Shared/**/*.cpp",
    "Modcode/**/*.cpp", "Modcode/**/*.hpp",
    "Engine/**/*.cpp", "Engine/**/*.hpp",
)


def _module_to_program(module):
    return "Game.exe" if module.lower() == "game" else f"{module}.dll"


def build_index(repo=None):
    """Scan the OpenD2 repo for @PD2S12 markers. Returns a list of dicts:
    {program, module, address, symbol, file, line, state}. `address` is
    lowercase hex without the 0x prefix (matches fun-doc's key format)."""
    repo = Path(repo or OPEND2_REPO)
    out = []
    seen = set()
    for pattern in _SRC_GLOBS:
        for path in repo.glob(pattern):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                m = _MARKER_RE.search(line)
                if not m:
                    continue
                program = _module_to_program(m.group("module"))
                addr = m.group("addr")[2:].lower()
                key = f"{program}::{addr}"
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "program": program,
                    "module": m.group("module"),
                    "address": addr,
                    "symbol": m.group("symbol"),
                    "file": str(path.relative_to(repo)).replace("\\", "/"),
                    "line": lineno,
                    "state": (m.group("state") or "PORTED").upper(),
                })
    return out


def coverage_summary(repo=None):
    """Per-program implementation coverage derived from the OpenD2 markers."""
    idx = build_index(repo)
    by_program = {}
    for e in idx:
        p = by_program.setdefault(e["program"], {"ported": 0, "proven": 0, "symbols": []})
        p["ported"] += 1
        if e["state"] == "PROVEN":
            p["proven"] += 1
        p["symbols"].append({"symbol": e["symbol"], "address": e["address"], "state": e["state"]})
    return {"total_ported": len(idx), "by_program": by_program}


def _extract_source_symbol(repo, file, symbol, hint_line=None):
    """Extract the C/C++ definition of `symbol` from `file`: find the signature
    line ('symbol('), then brace-match to the closing '}'. Returns
    (code, start_line) or (None, None). `hint_line` is searched first."""
    path = Path(repo or OPEND2_REPO) / file
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None, None
    sig_re = re.compile(r"\b" + re.escape(symbol) + r"\s*\(")
    order = list(range(max(0, (hint_line or 1) - 1), len(lines))) + list(range(0, len(lines)))
    start = next((i for i in order if sig_re.search(lines[i])), None)
    if start is None:
        return None, None
    depth = 0
    began = False
    end = start
    for j in range(start, len(lines)):
        for ch in lines[j]:
            if ch == "{":
                depth += 1
                began = True
            elif ch == "}":
                depth -= 1
        end = j
        if began and depth <= 0:
            break
    return "\n".join(lines[start:end + 1]), start + 1


def _ghidra_get(endpoint, params, timeout=8):
    import requests
    try:
        r = requests.get(f"{GHIDRA_HTTP}/{endpoint.lstrip('/')}", params=params, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as exc:  # noqa: BLE001 - surface the failure in the pane
        return f"<ghidra fetch failed: {exc}>"


def get_sidebyside(program, address, repo=None):
    """Assemble the 3-pane data for one function: original ASSEMBLY + decompiled
    PSEUDOCODE (from the live Ghidra plugin) + the linked OpenD2 implementation
    (if any). Safe to call without a linked port (opend2=None)."""
    repo = Path(repo or OPEND2_REPO)
    addr = address.lower().replace("0x", "")
    entry = next(
        (e for e in build_index(repo) if e["address"] == addr and e["program"] == program),
        None,
    )
    asm = _ghidra_get("disassemble_function", {"address": f"0x{addr}", "program": program})
    pseudo = _ghidra_get("decompile_function", {"address": f"0x{addr}", "program": program})
    opend2 = None
    if entry:
        code, resolved_line = _extract_source_symbol(repo, entry["file"], entry["symbol"], entry.get("line"))
        opend2 = {
            "file": entry["file"],
            "line": resolved_line,
            "symbol": entry["symbol"],
            "state": entry["state"],
            "code": code,
        }
    return {
        "program": program,
        "address": addr,
        "assembly": asm,
        "pseudocode": pseudo,
        "opend2": opend2,
        "implemented": entry is not None,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(coverage_summary(), indent=2))

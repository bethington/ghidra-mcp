"""Scaffold a new D2-derived core-tier function.

Given a Ghidra program path and an address, fetches the current
decompilation + plate comment + signature from the running Ghidra
instance and emits:

  fun-doc/benchmark/src/<name>.c         — starter source with the
                                            decompilation + plate
                                            pasted in as reference
                                            comments
  fun-doc/benchmark/truth/<name>.truth.yaml — starter truth overlay
                                               with synonyms /
                                               canonical plate /
                                               algorithm tag TODOs

The author then reads the reference material in the scaffolded .c,
writes plausible C below the scaffold block, fills in the truth
yaml, and adds the function to suites/core.yaml.

Usage:
    python tools/add_core_function.py \\
        --program /Mods/PD2-S12/D2Common.dll \\
        --address 6fd7f3a0 \\
        --name CalcDamageBonus

Env:
    GHIDRA_SERVER_URL   default http://127.0.0.1:8089
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re
import sys
import textwrap
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parents[1]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from ghidra_bridge import GhidraBridgeError, _get


SRC_DIR = BENCHMARK_DIR / "src"
TRUTH_DIR = BENCHMARK_DIR / "truth"
TEMPLATE_DIR = BENCHMARK_DIR / "templates"


def _sanitize_name(name: str) -> str:
    """snake_case-ify a PascalCase name, keep snake_case as-is.

    Ghidra / existing fun-doc names come in both flavors. Our .c file
    needs a valid C identifier; snake_case is the house convention.
    """
    # PascalCase → snake_case
    s1 = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s2 = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s1).lower()
    # Strip any non-identifier characters
    return re.sub(r"[^a-z0-9_]", "_", s2)


def _fetch_decompilation(program: str, address: str) -> str:
    """Get Ghidra's current decompilation for the target function."""
    try:
        resp = _get(
            "/decompile_function",
            params={"program": program, "address": address, "timeout": 60},
            timeout=90,
        )
    except GhidraBridgeError as e:
        return f"[decompile failed: {e}]"
    if isinstance(resp, dict):
        return resp.get("c") or resp.get("code") or resp.get("decompilation") or str(resp)
    return str(resp)


def _fetch_plate(program: str, address: str) -> str:
    try:
        resp = _get(
            "/get_plate_comment",
            params={"program": program, "address": address},
        )
    except GhidraBridgeError:
        return ""
    if isinstance(resp, dict):
        return resp.get("comment", "") or resp.get("plate", "") or ""
    return str(resp or "")


def _indent_block(text: str, prefix: str = " * ") -> str:
    """Prefix every line with ` * ` so the block sits inside a C comment."""
    if not text:
        return f"{prefix}(none)"
    out_lines = []
    for line in text.splitlines():
        if line:
            out_lines.append(f"{prefix}{line}")
        else:
            out_lines.append(f"{prefix.rstrip()}")
    return "\n".join(out_lines)


def _render_template(template_path: Path, substitutions: dict[str, str]) -> str:
    raw = template_path.read_text(encoding="utf-8")
    out = raw
    for key, val in substitutions.items():
        out = out.replace("{" + key + "}", val)
    return out


def scaffold(program: str, address: str, name: str, force: bool = False) -> None:
    fname = _sanitize_name(name)
    src_path = SRC_DIR / f"{fname}.c"
    truth_path = TRUTH_DIR / f"{fname}.truth.yaml"

    if src_path.exists() and not force:
        print(f"[scaffold] {src_path} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)
    if truth_path.exists() and not force:
        print(f"[scaffold] {truth_path} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    print(f"[scaffold] fetching decompilation for {program} @ {address}...")
    decomp = _fetch_decompilation(program, address)
    plate = _fetch_plate(program, address)

    now = _dt.datetime.now().isoformat(timespec="seconds")
    subs = {
        "FUNCTION_NAME": fname,
        "PROGRAM": program,
        "ADDRESS": address,
        "GENERATED_AT": now,
        "DECOMPILATION_BLOCK": _indent_block(decomp),
        "PLATE_BLOCK": _indent_block(plate if plate else "(no plate comment)"),
    }

    c_source = _render_template(TEMPLATE_DIR / "function_template.c", subs)
    truth_source = _render_template(TEMPLATE_DIR / "truth_template.yaml", subs)

    src_path.write_text(c_source, encoding="utf-8")
    truth_path.write_text(truth_source, encoding="utf-8")

    print(f"[scaffold] wrote {src_path}")
    print(f"[scaffold] wrote {truth_path}")
    print()
    print(textwrap.dedent(f"""\
        Next steps:
          1. Read {src_path} — the DECOMPILATION + EXISTING PLATE blocks
             at the top are reference material. Rewrite the function
             body below them into plausible C matching the decompile.
          2. Fill out the TODOs in {truth_path}
             (synonyms, canonical_plate, algorithm_tag).
          3. Add "{fname}" to fun-doc/benchmark/suites/core.yaml.
          4. Run `python build.py` and check that the compiled output
             decompiles similarly to the original (iterate if not).
          5. Author a baseline fixture at
             fixtures/{fname}.baseline.capture.json — copy from an
             existing one and edit.
          6. `python run_benchmark.py --mock --tier core` to verify.
    """))


def _unmangle_msys_path(raw: str) -> str:
    """Undo MSYS2 / Git-Bash automatic path conversion on Ghidra paths.

    When this script is invoked from git-bash with an argument like
    `/Mods/PD2-S12/D2Common.dll`, MSYS2 helpfully "translates" it to
    `C:/Program Files/Git/Mods/PD2-S12/D2Common.dll` before Python
    ever sees it. We detect that prefix and strip it.

    Also handles the generic `C:/Users/.../cygdrive` and similar cases
    by looking for `/Mods/` or `/Vanilla/` fragments that signal the
    true Ghidra path starts mid-string.
    """
    if not raw:
        return raw
    # Git-bash install-dir prefix
    lowered = raw.replace("\\", "/").lower()
    for marker in ("/mods/", "/vanilla/", "/benchmark/"):
        idx = lowered.find(marker)
        if idx > 0:
            # Keep original casing; slice based on the detected index.
            # Convert backslashes to forward to match Ghidra's path style.
            return raw.replace("\\", "/")[idx:]
    return raw


def main():
    ap = argparse.ArgumentParser(
        description="Scaffold a D2-derived core-tier benchmark function"
    )
    ap.add_argument("--program", required=True, help="Ghidra program path (e.g. /Mods/PD2-S12/D2Common.dll)")
    ap.add_argument("--address", required=True, help="hex address without 0x prefix")
    ap.add_argument("--name", required=True, help="function name (PascalCase or snake_case)")
    ap.add_argument("--force", action="store_true", help="overwrite existing files")
    args = ap.parse_args()
    program = _unmangle_msys_path(args.program)
    if program != args.program:
        print(f"[scaffold] auto-corrected MSYS-mangled path: {args.program!r} -> {program!r}")
    scaffold(program, args.address.lower().replace("0x", ""), args.name, force=args.force)


if __name__ == "__main__":
    main()

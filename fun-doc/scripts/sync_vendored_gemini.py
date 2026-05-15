#!/usr/bin/env python3
"""Refresh the vendored copy of gemini_agent_sdk.

fun-doc vendors the `gemini_agent_sdk` package (the Gemini worker
provider's dependency) under `fun-doc/vendored/gemini_agent_sdk/` so the
provider works with no install step. This script re-copies the package
from a local checkout of the upstream repo and rewrites the pinned-commit
line in `_VENDORED.md`.

Maintainer tool — end users never run it. Run it after pulling new
changes into the gemini-agent-sdk repo:

    python -m scripts.sync_vendored_gemini --source ../../gemini-agent-sdk

If --source is omitted it defaults to a sibling `gemini-agent-sdk/`
checkout next to the ghidra-mcp repo (the standard layout:
`source/mcp/ghidra-mcp` + `source/mcp/gemini-agent-sdk`).

The script:
  1. Copies every *.py from <source>/src/gemini_agent_sdk/ into the
     vendored directory (overwriting).
  2. Reads <source>'s git HEAD + the version from pyproject.toml.
  3. Rewrites the pinned-commit / pinned-version / vendored-on lines
     in _VENDORED.md.
  4. Prints a diff summary so the maintainer can eyeball the change
     before committing.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re
import shutil
import subprocess
import sys
from pathlib import Path

_FUNDOC_DIR = Path(__file__).resolve().parent.parent
_VENDORED_PKG = _FUNDOC_DIR / "vendored" / "gemini_agent_sdk"
_VENDORED_DOC = _VENDORED_PKG / "_VENDORED.md"
_REPO_ROOT = _FUNDOC_DIR.parent
# Standard sibling layout: source/mcp/ghidra-mcp + source/mcp/gemini-agent-sdk
_DEFAULT_SOURCE = _REPO_ROOT.parent / "gemini-agent-sdk"


def _git_head(repo: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _read_version(source: Path) -> str:
    pyproject = source / "pyproject.toml"
    if not pyproject.exists():
        return "unknown"
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else "unknown"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Re-vendor gemini_agent_sdk into fun-doc")
    p.add_argument(
        "--source",
        type=Path,
        default=_DEFAULT_SOURCE,
        help=f"Path to the gemini-agent-sdk repo checkout (default: {_DEFAULT_SOURCE})",
    )
    args = p.parse_args(argv)

    source: Path = args.source.resolve()
    src_pkg = source / "src" / "gemini_agent_sdk"
    if not src_pkg.is_dir():
        print(f"ERROR: {src_pkg} not found. Pass --source <path-to-gemini-agent-sdk>.",
              file=sys.stderr)
        return 1

    src_files = sorted(src_pkg.glob("*.py"))
    if not src_files:
        print(f"ERROR: no .py files in {src_pkg}", file=sys.stderr)
        return 1

    _VENDORED_PKG.mkdir(parents=True, exist_ok=True)

    # Copy every .py, overwriting. Drop vendored .py files that no longer
    # exist upstream so a removed module doesn't linger.
    upstream_names = {f.name for f in src_files}
    for stale in _VENDORED_PKG.glob("*.py"):
        if stale.name not in upstream_names:
            print(f"  removing stale {stale.name} (no longer upstream)")
            stale.unlink()
    for f in src_files:
        shutil.copy2(f, _VENDORED_PKG / f.name)
        print(f"  vendored {f.name}")

    # Rewrite the pinned-commit metadata in _VENDORED.md.
    commit = _git_head(source)
    version = _read_version(source)
    today = _dt.date.today().isoformat()
    if _VENDORED_DOC.exists():
        doc = _VENDORED_DOC.read_text(encoding="utf-8")
        doc = re.sub(r"(\| Pinned commit \| )`[^`]*`", rf"\g<1>`{commit}`", doc)
        doc = re.sub(r"(\| Pinned version \| )`[^`]*`", rf"\g<1>`{version}`", doc)
        doc = re.sub(r"(\| Vendored on \| )[0-9-]+", rf"\g<1>{today}", doc)
        _VENDORED_DOC.write_text(doc, encoding="utf-8")
        print(f"  updated _VENDORED.md -> commit {commit[:12]}, version {version}")

    print(f"\nDone. Vendored {len(src_files)} file(s) from {source}.")
    print("Review `git diff fun-doc/vendored/` then commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

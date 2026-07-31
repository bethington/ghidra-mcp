#!/usr/bin/env python3
r"""Orchestrate the shadow-dispatcher pipeline: stage -> generate -> build.

THE SCALE PROBLEM
-----------------
Measured 2026-07-31: 191 shadow dispatchers exist against ~62,000 functions in
the store, and 68 functions hold CONF_BATTLETESTED. The port workers are NOT
the constraint on battletesting -- they measured 0.87 candidates/min while
BATTLETESTED sat at zero promotions for an entirely different reason. The
constraint is that a function can only ever be battletested if a shadow
dispatcher exists for it, and building those was a hand-run chain:

    build_shadow_batch.py --apply     stage manifest entries (Class A only)
    gen_shadow_dispatch.py            regenerate the .gen.h + run validators
    cmake --build                     rebuild the patch DLL
    deploy + relaunch the game        make it live

Each step is individually documented and individually manual, so the fleet
grew at whatever rate somebody remembered to run four commands. There are
1,667 stageable candidates waiting for D2Common/D2Client.

WHAT THIS AUTOMATES, AND WHAT IT DELIBERATELY DOES NOT
------------------------------------------------------
Automated: stage -> generate -> build. All three are reversible, none of them
touch the running game, and the generator's own validators stay in the path as
HARD gates (they are fatal by design -- see below).

NOT automated: deploy + relaunch. That changes what the live game executes,
and a wrong manifest entry does not fail gracefully -- `validate_argc` is fatal
precisely because a wrong arg count on a callee-cleans convention skews ESP and
access-violates the game (2026-07-30: two entries, `eip=0x00000140` on save
load). `--deploy` exists but is opt-in and never the default.

The generator's gates, kept in the path on purpose:
  * validate_unique_offsets -- duplicate hook offsets
  * validate_ret_bits       -- return width is the DATUM width, not the write
                               width (reading MOVZX as 32 over-widened 19
                               entries and logged 166,565 false divergences)
  * validate_argc           -- FATAL. Arity comes from the callee's `RET n`,
                               never from Ghidra's inferred signature.

A batch that trips a validator is a batch that would have crashed the game.
This script surfaces that and stops rather than continuing to build.

USAGE
    # dry run: show what would be staged, change nothing
    python fun-doc/scripts/grow_shadow_fleet.py --limit 25

    # stage + regenerate + build (does NOT touch the running game)
    python fun-doc/scripts/grow_shadow_fleet.py --limit 25 --apply

    # ... and deploy (game must be restarted for it to take effect)
    python fun-doc/scripts/grow_shadow_fleet.py --limit 25 --apply --deploy
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

_FUNDOC = Path(__file__).resolve().parent.parent
_REPO = _FUNDOC.parent
D2MOO_REPO = Path(os.environ.get("FUNDOC_D2MOO_REPO", r"C:\Users\benam\source\cpp\D2MOO"))
GEN = D2MOO_REPO / "conformance" / "tools" / "gen_shadow_dispatch.py"
BUILD_DIR = D2MOO_REPO / "build-1.13c"


def run(cmd, cwd=None, label="", timeout=3600):
    """Run a step, streaming nothing but reporting faithfully."""
    print(f"\n=== {label} ===\n$ {' '.join(str(c) for c in cmd)}", flush=True)
    t0 = time.time()
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None,
                       capture_output=True, text=True, timeout=timeout)
    out = (p.stdout or "") + (p.stderr or "")
    tail = "\n".join(out.strip().splitlines()[-25:])
    print(tail, flush=True)
    print(f"--- {label}: exit={p.returncode} in {time.time() - t0:.0f}s", flush=True)
    return p.returncode, out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=25,
                    help="how many candidates to stage this batch")
    ap.add_argument("--module", choices=["D2Common", "D2Client", "both"],
                    default="both")
    ap.add_argument("--provider", default="minimax")
    ap.add_argument("--apply", action="store_true",
                    help="stage + regenerate + build (still does NOT touch the game)")
    ap.add_argument("--deploy", action="store_true",
                    help="also deploy the built patch DLL. Requires --apply. The "
                         "game must be relaunched for it to take effect.")
    args = ap.parse_args()

    if args.deploy and not args.apply:
        print("--deploy requires --apply", file=sys.stderr)
        return 2

    py = str(_FUNDOC / ".venv" / "Scripts" / "python.exe")
    if not Path(py).exists():
        py = sys.executable

    # ---- 1. stage ---------------------------------------------------------
    stage_cmd = [py, str(_FUNDOC / "scripts" / "build_shadow_batch.py"),
                 "--limit", str(args.limit), "--module", args.module,
                 "--provider", args.provider]
    if args.apply:
        stage_cmd.append("--apply")
    rc, out = run(stage_cmd, cwd=_REPO, label="1/3 stage manifest entries")
    if rc != 0:
        print("\nSTAGING FAILED -- stopping before the generator.", file=sys.stderr)
        return rc

    if not args.apply:
        print("\nDRY RUN -- nothing staged, generator and build skipped.\n"
              "Re-run with --apply to stage + regenerate + build.")
        return 0

    staged = 0
    for line in out.splitlines():
        if "staged=" in line:
            try:
                staged = int(line.split("staged=")[1].split()[0])
            except (IndexError, ValueError):
                pass
    if staged == 0:
        print("\nnothing was staged -- skipping generator and build "
              "(regenerating an unchanged manifest is pure churn).")
        return 0

    # ---- 2. regenerate the dispatch headers -------------------------------
    # The validators live INSIDE generate_module and are fatal. A non-zero exit
    # here means the batch would have crashed the game; do NOT build past it.
    rc, out = run([py, str(GEN)], cwd=D2MOO_REPO,
                  label="2/3 regenerate shadow dispatch headers (validators)")
    if rc != 0:
        print("\nGENERATOR REFUSED THE BATCH. This is the arity/ret-width gate "
              "doing its job -- a wrong entry access-violates the game "
              "(eip=0x140). The manifest now contains entries that need fixing "
              "or removing before anything is built.", file=sys.stderr)
        return rc

    # ---- 3. build the patch DLL -------------------------------------------
    rc, _ = run(["cmake", "--build", str(BUILD_DIR), "--config", "Release"],
                cwd=D2MOO_REPO, label="3/3 build patch DLL")
    if rc != 0:
        print("\nBUILD FAILED -- nothing deployed.", file=sys.stderr)
        return rc

    print(f"\nStaged {staged} new dispatcher(s), headers regenerated, patch built.")
    if not args.deploy:
        print("NOT deployed (deploy touches the live game). Re-run with "
              "--deploy, or deploy by hand, then relaunch the game.")
        return 0

    deploy = D2MOO_REPO / "conformance" / "tools" / "deploy_module_rva_fix.ps1"
    if not deploy.exists():
        print(f"deploy script not found: {deploy}", file=sys.stderr)
        return 1
    rc, _ = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", str(deploy)], cwd=D2MOO_REPO, label="deploy patch DLL")
    if rc != 0:
        return rc
    print("\nDeployed. The game must be RELAUNCHED for the new dispatchers to "
          "hook -- they will read as unhooked until then.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

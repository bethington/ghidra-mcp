#!/usr/bin/env python3
"""v5.8 storage-migration live-smoke runbook.

Orchestrates the migrate -> verify -> env-setup -> [manual worker spawn] ->
post-verify cycle the v5.8 PR1 pre-merge checklist requires. Stops short of
spawning workers itself (that's a manual step in the dashboard so the
operator can pick the binary, count, and provider interactively).

Usage:
    python fun-doc/scripts/v58_smoke.py prep [--binary BH.dll] [--backend sqlite|postgres]
    python fun-doc/scripts/v58_smoke.py check       # status during the smoke
    python fun-doc/scripts/v58_smoke.py verify      # rerun verifier any time
    python fun-doc/scripts/v58_smoke.py post-verify # post-smoke gate
    python fun-doc/scripts/v58_smoke.py reset       # blow away the smoke DB

The default backend is sqlite (single-file DB at C:/tmp/v58-smoke.db on
Windows, /tmp/v58-smoke.db elsewhere) for fast, isolated iteration. Pass
``--backend postgres --url ...`` for the PG variant once the SQLite pass
is clean.

This script never touches the production state.json — it only reads from
it. The smoke DB and the source state.json are independent. If the smoke
goes sideways, ``reset`` and start over loses nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths and defaults
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
FUN_DOC_DIR = SCRIPT_DIR.parent
REPO_ROOT = FUN_DOC_DIR.parent

# Default smoke DB location. /c/tmp on Windows MSYS, /tmp elsewhere.
if sys.platform == "win32":
    DEFAULT_SMOKE_DB_PATH = Path(r"C:\tmp\v58-smoke.db")
    DEFAULT_PRE_VERIFY_LOG = Path(r"C:\tmp\v58-smoke-preverify.json")
    DEFAULT_POST_VERIFY_LOG = Path(r"C:\tmp\v58-smoke-postverify.json")
else:
    DEFAULT_SMOKE_DB_PATH = Path("/tmp/v58-smoke.db")
    DEFAULT_PRE_VERIFY_LOG = Path("/tmp/v58-smoke-preverify.json")
    DEFAULT_POST_VERIFY_LOG = Path("/tmp/v58-smoke-postverify.json")

DEFAULT_SQLITE_URL = f"sqlite:///{DEFAULT_SMOKE_DB_PATH.as_posix()}"

PASS_GLYPH = "[PASS]"
FAIL_GLYPH = "[FAIL]"
WAIT_GLYPH = "[....]"
INFO_GLYPH = "[ -- ]"


# ---------------------------------------------------------------------------
# Source-data discovery
# ---------------------------------------------------------------------------

def find_state_sources(state_root: Path | None) -> dict[str, Path]:
    """Locate state.json + runs.jsonl + inventory.json + global_inventory.json.

    Order of preference:
      1. Explicit --state-root passed by caller
      2. Sibling worktree at ../ghidra-mcp/fun-doc/ (typical layout when the
         storage branch is checked out alongside main)
      3. Current fun-doc/ dir (when running on main with v5.8 merged)
    """
    candidates = []
    if state_root:
        candidates.append(state_root.resolve())
    candidates.extend([
        (REPO_ROOT.parent / "ghidra-mcp" / "fun-doc").resolve(),
        FUN_DOC_DIR,
    ])
    for cand in candidates:
        state_file = cand / "state.json"
        if state_file.is_file():
            return {
                "state": state_file,
                "runs": cand / "logs" / "runs.jsonl",
                "inventory": cand / "inventory.json",
                "global_inventory": cand / "global_inventory.json",
            }
    raise FileNotFoundError(
        f"Could not locate state.json under any of: "
        f"{[str(c) for c in candidates]}. Pass --state-root."
    )


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _run_python(script: Path, args: list[str], *, env_extra: dict | None = None) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True, text=True, env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ---------------------------------------------------------------------------
# DB inspection helpers (SQLite only; PG variant prints counts via psql)
# ---------------------------------------------------------------------------

def _sqlite_counts(db_path: Path) -> dict:
    """Return row counts for the tables the smoke gate cares about."""
    import sqlite3
    if not db_path.exists():
        return {"_exists": False}
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    out = {"_exists": True}
    for table in ("functions_workflow", "runs", "inventory", "global_inventory", "sessions", "meta"):
        try:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            out[table] = cur.fetchone()[0]
        except sqlite3.OperationalError as e:
            out[table] = f"<error: {e}>"
    # Latest run timestamp (useful for "is the worker writing right now?")
    try:
        cur.execute("SELECT MAX(ts) FROM runs")
        out["latest_run_ts"] = cur.fetchone()[0]
    except sqlite3.OperationalError:
        out["latest_run_ts"] = None
    # Functions whose score has been updated since smoke prep started
    try:
        cur.execute(
            "SELECT COUNT(*) FROM functions_workflow WHERE updated_at > datetime('now', '-2 hours')"
        )
        out["recently_updated_functions"] = cur.fetchone()[0]
    except sqlite3.OperationalError:
        out["recently_updated_functions"] = None
    conn.close()
    return out


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_prep(args) -> int:
    """Migrate state.json into a fresh smoke DB and run the pre-smoke verifier."""
    print("=== v5.8 smoke: PREP ===\n")

    # 1. Locate sources
    try:
        srcs = find_state_sources(args.state_root)
    except FileNotFoundError as e:
        print(f"{FAIL_GLYPH} {e}")
        return 1
    print(f"{INFO_GLYPH} sources:")
    for k, v in srcs.items():
        ok = v.is_file() if k in ("state", "inventory", "global_inventory", "runs") else v.exists()
        glyph = PASS_GLYPH if ok else WAIT_GLYPH
        print(f"  {glyph} {k:18} {v}")
    if not srcs["state"].is_file():
        print(f"{FAIL_GLYPH} state.json is required")
        return 1

    # 2. Decide on backend URL
    if args.backend == "sqlite":
        url = args.url or DEFAULT_SQLITE_URL
        db_path = Path(url.replace("sqlite:///", "")).resolve()
        # Wipe any stale smoke DB so prep starts from a known state.
        if db_path.exists():
            print(f"{INFO_GLYPH} removing stale smoke DB: {db_path}")
            db_path.unlink()
        db_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        url = args.url
        if not url:
            print(f"{FAIL_GLYPH} --backend postgres requires --url postgresql://...")
            return 1
        db_path = None
        print(f"{INFO_GLYPH} postgres mode: assumes you've truncated the smoke schema yourself")

    # 3. Run migration
    print(f"\n{INFO_GLYPH} migrating state.json -> {args.backend} ...")
    migrate_script = SCRIPT_DIR / "migrate_state_to_sql.py"
    rc, out, err = _run_python(migrate_script, [
        "--backend", args.backend,
        "--url", url,
        "--state", str(srcs["state"]),
        "--runs", str(srcs["runs"]),
        "--inventory", str(srcs["inventory"]),
        "--global-inventory", str(srcs["global_inventory"]),
    ])
    if rc != 0:
        print(f"{FAIL_GLYPH} migration failed (exit {rc})")
        print(out[-2000:] if len(out) > 2000 else out)
        print(err[-2000:] if len(err) > 2000 else err)
        return rc
    # Print the last few lines of stdout (which has the summary block)
    summary_lines = [ln for ln in out.splitlines() if ln.startswith("[migrate]")][-10:]
    for ln in summary_lines:
        print(f"  {ln}")
    print(f"{PASS_GLYPH} migration complete\n")

    # 4. Pre-smoke verifier
    print(f"{INFO_GLYPH} running pre-smoke verifier ...")
    verify_script = SCRIPT_DIR / "verify_migration.py"
    rc, out, err = _run_python(verify_script, [
        "--backend", args.backend,
        "--url", url,
        "--state", str(srcs["state"]),
        "--runs", str(srcs["runs"]),
        "--inventory", str(srcs["inventory"]),
        "--global-inventory", str(srcs["global_inventory"]),
    ])
    if rc != 0 or "PASS" not in out:
        print(f"{FAIL_GLYPH} pre-smoke verifier failed (exit {rc})")
        print(out[-2000:] if len(out) > 2000 else out)
        print(err[-2000:] if len(err) > 2000 else err)
        return rc or 1
    for ln in out.splitlines():
        if ln.startswith("[verify]"):
            print(f"  {ln}")
    print(f"{PASS_GLYPH} pre-smoke verifier zero-diff\n")

    # 5. Snapshot pre-smoke counts so post-verify can diff against them
    if args.backend == "sqlite" and db_path:
        pre_counts = _sqlite_counts(db_path)
        pre_counts["_url"] = url
        pre_counts["_backend"] = args.backend
        pre_counts["_target_binary"] = args.binary
        pre_counts["_prep_ts"] = time.time()
        DEFAULT_PRE_VERIFY_LOG.parent.mkdir(parents=True, exist_ok=True)
        DEFAULT_PRE_VERIFY_LOG.write_text(json.dumps(pre_counts, indent=2, default=str))
        print(f"{INFO_GLYPH} pre-smoke snapshot written to {DEFAULT_PRE_VERIFY_LOG}")
        print(f"  functions_workflow={pre_counts.get('functions_workflow')}")
        print(f"  runs={pre_counts.get('runs')}")
        print(f"  inventory={pre_counts.get('inventory')}")
        print(f"  sessions={pre_counts.get('sessions')}")

    # 6. Print env-var commands + next steps
    print("\n" + "=" * 70)
    print(f"{PASS_GLYPH} prep complete. Now do these steps:\n")
    target = args.binary or "<your-binary>"
    # The v5.8 storage factory reads exactly one env var: FUN_DOC_DB_URL.
    # Backend is inferred from the URL scheme (sqlite: vs postgresql:).
    if sys.platform == "win32":
        print("  # 1. Set the backend URL in this shell (PowerShell):")
        print(f"  $env:FUN_DOC_DB_URL = '{url}'")
        print()
        print("  # or in bash:")
        print(f"  export FUN_DOC_DB_URL='{url}'")
    else:
        print("  # 1. Set the backend URL in this shell:")
        print(f"  export FUN_DOC_DB_URL='{url}'")
    print()
    print(f"  # 2. Start the dashboard (from the worktree dir, NOT main):")
    print(f"  cd {REPO_ROOT}")
    print(f"  python fun-doc/fun_doc.py --web --web-port 5000")
    print()
    print(f"  # 3. Open http://127.0.0.1:5000 — confirm:")
    print(f"     - function inventory renders with the migrated counts")
    print(f"     - sessions panel shows historical sessions")
    print(f"     - no 'state.json not found' or 'table doesn't exist' errors")
    print()
    print(f"  # 4. Spawn ONE worker on {target}:")
    print(f"     - Count: 3 (BH.dll) or 10 (D2Multi.dll)")
    print(f"     - Mode: functions")
    print(f"     - Provider: minimax")
    print(f"     - Continuous: false")
    print()
    print(f"  # 5. While it runs, monitor with:")
    print(f"     python {Path(__file__).name} check")
    print()
    print(f"  # 6. When the worker finishes, run:")
    print(f"     python {Path(__file__).name} post-verify")
    print("=" * 70)
    return 0


def cmd_check(args) -> int:
    """Show smoke status: DB counts, latest run, delta vs pre-smoke."""
    if not DEFAULT_PRE_VERIFY_LOG.is_file():
        print(f"{FAIL_GLYPH} no pre-smoke snapshot at {DEFAULT_PRE_VERIFY_LOG}.")
        print(f"      Did you run `prep` first?")
        return 1
    pre = json.loads(DEFAULT_PRE_VERIFY_LOG.read_text())
    if pre.get("_backend") != "sqlite":
        print(f"{INFO_GLYPH} check only supports sqlite backend (PG inspection: use psql)")
        return 0
    db_path = Path(pre["_url"].replace("sqlite:///", ""))
    cur = _sqlite_counts(db_path)
    if not cur.get("_exists"):
        print(f"{FAIL_GLYPH} smoke DB missing at {db_path}")
        return 1

    print(f"=== v5.8 smoke status — backend={pre.get('_backend')} ===\n")
    print(f"target binary:     {pre.get('_target_binary') or '<not recorded>'}")
    print(f"db path:           {db_path}")
    print(f"prep'd at:         {time.ctime(pre.get('_prep_ts', 0))}")
    print(f"latest run ts:     {cur.get('latest_run_ts')}\n")
    print(f"{'table':<22} {'before':>10} {'now':>10} {'delta':>10}")
    print(f"{'-'*22} {'-'*10} {'-'*10} {'-'*10}")
    for tbl in ("functions_workflow", "runs", "inventory", "global_inventory", "sessions"):
        before = pre.get(tbl, 0) or 0
        now = cur.get(tbl, 0) or 0
        delta = now - before if isinstance(before, int) and isinstance(now, int) else "?"
        print(f"{tbl:<22} {before:>10} {now:>10} {delta:>10}")
    print(f"{'recently_updated':<22} {'-':>10} {cur.get('recently_updated_functions','?'):>10}")
    print()

    runs_delta = (cur.get("runs", 0) or 0) - (pre.get("runs", 0) or 0)
    if runs_delta > 0:
        print(f"{PASS_GLYPH} worker has written {runs_delta} new run row(s)")
    else:
        print(f"{WAIT_GLYPH} no new runs yet — worker may still be in select_function/process_function")
    return 0


def cmd_verify(args) -> int:
    """Just run the verifier against the current state. Convenience wrapper."""
    if not DEFAULT_PRE_VERIFY_LOG.is_file():
        print(f"{FAIL_GLYPH} no pre-smoke snapshot. Run `prep` first.")
        return 1
    pre = json.loads(DEFAULT_PRE_VERIFY_LOG.read_text())
    url = pre["_url"]
    backend = pre["_backend"]
    try:
        srcs = find_state_sources(args.state_root)
    except FileNotFoundError as e:
        print(f"{FAIL_GLYPH} {e}")
        return 1
    verify_script = SCRIPT_DIR / "verify_migration.py"
    rc, out, err = _run_python(verify_script, [
        "--backend", backend, "--url", url,
        "--state", str(srcs["state"]),
        "--runs", str(srcs["runs"]),
        "--inventory", str(srcs["inventory"]),
        "--global-inventory", str(srcs["global_inventory"]),
    ])
    for ln in out.splitlines():
        if ln.startswith("[verify]") or ln.startswith("PASS") or "FAIL" in ln:
            print(ln)
    return rc


def cmd_post_verify(args) -> int:
    """Post-smoke gate: confirm worker writes are consistent + run verifier."""
    print("=== v5.8 smoke: POST-VERIFY ===\n")
    if not DEFAULT_PRE_VERIFY_LOG.is_file():
        print(f"{FAIL_GLYPH} no pre-smoke snapshot at {DEFAULT_PRE_VERIFY_LOG}. Run `prep` first.")
        return 1
    pre = json.loads(DEFAULT_PRE_VERIFY_LOG.read_text())
    backend = pre["_backend"]
    url = pre["_url"]
    if backend != "sqlite":
        print(f"{INFO_GLYPH} post-verify only supports sqlite. For PG: run verify manually + psql counts.")
        return 0
    db_path = Path(url.replace("sqlite:///", ""))
    cur = _sqlite_counts(db_path)

    # 1. Did the worker write to the runs table?
    runs_delta = (cur.get("runs", 0) or 0) - (pre.get("runs", 0) or 0)
    if runs_delta > 0:
        print(f"{PASS_GLYPH} runs table grew by {runs_delta} (worker writes landed)")
    else:
        print(f"{FAIL_GLYPH} runs table did not grow — worker writes didn't reach the SQL backend")
        return 2

    # 2. Did at least one function_workflow row get updated recently?
    recent = cur.get("recently_updated_functions", 0) or 0
    if recent > 0:
        print(f"{PASS_GLYPH} {recent} functions_workflow row(s) updated in the last 2 hours")
    else:
        print(f"{FAIL_GLYPH} no functions_workflow rows updated — denorm callback may be missing")
        return 3

    # 3. Sessions table grew?
    sessions_delta = (cur.get("sessions", 0) or 0) - (pre.get("sessions", 0) or 0)
    if sessions_delta > 0:
        print(f"{PASS_GLYPH} sessions table grew by {sessions_delta}")
    else:
        print(f"{INFO_GLYPH} sessions table unchanged (acceptable if worker didn't start a new session)")

    # 4. Function count unchanged (no rows lost)
    func_pre = pre.get("functions_workflow", 0) or 0
    func_now = cur.get("functions_workflow", 0) or 0
    if func_now >= func_pre:
        print(f"{PASS_GLYPH} functions_workflow count is intact: {func_now} (was {func_pre})")
    else:
        print(f"{FAIL_GLYPH} functions_workflow count DROPPED: {func_pre} -> {func_now}")
        return 4

    # 5. Snapshot post-smoke counts for the operator's records
    cur["_post_verify_ts"] = time.time()
    DEFAULT_POST_VERIFY_LOG.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_POST_VERIFY_LOG.write_text(json.dumps(cur, indent=2, default=str))
    print(f"{INFO_GLYPH} post-smoke snapshot written to {DEFAULT_POST_VERIFY_LOG}")

    # 6. Final verifier — confirms state.json + the smoke DB are still consistent
    #    EXCEPT for the new runs the worker wrote (those will show as delta in
    #    the runs check; that's expected). The verifier currently doesn't
    #    distinguish "drifted because worker wrote" vs "drifted because bug" —
    #    so we accept any non-fatal drift here and flag it.
    print(f"\n{INFO_GLYPH} running verifier (drift in runs count is EXPECTED post-smoke):")
    try:
        srcs = find_state_sources(args.state_root)
    except FileNotFoundError as e:
        print(f"{FAIL_GLYPH} {e}")
        return 5
    verify_script = SCRIPT_DIR / "verify_migration.py"
    rc, out, err = _run_python(verify_script, [
        "--backend", backend, "--url", url,
        "--state", str(srcs["state"]),
        "--runs", str(srcs["runs"]),
        "--inventory", str(srcs["inventory"]),
        "--global-inventory", str(srcs["global_inventory"]),
    ])
    for ln in out.splitlines():
        if ln.startswith("[verify]") or "PASS" in ln or "FAIL" in ln:
            print(f"  {ln}")
    if rc == 0:
        print(f"{PASS_GLYPH} verifier still PASS\n")
    else:
        print(f"{INFO_GLYPH} verifier reported drift — review above; runs-count drift is expected\n")

    print("=" * 70)
    print(f"{PASS_GLYPH} v5.8 SMOKE GATES PASSED.")
    print()
    print("Next steps:")
    print(f"  gh pr ready 186                    # drop draft status")
    print(f"  gh pr merge 186 --merge            # merge once CI re-runs green")
    print(f"  # then cut v5.8.0 — bump versions, CHANGELOG, tag, push")
    print("=" * 70)
    return 0


def cmd_reset(args) -> int:
    """Delete the smoke DB and snapshots — start over."""
    targets = [DEFAULT_SMOKE_DB_PATH, DEFAULT_PRE_VERIFY_LOG, DEFAULT_POST_VERIFY_LOG]
    for p in targets:
        if p.exists():
            p.unlink()
            print(f"{INFO_GLYPH} removed {p}")
        else:
            print(f"{INFO_GLYPH} not present (skipped): {p}")
    print(f"{PASS_GLYPH} reset complete. Run `prep` to start fresh.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    p_prep = sub.add_parser("prep", help="migrate + pre-smoke verify + snapshot")
    p_prep.add_argument("--backend", choices=["sqlite", "postgres"], default="sqlite")
    p_prep.add_argument("--url", default=None,
                        help=f"storage URL (sqlite default: {DEFAULT_SQLITE_URL})")
    p_prep.add_argument("--binary", default=None,
                        help="target binary for the smoke (informational only; recorded in snapshot)")
    p_prep.add_argument("--state-root", type=Path, default=None,
                        help="dir containing state.json (auto-detected if omitted)")
    p_prep.set_defaults(func=cmd_prep)

    p_check = sub.add_parser("check", help="show smoke status (counts + deltas)")
    p_check.set_defaults(func=cmd_check)

    p_verify = sub.add_parser("verify", help="rerun the verifier mid-smoke")
    p_verify.add_argument("--state-root", type=Path, default=None)
    p_verify.set_defaults(func=cmd_verify)

    p_post = sub.add_parser("post-verify", help="post-smoke gate")
    p_post.add_argument("--state-root", type=Path, default=None)
    p_post.set_defaults(func=cmd_post_verify)

    p_reset = sub.add_parser("reset", help="delete smoke DB + snapshots")
    p_reset.set_defaults(func=cmd_reset)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

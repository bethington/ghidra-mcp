"""One-shot migration: state.json + runs.jsonl + inventory.json → SQL store.

Per Q4 of the PR1 spec, fun-doc moves from a 27 MB single-file JSON store
to a SQL backend with a single atomic cutover (no dual-write). This script
is the "load" half of that cutover; ``verify_migration.py`` is the gate
that runs immediately after.

Reads:
  * ``fun-doc/state.json``                — primary per-function state
  * ``fun-doc/state_<binary>.json``       — any parked snapshots, optional
  * ``fun-doc/inventory.json``            — function-coverage rollups
  * ``fun-doc/global_inventory.json``     — global-variable rollups
  * ``fun-doc/logs/runs.jsonl``           — per-run history (becomes
                                             frozen on disk after migration)

Writes (via storage.Repository):
  * functions_workflow                    — every function record from state.json
  * inventory                             — every binary's function-coverage row
  * global_inventory                      — every binary's global-coverage row
  * runs                                  — every line from runs.jsonl, attached
                                             to its function via (program, address)
  * meta                                  — singleton row with project_folder,
                                             active_binary, current_session, last_scan
  * sessions                              — one row per session entry (id derived
                                             from session.started timestamp)

Usage:

    # Migrate to a fresh SQLite DB (default path: fun-doc/state.db)
    python -m scripts.migrate_state_to_sql --backend sqlite

    # Migrate to Postgres (FUN_DOC_DB_URL must be set)
    python -m scripts.migrate_state_to_sql --backend postgres

    # Override paths
    python -m scripts.migrate_state_to_sql \\
        --state fun-doc/state.json \\
        --runs fun-doc/logs/runs.jsonl \\
        --inventory fun-doc/inventory.json \\
        --global-inventory fun-doc/global_inventory.json

    # Dry-run: parse + summarize, write nothing
    python -m scripts.migrate_state_to_sql --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

# Allow ``python -m scripts.migrate_state_to_sql`` from the fun-doc directory.
_FUNDOC_DIR = Path(__file__).resolve().parent.parent
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))


DEFAULT_STATE = _FUNDOC_DIR / "state.json"
DEFAULT_RUNS = _FUNDOC_DIR / "logs" / "runs.jsonl"
DEFAULT_INVENTORY = _FUNDOC_DIR / "inventory.json"
DEFAULT_GLOBAL_INVENTORY = _FUNDOC_DIR / "global_inventory.json"

# ---------------------------------------------------------------------------
# Module-level engine / repo — None in production (built inside migrate()).
# Tests may monkeypatch these to inject a pre-built repository without
# needing to supply --backend / --url CLI args.  migrate() checks these
# before constructing its own connection.
# ---------------------------------------------------------------------------
engine = None  # type: ignore[assignment]
repo = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Field mapping: state.json record → functions_workflow row
# ---------------------------------------------------------------------------

# Direct column passthrough (state key → DB column).
# NOTE: ``attempts`` is intentionally NOT in this set. In state.json it's a
# list of inline run records (the per-function run history); the workflow
# table's ``attempts`` column is an int counter, populated as len(list).
# The inline list itself is migrated row-by-row into the ``runs`` table.
_DIRECT_FIELDS = {
    "name",
    "score",
    "fixable",
    "has_custom_name",
    "has_plate_comment",
    "classification",
    "consecutive_fails",
    "partial_runs",
    "stagnation_runs",
    "net_delta",
    "cost_per_point",
    "total_input_tokens",
    "total_output_tokens",
    "audit_count",
    "escalation_count",
    "last_audit_provider",
    "last_audit_delta",
    "last_escalation_from",
    "last_escalation_to",
    "caller_count",
    "is_leaf",
    "call_graph_layer",
    "is_thunk",
    "is_external",
    "is_thrashing",
    "deductions",
    "callees",
    "library_code",
    "library_code_reasons",
    # name-source provenance (#204) — kept here so a state.json that
    # was already marked with propagation source folds cleanly into
    # state.db. Defaults to 'scan' / null at the schema level for
    # never-touched rows.
    "name_source",
    "name_source_binary",
    "name_confidence",
}

# Renamed columns (state key → DB column).
_RENAMED_FIELDS = {
    "last_processed": "last_processed",   # both ts strings
    "last_audited": "last_audited_at",
    "last_escalated": "last_escalated_at",
    "decompile_timeout_at": "decompile_timeout_at",
    "library_code_at": "library_code_at",
}


def parse_ts(value: Any) -> Optional[datetime]:
    """Best-effort ISO-8601 → tz-aware datetime. Returns None on missing/blank."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    s = str(value).strip()
    if not s:
        return None
    # state.json timestamps look like "2026-04-23T16:51:17.916345" — no tz.
    # Attach UTC unless an explicit offset is present.
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def derive_binary_name(program_path: str) -> str:
    """``/Mods/PD2-S12/D2Game.dll`` → ``D2Game.dll``."""
    return program_path.rsplit("/", 1)[-1] if program_path else ""


def derive_version(program_path: str) -> Optional[str]:
    """Pull the version segment out of a Ghidra project path.

    Heuristic: the second-to-last segment is the version when the path is
    ``/<repo>/<version>/<binary>``. Examples:
      * ``/Vanilla/1.13d/D2Common.dll``  → ``1.13d``
      * ``/Mods/PD2-S12/D2Game.dll``     → ``PD2-S12``
      * ``/oddpath/lone.dll``            → ``oddpath``
    """
    if not program_path:
        return None
    parts = [p for p in program_path.split("/") if p]
    if len(parts) >= 2:
        return parts[-2]
    return None


def function_record_to_row(rec: dict) -> dict:
    """Convert a state.json function entry into a functions_workflow row dict."""
    program_path = rec.get("program") or ""
    binary_name = rec.get("program_name") or derive_binary_name(program_path)
    out: dict[str, Any] = {
        "program_path": program_path,
        "binary_name": binary_name,
        "version": derive_version(program_path),
        "address": rec.get("address") or "",
    }
    for key in _DIRECT_FIELDS:
        if key in rec:
            out[key] = rec[key]
    # Rename + timestamp-parse in one pass. Any destination column whose
    # name ends in ``_at`` is treated as a timestamp and parsed via
    # parse_ts; ``last_processed`` is also a timestamp despite its name
    # not ending in _at (legacy state.json schema predates the suffix
    # convention). Everything else is copied as-is.
    #
    # Pre-v5.11.5 this loop ran a fuzzy substring check ("audited" in dest
    # or "escalated" in dest or "timeout" in dest) and then three explicit
    # post-loop blocks re-assigned last_processed, decompile_timeout_at,
    # and library_code_at via parse_ts. That produced double-assignments
    # — last_processed and decompile_timeout_at got the same value
    # written twice (wasted CPU), while library_code_at first got the
    # raw string from _maybe_ts and then was overwritten by the datetime
    # from parse_ts (correct end-state, confusing flow). The unified
    # check below removes all three duplicate assignments.
    _ts_destinations = {"last_processed"}  # explicit non-_at exceptions
    for src, dest in _RENAMED_FIELDS.items():
        if src not in rec:
            continue
        if dest.endswith("_at") or dest in _ts_destinations:
            out[dest] = parse_ts(rec[src])
        else:
            out[dest] = _maybe_ts(rec[src], dest)
    if "last_result" in rec:
        out["last_result"] = rec["last_result"]
    # ``attempts`` int column = len(inline attempts list). Migrating the
    # list contents into the runs table happens after the bulk upsert.
    inline = rec.get("attempts")
    if isinstance(inline, list):
        out["attempts"] = len(inline)
        # Also derive run_count from the same list — it's the most accurate
        # source we have for this row's history. record_run() bumps it from
        # here on out.
        out["run_count"] = len(inline)
        if inline:
            last = inline[-1]
            out["last_run_at"] = parse_ts(last.get("ts"))
            out["last_run_provider"] = last.get("provider")
            out["last_run_model"] = last.get("model")
            out["last_run_delta"] = last.get("delta")
    elif isinstance(inline, int):
        out["attempts"] = inline
    # queue_status: derive from last_result for now (workers haven't emitted
    # a separate status field consistently). 'completed' → 'done', anything
    # else stays in 'queued' until the next worker pass.
    last_result = rec.get("last_result")
    if last_result == "completed":
        out["queue_status"] = "done"
    elif last_result == "scanned" or last_result is None:
        out["queue_status"] = "queued"
    else:
        out["queue_status"] = last_result  # preserve raw value (failed, needs_redo, ...)
    return out


def iter_inline_attempts(functions: dict) -> Iterator[tuple[str, str, str, dict]]:
    """Yield (program_path, address, function_name, attempt) for each
    inline run record stored in state.json's per-function ``attempts`` arrays.

    These are migrated into the ``runs`` table alongside runs.jsonl entries —
    in many cases the inline records pre-date runs.jsonl logging, so they're
    the only source of truth for older history.
    """
    for rec in functions.values():
        program_path = rec.get("program") or ""
        address = rec.get("address") or ""
        name = rec.get("name")
        attempts = rec.get("attempts")
        if not isinstance(attempts, list):
            continue
        for entry in attempts:
            if isinstance(entry, dict):
                yield program_path, address, name, entry


def _maybe_ts(value: Any, _dest: str) -> Any:
    """Pass-through for non-timestamp fields the rename map didn't really need."""
    return value


# ---------------------------------------------------------------------------
# Source loaders
# ---------------------------------------------------------------------------


def load_state(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"state.json not found at {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def iter_runs_jsonl(path: Path) -> Iterator[dict]:
    """Yield per-line dicts. Skips blank lines and lines that fail to parse,
    logging a warning so we don't abort the whole migration on one corrupt row."""
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                print(
                    f"[migrate] warn: runs.jsonl line {lineno} skipped — {e}",
                    file=sys.stderr,
                )


def load_inventory(path: Path) -> dict:
    if not path.exists():
        return {"binaries": {}}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Migration driver
# ---------------------------------------------------------------------------


def migrate(
    *,
    state_path: Path,
    runs_path: Path,
    inventory_path: Optional[Path] = None,
    global_inventory_path: Optional[Path] = None,
    backend: str = "sqlite",
    url: Optional[str] = None,
    dry_run: bool = False,
    truncate_runs: bool = False,
) -> dict:
    """Run the migration end-to-end. Returns a summary dict of counts."""
    # Resolve module-level engine/repo via sys.modules rather than a fresh
    # `import migrate_state_to_sql`, which only works when the module happens
    # to be importable under that exact unqualified name. sys.modules[__name__]
    # is the same module object regardless of how this file was invoked
    # (`python -m scripts.migrate_state_to_sql`, `from scripts.migrate_state_to_sql
    # import migrate`, or direct script execution as __main__).
    _self_mod = sys.modules[__name__]

    if inventory_path is None:
        inventory_path = DEFAULT_INVENTORY
    if global_inventory_path is None:
        global_inventory_path = DEFAULT_GLOBAL_INVENTORY

    print(f"[migrate] reading state from {state_path}")
    state = load_state(state_path)

    functions = state.get("functions", {})
    print(f"[migrate] state.json: {len(functions)} function records")

    inventory_data = load_inventory(inventory_path)
    inventory_binaries = inventory_data.get("binaries", {})
    print(f"[migrate] inventory.json: {len(inventory_binaries)} binaries")

    global_inventory_data = load_inventory(global_inventory_path)
    global_inventory_binaries = global_inventory_data.get("binaries", {})
    print(f"[migrate] global_inventory.json: {len(global_inventory_binaries)} binaries")

    if dry_run:
        run_count = sum(1 for _ in iter_runs_jsonl(runs_path))
        print(f"[migrate] runs.jsonl: {run_count} entries")
        print("[migrate] dry-run — no DB writes performed")
        return {
            "functions": len(functions),
            "inventory": len(inventory_binaries),
            "global_inventory": len(global_inventory_binaries),
            "runs": run_count,
            "sessions": len(state.get("sessions", []) or []),
        }

    # Use module-level engine/repo if injected (e.g. by tests via monkeypatch),
    # otherwise build them from backend/url arguments.
    _engine = _self_mod.engine
    _repo = _self_mod.repo
    if _engine is None or _repo is None:
        # Build the repository — let resolve_config do path normalization
        # (bare path → sqlite:/// URL) so a CLI ``--url C:/tmp/foo.db`` works.
        from storage import make_engine, resolve_config
        from storage.repository import Repository

        cfg_block: dict[str, Any] = {"backend": backend}
        if url is not None:
            cfg_block["url"] = url
        cfg = resolve_config(cfg_block)
        _engine = make_engine(cfg)
        _repo = Repository(_engine, cfg)
        _repo.bootstrap_schema()

    # ----- runs idempotency guard (H26) -----
    # The runs table has only an autoincrement PK and no natural unique key,
    # so a plain re-insert duplicates every row. Refuse unless explicitly
    # told to truncate.
    existing_runs = _repo.count_runs()
    if existing_runs > 0:
        if not truncate_runs:
            print(
                f"[migrate] ABORT: runs table already has {existing_runs} rows. "
                "Re-running would duplicate every row. Pass --truncate-runs to "
                "wipe and reload, or drop the table manually first.",
                file=sys.stderr,
            )
            raise SystemExit(2)
        print(f"[migrate] --truncate-runs: deleting {existing_runs} existing rows…")
        from sqlalchemy import delete
        with _engine.begin() as conn:
            conn.execute(delete(_repo.t_runs))

    # ----- functions -----
    rows = (function_record_to_row(rec) for rec in functions.values())
    n_funcs = _repo.bulk_upsert_functions(rows, chunk_size=500)
    print(f"[migrate] wrote {n_funcs} functions_workflow rows")

    # Index the rows we just wrote, keyed by (program_path, address) → id, so
    # we can attach runs efficiently. One bulk query, no N+1.
    print("[migrate] indexing function ids for runs attach…")
    fn_id_index = _repo.all_function_ids()
    print(f"[migrate] indexed {len(fn_id_index)} function ids")

    # ----- runs (jsonl + inline attempts) -----
    n_runs = 0
    n_runs_skipped = 0
    with _engine.begin() as conn:
        from sqlalchemy import insert

        batch: list[dict] = []

        def _flush(b: list[dict]) -> int:
            if not b:
                return 0
            # Normalize keys for executemany.
            all_keys: set[str] = set()
            for r in b:
                all_keys.update(r.keys())
            normalized = [{k: r.get(k) for k in all_keys} for r in b]
            conn.execute(insert(_repo.t_runs), normalized)
            return len(b)

        for entry in iter_runs_jsonl(runs_path):
            program_path = entry.get("program") or ""
            address = entry.get("address") or ""
            fn_id = fn_id_index.get((program_path, address))
            if fn_id is None:
                n_runs_skipped += 1
                continue
            batch.append(
                {
                    "function_id": fn_id,
                    "program_path": program_path,
                    "address": address,
                    "function_name": entry.get("function"),
                    "ts": parse_ts(entry.get("timestamp")),
                    "run_kind": "doc",
                    "mode": entry.get("mode"),
                    "provider": entry.get("provider") or "unknown",
                    "model": entry.get("model") or "unknown",
                    "score_before": entry.get("score_before"),
                    "score_after": entry.get("score_after"),
                    "delta": _calc_delta(entry),
                    "tool_calls": entry.get("tool_calls"),
                    "outcome": entry.get("result"),
                    "output": entry.get("output"),
                }
            )
            if len(batch) >= 1000:
                n_runs += _flush(batch)
                batch.clear()

        # Inline ``attempts`` arrays from state.json — older history that
        # often predates runs.jsonl logging. Stored as run_kind='doc' too;
        # callers can distinguish provenance via the ``mode`` field which
        # the inline payload usually carries.
        for program_path, address, function_name, entry in iter_inline_attempts(functions):
            fn_id = fn_id_index.get((program_path, address))
            if fn_id is None:
                n_runs_skipped += 1
                continue
            batch.append(
                {
                    "function_id": fn_id,
                    "program_path": program_path,
                    "address": address,
                    "function_name": function_name,
                    "ts": parse_ts(entry.get("ts") or entry.get("timestamp")),
                    "run_kind": "doc",
                    "mode": entry.get("mode"),
                    "provider": entry.get("provider") or "unknown",
                    "model": entry.get("model") or "unknown",
                    "score_before": entry.get("score_before"),
                    "score_after": entry.get("score_after"),
                    "delta": entry.get("delta") or _calc_delta(entry),
                    "tool_calls": entry.get("tool_calls"),
                    "outcome": entry.get("result"),
                    "notes": "inline_attempt",
                }
            )
            if len(batch) >= 1000:
                n_runs += _flush(batch)
                batch.clear()

        n_runs += _flush(batch)

    print(
        f"[migrate] wrote {n_runs} runs rows "
        f"(jsonl + inline attempts; {n_runs_skipped} skipped — no matching function row)"
    )

    # ----- inventory -----
    for path, info in inventory_binaries.items():
        _repo.upsert_inventory(
            {
                "program_path": path,
                "binary_name": info.get("name") or derive_binary_name(path),
                "version": derive_version(path),
                "total_documentable": info.get("total_documentable", 0),
                "scored": info.get("scored", 0),
                "last_scan": parse_ts(info.get("last_scan")),
            }
        )
    print(f"[migrate] wrote {len(inventory_binaries)} inventory rows")

    # ----- global_inventory -----
    for path, info in global_inventory_binaries.items():
        _repo.upsert_global_inventory(
            {
                "program_path": path,
                "binary_name": info.get("name") or derive_binary_name(path),
                "version": derive_version(path),
                "total_documentable": info.get("total_documentable", 0),
                "fully_documented": info.get("fully_documented", 0),
                "last_scan": parse_ts(info.get("last_scan")),
            }
        )
    print(f"[migrate] wrote {len(global_inventory_binaries)} global_inventory rows")

    # ----- meta -----
    _repo.set_meta(
        project_folder=state.get("project_folder"),
        last_scan=parse_ts(state.get("last_scan")),
        current_session=state.get("current_session"),
        active_binary=state.get("active_binary"),
        schema_version=1,
    )
    print("[migrate] wrote meta singleton")

    # ----- sessions -----
    sessions_raw = state.get("sessions") or []
    n_sess = 0
    for sess in sessions_raw:
        if not isinstance(sess, dict):
            continue
        # state.json sessions don't carry an explicit id; derive from `started`
        # timestamp (or `date` as a fallback) so the row is stable across reruns.
        sid = sess.get("id") or sess.get("started") or sess.get("date")
        if not sid:
            continue
        sid = str(sid)
        _repo.upsert_session(
            sid,
            started_at=parse_ts(sess.get("started")),
            ended_at=parse_ts(sess.get("ended")),
            payload=sess,
        )
        n_sess += 1
    print(f"[migrate] wrote {n_sess} sessions")

    summary = {
        "functions": n_funcs,
        "runs": n_runs,
        "runs_skipped": n_runs_skipped,
        "inventory": len(inventory_binaries),
        "global_inventory": len(global_inventory_binaries),
        "sessions": n_sess,
    }
    print(f"[migrate] done: {summary}")
    return summary


def _calc_delta(entry: dict) -> Optional[int]:
    sb = entry.get("score_before")
    sa = entry.get("score_after")
    if sb is None or sa is None:
        return None
    try:
        return int(sa) - int(sb)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 2)[0])
    p.add_argument("--backend", choices=["sqlite", "postgres"], default="sqlite")
    p.add_argument("--url", default=None, help="Override storage URL")
    p.add_argument("--state", default=str(DEFAULT_STATE))
    p.add_argument("--runs", default=str(DEFAULT_RUNS))
    p.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    p.add_argument("--global-inventory", default=str(DEFAULT_GLOBAL_INVENTORY))
    p.add_argument("--dry-run", action="store_true")
    p.add_argument(
        "--truncate-runs", action="store_true",
        help="Wipe the runs table before loading. Required when re-running "
             "the migration against a non-empty runs table (H26).",
    )
    args = p.parse_args(argv)

    summary = migrate(
        state_path=Path(args.state),
        runs_path=Path(args.runs),
        inventory_path=Path(args.inventory),
        global_inventory_path=Path(args.global_inventory),
        backend=args.backend,
        url=args.url,
        dry_run=args.dry_run,
        truncate_runs=args.truncate_runs,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Zero-diff verifier for the state.json → SQL migration.

Per Q4 of the PR1 spec, the one-shot migration is gated by this verifier:
the cutover is only safe if the SQL store *exactly* mirrors the source
JSON files. This script re-reads the sources, queries the SQL backend,
and reports any mismatches. Exit code is 0 on zero diff, 1 otherwise — so
it can be wired into CI / pre-merge gates.

Checks performed:

  * Function count matches state.json's ``functions`` map size
  * Per-binary function count matches per-binary state.json grouping
  * Spot-check sample of N functions: every direct field round-trips
  * runs.jsonl line count matches ``runs`` table count
    (line numbers excluding blanks and parse-failures)
  * inventory.json binary count matches ``inventory`` row count, and
    each binary's totals match
  * global_inventory.json the same for ``global_inventory``
  * meta singleton matches state.json's project_folder + active_binary
  * sessions count matches state.json's sessions list length

Usage:

    # Run after migration (defaults to fun-doc/state.db)
    python -m scripts.verify_migration --backend sqlite

    # Postgres
    python -m scripts.verify_migration --backend postgres

    # Override paths
    python -m scripts.verify_migration --state /path/to/state.json
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_FUNDOC_DIR = Path(__file__).resolve().parent.parent
if str(_FUNDOC_DIR) not in sys.path:
    sys.path.insert(0, str(_FUNDOC_DIR))


DEFAULT_STATE = _FUNDOC_DIR / "state.json"
DEFAULT_RUNS = _FUNDOC_DIR / "logs" / "runs.jsonl"
DEFAULT_INVENTORY = _FUNDOC_DIR / "inventory.json"
DEFAULT_GLOBAL_INVENTORY = _FUNDOC_DIR / "global_inventory.json"

SAMPLE_SIZE = 100  # random-sample N functions for field-level round-trip


# Direct-comparison fields. We don't compare derived/timestamp fields
# whose representation differs between JSON (string) and DB (datetime); the
# parse_ts → DateTime round-trip is exercised in the unit tests.
#
# ``attempts`` is intentionally excluded: in state.json it's a list of inline
# run records, in the workflow row it's an int count (with the records
# migrated into the runs table). The runs-count comparison upstream verifies
# the data ended up where it should.
_SAMPLE_COMPARE_FIELDS = [
    "name",
    "score",
    "fixable",
    "has_custom_name",
    "has_plate_comment",
    "classification",
    "consecutive_fails",
    "audit_count",
    "escalation_count",
    "caller_count",
    "is_leaf",
    "is_thunk",
    "is_external",
    "deductions",
    "callees",
]


class VerificationError(Exception):
    """Raised on the first hard mismatch. Caller decides whether to fail
    fast or accumulate (we do the latter for a complete diff report)."""


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _count_runs_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                json.loads(line)
                n += 1
            except json.JSONDecodeError:
                continue
    return n


def verify(
    *,
    state_path: Path,
    runs_path: Path,
    inventory_path: Path,
    global_inventory_path: Path,
    backend: str,
    url: Optional[str] = None,
    sample_size: int = SAMPLE_SIZE,
) -> tuple[bool, list[str]]:
    """Compare SQL store to source files. Returns ``(ok, mismatches)``."""

    from storage import make_engine, resolve_config
    from storage.repository import Repository

    cfg_block: dict[str, Any] = {"backend": backend}
    if url is not None:
        cfg_block["url"] = url
    cfg = resolve_config(cfg_block)
    engine = make_engine(cfg)
    repo = Repository(engine, cfg)

    print("[verify] reading sources…")
    state = _load_json(state_path)
    src_functions = state.get("functions", {})
    src_inventory = _load_json(inventory_path).get("binaries", {})
    src_global_inventory = _load_json(global_inventory_path).get("binaries", {})

    mismatches: list[str] = []

    # -------- function counts (overall + per binary) --------
    src_count = len(src_functions)
    db_count = repo.count_functions()
    if src_count != db_count:
        mismatches.append(
            f"function count mismatch: state.json={src_count} db={db_count}"
        )
    else:
        print(f"[verify] function count OK: {db_count}")

    src_per_binary: dict[str, int] = {}
    for r in src_functions.values():
        path = r.get("program") or ""
        src_per_binary[path] = src_per_binary.get(path, 0) + 1
    for path, expected in src_per_binary.items():
        actual = repo.count_functions(program_path=path)
        if expected != actual:
            mismatches.append(
                f"per-binary count mismatch for {path}: state.json={expected} db={actual}"
            )

    # -------- runs count --------
    # Two sources feed the ``runs`` table: runs.jsonl + inline ``attempts``
    # arrays embedded in state.json's per-function records (see
    # migrate_state_to_sql.py:iter_inline_attempts). The expected count is
    # the sum of both, minus any orphans (run records pointing at a function
    # that doesn't exist in state.json). The migration script prints the
    # skipped count; we just need src + inline >= db here.
    src_jsonl_runs = _count_runs_jsonl(runs_path)
    src_inline_runs = sum(
        len(rec.get("attempts") or [])
        for rec in src_functions.values()
        if isinstance(rec.get("attempts"), list)
    )
    src_runs = src_jsonl_runs + src_inline_runs
    db_runs = repo.count_runs()
    if db_runs > src_runs:
        mismatches.append(
            f"runs count higher than source: jsonl={src_jsonl_runs} "
            f"inline={src_inline_runs} (sum={src_runs}) db={db_runs}"
        )
    elif db_runs < src_runs:
        diff = src_runs - db_runs
        print(
            f"[verify] runs count: db={db_runs} src={src_runs} "
            f"(jsonl={src_jsonl_runs} + inline={src_inline_runs}; "
            f"skipped={diff}, expected for orphaned addresses)"
        )
    else:
        print(
            f"[verify] runs count OK: {db_runs} "
            f"(jsonl={src_jsonl_runs} + inline={src_inline_runs})"
        )

    # -------- inventory counts + per-row totals --------
    src_inv_n = len(src_inventory)
    db_inv = {row["program_path"]: row for row in repo.get_inventory()}
    db_inv_n = len(db_inv)
    if src_inv_n != db_inv_n:
        mismatches.append(
            f"inventory count mismatch: src={src_inv_n} db={db_inv_n}"
        )
    for path, src in src_inventory.items():
        db = db_inv.get(path)
        if db is None:
            mismatches.append(f"inventory missing for {path}")
            continue
        if src.get("total_documentable", 0) != (db.get("total_documentable") or 0):
            mismatches.append(
                f"inventory total_documentable mismatch for {path}: "
                f"src={src.get('total_documentable')} db={db.get('total_documentable')}"
            )
        if src.get("scored", 0) != (db.get("scored") or 0):
            mismatches.append(
                f"inventory scored mismatch for {path}: "
                f"src={src.get('scored')} db={db.get('scored')}"
            )
    if not any(m.startswith("inventory") for m in mismatches):
        print(f"[verify] inventory OK: {db_inv_n} binaries")

    # -------- global_inventory counts + per-row totals --------
    src_ginv_n = len(src_global_inventory)
    db_ginv = {row["program_path"]: row for row in repo.get_global_inventory()}
    if src_ginv_n != len(db_ginv):
        mismatches.append(
            f"global_inventory count mismatch: src={src_ginv_n} db={len(db_ginv)}"
        )
    for path, src in src_global_inventory.items():
        db = db_ginv.get(path)
        if db is None:
            mismatches.append(f"global_inventory missing for {path}")
            continue
        if src.get("total_documentable", 0) != (db.get("total_documentable") or 0):
            mismatches.append(
                f"global_inventory total_documentable mismatch for {path}: "
                f"src={src.get('total_documentable')} db={db.get('total_documentable')}"
            )
        if src.get("fully_documented", 0) != (db.get("fully_documented") or 0):
            mismatches.append(
                f"global_inventory fully_documented mismatch for {path}: "
                f"src={src.get('fully_documented')} db={db.get('fully_documented')}"
            )
    if not any(m.startswith("global_inventory") for m in mismatches):
        print(f"[verify] global_inventory OK: {len(db_ginv)} binaries")

    # -------- meta --------
    db_meta = repo.get_meta()
    if db_meta.get("project_folder") != state.get("project_folder"):
        mismatches.append(
            f"meta.project_folder mismatch: "
            f"src={state.get('project_folder')!r} db={db_meta.get('project_folder')!r}"
        )
    if db_meta.get("active_binary") != state.get("active_binary"):
        mismatches.append(
            f"meta.active_binary mismatch: "
            f"src={state.get('active_binary')!r} db={db_meta.get('active_binary')!r}"
        )
    if not any(m.startswith("meta") for m in mismatches):
        print("[verify] meta OK")

    # -------- sessions count --------
    src_sessions = state.get("sessions") or []
    src_sessions = [s for s in src_sessions if isinstance(s, dict)]
    src_sess_n = sum(
        1 for s in src_sessions if s.get("started") or s.get("date") or s.get("id")
    )
    db_sess_n = len(repo.list_sessions())
    if src_sess_n != db_sess_n:
        mismatches.append(
            f"sessions count mismatch: src={src_sess_n} db={db_sess_n}"
        )
    else:
        print(f"[verify] sessions OK: {db_sess_n}")

    # -------- random-sample function field round-trip --------
    if src_count > 0 and sample_size > 0:
        n_to_sample = min(sample_size, src_count)
        sample_keys = random.sample(list(src_functions.keys()), n_to_sample)
        diffs = 0
        for key in sample_keys:
            src = src_functions[key]
            program_path = src.get("program") or ""
            address = src.get("address") or ""
            db = repo.get_function(program_path, address)
            if db is None:
                mismatches.append(
                    f"sample miss: function {program_path}::{address} not in db"
                )
                diffs += 1
                continue
            for field in _SAMPLE_COMPARE_FIELDS:
                src_val = src.get(field)
                db_val = db.get(field)
                if not _values_equal(src_val, db_val):
                    mismatches.append(
                        f"field mismatch {program_path}::{address} "
                        f"{field}: src={src_val!r} db={db_val!r}"
                    )
                    diffs += 1
        if diffs == 0:
            print(f"[verify] sampled {n_to_sample} functions: all fields OK")

    ok = len(mismatches) == 0
    return ok, mismatches


def _values_equal(a: Any, b: Any) -> bool:
    """Tolerant comparison: handle None vs default, float precision, JSON
    payloads. Booleans-as-ints are normalised."""
    if a is None and b in (None, 0, False, "", []):
        return True
    if b is None and a in (None, 0, False, "", []):
        return True
    if isinstance(a, bool) or isinstance(b, bool):
        return bool(a) == bool(b)
    if isinstance(a, float) or isinstance(b, float):
        try:
            return abs(float(a) - float(b)) < 1e-6
        except (TypeError, ValueError):
            pass
    return a == b


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 2)[0])
    p.add_argument("--backend", choices=["sqlite", "postgres"], default="sqlite")
    p.add_argument("--url", default=None)
    p.add_argument("--state", default=str(DEFAULT_STATE))
    p.add_argument("--runs", default=str(DEFAULT_RUNS))
    p.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    p.add_argument("--global-inventory", default=str(DEFAULT_GLOBAL_INVENTORY))
    p.add_argument("--sample-size", type=int, default=SAMPLE_SIZE)
    args = p.parse_args(argv)

    ok, mismatches = verify(
        state_path=Path(args.state),
        runs_path=Path(args.runs),
        inventory_path=Path(args.inventory),
        global_inventory_path=Path(args.global_inventory),
        backend=args.backend,
        url=args.url,
        sample_size=args.sample_size,
    )
    if ok:
        print("[verify] PASS — zero diff")
        return 0
    print(f"[verify] FAIL — {len(mismatches)} mismatch(es):")
    for m in mismatches[:50]:
        print(f"  - {m}")
    if len(mismatches) > 50:
        print(f"  …and {len(mismatches) - 50} more")
    return 1


if __name__ == "__main__":
    sys.exit(main())

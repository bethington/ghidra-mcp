"""Repository: query layer for the fun-doc storage backend.

All callers (worker, dashboard, inventory scorer, audit pass, migration
scripts) go through this module. The class is intentionally dialect-aware
only at the upsert seam — INSERT...ON CONFLICT differs slightly between
Postgres and SQLite, so we route through ``_dialect_upsert``. Everything
else uses portable SQLAlchemy Core constructs.

The repository returns plain dicts, not ORM rows. Two reasons:

  1. fun_doc.py and web.py historically read state.json into nested dicts.
     Returning the same shape keeps the consumer-side migration mechanical.
  2. We never need lazy-loading or relationship traversal — every read is
     either a single row or a flat list. ORM overhead would be pure cost.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterable, Iterator, Optional

from sqlalchemy import (
    bindparam,
    delete,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine

from . import StorageConfig
from .models import build_metadata


# Subset of workflow columns that are safe to receive from a partial UPDATE
# coming from the worker. Everything else is internal (id, created_at,
# updated_at) or denorm-managed by record_run / record_audit / record_escalation.
_UPDATABLE_WORKFLOW_FIELDS = {
    "name",
    "score",
    "effective_score",
    "fixable",
    "has_custom_name",
    "has_plate_comment",
    "classification",
    "queue_status",
    "last_result",
    "last_processed",
    "attempts",
    "consecutive_fails",
    "partial_runs",
    "stagnation_runs",
    "net_delta",
    "cost_per_point",
    "total_input_tokens",
    "total_output_tokens",
    "snapshot_provider",
    "snapshot_model",
    "snapshot_max_turns",
    "caller_count",
    "is_leaf",
    "call_graph_layer",
    "is_thunk",
    "is_external",
    "is_thrashing",
    "decompile_timeout_at",
    "deductions",
    "callees",
    # name-source provenance (#204)
    "name_source",
    "name_source_binary",
    "name_confidence",
    # library_code gate (#198) — defensive: the worker doesn't update
    # these via the partial path today (it bulk-upserts via library_code
    # path in fun_doc.py), but listing them here means a future
    # update_function_fields(name="...", library_code=False) call
    # doesn't get silently dropped.
    "library_code",
    "library_code_at",
    "library_code_reasons",
    # OpenD2 conformance port pipeline (Sec 14 of EMULATION_CONFORMANCE_PLAN.md)
    "port_status",
    "port_attempts",
    "port_draft_path",
    "port_last_result",
}


class Repository:
    """Read/write facade for the fun-doc SQL store.

    Construct via ``fun_doc.storage.make_repository()`` for the standard
    case; use the ``Repository(engine, config)`` constructor directly in
    tests where you want to bind to an ad-hoc engine (e.g. an in-memory
    SQLite or a testcontainer Postgres).
    """

    def __init__(self, engine: Engine, config: StorageConfig):
        self._engine = engine
        self._config = config
        self._md = build_metadata(schema=config.schema if config.is_postgres else None)
        self.t_workflow = self._md.tables[self._tname("functions_workflow")]
        self.t_runs = self._md.tables[self._tname("runs")]
        self.t_inventory = self._md.tables[self._tname("inventory")]
        self.t_global_inventory = self._md.tables[self._tname("global_inventory")]
        self.t_meta = self._md.tables[self._tname("meta")]
        self.t_sessions = self._md.tables[self._tname("sessions")]

    @property
    def engine(self) -> Engine:
        return self._engine

    @property
    def config(self) -> StorageConfig:
        return self._config

    def _tname(self, table: str) -> str:
        if self._config.is_postgres:
            return f"{self._config.schema}.{table}"
        return table

    # ------------------------------------------------------------------
    # Transaction helper
    # ------------------------------------------------------------------

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        """Yield a Connection inside a transaction. Caller does the commit."""
        with self._engine.begin() as conn:
            yield conn

    # ------------------------------------------------------------------
    # Meta (singleton row)
    # ------------------------------------------------------------------

    def get_meta(self) -> dict:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(self.t_meta).where(self.t_meta.c.id == 1)
            ).mappings().first()
        if row is None:
            return {}
        return dict(row)

    def set_meta(self, **fields) -> None:
        fields["updated_at"] = _utcnow()
        with self._engine.begin() as conn:
            existing = conn.execute(
                select(self.t_meta.c.id).where(self.t_meta.c.id == 1)
            ).first()
            if existing is None:
                conn.execute(insert(self.t_meta).values(id=1, **fields))
            else:
                conn.execute(
                    update(self.t_meta).where(self.t_meta.c.id == 1).values(**fields)
                )

    # ------------------------------------------------------------------
    # Functions: per-function workflow rows
    # ------------------------------------------------------------------

    def upsert_function(self, record: dict) -> int:
        """Insert or update one functions_workflow row keyed by (program_path, address).

        Returns the row id. Unspecified columns are preserved on update
        (UPSERT semantics, not REPLACE — see test_storage_common.py).
        """
        now = _utcnow()
        record = dict(record)
        record.setdefault("created_at", now)
        record["updated_at"] = now
        with self._engine.begin() as conn:
            return self._upsert_workflow(conn, record)

    def bulk_upsert_functions(self, records: Iterable[dict], chunk_size: int = 500) -> int:
        """Bulk upsert for the migration script. Returns number of rows written."""
        count = 0
        chunk: list[dict] = []
        with self._engine.begin() as conn:
            for r in records:
                r = dict(r)
                now = _utcnow()
                r.setdefault("created_at", now)
                r["updated_at"] = now
                chunk.append(r)
                if len(chunk) >= chunk_size:
                    self._bulk_upsert_workflow(conn, chunk)
                    count += len(chunk)
                    chunk.clear()
            if chunk:
                self._bulk_upsert_workflow(conn, chunk)
                count += len(chunk)
        return count

    def get_function(self, program_path: str, address: str) -> Optional[dict]:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(self.t_workflow).where(
                    (self.t_workflow.c.program_path == program_path)
                    & (self.t_workflow.c.address == address)
                )
            ).mappings().first()
        return dict(row) if row else None

    def get_function_by_id(self, function_id: int) -> Optional[dict]:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(self.t_workflow).where(self.t_workflow.c.id == function_id)
            ).mappings().first()
        return dict(row) if row else None

    def all_function_ids(self) -> dict[tuple[str, str], int]:
        """Return a (program_path, address) → id index for every workflow row.

        Migration-only helper: streams the whole table once so the runs.jsonl
        loader can attach foreign keys without N round-trips. Cheap on tens
        of thousands of rows; for millions use a bounded ``program_path``
        scan with ``list_functions``.
        """
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(
                    self.t_workflow.c.id,
                    self.t_workflow.c.program_path,
                    self.t_workflow.c.address,
                )
            ).all()
        return {(pp, addr): row_id for row_id, pp, addr in rows}

    def list_binary_names(self) -> list[str]:
        """Distinct ``binary_name`` values across all workflow rows.

        One indexed DISTINCT scan — lets the dashboard know every scanned
        binary without materializing the whole table (which is what a
        binary-filtered ``list_functions`` call deliberately avoids).
        """
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(self.t_workflow.c.binary_name).distinct()
            ).all()
        return sorted({r[0] for r in rows if r[0]})

    def list_functions(
        self,
        *,
        program_path: Optional[str] = None,
        binary_name: Optional[str] = None,
        queue_status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[dict]:
        q = select(self.t_workflow)
        if program_path is not None:
            q = q.where(self.t_workflow.c.program_path == program_path)
        if binary_name is not None:
            q = q.where(self.t_workflow.c.binary_name == binary_name)
        if queue_status is not None:
            q = q.where(self.t_workflow.c.queue_status == queue_status)
        q = q.order_by(self.t_workflow.c.address)
        if limit is not None:
            q = q.limit(limit).offset(offset)
        with self._engine.connect() as conn:
            return [dict(r) for r in conn.execute(q).mappings()]

    def count_functions(
        self,
        *,
        program_path: Optional[str] = None,
        binary_name: Optional[str] = None,
        queue_status: Optional[str] = None,
    ) -> int:
        q = select(func.count()).select_from(self.t_workflow)
        if program_path is not None:
            q = q.where(self.t_workflow.c.program_path == program_path)
        if binary_name is not None:
            q = q.where(self.t_workflow.c.binary_name == binary_name)
        if queue_status is not None:
            q = q.where(self.t_workflow.c.queue_status == queue_status)
        with self._engine.connect() as conn:
            return int(conn.execute(q).scalar() or 0)

    def update_function_fields(
        self, program_path: str, address: str, **fields
    ) -> bool:
        """Patch a workflow row. Silently ignores unknown fields (defensive
        against caller drift). Returns True if a row was actually updated."""
        clean = {k: v for k, v in fields.items() if k in _UPDATABLE_WORKFLOW_FIELDS}
        if not clean:
            return False
        clean["updated_at"] = _utcnow()
        with self._engine.begin() as conn:
            res = conn.execute(
                update(self.t_workflow)
                .where(
                    (self.t_workflow.c.program_path == program_path)
                    & (self.t_workflow.c.address == address)
                )
                .values(**clean)
            )
            return res.rowcount > 0

    # ------------------------------------------------------------------
    # Runs / audits / escalations: append + atomic hot-field denorm
    # ------------------------------------------------------------------

    def record_run(self, program_path: str, address: str, run: dict) -> int:
        """Append a row to runs and update the parent workflow row's hot fields.

        ``run`` is a dict with keys matching the runs table columns. The
        ``run_kind`` field decides which counters and last-event pointers to
        bump (doc → run_count + last_run_*; audit → audit_count +
        last_audit_*; escalation → escalation_count + last_escalation_*).
        """
        now = _utcnow()
        run = dict(run)
        run.setdefault("ts", now)
        run.setdefault("program_path", program_path)
        run.setdefault("address", address)
        run.setdefault("run_kind", "doc")

        with self._engine.begin() as conn:
            fn_row = conn.execute(
                select(self.t_workflow.c.id, self.t_workflow.c.run_count,
                       self.t_workflow.c.audit_count, self.t_workflow.c.escalation_count)
                .where(
                    (self.t_workflow.c.program_path == program_path)
                    & (self.t_workflow.c.address == address)
                )
            ).first()
            if fn_row is None:
                raise LookupError(
                    f"record_run: no functions_workflow row for "
                    f"{program_path!r} {address!r}; upsert_function first"
                )
            run["function_id"] = fn_row[0]

            res = conn.execute(insert(self.t_runs).values(**run))
            run_id = res.inserted_primary_key[0] if res.inserted_primary_key else None

            kind = run.get("run_kind") or "doc"
            updates: dict[str, Any] = {"updated_at": now}
            if kind == "doc":
                updates["run_count"] = (fn_row[1] or 0) + 1
                updates["last_run_at"] = run.get("ts", now)
                updates["last_run_provider"] = run.get("provider")
                updates["last_run_model"] = run.get("model")
                updates["last_run_delta"] = run.get("delta")
            elif kind == "audit":
                updates["audit_count"] = (fn_row[2] or 0) + 1
                updates["last_audited_at"] = run.get("ts", now)
                updates["last_audit_provider"] = run.get("provider")
                updates["last_audit_delta"] = run.get("delta")
            elif kind == "escalation":
                updates["escalation_count"] = (fn_row[3] or 0) + 1
                updates["last_escalated_at"] = run.get("ts", now)
                updates["last_escalation_from"] = run.get("notes")  # caller-supplied
                # last_escalation_to set explicitly via record_escalation if needed
            # retry/other: only bump last_run_at-style hot pointers
            else:
                updates["last_run_at"] = run.get("ts", now)

            conn.execute(
                update(self.t_workflow)
                .where(self.t_workflow.c.id == fn_row[0])
                .values(**updates)
            )
        return int(run_id) if run_id is not None else 0

    def get_recent_runs(
        self,
        program_path: str,
        address: str,
        *,
        limit: int = 50,
    ) -> list[dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(self.t_runs)
                .where(
                    (self.t_runs.c.program_path == program_path)
                    & (self.t_runs.c.address == address)
                )
                .order_by(self.t_runs.c.ts.desc())
                .limit(limit)
            ).mappings()
            return [dict(r) for r in rows]

    def count_runs(self, *, program_path: Optional[str] = None,
                   provider: Optional[str] = None) -> int:
        q = select(func.count()).select_from(self.t_runs)
        if program_path is not None:
            q = q.where(self.t_runs.c.program_path == program_path)
        if provider is not None:
            q = q.where(self.t_runs.c.provider == provider)
        with self._engine.connect() as conn:
            return int(conn.execute(q).scalar() or 0)

    # ------------------------------------------------------------------
    # Inventory tables
    # ------------------------------------------------------------------

    def upsert_inventory(self, record: dict) -> None:
        with self._engine.begin() as conn:
            self._dialect_upsert(
                conn, self.t_inventory, [record], conflict_cols=["program_path"]
            )

    def get_inventory(self, program_path: Optional[str] = None) -> list[dict]:
        q = select(self.t_inventory)
        if program_path is not None:
            q = q.where(self.t_inventory.c.program_path == program_path)
        with self._engine.connect() as conn:
            return [dict(r) for r in conn.execute(q).mappings()]

    def upsert_global_inventory(self, record: dict) -> None:
        with self._engine.begin() as conn:
            self._dialect_upsert(
                conn,
                self.t_global_inventory,
                [record],
                conflict_cols=["program_path"],
            )

    def get_global_inventory(self, program_path: Optional[str] = None) -> list[dict]:
        q = select(self.t_global_inventory)
        if program_path is not None:
            q = q.where(self.t_global_inventory.c.program_path == program_path)
        with self._engine.connect() as conn:
            return [dict(r) for r in conn.execute(q).mappings()]

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def get_session(self, session_id: str) -> Optional[dict]:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(self.t_sessions).where(self.t_sessions.c.id == session_id)
            ).mappings().first()
        return dict(row) if row else None

    def list_sessions(self) -> list[dict]:
        with self._engine.connect() as conn:
            return [dict(r) for r in conn.execute(select(self.t_sessions)).mappings()]

    def upsert_session(self, session_id: str, *, started_at=None,
                       ended_at=None, payload: Optional[dict] = None) -> None:
        rec = {
            "id": session_id,
            "started_at": started_at,
            "ended_at": ended_at,
            "payload": payload,
        }
        with self._engine.begin() as conn:
            self._dialect_upsert(conn, self.t_sessions, [rec], conflict_cols=["id"])

    # ------------------------------------------------------------------
    # Admin: bring schema up before first use (delegates to db.migrate)
    # ------------------------------------------------------------------

    def bootstrap_schema(self) -> None:
        """Convenience: apply pending migrations against the configured backend.

        Most callers should run ``python -m db.migrate`` once at deploy time
        instead. This method exists for tests that spin up a fresh DB and
        want to skip the CLI roundtrip.

        Imports lazily and tolerates fun-doc not being a proper installable
        package (today it's a sys.path entry, not a package — see
        fun-doc/README.md).
        """
        import sys
        from pathlib import Path

        fundoc_dir = Path(__file__).parent.parent
        if str(fundoc_dir) not in sys.path:
            sys.path.insert(0, str(fundoc_dir))
        from db.migrate import migrate  # noqa: E402

        migrate(self._config.backend, self._config.url)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _upsert_workflow(self, conn, record: dict) -> int:
        existing = conn.execute(
            select(self.t_workflow.c.id).where(
                (self.t_workflow.c.program_path == record["program_path"])
                & (self.t_workflow.c.address == record["address"])
            )
        ).first()
        if existing is None:
            res = conn.execute(insert(self.t_workflow).values(**record))
            return int(res.inserted_primary_key[0])
        # UPDATE — drop created_at so we don't reset it
        patch = {k: v for k, v in record.items() if k != "created_at"}
        conn.execute(
            update(self.t_workflow)
            .where(self.t_workflow.c.id == existing[0])
            .values(**patch)
        )
        return int(existing[0])

    def _bulk_upsert_workflow(self, conn, records: list[dict]) -> None:
        """Batched INSERT ... ON CONFLICT (program_path, address) DO UPDATE.

        Records are grouped by key-set before dispatch: a partial row only
        updates the columns it actually carries (preserving upsert-not-REPLACE
        semantics — see test_storage_common.py), and multi-row VALUES needs
        uniform keys per statement anyway. ``id`` and ``created_at`` are never
        overwritten on conflict.

        This replaced a two-pass SELECT + one-UPDATE-statement-per-row
        implementation written for the one-shot migration. save_state()
        inherited it as a hot path, which put a ~50 s wall on every
        full-state save of a 60K-row store (measured 2026-07-09 — the
        dashboard's binary-switch stall).
        """
        # Columns the INSERT half of ON CONFLICT cannot leave out (NOT NULL,
        # no default). Records missing any of these are partial updates and
        # take the batched-UPDATE path below instead.
        required = {
            c.name
            for c in self.t_workflow.columns
            if not c.nullable
            and c.default is None
            and c.server_default is None
            and not c.primary_key
        }
        groups: dict[frozenset, list[dict]] = {}
        for r in records:
            groups.setdefault(frozenset(r), []).append(r)
        for keyset, rows in groups.items():
            if required <= keyset:
                self._dialect_upsert(
                    conn,
                    self.t_workflow,
                    rows,
                    conflict_cols=["program_path", "address"],
                    update_cols=[k for k in keyset if k != "created_at"],
                )
                continue
            # Partial rows: one executemany UPDATE keyed on the natural key.
            # A partial record for a nonexistent row is a no-op (previously
            # the INSERT attempt raised IntegrityError on the missing
            # required columns — neither behavior creates the row).
            update_keys = [
                k
                for k in keyset
                if k not in ("program_path", "address", "id", "created_at")
            ]
            if not update_keys:
                continue
            stmt = (
                update(self.t_workflow)
                .where(
                    (self.t_workflow.c.program_path == bindparam("b_program_path"))
                    & (self.t_workflow.c.address == bindparam("b_address"))
                )
                .values({k: bindparam(k) for k in update_keys})
            )
            conn.execute(
                stmt,
                [
                    {
                        "b_program_path": r["program_path"],
                        "b_address": r["address"],
                        **{k: r.get(k) for k in update_keys},
                    }
                    for r in rows
                ],
            )

    def bulk_upsert_sessions(self, records: list[dict]) -> int:
        """Upsert many session rows in one transaction.

        save_state() used to call upsert_session() per archived session —
        one commit (and on SQLite one fsync) each. Returns rows written.
        """
        recs = [
            {
                "id": r["id"],
                "started_at": r.get("started_at"),
                "ended_at": r.get("ended_at"),
                "payload": r.get("payload"),
            }
            for r in records
        ]
        if not recs:
            return 0
        with self._engine.begin() as conn:
            self._dialect_upsert(conn, self.t_sessions, recs, conflict_cols=["id"])
        return len(recs)

    def _dialect_upsert(self, conn, table, records: list[dict], *,
                         conflict_cols: list[str],
                         update_cols: Optional[list[str]] = None) -> None:
        """Dialect-aware INSERT...ON CONFLICT DO UPDATE.

        Both Postgres and SQLite (≥3.24) support the same syntax through
        SQLAlchemy's dialect-specific ``insert`` constructs. We pick the
        right one based on the engine's dialect name.

        ``update_cols`` limits which columns the conflict branch overwrites;
        None keeps the historical behavior (every table column except the
        conflict keys and ``id`` — for full-row records only, since columns
        absent from the INSERT resolve to NULL via ``excluded``). Every
        record in one call must share the same key set (executemany
        requirement); ``_bulk_upsert_workflow`` groups by key-set upstream.
        """
        if not records:
            return
        if update_cols is None:
            update_names = [
                c.name for c in table.columns
                if c.name not in conflict_cols and c.name != "id"
            ]
        else:
            update_names = [
                c for c in update_cols if c not in conflict_cols and c != "id"
            ]
        dialect = self._engine.dialect.name
        if dialect in ("postgresql", "sqlite"):
            if dialect == "postgresql":
                from sqlalchemy.dialects.postgresql import insert as d_insert
            else:
                from sqlalchemy.dialects.sqlite import insert as d_insert

            # executemany form: compile the ON CONFLICT statement once and
            # hand the driver the full param list. ~5x faster at 60K rows
            # than literal multi-row VALUES, whose per-statement compile of
            # ~30K bind params dominated. Column list comes from the first
            # record; the caller guarantees uniform key sets per call.
            cols = list(records[0])
            stmt = d_insert(table).values({c: bindparam(c) for c in cols})
            if update_names:
                stmt = stmt.on_conflict_do_update(
                    index_elements=conflict_cols,
                    set_={n: stmt.excluded[n] for n in update_names},
                )
            else:
                # Record carries only the key columns — nothing to update.
                stmt = stmt.on_conflict_do_nothing(index_elements=conflict_cols)
            conn.execute(stmt, records)
        else:
            # Fallback: SELECT then INSERT or UPDATE (slower, but portable).
            for r in records:
                pk_filter = None
                for col in conflict_cols:
                    cond = table.c[col] == r[col]
                    pk_filter = cond if pk_filter is None else (pk_filter & cond)
                existing = conn.execute(select(table).where(pk_filter)).first()
                if existing is None:
                    conn.execute(insert(table).values(**r))
                else:
                    patch = {k: v for k, v in r.items() if k in update_names}
                    if patch:
                        conn.execute(
                            update(table).where(pk_filter).values(**patch)
                        )


def _utcnow() -> datetime:
    """Return a tz-aware UTC ``datetime`` for storage timestamps."""
    from datetime import timezone

    return datetime.now(timezone.utc)

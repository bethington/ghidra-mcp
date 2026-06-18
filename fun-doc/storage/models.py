"""SQLAlchemy Core table definitions for the fun-doc storage layer.

This module is dialect-neutral: the same Table objects bind to either the
``fun_doc`` Postgres schema or the default SQLite database. Type choices
(``JSON``, ``DateTime(timezone=True)``, etc.) intentionally lean on
SQLAlchemy's portable types so the same query goes against both engines
without a dialect branch in the repository.

If you change a column here, you also need to change the matching SQL in
``fun-doc/db/migrations/0001_initial.sql`` and ``0001_initial.sqlite.sql``.
The migrations are the source of truth for the on-disk shape; this module
mirrors them for the query layer. We don't auto-generate either side
because the diff would be invisible at code review time.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    text,
)


def build_metadata(schema: str | None = None) -> MetaData:
    """Build a fresh MetaData with all fun-doc tables bound to ``schema``.

    Postgres callers pass ``schema="fun_doc"``; SQLite callers pass ``None``
    (SQLite has no schemas). Repository.__init__ does this once at construction.
    """
    md = MetaData(schema=schema)

    Table(
        "functions_workflow",
        md,
        Column("id", BigInteger, primary_key=True, autoincrement=True),
        # identity
        Column("project_folder", String),
        Column("program_path", String, nullable=False),
        Column("binary_name", String, nullable=False),
        Column("version", String),
        Column("address", String, nullable=False),
        Column("name", String),
        # scoring
        Column("score", Integer),
        Column("effective_score", Integer),
        Column("fixable", Float),
        Column("has_custom_name", Boolean),
        Column("has_plate_comment", Boolean),
        Column("classification", String),
        # queue / workflow
        Column("queue_status", String),
        Column("last_result", String),
        Column("last_processed", DateTime(timezone=True)),
        Column("attempts", Integer, default=0),
        Column("consecutive_fails", Integer, default=0),
        Column("partial_runs", Integer, default=0),
        Column("stagnation_runs", Integer, default=0),
        Column("net_delta", Integer, default=0),
        Column("cost_per_point", Float),
        Column("total_input_tokens", Integer, default=0),
        Column("total_output_tokens", Integer, default=0),
        # snapshot
        Column("snapshot_provider", String),
        Column("snapshot_model", String),
        Column("snapshot_max_turns", Integer),
        # hot counters
        Column("run_count", Integer, default=0),
        Column("audit_count", Integer, default=0),
        Column("escalation_count", Integer, default=0),
        # hot last-event pointers
        Column("last_run_at", DateTime(timezone=True)),
        Column("last_run_provider", String),
        Column("last_run_model", String),
        Column("last_run_delta", Integer),
        Column("last_audited_at", DateTime(timezone=True)),
        Column("last_audit_provider", String),
        Column("last_audit_delta", Integer),
        Column("last_escalated_at", DateTime(timezone=True)),
        Column("last_escalation_from", String),
        Column("last_escalation_to", String),
        # static analysis
        Column("caller_count", Integer, default=0),
        Column("is_leaf", Boolean, default=False),
        Column("call_graph_layer", Integer),
        Column("is_thunk", Boolean, default=False),
        Column("is_external", Boolean, default=False),
        # transient worker state
        Column("is_thrashing", Boolean, default=False),
        # selector one-shot blacklist flags (H22) — without these the
        # selector re-picks pathological functions on every iteration.
        Column("recovery_pass_done", Boolean, default=False),
        Column("decompile_timeout", Boolean, default=False),
        Column("not_a_function", Boolean, default=False),
        Column("decompile_timeout_at", DateTime(timezone=True)),
        Column("library_code", Boolean, default=False),
        Column("library_code_at", DateTime(timezone=True)),
        Column("library_code_reasons", JSON),
        # name-source provenance (#204) — drives the "skip propagated
        # CRT/STL with no archive backing" gate in the selector
        Column("name_source", String, default="scan"),
        Column("name_source_binary", String),
        Column("name_confidence", Float),
        # JSONB blobs
        Column("deductions", JSON),
        Column("callees", JSON),
        # timestamps
        Column("created_at", DateTime(timezone=True)),
        Column("updated_at", DateTime(timezone=True)),
        UniqueConstraint("program_path", "address", name="uq_workflow_path_addr"),
    )

    Table(
        "runs",
        md,
        Column("id", BigInteger, primary_key=True, autoincrement=True),
        Column(
            "function_id",
            BigInteger,
            ForeignKey(
                _qualified("functions_workflow.id", schema), ondelete="CASCADE"
            ),
        ),
        Column("program_path", String),
        Column("address", String),
        Column("function_name", String),
        Column("ts", DateTime(timezone=True)),
        Column("run_kind", String, nullable=False),
        Column("mode", String),
        Column("provider", String, nullable=False),
        Column("model", String, nullable=False),
        Column("score_before", Integer),
        Column("score_after", Integer),
        Column("delta", Integer),
        Column("tool_calls", Integer),
        Column("duration_ms", Integer),
        Column("outcome", String),
        Column("error_class", String),
        Column("output", String),
        Column("notes", String),
    )

    Table(
        "inventory",
        md,
        Column("program_path", String, primary_key=True),
        Column("binary_name", String, nullable=False),
        Column("version", String),
        Column("total_documentable", Integer, default=0),
        Column("scored", Integer, default=0),
        Column("last_scan", DateTime(timezone=True)),
    )

    Table(
        "global_inventory",
        md,
        Column("program_path", String, primary_key=True),
        Column("binary_name", String, nullable=False),
        Column("version", String),
        Column("total_documentable", Integer, default=0),
        Column("fully_documented", Integer, default=0),
        Column("last_scan", DateTime(timezone=True)),
    )

    Table(
        "meta",
        md,
        Column("id", Integer, primary_key=True),
        Column("project_folder", String),
        Column("last_scan", DateTime(timezone=True)),
        Column("current_session", String),
        Column("active_binary", String),
        Column("schema_version", Integer, nullable=False, default=1),
        Column("updated_at", DateTime(timezone=True)),
        CheckConstraint("id = 1", name="ck_meta_singleton"),
    )

    Table(
        "sessions",
        md,
        Column("id", String, primary_key=True),
        Column("started_at", DateTime(timezone=True)),
        Column("ended_at", DateTime(timezone=True)),
        Column("payload", JSON),
    )

    return md


def _qualified(name: str, schema: str | None) -> str:
    """Schema-qualify a table.column reference for ForeignKey strings.

    SQLAlchemy ForeignKey strings need the schema prefix on Postgres but
    must NOT include one on SQLite. Centralizing the conditional keeps the
    table definitions readable.
    """
    if schema:
        return f"{schema}.{name}"
    return name

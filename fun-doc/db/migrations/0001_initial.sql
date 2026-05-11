-- fun-doc PR1 initial schema (Postgres dialect).
--
-- Mirrored at fun-doc/db/migrations/0001_initial.sqlite.sql for the SQLite
-- fallback backend. Differences are dialect-only (BIGSERIAL vs INTEGER,
-- TIMESTAMPTZ vs TEXT, JSONB vs JSON). The application layer reads through
-- SQLAlchemy Core and never branches on backend.
--
-- Hot fields are denormalized onto functions_workflow; per-run history lives
-- in the runs child table. See ~/.claude/plans/fun-doc-postgres-storage-migration.md
-- for the design decisions behind this layout (Q6 in the 8-question spec).

CREATE SCHEMA IF NOT EXISTS fun_doc;

-- ---------- functions_workflow ----------
-- One row per function. UPDATE-heavy: the worker bumps counters and last-event
-- pointers in the same transaction as the runs INSERT.

CREATE TABLE IF NOT EXISTS fun_doc.functions_workflow (
    id                   BIGSERIAL PRIMARY KEY,

    -- identity
    project_folder       TEXT,                       -- Ghidra project root, e.g. F:\GhidraProjects\diablo2
    program_path         TEXT NOT NULL,              -- e.g. /Mods/PD2-S12/D2Common.dll
    binary_name          TEXT NOT NULL,              -- e.g. D2Common.dll
    version              TEXT,                       -- derived from program_path, e.g. 1.13d / PD2-S12
    address              TEXT NOT NULL,              -- hex string, e.g. 6fc21000
    name                 TEXT,

    -- scoring
    score                INTEGER,
    effective_score      INTEGER,                    -- score - structural deductions (cached, recomputed on save)
    fixable              REAL,                       -- total fixable points
    has_custom_name      BOOLEAN,
    has_plate_comment    BOOLEAN,
    classification       TEXT,                       -- wrapper|leaf|orchestrator|...

    -- queue / workflow
    queue_status         TEXT,                       -- queued|in_progress|done|skipped|blacklisted
    last_result          TEXT,                       -- scanned|completed|needs_redo|failed
    last_processed       TIMESTAMPTZ,
    attempts             INTEGER DEFAULT 0,
    consecutive_fails    INTEGER DEFAULT 0,
    partial_runs         INTEGER DEFAULT 0,
    stagnation_runs      INTEGER DEFAULT 0,
    net_delta            INTEGER DEFAULT 0,
    cost_per_point       REAL,
    total_input_tokens   INTEGER DEFAULT 0,
    total_output_tokens  INTEGER DEFAULT 0,

    -- snapshot (frozen at worker start, per existing v5.6 behavior)
    snapshot_provider    TEXT,
    snapshot_model       TEXT,
    snapshot_max_turns   INTEGER,

    -- hot counters (denormalized from runs / audits / escalations)
    run_count            INTEGER DEFAULT 0,
    audit_count          INTEGER DEFAULT 0,
    escalation_count     INTEGER DEFAULT 0,

    -- hot last-event pointers
    last_run_at          TIMESTAMPTZ,
    last_run_provider    TEXT,
    last_run_model       TEXT,
    last_run_delta       INTEGER,
    last_audited_at      TIMESTAMPTZ,
    last_audit_provider  TEXT,
    last_audit_delta     INTEGER,
    last_escalated_at    TIMESTAMPTZ,
    last_escalation_from TEXT,
    last_escalation_to   TEXT,

    -- static analysis facts (from Ghidra, immutable for a given binary build)
    caller_count         INTEGER DEFAULT 0,
    is_leaf              BOOLEAN DEFAULT FALSE,
    call_graph_layer     INTEGER,
    is_thunk             BOOLEAN DEFAULT FALSE,
    is_external          BOOLEAN DEFAULT FALSE,

    -- transient worker state (cleared on worker restart)
    is_thrashing         BOOLEAN DEFAULT FALSE,
    decompile_timeout_at TIMESTAMPTZ,

    -- JSONB blobs (single-row read for dashboard, not aggregate-queried)
    deductions           JSONB,                      -- [{category, points, fixable, count, description}, ...]
    callees              JSONB,                      -- ["6fc2a27a", ...]

    created_at           TIMESTAMPTZ DEFAULT now(),
    updated_at           TIMESTAMPTZ DEFAULT now(),

    UNIQUE (program_path, address)
);

CREATE INDEX IF NOT EXISTS ix_workflow_binary_version
    ON fun_doc.functions_workflow (binary_name, version);
CREATE INDEX IF NOT EXISTS ix_workflow_queue_status
    ON fun_doc.functions_workflow (queue_status)
    WHERE queue_status != 'done';
CREATE INDEX IF NOT EXISTS ix_workflow_classification
    ON fun_doc.functions_workflow (classification);
CREATE INDEX IF NOT EXISTS ix_workflow_score
    ON fun_doc.functions_workflow (score);

-- ---------- runs ----------
-- Append-only per-run history. Mirrors fun-doc/logs/runs.jsonl (which becomes
-- a frozen on-disk artifact after migration).

CREATE TABLE IF NOT EXISTS fun_doc.runs (
    id            BIGSERIAL PRIMARY KEY,
    function_id   BIGINT REFERENCES fun_doc.functions_workflow(id) ON DELETE CASCADE,

    -- duplicate identity for cross-binary / standalone queries (no JOIN required)
    program_path  TEXT,
    address       TEXT,
    function_name TEXT,

    ts            TIMESTAMPTZ DEFAULT now(),

    run_kind      TEXT NOT NULL,              -- doc|audit|escalation|retry
    mode          TEXT,                       -- FULL|FIX|FULL:recovery
    provider      TEXT NOT NULL,
    model         TEXT NOT NULL,

    score_before  INTEGER,
    score_after   INTEGER,
    delta         INTEGER,                    -- score_after - score_before
    tool_calls    INTEGER,
    duration_ms   INTEGER,
    outcome       TEXT,                       -- success|improved|regressed|no_change|error|needs_redo
    error_class   TEXT,
    output        TEXT,                       -- model's full text output (can be large)
    notes         TEXT
);

CREATE INDEX IF NOT EXISTS ix_runs_function_ts
    ON fun_doc.runs (function_id, ts DESC);
CREATE INDEX IF NOT EXISTS ix_runs_provider_ts
    ON fun_doc.runs (provider, ts DESC);
CREATE INDEX IF NOT EXISTS ix_runs_program_address
    ON fun_doc.runs (program_path, address);

-- ---------- inventory ----------
-- Per-binary function-coverage rollup. Replaces fun-doc/inventory.json.

CREATE TABLE IF NOT EXISTS fun_doc.inventory (
    program_path       TEXT PRIMARY KEY,
    binary_name        TEXT NOT NULL,
    version            TEXT,
    total_documentable INTEGER DEFAULT 0,
    scored             INTEGER DEFAULT 0,
    last_scan          TIMESTAMPTZ
);

-- ---------- global_inventory ----------
-- Per-binary global-variable-coverage rollup. Replaces fun-doc/global_inventory.json.
-- Shape mirrors inventory but tracks a different subject (globals, not functions).

CREATE TABLE IF NOT EXISTS fun_doc.global_inventory (
    program_path       TEXT PRIMARY KEY,
    binary_name        TEXT NOT NULL,
    version            TEXT,
    total_documentable INTEGER DEFAULT 0,
    fully_documented   INTEGER DEFAULT 0,
    last_scan          TIMESTAMPTZ
);

-- ---------- meta ----------
-- Project-level state that lived at the top of state.json (project_folder,
-- last_scan, current_session, active_binary). One row per fun-doc instance;
-- single-tenant assumption matches today's deployment.

CREATE TABLE IF NOT EXISTS fun_doc.meta (
    id                INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    project_folder    TEXT,
    last_scan         TIMESTAMPTZ,
    current_session   TEXT,
    active_binary     TEXT,
    schema_version    INTEGER NOT NULL DEFAULT 1,
    updated_at        TIMESTAMPTZ DEFAULT now()
);

INSERT INTO fun_doc.meta (id, schema_version) VALUES (1, 1)
    ON CONFLICT (id) DO NOTHING;

-- ---------- sessions ----------
-- Per-session metadata. state.json carries a list of sessions; we normalize
-- each into its own row keyed by session id (timestamp-derived in v5.x).

CREATE TABLE IF NOT EXISTS fun_doc.sessions (
    id          TEXT PRIMARY KEY,                  -- session id (matches state.json key)
    started_at  TIMESTAMPTZ,
    ended_at    TIMESTAMPTZ,
    payload     JSONB                              -- raw session data; shape evolves between releases
);

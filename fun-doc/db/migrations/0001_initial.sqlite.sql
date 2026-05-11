-- fun-doc PR1 initial schema (SQLite dialect).
--
-- Same logical schema as 0001_initial.sql. Differences:
--   * No CREATE SCHEMA — SQLite has no schemas; the "fun_doc" namespace is
--     dropped from table names. Tables live in the default database.
--   * BIGSERIAL → INTEGER PRIMARY KEY AUTOINCREMENT
--   * TIMESTAMPTZ → TEXT (ISO-8601 strings; SQLAlchemy handles conversion)
--   * BOOLEAN → INTEGER (0/1; SQLAlchemy handles conversion)
--   * JSONB → TEXT (JSON1 extension provides query operators if needed)
--   * Partial-index WHERE clauses are supported in SQLite ≥ 3.8.0
--
-- The application layer reads through SQLAlchemy Core and never branches on
-- backend; this file only exists because raw SQL bootstrap is faster and
-- more transparent than ORM-driven migrations.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------- functions_workflow ----------

CREATE TABLE IF NOT EXISTS functions_workflow (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,

    project_folder       TEXT,
    program_path         TEXT NOT NULL,
    binary_name          TEXT NOT NULL,
    version              TEXT,
    address              TEXT NOT NULL,
    name                 TEXT,

    score                INTEGER,
    effective_score      INTEGER,
    fixable              REAL,
    has_custom_name      INTEGER,                   -- bool 0/1
    has_plate_comment    INTEGER,                   -- bool 0/1
    classification       TEXT,

    queue_status         TEXT,
    last_result          TEXT,
    last_processed       TEXT,                      -- ISO-8601
    attempts             INTEGER DEFAULT 0,
    consecutive_fails    INTEGER DEFAULT 0,
    partial_runs         INTEGER DEFAULT 0,
    stagnation_runs      INTEGER DEFAULT 0,
    net_delta            INTEGER DEFAULT 0,
    cost_per_point       REAL,
    total_input_tokens   INTEGER DEFAULT 0,
    total_output_tokens  INTEGER DEFAULT 0,

    snapshot_provider    TEXT,
    snapshot_model       TEXT,
    snapshot_max_turns   INTEGER,

    run_count            INTEGER DEFAULT 0,
    audit_count          INTEGER DEFAULT 0,
    escalation_count     INTEGER DEFAULT 0,

    last_run_at          TEXT,
    last_run_provider    TEXT,
    last_run_model       TEXT,
    last_run_delta       INTEGER,
    last_audited_at      TEXT,
    last_audit_provider  TEXT,
    last_audit_delta     INTEGER,
    last_escalated_at    TEXT,
    last_escalation_from TEXT,
    last_escalation_to   TEXT,

    caller_count         INTEGER DEFAULT 0,
    is_leaf              INTEGER DEFAULT 0,         -- bool 0/1
    call_graph_layer     INTEGER,
    is_thunk             INTEGER DEFAULT 0,         -- bool 0/1
    is_external          INTEGER DEFAULT 0,         -- bool 0/1

    is_thrashing         INTEGER DEFAULT 0,         -- bool 0/1
    decompile_timeout_at TEXT,

    deductions           TEXT,                      -- JSON
    callees              TEXT,                      -- JSON

    created_at           TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at           TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    UNIQUE (program_path, address)
);

CREATE INDEX IF NOT EXISTS ix_workflow_binary_version
    ON functions_workflow (binary_name, version);
CREATE INDEX IF NOT EXISTS ix_workflow_queue_status
    ON functions_workflow (queue_status)
    WHERE queue_status != 'done';
CREATE INDEX IF NOT EXISTS ix_workflow_classification
    ON functions_workflow (classification);
CREATE INDEX IF NOT EXISTS ix_workflow_score
    ON functions_workflow (score);

-- ---------- runs ----------

CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id   INTEGER REFERENCES functions_workflow(id) ON DELETE CASCADE,

    program_path  TEXT,
    address       TEXT,
    function_name TEXT,

    ts            TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    run_kind      TEXT NOT NULL,
    mode          TEXT,
    provider      TEXT NOT NULL,
    model         TEXT NOT NULL,

    score_before  INTEGER,
    score_after   INTEGER,
    delta         INTEGER,
    tool_calls    INTEGER,
    duration_ms   INTEGER,
    outcome       TEXT,
    error_class   TEXT,
    output        TEXT,
    notes         TEXT
);

CREATE INDEX IF NOT EXISTS ix_runs_function_ts
    ON runs (function_id, ts DESC);
CREATE INDEX IF NOT EXISTS ix_runs_provider_ts
    ON runs (provider, ts DESC);
CREATE INDEX IF NOT EXISTS ix_runs_program_address
    ON runs (program_path, address);

-- ---------- inventory ----------

CREATE TABLE IF NOT EXISTS inventory (
    program_path       TEXT PRIMARY KEY,
    binary_name        TEXT NOT NULL,
    version            TEXT,
    total_documentable INTEGER DEFAULT 0,
    scored             INTEGER DEFAULT 0,
    last_scan          TEXT
);

-- ---------- global_inventory ----------

CREATE TABLE IF NOT EXISTS global_inventory (
    program_path       TEXT PRIMARY KEY,
    binary_name        TEXT NOT NULL,
    version            TEXT,
    total_documentable INTEGER DEFAULT 0,
    fully_documented   INTEGER DEFAULT 0,
    last_scan          TEXT
);

-- ---------- meta ----------

CREATE TABLE IF NOT EXISTS meta (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    project_folder    TEXT,
    last_scan         TEXT,
    current_session   TEXT,
    active_binary     TEXT,
    schema_version    INTEGER NOT NULL DEFAULT 1,
    updated_at        TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT OR IGNORE INTO meta (id, schema_version) VALUES (1, 1);

-- ---------- sessions ----------

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    started_at  TEXT,
    ended_at    TEXT,
    payload     TEXT                                -- JSON
);

-- fun-doc migration 0003: name_source provenance tracking (SQLite dialect).
--
-- Mirror of 0003_name_source.sql for the SQLite backend. Differences are
-- dialect-only (TIMESTAMPTZ -> TEXT, REAL is supported natively, no
-- schema prefix). See the Postgres file for design rationale and the
-- consumer wiring in repository.py + fun_doc.py.
--
-- SQLite doesn't support ALTER TABLE ADD COLUMN IF NOT EXISTS. fun-doc's
-- migration runner (db/migrate.py) makes this idempotent automatically by
-- inspecting PRAGMA table_info(functions_workflow) before each ADD COLUMN
-- and skipping ones whose column is already present.

ALTER TABLE functions_workflow ADD COLUMN name_source TEXT DEFAULT 'scan';
ALTER TABLE functions_workflow ADD COLUMN name_source_binary TEXT;
ALTER TABLE functions_workflow ADD COLUMN name_confidence REAL;

CREATE INDEX IF NOT EXISTS ix_functions_workflow_name_source
    ON functions_workflow (name_source);

-- fun-doc migration 0003: name_source provenance tracking (SQLite dialect).
--
-- Mirror of 0003_name_source.sql for the SQLite backend. Differences are
-- dialect-only (TIMESTAMPTZ -> TEXT, REAL is supported natively, no
-- schema prefix). See the Postgres file for design rationale and the
-- consumer wiring in repository.py + fun_doc.py.
--
-- SQLite doesn't support ALTER TABLE IF NOT EXISTS for ADD COLUMN, so we
-- use one ALTER per column. Re-running this migration after partial
-- application requires manual recovery; the normal path of
-- `python -m db.migrate` records the version in schema_versions and
-- skips re-running entirely.

ALTER TABLE functions_workflow ADD COLUMN name_source TEXT DEFAULT 'scan';
ALTER TABLE functions_workflow ADD COLUMN name_source_binary TEXT;
ALTER TABLE functions_workflow ADD COLUMN name_confidence REAL;

CREATE INDEX IF NOT EXISTS ix_functions_workflow_name_source
    ON functions_workflow (name_source);

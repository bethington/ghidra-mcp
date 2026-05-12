-- fun-doc migration 0002: library_code auto-classification (SQLite dialect).
--
-- Mirror of 0002_library_code.sql for the SQLite backend. Differences are
-- dialect-only (TIMESTAMPTZ -> TEXT, JSONB -> TEXT, BOOLEAN -> INTEGER 0/1).
-- See the Postgres file for design rationale and the consumer wiring in
-- library_code_detector.py + fun_doc.py.
--
-- SQLite doesn't support ALTER TABLE IF NOT EXISTS for ADD COLUMN, so we use
-- one ALTER per column. Re-running this migration after partial application
-- (e.g. one column added, the next failed) requires manual recovery; the
-- normal path of `python -m db.migrate` records the version in
-- schema_versions and skips re-running entirely.

ALTER TABLE functions_workflow ADD COLUMN library_code INTEGER DEFAULT 0;
ALTER TABLE functions_workflow ADD COLUMN library_code_at TEXT;
ALTER TABLE functions_workflow ADD COLUMN library_code_reasons TEXT;

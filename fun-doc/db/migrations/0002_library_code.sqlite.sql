-- fun-doc migration 0002: library_code auto-classification (SQLite dialect).
--
-- Mirror of 0002_library_code.sql for the SQLite backend. Differences are
-- dialect-only (TIMESTAMPTZ -> TEXT, JSONB -> TEXT, BOOLEAN -> INTEGER 0/1).
-- See the Postgres file for design rationale and the consumer wiring in
-- library_code_detector.py + fun_doc.py.
--
-- SQLite doesn't support ALTER TABLE ADD COLUMN IF NOT EXISTS. fun-doc's
-- migration runner (db/migrate.py) makes this idempotent automatically by
-- inspecting PRAGMA table_info(functions_workflow) before each ADD COLUMN
-- and skipping ones whose column is already present. A crashed-mid-script
-- retry (where the column landed but the schema_versions row didn't) now
-- succeeds on the next run instead of requiring manual recovery.

ALTER TABLE functions_workflow ADD COLUMN library_code INTEGER DEFAULT 0;
ALTER TABLE functions_workflow ADD COLUMN library_code_at TEXT;
ALTER TABLE functions_workflow ADD COLUMN library_code_reasons TEXT;

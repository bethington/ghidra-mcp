-- fun-doc migration 0005: OpenD2 conformance port pipeline (SQLite).
-- See 0005_port_pipeline.sql for rationale. db/migrate.py handles
-- IF-NOT-EXISTS via PRAGMA table_info inspection.

ALTER TABLE functions_workflow ADD COLUMN port_status VARCHAR;
ALTER TABLE functions_workflow ADD COLUMN port_attempts INTEGER DEFAULT 0;
ALTER TABLE functions_workflow ADD COLUMN port_draft_path VARCHAR;
ALTER TABLE functions_workflow ADD COLUMN port_last_result VARCHAR;

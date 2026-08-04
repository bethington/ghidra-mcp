-- fun-doc migration 0007: falsifiability axis + audit tool-call persistence (SQLite).
-- See 0007_falsifiability.sql for rationale. db/migrate.py handles
-- IF-NOT-EXISTS via PRAGMA table_info inspection.

ALTER TABLE functions_workflow ADD COLUMN falsify_status VARCHAR;
ALTER TABLE functions_workflow ADD COLUMN falsify_checked_at TIMESTAMP;
ALTER TABLE functions_workflow ADD COLUMN falsify_findings JSON;
ALTER TABLE functions_workflow ADD COLUMN falsify_source VARCHAR;
ALTER TABLE functions_workflow ADD COLUMN audit_tool_calls INTEGER;
ALTER TABLE functions_workflow ADD COLUMN audit_tool_calls_known BOOLEAN;

CREATE INDEX IF NOT EXISTS ix_functions_workflow_falsify_status
    ON functions_workflow (falsify_status);

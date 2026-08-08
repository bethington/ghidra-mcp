-- fun-doc migration 0008: graph-inferred scope exclusion (SQLite).
-- See 0008_scope_excluded.sql for rationale -- in short: `library_code` means a
-- lane matched an artifact, `scope_excluded` means the reference graph inferred
-- it, and the two must stay countable apart. db/migrate.py handles
-- IF-NOT-EXISTS via PRAGMA table_info inspection.

ALTER TABLE functions_workflow ADD COLUMN scope_excluded BOOLEAN;
ALTER TABLE functions_workflow ADD COLUMN scope_excluded_at TIMESTAMP;
ALTER TABLE functions_workflow ADD COLUMN scope_excluded_reasons JSON;

CREATE INDEX IF NOT EXISTS ix_functions_workflow_scope_excluded
    ON functions_workflow (scope_excluded);

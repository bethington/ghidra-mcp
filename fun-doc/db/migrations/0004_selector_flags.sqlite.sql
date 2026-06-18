-- fun-doc migration 0004: selector one-shot blacklist flags (SQLite).
-- See 0004_selector_flags.sql for rationale. db/migrate.py handles
-- IF-NOT-EXISTS via PRAGMA table_info inspection.

ALTER TABLE functions_workflow ADD COLUMN recovery_pass_done BOOLEAN DEFAULT 0;
ALTER TABLE functions_workflow ADD COLUMN decompile_timeout BOOLEAN DEFAULT 0;
ALTER TABLE functions_workflow ADD COLUMN not_a_function BOOLEAN DEFAULT 0;

UPDATE functions_workflow
   SET decompile_timeout = 1
 WHERE decompile_timeout_at IS NOT NULL AND decompile_timeout != 1;

UPDATE functions_workflow
   SET not_a_function = 1
 WHERE last_result = 'not_a_function' AND not_a_function != 1;

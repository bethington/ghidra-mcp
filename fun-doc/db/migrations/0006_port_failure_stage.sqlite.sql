-- fun-doc migration 0006: persist the port prove failure stage (SQLite).
-- See 0006_port_failure_stage.sql for rationale. db/migrate.py handles
-- IF-NOT-EXISTS via PRAGMA table_info inspection.

ALTER TABLE functions_workflow ADD COLUMN port_failure_stage VARCHAR;

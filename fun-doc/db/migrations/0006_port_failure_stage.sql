-- fun-doc migration 0006: persist the port prove failure stage (Postgres).
--
-- process_port_candidate has been writing `port_failure_stage` on every failed
-- live prove since the failure-stage taxonomy landed, but the column never
-- existed: update_function_state filters writes against
-- storage.repository._UPDATABLE_WORKFLOW_FIELDS, so the value was dropped
-- silently, with no exception and no log line. (The same both-lists trap is
-- called out in CLAUDE.md -- it previously no-op'd port_status persistence.)
--
-- The cost of losing it showed up on 2026-07-30: answering "how many functions
-- were retired terminally because the ORACLE was down rather than because
-- anything was wrong with the function" required reconstructing the stage for
-- 234 rows from logs/runs.jsonl, because the authoritative field had been
-- thrown away on every write.
--
-- Values (see port_live_prove.py's taxonomy comment):
--   build_candidate | build_provider_cascade | oracle_unreachable
--   | oracle_died_during | marshal_fault | mismatch | prove_timeout | prove
--   | provider_degraded | weak_uniform

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS port_failure_stage VARCHAR;

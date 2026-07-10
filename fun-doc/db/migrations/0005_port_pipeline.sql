-- fun-doc migration 0005: OpenD2 conformance port pipeline (Postgres).
--
-- Adds the columns needed to track Stage 2/3 ("port" + "prove") of the
-- document -> port -> prove pipeline described in
-- OpenD2/docs/EMULATION_CONFORMANCE_PLAN.md Sec 14. Populated only for
-- functions the new PORT worker mode has touched.
--
-- port_status values: none | drafted | vectors_minted | harness_failed
--                    | proven_pending_review | integrated
-- port_last_result: the most recent harness outcome (a short human-readable
--   PASS/FAIL summary), for surfacing in the dashboard without re-running
--   the harness.

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS port_status VARCHAR;
ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS port_attempts INTEGER DEFAULT 0;
ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS port_draft_path VARCHAR;
ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS port_last_result VARCHAR;

-- fun-doc migration 0004: selector one-shot blacklist flags (Postgres).
--
-- H22 from the 2026-06-17 deep review: process_function() sets
-- recovery_pass_done / decompile_timeout / not_a_function on the in-memory
-- func dict, but _state_func_to_row never forwarded them and this table
-- had no columns to receive them. The selector then re-picked the same
-- pathological functions forever (forced-recovery giants, 60s decompile
-- timeouts, data-not-code addresses at 100K-500K input tokens each).
--
-- Backfill: derive the flag from existing evidence where we can.

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS recovery_pass_done BOOLEAN DEFAULT FALSE;
ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS decompile_timeout BOOLEAN DEFAULT FALSE;
ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS not_a_function BOOLEAN DEFAULT FALSE;

-- Backfill from columns that were already persisted.
UPDATE fun_doc.functions_workflow
   SET decompile_timeout = TRUE
 WHERE decompile_timeout_at IS NOT NULL AND decompile_timeout IS NOT TRUE;

UPDATE fun_doc.functions_workflow
   SET not_a_function = TRUE
 WHERE last_result = 'not_a_function' AND not_a_function IS NOT TRUE;

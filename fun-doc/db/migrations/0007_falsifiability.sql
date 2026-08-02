-- fun-doc migration 0007: the falsifiability axis + audit tool-call persistence (Postgres).
--
-- Falsifiability is the second documentation metric, orthogonal to the
-- completeness score. Completeness is computed entirely FROM the documentation
-- (presence + form), so no observation about the binary can ever lower it -- a
-- confidently wrong plate scores 100. falsify.py closes that gap with
-- mechanical, model-free contradiction checks (declared calling convention vs
-- the callee's actual RET n, documented params vs the live signature, reader
-- names that write globals, ...). These columns persist the verdict:
--
--   falsify_status:      'unchecked' (never ran) | 'passed' (ran, zero tier-1
--                        findings) | 'contradicted' (>=1 tier-1 mechanical
--                        contradiction) | 'unfalsifiable' (every applicable
--                        check hit a confidence guard -- multi-RET epilogue,
--                        varargs, no declared claims). Mirrors CONF_BLOCKED's
--                        rule: "can't be checked" is NOT "passed".
--   falsify_checked_at:  when the checks last ran.
--   falsify_findings:    JSON list of the latest run's findings
--                        [{check_id, tier, claim, evidence, detail}, ...].
--                        A contradicted function keeps its counterexample --
--                        the CONF_REFUTED lesson: erasing the finding lets the
--                        same wrong doc get re-written and re-promoted with no
--                        memory of the contradiction.
--   falsify_source:      'worker' (post-doc stage) | 'sweep'
--                        (scripts/falsify_sweep.py) | 'cross_version'
--                        (scripts/cross_version_disagreement.py).
--
-- The selector keeps 'contradicted' functions eligible past the
-- score-good-enough retire gate (a 100-scoring function carrying a known-false
-- claim is exactly the one that must come back), and DOC_VERIFIED is gated on
-- surviving falsification, not on the score alone.
--
-- Also fixes a live instance of the both-lists trap (CLAUDE.md): the audit
-- stage has stamped audit_tool_calls / audit_tool_calls_known on every audited
-- function since the audit landed, but the columns never existed and the
-- fields are in NEITHER _STATE_DIRECT_FIELDS NOR _UPDATABLE_WORKFLOW_FIELDS,
-- so they were dropped silently on every write (surviving only in runs.jsonl).
-- Same failure shape as 0006's port_failure_stage.

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS falsify_status VARCHAR;

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS falsify_checked_at TIMESTAMPTZ;

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS falsify_findings JSONB;

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS falsify_source VARCHAR;

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS audit_tool_calls INTEGER;

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS audit_tool_calls_known BOOLEAN;

-- The dashboard's falsifiability panel and the selector's contradicted-stays-
-- eligible carve-out both filter on status; keep them off full-table scans.
CREATE INDEX IF NOT EXISTS ix_functions_workflow_falsify_status
    ON fun_doc.functions_workflow (falsify_status);

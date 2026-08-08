-- fun-doc migration 0008: graph-inferred scope exclusion (Postgres).
--
-- `library_code` records that a lane MATCHED AN ARTIFACT: relocation-masked
-- bytes against a real .lib, a Function ID database hit, a BSim match past
-- calibrated floors. It is a claim about what the function IS, and it is
-- checkable.
--
-- `scope_graph` answers a different question and needs its own column.  Its
-- rule is "every function that references this one is library code, to a fixed
-- point" -- an inference from the reference graph, with no artifact behind it.
-- That rule is also satisfied, BY CONSTRUCTION, by every mod entry point the
-- CRT calls: `PD2EXT_InstallBootstrapHook` is authored, is not an export, and
-- its only referrer is the CRT's DllMain. So a swept function is not
-- necessarily library code at all -- it may be third-party, or authored and
-- unreachable.
--
-- Writing that verdict into `library_code` would record "this IS library code"
-- for something nothing was ever matched against, and the only way back would
-- be parsing `library_code_reasons` strings to work out which rows were
-- inferred. With a separate column, correcting a bad verdict is a boolean flip
-- and the two populations stay countable apart -- which the dashboards need,
-- because an inferred exclusion must never render as an identification.
--
--   scope_excluded:          the graph swept this function out of scope.
--   scope_excluded_at:       when the verdict was applied.
--   scope_excluded_reasons:  JSON list of why -- the referrers that justified
--                            it, so the verdict carries its own counterexample
--                            hunt. Same argument as falsify_findings in 0007:
--                            erasing the evidence lets the same wrong verdict
--                            be re-derived with no memory of the last review.
--
-- The selector skips on `library_code OR scope_excluded`; both are caches of
-- durable Ghidra tags (LIB_* and SCOPE_EXCLUDED respectively), and the tag is
-- the authority because it survives a rename.
--
-- Both column names must also appear in fun_doc._STATE_DIRECT_FIELDS AND in
-- storage.repository._UPDATABLE_WORKFLOW_FIELDS. Missing either one drops the
-- field on write with no exception -- the trap that silently no-op'd
-- port_status (0005) and audit_tool_calls (0007). There is a test for it.

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS scope_excluded BOOLEAN;

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS scope_excluded_at TIMESTAMPTZ;

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS scope_excluded_reasons JSONB;

-- The selector filters on this on every pick, and the dashboard counts it per
-- binary; neither should be a full-table scan.
CREATE INDEX IF NOT EXISTS ix_functions_workflow_scope_excluded
    ON fun_doc.functions_workflow (scope_excluded);

-- fun-doc migration 0003: name_source provenance tracking (Postgres dialect).
--
-- Adds three columns to functions_workflow tracking the provenance of the
-- current function name. The selector consults `name_source` (and the
-- companion `name_confidence` score, populated by Q5-D archive gate or
-- BSim match) to decide whether a propagated name should be trusted
-- enough to skip LLM spend, or whether it needs scoring just like an
-- unrenamed FUN_* candidate.
--
-- Motivation: cross-version hash propagation (the workflow that copies
-- function names + plates between binary versions when a SHA-256
-- byte-hash matches) is the dominant source of LLM-token waste on
-- statically-linked CRT/STL code. The propagator gives plausible
-- D2-style names (DATATBLS_*, ROOM_*, CLIENT_*, NET_*, GAME_*) to
-- functions that are actually nlohmann::json templates, std::map
-- operations, iostream parsers etc. -- code that doesn't exist in the
-- binary's authored source. ~10M input tokens were burned on the top 7
-- such misidentifications in BH.dll's last 24h before this gate landed.
-- See #204 for the quantified impact table.
--
-- Values for `name_source`:
--   'scan'        - default, set by /list_functions or the scan pass
--   'manual'      - set by the fun-doc worker after a successful rename
--   'propagation' - set by the cross-version hash propagation scripts
--   'pdb'         - set by ImportMSDLPDB or another PDB-driven path
--   'archive'     - set by the re-kb archive lookup (Q5-D gate pass)
--
-- `name_source_binary` carries the source binary path when name_source
-- = 'propagation'; null otherwise. Lets the user trace a suspect name
-- back to "where did this come from?" without rerunning the propagator.
--
-- `name_confidence` is a 0.0-1.0 score the archive gate / BSim match
-- can populate to override the "skip propagated" rule. Null means
-- "unknown" (treat as low confidence). High confidence + non-pinned +
-- propagation source = "trust the name, don't waste LLM cycles".

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS name_source TEXT DEFAULT 'scan';

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS name_source_binary TEXT;

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS name_confidence REAL;

-- Index helps the selector's "skip propagated, low-confidence,
-- non-pinned" query stay O(log n) instead of full-table scanning on
-- workspaces with 500k+ propagated rows.
CREATE INDEX IF NOT EXISTS ix_functions_workflow_name_source
    ON fun_doc.functions_workflow (name_source);

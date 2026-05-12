-- fun-doc migration 0002: library_code auto-classification (Postgres dialect).
--
-- Adds three columns to functions_workflow tracking the heuristic library-code
-- classification gate that runs before the LLM. When the detector
-- (library_code_detector.py) decides a function is statically-linked MSVC CRT
-- / STL / iostream / SEH code, the worker stamps a generic plate and sets
-- library_code = TRUE so the selector permanently skips the function. Cleared
-- by the existing refresh paths (--scan --refresh, dashboard Refresh Top N).
--
-- See library_code_detector.py for the signal list. Mirrored at
-- 0002_library_code.sqlite.sql for the SQLite backend.

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS library_code BOOLEAN DEFAULT FALSE;

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS library_code_at TIMESTAMPTZ;

ALTER TABLE fun_doc.functions_workflow
    ADD COLUMN IF NOT EXISTS library_code_reasons JSONB;

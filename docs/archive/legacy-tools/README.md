# Legacy CLI Tools (archived 2026-05-14)

These three Python scripts were last touched on 2025-10-10 (v1.6.0).
They find undocumented functions, rank them by xref count and document
them, but without per-function state persistence, run history, parallel
workers, completeness scoring or provider routing. They were superseded
by an external documentation orchestrator that is not part of this
repository.

Anyone hitting "I want to document a binary's undocumented functions"
should drive the MCP tools directly from an AI client, following
[`docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md`](../../prompts/FUNCTION_DOC_WORKFLOW_V5.md).
These files are kept here only as a historical record; they still work against `http://127.0.0.1:8089`
endpoints (those API contracts are stable), but they're not maintained
and won't see new endpoints or convention updates.

## Files

| File | Notes |
| --- | --- |
| `scan_undocumented_functions.py` | "Find all `FUN_*` ranked by xref count". `find_functions` (filter by name, xref count, user-given vs default name) covers this from any MCP client. |
| `scan_functions_mcp.py` | Near-duplicate of `scan_undocumented_functions.py` with a different API path. |
| `document_function.py` | Single-function-at-a-time documentation; the V5 workflow prompt does this interactively. |

## If you really need one

```bash
# Move it back into place (paths preserved):
git mv docs/archive/legacy-tools/<name>.py tools/<name>.py
```

But first check whether the MCP tools and the V5 workflow prompt cover
your case — they almost certainly do.

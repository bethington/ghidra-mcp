# Legacy CLI Tools (archived 2026-05-14)

These three Python scripts predate `fun-doc/` by ~7 months and were
last touched on 2025-10-10 (v1.6.0). They solved the same problem
`fun-doc/` solves today — find undocumented functions, rank them by
xref count, document them — but without:

- per-function state persistence (`fun-doc/state.db`)
- run-history tracking (`runs.jsonl`)
- parallel workers with watchdog/heartbeat
- the completeness scoring rubric
- provider routing / fallback
- the web dashboard
- block-reason / library-code detection
- prompt cache reuse

Anyone hitting "I want to document a binary's undocumented functions"
should reach for `fun-doc/` instead. These files are kept here only as
a historical record; they still work against `http://127.0.0.1:8089`
endpoints (those API contracts are stable), but they're not maintained
and won't see new endpoints or convention updates.

## Files

| File | Replaced by | Notes |
| --- | --- | --- |
| `scan_undocumented_functions.py` | `fun-doc/` selector + dashboard "Worker" tab | "Find all `FUN_*` ranked by xref count" — fun-doc does this continuously with proper state. |
| `scan_functions_mcp.py` | Same as above | Near-duplicate of `scan_undocumented_functions.py` with a different API path. |
| `document_function.py` | `fun-doc/` worker (`python fun_doc.py --manual --address ...`) | Single-function-at-a-time documentation. fun-doc's worker does the same thing with retry, scoring, provider routing, and state persistence. |

## If you really need one

```bash
# Move it back into place (paths preserved):
git mv docs/archive/legacy-tools/<name>.py tools/<name>.py
```

But first check whether `python fun_doc.py --help` covers your case —
it almost certainly does.

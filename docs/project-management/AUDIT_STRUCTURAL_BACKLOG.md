# Structural / Tech-Debt Backlog (2026-06 audit)

Deferred items from the 2026-06 project audit. The acute fixes (threading, recreate_struct
atomicity, CI gates, doc drift, the medium-severity batch) shipped on `audit/fixes-2026-06`.
The items below are larger refactors or lower-severity cleanups that should be scheduled
deliberately rather than rushed — none is a release blocker.

## High-value refactors

1. **`fun_doc.py` `process_function` god-function** (~1,600 lines, nesting up to 8 levels,
   around `fun-doc/fun_doc.py:6935`). Extract the library-code gate, archive-match gate,
   provider-invocation + handoff, and post-scoring/finalization into named module-level
   functions taking an explicit context object. This is the single biggest maintainability
   risk and the hardest surface to unit-test in isolation.

2. **`web.py` `create_app`** (~2,223-line factory, `fun-doc/web.py:1043`). Split routes into
   Flask blueprints and move the worker-loop body (`_run_worker_functions`,
   `_yield_for_quota_pause`) out of the closure so routes are testable per-blueprint.

3. **Untested Java service layer** (~15K LOC) — *MOSTLY DONE*. The
   `DatatypeMcpToolsHandlerValidationTest` stub-provider pattern (drive real service methods
   to hit validation/early-error + no-program branches, no live Ghidra) was extended to every
   previously-untested service: `AnalysisService`, `DocumentationHashService`,
   `XrefCallGraphService`, `SymbolLabelService`, `CommentService`, `MalwareSecurityService`,
   `EmulationService`, `ListingService` (incl. functional `convert_number`),
   `ProgramScriptService` (required-param + GUI-mode + script-execution security gate), and
   `BinaryComparisonService` (functional `computeSimilarity`). The offline Java suite grew
   149 → 221 tests. **Remaining (optional, deeper):** these are validation/early-error +
   graceful-degradation contracts, not full behavioral coverage of the happy paths (which
   need a live program — see the integration tier). Deeper happy-path coverage of the large
   `AnalysisService` surface could still be added against a live fixture.

## Correctness follow-ups (deferred from the shipped fixes)

4. **`tests/performance/` cross-file isolation leak. — RESOLVED.** Symptom: in a single
   process, `test_state_atomicity.py` (×3) and `test_state_lock_reentrant.py` failed with
   "the non-reentrant Lock deadlock has regressed"; each passed in isolation. Real root cause
   (not a leaked lock): `load_state()` goes through `_get_storage_repo()`, which fell back to
   the developer's **real** `fun-doc/state.db` (the conftest size-guard correctly refuses to
   delete a populated DB). Real multi-thousand-row queries + SQLite write-lock contention made
   the 5s timeout trip under single-process load. It only reproduced on a dev machine with real
   data (clean CI had none), which is why each file and clean CI passed. Fix: the autouse
   `_isolate_storage_repo` fixture now forces `FUN_DOC_DB_URL` to a per-test throwaway SQLite,
   so no test ever opens the real DB (also bulletproofs the documented data-loss incident). The
   suite is now collectible in one process (428 passed, 0 failures even with live Ghidra + real
   data), and CI runs it as a single invocation. A separate, purely local artifact remains: a
   global-scorer test picks up the live Ghidra server's open programs when one is running — it
   skips/mocks correctly in CI; left as-is.

5. **`provider_pause.py` full cross-process lost-update.** The shipped fix serializes writes
   with an OS-level interprocess lock and retries `replace()` on Windows `PermissionError`,
   which prevents torn files. It does NOT yet prevent lost-update when two spawned workers
   install different `(provider, model)` pauses concurrently (last-writer-wins). A correct fix
   is a locked read-modify-write that merges on-disk entries — but it needs tombstones so a
   concurrent `clear()` is not undone by the merge. Defer until the merge semantics are
   designed.

6. **`AnalysisService` read-only `invokeAndWait` sites.** The threading refactor converted all
   *transactional* sites to `threadingStrategy`. Several read-only `invokeAndWait` sites remain
   (completeness/analysis computation, the deliberately per-call EDT-yielding loops). For full
   headless consistency these could route through `threadingStrategy.executeRead`, but they are
   read-only and some have explicit EDT-yielding rationale, so this is low priority.

7. **Legacy `state.json` file-fallback block.** `load_state()`/`save_state()` are the live
   facade over the SQL storage layer (called 20+ times) — NOT dead code. Only the in-function
   file fallback (read `state.json` when the SQL repo can't load) is legacy, and
   `_get_storage_repo` already `sys.exit(1)`s before it is reachable. Confirm it is truly
   unreachable, then remove just that block (and the on-disk `state.json` if stale). Keep the
   dict-based API. Update the `test_state_atomicity.py` "(legacy fallback)" tests accordingly.

## Lower-severity cleanups

8. **`EndpointsJsonParityTest` is one-directional.** It asserts every `@McpTool` is in
   `tests/endpoints.json` but not the reverse, so a removed tool leaves an orphaned catalog
   entry that parity won't catch. Add a reverse check (every catalog path resolves to a live
   `@McpTool`).

9. **Provider-invoker event-loop duplication.** `_invoke_gemini` / `_invoke_claude` /
   `_invoke_minimax` each re-implement ~300 lines of near-identical `async for event` dispatch
   (Init/Message/ToolUse/ToolResult handling, `pending_tool_calls` correlation, `provider_turn`
   bus emits). Factor a shared `_consume_provider_events(stream, provider)` helper; keep only
   the per-SDK client setup distinct.

10. **Bridge reaches into FastMCP private internals.** `bridge_mcp_ghidra.py` mutates
    `mcp._tool_manager._tools` directly (wrapped in `except Exception: pass`) to unregister
    dynamic tools — fragile across FastMCP upgrades and fails silently. Use a public
    unregister API if one exists; otherwise at least log on failure.

11. **`build.yml` / `tests.yml` overlap.** Both download Ghidra + install ~18 JARs + build;
    they disagree on trigger branches (`main` vs `main`+`develop`). Consolidating would roughly
    halve the per-push Ghidra-download cost.

12. **Lint/format jobs are non-gating.** `code-quality` (flake8/black `|| true`) and
    `markdown-lint` (`continue-on-error`) always report success. Fine as informational, but they
    imply enforcement that does not exist — either gate them or label them advisory.

## Documented design gap

13. **`SecurityConfig` `GHIDRA_MCP_FILE_ROOT` doc vs. scope.** The class doc says the root
    applies to `/import_file`, `/delete_file`, and `/open_project`. Only `/import_file` takes a
    real filesystem path (now guarded). `/delete_file` and `/open_project` take Ghidra *project*
    domain paths; their analogous guard is project-folder scope (`isPathInProjectScope`), not
    file-root canonicalization. Reword the doc, and wire project-scope enforcement for those two
    if network exposure is ever in scope.

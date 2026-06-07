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

3. **Untested Java service layer** (~15K LOC with no behavioral tests): `AnalysisService`
   (5,198 LOC — the largest file in the repo), `DocumentationHashService`,
   `XrefCallGraphService`, and the Symbol/Comment/Malware/BinaryComparison/Emulation
   services. The `DatatypeMcpToolsHandlerValidationTest` pattern (drive real service methods
   with a stub provider to hit validation/early-error branches, no live Ghidra) is a proven
   template that extends here cheaply.

## Correctness follow-ups (deferred from the shipped fixes)

4. **`tests/performance/` cross-file isolation leak.** When the offline perf suite is
   collected in one process, `test_state_atomicity.py` (×3) and
   `test_state_lock_reentrant.py` fail with "the non-reentrant Lock deadlock has regressed";
   each file passes in isolation. An earlier file leaves `fun_doc._state_lock` held by a
   leaked daemon thread. CI now runs each file in its own process (`python-offline-regression`
   job) to sidestep this, but the underlying leaked thread/lock should be root-caused and the
   suite made collectible in one process.

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

> **Archived 2026-10-07.** Deferred items from the 2026-06 project audit; several are resolved and the fun-doc items left this repo with fun-doc (now in `d2-game-exe`), so it no longer tracks current work.

# Structural / Tech-Debt Backlog (2026-06 audit)

Deferred items from the 2026-06 project audit. The acute fixes (threading, recreate_struct
atomicity, CI gates, doc drift, the medium-severity batch) shipped on `audit/fixes-2026-06`.
The items below are larger refactors or lower-severity cleanups that should be scheduled
deliberately rather than rushed — none is a release blocker.

Items that concerned `fun-doc` (its `process_function` / `create_app` factories,
provider-pause locking, the legacy `state.json` fallback, provider-invoker duplication and
its storage-isolation fix) left this backlog when `fun-doc` moved to its own repository on
2026-08-11; they belong to that repository now.

## High-value refactors

1. **Untested Java service layer** (~15K LOC) — *MOSTLY DONE*. The
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

2. **`AnalysisService` read-only `invokeAndWait` sites.** The threading refactor converted all
   *transactional* sites to `threadingStrategy`. Several read-only `invokeAndWait` sites remain
   (completeness/analysis computation, the deliberately per-call EDT-yielding loops). For full
   headless consistency these could route through `threadingStrategy.executeRead`, but they are
   read-only and some have explicit EDT-yielding rationale, so this is low priority.

## Lower-severity cleanups

3. **`EndpointsJsonParityTest` is one-directional.** It asserts every `@McpTool` is in
   `tests/endpoints.json` but not the reverse, so a removed tool leaves an orphaned catalog
   entry that parity won't catch. Add a reverse check (every catalog path resolves to a live
   `@McpTool`).

4. **Bridge reaches into FastMCP private internals.** `bridge_mcp_ghidra.py` mutates
   `mcp._tool_manager._tools` directly (wrapped in `except Exception: pass`) to unregister
   dynamic tools — fragile across FastMCP upgrades and fails silently. Use a public
   unregister API if one exists; otherwise at least log on failure.

5. **`build.yml` / `tests.yml` overlap.** Both download Ghidra + install ~18 JARs + build;
   they disagree on trigger branches (`main` vs `main`+`develop`). Consolidating would roughly
   halve the per-push Ghidra-download cost.

6. **Lint/format jobs are non-gating.** `code-quality` (flake8/black `|| true`) and
   `markdown-lint` (`continue-on-error`) always report success. Fine as informational, but they
   imply enforcement that does not exist — either gate them or label them advisory.

## Documented design gap

7. **`SecurityConfig` `GHIDRA_MCP_FILE_ROOT` doc vs. scope.** The class doc says the root
   applies to `/import_file`, `/delete_file`, and `/open_project`. Only `/import_file` takes a
   real filesystem path (now guarded). `/delete_file` and `/open_project` take Ghidra *project*
   domain paths; their analogous guard is project-folder scope (`isPathInProjectScope`), not
   file-root canonicalization. Reword the doc, and wire project-scope enforcement for those two
   if network exposure is ever in scope.

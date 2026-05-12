# Release Documentation Index

This directory contains version-specific release documentation for the Ghidra MCP project.

For the full version history, see [CHANGELOG.md](../../CHANGELOG.md) in the project root.

For the release preparation runbook, see
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).

## Current Releases

### v5.9.0 (Latest) — fun-doc SQL storage migration (PR1)

Major release: fun-doc's per-function workflow state moves out of `state.json` (~106 MB single file, swapped per-binary by hand) into a SQL-backed repository abstraction. SQLite is the default backend (`fun-doc/state.db`); set `FUN_DOC_DB_URL=postgresql://...` to use Postgres instead. No endpoint changes — count unchanged at 241.

- **Storage abstraction** (`fun-doc/storage/`) — SQLAlchemy Core schema, factory, repository CRUD, slow-query log. Hot fields denormalized so dashboard reads stay O(1).
- **Schema migrations** (`fun-doc/db/migrations/`) — Postgres and SQLite mirrors. Idempotent migrate runner.
- **One-shot migration tools** — `migrate_state_to_sql.py` + `verify_migration.py` (zero-diff gate).
- **Pre-release smoke runbook** (`fun-doc/scripts/v58_smoke.py`) — single-command migrate/check/verify cycle.
- **Tier-2 doc-quality regression** (`fun-doc/benchmark/bh/`) — grades BH.dll documentation against the upstream Project-Diablo-2/BH source as ground truth. Baseline corpus score 0.442 captured.

Migration path for existing users:
```bash
pip install -r fun-doc/requirements.txt
python fun-doc/scripts/migrate_state_to_sql.py [--state ... --runs ... --inventory ... --global-inventory ...]
python fun-doc/scripts/verify_migration.py [same args]   # expect: zero diff
# restart dashboard — fun-doc/state.db is now canonical; state.json remains for back-compat
```

Known follow-ups (not blockers): globals worker run-write path is JSON-only; `runs.model` persists as 'unknown'; `functions_workflow.run_count` denorm doesn't tick; `/api/stats` slow. PR2 (re-kb FastAPI gateway) deferred to v5.9.0.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.7.2 — critical bridge fix + Linux/Nix compat + toggle extension

Patch release bundling one critical bridge fix and two Linux/Nix setup fixes, plus an extension of the v5.7.1 toggle.

- **Bridge `duplicate parameter name: 'dry_run'` fix** (synthol, [#193](https://github.com/bethington/ghidra-mcp/pull/193), closes [#187](https://github.com/bethington/ghidra-mcp/issues/187)) — the bridge no longer collides its synthetic `dry_run` param with schema-declared ones. Affected every v5.7.0/v5.7.1 user whose plugin exposed `archive_ingest_function` or `archive_ingest_program`; the bridge failed to register tools on startup.
- **Linux/Nix `tools.setup` compat** ([#194](https://github.com/bethington/ghidra-mcp/pull/194), closes [#190](https://github.com/bethington/ghidra-mcp/issues/190) + [#191](https://github.com/bethington/ghidra-mcp/issues/191)) — new `pip_command()` helper probes `python -m pip` first then falls back to a bare `pip` on PATH, fixing setup on Nix-managed Python environments where pip is exposed as a binary but not importable. `find_ghidra_executable` is platform-aware so `ghidraRun.bat` is no longer preferred on Linux. Reported by @Molkars + @letsjustfixit.
- **Strict Naming Enforcement extended to globals** (Hummer12007, [#188](https://github.com/bethington/ghidra-mcp/pull/188)) — the existing Ghidra Tool Option remains strict by default, but disabling it now downgrades the hard name-quality rejects in `rename_data`, `rename_global_variable`, `set_global`, and the `apply_data_type` prefix/type guard to warnings, matching `rename_function_by_address`. Legacy saved values from the **Strict Function Name Enforcement** Tool Option migrate automatically.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.7.1 — community contributions + post-release triage

Patch release bundling five community-contributed PRs and three post-release bug fixes.

- **Function tags** (chompie1337, [#179](https://github.com/bethington/ghidra-mcp/pull/179)) — 10 new MCP endpoints for tagging functions with program-wide labels (`add_function_tag`, `search_functions_by_tag`, `batch_add_function_tags`, etc.). Endpoint catalog grows 231 → 241.
- **isThunk/isExternal filters** (c8rri3r, [#178](https://github.com/bethington/ghidra-mcp/pull/178)) — `search_functions_enhanced` exposes the fields and accepts `is_thunk`/`is_external` query parameters. Closes [#177](https://github.com/bethington/ghidra-mcp/issues/177).
- **Function-name enforcement toggle** (Hummer12007, [#171](https://github.com/bethington/ghidra-mcp/pull/171)) — Ghidra Tool Option to switch verb-tier rejection between hard-reject (default) and warning-only. Power-user escape hatch.
- **Headless startup crash fix** ([#180](https://github.com/bethington/ghidra-mcp/issues/180), originally diagnosed by @MMOStars) — duplicate route registration of `/create_folder` and `/delete_file` was tripping `HttpServerImpl.createContext` with `IllegalArgumentException`. Removed the manual registrations; the `@McpTool` annotations carry them. Affected every Docker/headless deployment.
- **8051 (and similar) address-space fix** ([#184](https://github.com/bethington/ghidra-mcp/issues/184), reported by @Artem-B) — bridge no longer lowercases space names, which broke `CODE:123` etc. on architectures with uppercase-declared spaces.
- **Docker build fix** ([#183](https://github.com/bethington/ghidra-mcp/issues/183), reported by @RocketMaDev) — `Dockerfile` `GHIDRA_VERSION` ARG bumped from `12.0.3` → `12.0.4` to match `pom.xml`.
- **Maven Windows fix** (deckbsd, [#176](https://github.com/bethington/ghidra-mcp/pull/176)) — platform-aware `M2_HOME` candidate (only adds `mvn.cmd` on Windows) eliminates the `OSError` during setup discovery.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.7.0 — globals quality, scope guard, archive integration

- **Four-axis "documented global" bar** — globals must have a meaningful name (`g_` + Hungarian + descriptor), a real type (not `undefined*`), bytes formatted to that type's expected length, and a plate comment with a meaningful one-line summary.
- **`rename_data` / `rename_global_variable` validator gate** — hard-rejects names that fail `NamingConventions.checkGlobalNameQuality(name, type)` with a structured error including the conflicting issue, current type, and a concrete suggestion.
- **New `audit_global` / `audit_globals_in_function` / `set_global` MCP endpoints** — read inspector, per-function bulk auditor, and atomic single-transaction writer. `set_global` applies type, optional `array_length`, name, and plate as a unit with pre-flight rejection (no partial writes), replacing the four-tool chain (`apply_data_type` → `rename_data` → `batch_set_comments` → `create_label`).
- **Per-function scorer deductions** — four new categories cap globals quality at -20 aggregate (`untyped_global` -8, `unformatted_global_bytes` -5, `generic_global_name` -5, `missing_global_plate_comment` -3) so bad globals surface in the work queue at scoring time.
- **Binary-wide bulk scorer** (`fun-doc/global_scorer.py`) — opt-in idle-time daemon mirroring `inventory_scorer.py`'s architecture; persists per-binary coverage to `fun-doc/global_inventory.json`. Dashboard "Global Inventory" panel shows per-binary table with retry on blacklist.
- **Globals worker** — `process_global` pre-audit short-circuit, completed/no_change/regressed classification, `runs.jsonl` rows with `mode="globals"`. `WorkerManager` requires `binary` and rejects a second launch on the same binary (Q11 per-binary lock).
- **Project-folder scope guard** — opt-in two-layer guard preventing multi-version work from accidentally writing to the wrong binary. Layer 1 fun-doc Python validation, Layer 2 Ghidra Java `FrontEndProgramProvider` + `SecurityConfig.isPathInProjectScope`. Off by default (`GHIDRA_MCP_PROJECT_FOLDER` env var).
- **Cross-version doc archive integration** — fun-doc mirrors documented functions to the re-kb FastAPI service and reads from it before invoking the LLM. Q5-D gate (hash-exact OR BSim≥0.9 AND score≥80) applies the archived name + plate via existing MCP tools and skips the LLM. Two new MCP tools (`archive_ingest_function`, `archive_ingest_program`).
- **state.json truncation hardening** — root-caused and fixed an incident where a duplicate `load_state()` raced a writer and saved an empty stub over the real state. `web.py` now delegates to `fun_doc.load_state` (5 retries → `.bak` → raise) and uses atomic-write with an empty-stub guardrail.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.6.0 — release regression + fun-doc workflow

Deploy / regression / debugger:

- **Live deploy regression tiers** — `tools.setup deploy` can run selected contract, benchmark read/write, multi-program, negative-contract, debugger-live, and release-grade suites.
- **Benchmark debugger fixture** — `fun-doc/benchmark` now builds `BenchmarkDebug.exe` alongside `Benchmark.dll` so debugger endpoints can be exercised against a real launched process.
- **Scoped prompt policy** — `/prompt_policy` temporarily handles known automation dialogs during deploy/regression runs while leaving normal interactive prompts untouched.
- **Safer deploy lifecycle** — deploy saves open programs/traces, exits or force-kills matching Ghidra processes, starts Ghidra, waits for MCP/project readiness, and runs schema smoke checks.

fun-doc workflow:

- **Worker config snapshot** — workers freeze policy fields (`good_enough_score`, audit/handoff providers, per-provider `provider_max_turns` + `provider_models`) at start; mid-run live edits no longer affect a running worker. Dashboard renders a per-worker config sub-line and toasts when saved config diverges from a running worker's snapshot.
- **Background inventory scorer** — opt-in idle-time daemon that fills missing `analyze_function_completeness` scores across every binary in the Ghidra project tree. Most-missing-first ordering, single-thread, cooperative pause when doc workers run, session blacklist after 3 strikes. Inventory panel shows per-binary coverage.
- **Quota-aware provider pause/resume** — fun-doc parses provider quota-wall errors (gemini "exhausted your capacity", claude "credit balance is too low", codex "insufficient_quota", minimax) and parks every worker on the affected (provider, model) until the parsed reset time. Soft rate limits (<5 min) stay in retry logic; hard walls (≥5 min) install a pause. Dashboard shows a `quota_paused` worker state with a live wake-time countdown.
- **Function-block worker output** — per-function logs are wrapped in a three-sided gold bracket (top + left + bottom), with header + footer showing the function name (post-rescore name in the footer so renames are visible). Three-column worker grid for higher density.
- **Three new endpoints** — `GET/POST /api/inventory/...` and `GET/POST /api/provider_pauses/...`.

Function-name quality enforcement:

- **Verb-tier rules** at the rename layer: `rename_function_by_address` hard-rejects names that fail Tier 1 / Tier 2 / Tier 3 specificity checks or collide via token-subset with another function in the same program. Returns a structured error (`vague_verb`, `weak_noun_only`, `missing_specifier`, `name_collision`) with a concrete suggestion. Three new completeness deductions surface existing bad names in the work queue.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.5.0 — maintenance release

- **Decompiler lifecycle fixes** — `FunctionService` now disposes owned `DecompInterface` instances across success, early-return, and exception paths instead of leaking subprocesses in long-running sessions.
- **Bridge compatibility fix** — Python tool-name sanitization now enforces Claude/CAPI's 64-character limit and valid-character rules during collision handling.
- **Bundled script hardening** — script-side `DecompInterface` ownership was normalized to scoped cleanup, and Claude-invoking scripts now use bounded waits with terminate/kill fallback.
- **Contributor guidance** — `CONTRIBUTING.md` includes a release-relevant resource-ownership checklist for disposables, transactions, child-process handling, and timeout expectations.
- **Release metadata refresh** — Maven/package metadata, headless/plugin fallback versions, endpoint catalog version, and release docs were updated to `5.5.0`.
- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.4.1 — security release

- **Bearer-token auth** — when `GHIDRA_MCP_AUTH_TOKEN` is set, every HTTP request must carry `Authorization: Bearer <token>`. Timing-safe comparison. `/mcp/health`, `/health`, `/check_connection` are auth-exempt.
- **Bind hardening** — headless server refuses to start on non-loopback `--bind` unless a token is configured.
- **Script gate (breaking change)** — `/run_script_inline` and `/run_ghidra_script` default to 403 unless `GHIDRA_MCP_ALLOW_SCRIPTS=1` is set. These endpoints execute arbitrary Java against the Ghidra process; the pre-v5.4.1 default was unauthenticated RCE when exposed beyond loopback.
- **`GHIDRA_MCP_FILE_ROOT` mechanism** — path-root canonicalization helper for file-handling endpoints. Per-endpoint wire-up scheduled for a follow-on release.
- **CI / ops** — Debugger JARs installed across all 4 GitHub Actions workflows; offline Java tests (11, ~3s) now gate every push/PR; deprecated Ghidra API warnings suppressed; `requests` floor raised to 2.32.0 per CVE-2024-35195.
- **Docs refresh** — `README.md` Security section, `CLAUDE.md`, `CHANGELOG.md` (v5.4.0 entry backfilled), operator prompt docs now cover emulation / debugger / data-flow.
- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.4.0 — feature release

- **P-code emulation** — `EmulationService` adds `/emulate_function` and `/emulate_hash_batch` (brute-force API hash resolution, collision-safe).
- **Live debugger integration** — new `DebuggerService` (17 `/debugger/*` Java endpoints) wrapping Ghidra's TraceRmi framework. Standalone Python `debugger/` package on port 8099 with 22 bridge proxy tools. GUI-only.
- **Data flow analysis** — `/analyze_dataflow` traces PCode-graph value propagation (forward = consumers, backward = producers).
- **Headless program/project management** — `HeadlessManagementService` moves 8 previously-hand-registered headless endpoints into the annotation scanner.
- **Tool count 199 → 222** after catalog regeneration.
- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.3.2 — hotfix

- Pass 2 (`FULL:comments`) now runs for codex and claude — gate fixed so the `-1` sentinel no longer silently skips comments pass.
- `stagnation_runs` one-shot blacklist — stops infinite re-pick loops (200+ stuck-loop runs eliminated in first session).
- Claude `BLOCKED:` false-positive fix — system prompt directs claude to call `mcp__ghidra-mcp__<tool>` directly instead of using `ToolSearch`.
- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.3.1 — hotfix

- `NO_RETRY_DECOMPILE_TIMEOUT = 12s` on all MCP scoring handler paths — eliminates EDT saturation deadlocks.
- 4 additional MCP handler call sites routed through `decompileFunctionNoRetry`.
- Live-verified: 63 runs × 3 providers × 6 parallel workers with zero failures over 125 min.
- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.3.0 — stability + observability

- `/mcp/health` endpoint: pool stats, uptime, memory, active request count.
- HTTP thread pool (size 3): fixes EDT saturation deadlocks.
- Offline annotation-scanner test suite — catches `@McpTool` / `endpoints.json` drift without Ghidra.
- Atomic `state.json` writes via temp + fsync + os.replace + .bak rotation.
- 199 MCP tools.
- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.2.0 — scoring redesign + naming enforcement

- Log-scaled budget scoring system with tiered plate comment quality.
- `NamingConventions.java`: auto-fix Hungarian prefixes, PascalCase validation, module prefix support.
- New tools: `set_variables`, `check_tools`, `rename_variables`.
- 193 MCP tools.
- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v4.3.0 — knowledge DB + BSim

- 5 new knowledge DB MCP tools (store/query function knowledge, ordinal mappings, export).
- BSim Ghidra scripts for cross-version function similarity matching.
- Fixed enum value parsing (GitHub issue #44).
- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v4.1.0 — parallel multi-binary

- Every program-scoped MCP tool now accepts optional `program` parameter.
- 188 MCP tools.
- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v4.0.0 — service layer refactor

- Extracted 12 shared service classes (`com.xebyte.core/`). Plugin reduced 69%, headless reduced 67%. Zero breaking changes.
- 184 MCP tools.
- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

## Earlier Releases (v1.x – v3.x)

Summarized below; detailed per-release docs are in [archive/](archive/).

| Version | Type | Highlights |
|---------|------|-----------|
| v3.2.0 | fixes | Trailing slash, fuzzy match JSON, completeness checker overhaul |
| v3.1.0 | feature | Server control menu, deployment automation, TCD auto-activation |
| v3.0.0 | major | Headless server parity, 8 new tool categories, 179 tools |
| v2.0.2 | compat | Ghidra 12.0.4 support, large-function pagination |
| v2.0.0 – v2.0.1 | fixes | Label deletion endpoints, CI fixes |
| v1.9.4 | feature | Function hash index, cross-binary documentation propagation |
| v1.9.3 | feature | Documentation organization, workflow enhancements |
| v1.9.2 | release | Features, fixes, release checklist |
| v1.7.3 | release | Version 1.7.3 changes |
| v1.7.2 | release | Version 1.7.2 changes |
| v1.7.0 | release | Version 1.7.0 changes |
| v1.6.0 | feature | Feature status, implementation summary, verification report |
| v1.5.1 | hotfix | Final improvements |
| v1.5.0 | feature | Implementation details, hotfix v1.5.0.1 |
| v1.4.0 | feature | Data structures, field analysis, code review |

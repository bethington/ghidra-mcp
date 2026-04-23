# Release Documentation Index

This directory contains version-specific release documentation for the Ghidra MCP project.

For the full version history, see [CHANGELOG.md](../../CHANGELOG.md) in the project root.

## Current Releases

### v5.5.0 (Latest) — maintenance release

- **Decompiler lifecycle fixes** — `FunctionService` now disposes owned `DecompInterface` instances across success, early-return, and exception paths instead of leaking subprocesses in long-running sessions.
- **Bridge compatibility fix** — Python tool-name sanitization now enforces Claude/CAPI's 64-character limit and valid-character rules during collision handling.
- **Bundled script hardening** — script-side `DecompInterface` ownership was normalized to scoped cleanup, and Claude-invoking scripts now use bounded waits with terminate/kill fallback.
- **Contributor guidance** — `CONTRIBUTING.md` now includes a release-relevant resource-ownership checklist for disposables, transactions, child-process handling, and timeout expectations.
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

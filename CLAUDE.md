# Ghidra MCP - Claude Code Guide

## Overview

MCP server bridging Ghidra reverse engineering with AI tools. 256 MCP tools for binary analysis.

- **Package**: `com.xebyte` | **Version**: 5.15.0 | **Java**: 21 LTS | **Ghidra**: 12.1.2

## Boil the ocean

The marginal cost of completeness is near zero with AI. Do the whole thing. Do it right. Do it with tests. Do it with documentation. Do it so well that Ben is genuinely impressed — not politely satisfied, actually impressed. Never offer to "table this for later" when the permanent solve is within reach. Never leave a dangling thread when tying it off takes five more minutes. Never present a workaround when the real fix exists. The standard isn't "good enough" — it's "holy shit, that's done." Search before building. Test before shipping. Ship the complete thing. When Ben asks for something, the answer is the finished product, not a plan to build it. Time is not an excuse. Fatigue is not an excuse. Complexity is not an excuse. Boil the ocean.

**Scope of "boil the ocean": code, analysis, and local work — never public or community actions.** It means finish the *engineering*. It does NOT mean act autonomously on the community's behalf. See the next section.

## Community interaction (read-only by default)

This is a public repo with real external contributors. Their issues, PRs, and commits are theirs, not yours to dispose of. Reading is always fine; every write below is the human maintainer's to do, and you may only *draft* text for Ben to review and post himself.

- **Never edit, close, comment on, merge, or reopen another person's issue or PR** without Ben's explicit, per-action go-ahead. Never edit anyone's issue/PR/comment *text* — that reads as tampering and is never acceptable.
- **Draft / WIP / "do not merge" means hands off.** Never cherry-pick, merge, or otherwise pull in a draft PR's work. Draft is the contributor's signal that it isn't ready; respect it.
- **To use a contributor's work, merge their PR through the normal flow** (which credits them) — never extract the commit around them or push it to `main` directly.
- **Never post AI-generated text as if it were Ben's own analysis**, and never post a claim about someone else's work without verifying it against the code first.
- When Ben asks for a reply to a contributor, produce a short draft *for him to send in his own words* — do not post it, and do not make it sound machine-generated.
- A local `.claude/` hook (`block-community-github-writes.py`) enforces a slice of this by denying write-shaped `gh` commands; treat that as a backstop, not the boundary. The boundary is this section.

## Architecture

```
AI Tools <-> MCP Bridge (python/bridge_mcp_ghidra/) <-> Ghidra Plugin (GhidraMCPPlugin.jar)
```

- **Plugin**: `src/main/java/com/xebyte/GhidraMCPPlugin.java` -- HTTP server, delegates to services
- **Bridge**: `python/bridge_mcp_ghidra/` (package, split into focused modules: `config`, `state`, `server`, `validation`, `transport`, `discovery`, `schema`, `dispatch`, `registry`, `static_tools`, `debugger`, `cli`) -- dynamic tool registration from `/mcp/schema` + static tools (7 instance/tool-group/import: `list_instances`, `connect_instance`, `list_tool_groups`, `load_tool_group`, `unload_tool_group`, `check_tools`, `import_file`; + 22 debugger proxy via `GHIDRA_DEBUGGER_URL`). Ships as the `ghidra-mcp-bridge` wheel; `bridge-mcp-ghidra` console script. Cross-module functions are called module-qualified (e.g. `transport.do_request`, `dispatch.dispatch_get`) and mutable runtime state lives in `state.py`, so each function has one canonical mock-patch target.
- **Service Layer**: `src/main/java/com/xebyte/core/` -- 14 service classes (~20K lines), `@McpTool`/`@Param` annotated. v5.4.0 adds `EmulationService` (P-code emulation), `DebuggerService` (TraceRmi wrapping — GUI-only)
- **Debugger (Python)**: `debugger/` -- standalone HTTP server on port 8099 (engine, protocol, tracing, address_map, d2/ conventions). Bridge proxies via `GHIDRA_DEBUGGER_URL` env var.
- **Headless**: `src/main/java/com/xebyte/headless/` -- standalone server without GUI. Includes `HeadlessManagementService` for program/project lifecycle.
- **fun-doc**: `fun-doc/` -- AI-driven function documentation workflow (separate from MCP tools). `fun_doc.py` (~9,800 lines) manages a priority queue of functions, routes LLM scoring, and persists per-function workflow state, run history, and inventories to a SQL store via `fun-doc/storage/` (SQLAlchemy Core abstraction; SQLite default at `fun-doc/state.db`, Postgres opt-in via `FUN_DOC_DB_URL` or `priority_queue.json -> config.storage`). The `fun_doc` Postgres schema is sibling to `re_kb` in the same `bsim` instance — see [RE-Universe](https://github.com/bethington/re-universe) for the published API. Migration tooling lives in `fun-doc/scripts/migrate_state_to_sql.py` + `verify_migration.py` (zero-diff gate); see `~/.claude/plans/fun-doc-postgres-storage-migration.md` for the design. `web.py` is the web dashboard. Sibling modules: `inventory_scorer.py` (idle-time daemon filling missing completeness scores; persists to `fun_doc.inventory`) and `provider_pause.py` (per-(provider, model) quota-wall detector backed by `fun-doc/provider_pauses.json`). Workers freeze a config snapshot at start so live edits don't affect running workers. Legacy `state.json` is read only as a fallback when the SQL backend can't be loaded. Not exposed as MCP tools — internal curation subsystem. See `tests/performance/test_state_atomicity.py` (legacy fallback) and `test_storage_*.py` (SQL backend) for regression coverage.
- **Annotation Scanner**: `AnnotationScanner.java` discovers `@McpTool` methods, generates `/mcp/schema`

Services use constructor injection: `ProgramProvider` + `ThreadingStrategy`.
- FrontEnd mode: `FrontEndProgramProvider` + `DirectThreadingStrategy`
- Headless mode: `HeadlessProgramProvider` + `DirectThreadingStrategy`

## Tool Inventory

Do not try to keep the full tool list in this file.

- **Authoritative repo snapshot**: `tests/endpoints.json` (251 endpoints, categories, descriptions)
- **Authoritative runtime schema**: `/mcp/schema` from the running server
- **Usage patterns / operator guide**: `docs/prompts/TOOL_USAGE_GUIDE.md`

Use this file for architecture, conventions, and implementation guidance; use the schema and endpoint catalog for the complete tool inventory.

## Build & Deploy

Two backends are supported. Maven is the default used by `tools.setup`; Gradle is available through the wrapper when Maven is not installed or when testing the migration path. Switch with `TOOLS_SETUP_BACKEND=gradle`.

**Gradle fallback / migration path (set `TOOLS_SETUP_BACKEND=gradle` or invoke directly):**

```text
# Direct Gradle invocation — no tools.setup required
./gradlew buildExtension -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC
./gradlew preflight      -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC
./gradlew deploy         -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC
./gradlew startGhidra    -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC

# Via tools.setup facade (same commands, Gradle backend)
$env:TOOLS_SETUP_BACKEND = "gradle"
python -m tools.setup build
python -m tools.setup preflight --ghidra-path F:\ghidra_12.1.2_PUBLIC
python -m tools.setup deploy    --ghidra-path F:\ghidra_12.1.2_PUBLIC
```

**Maven (default — existing tooling unchanged):**

```text
python -m tools.setup build
python -m tools.setup preflight      --ghidra-path F:\ghidra_12.1.2_PUBLIC
python -m tools.setup ensure-prereqs --ghidra-path F:\ghidra_12.1.2_PUBLIC
python -m tools.setup deploy         --ghidra-path F:\ghidra_12.1.2_PUBLIC
```

- Maven: `C:\Users\benam\tools\apache-maven-3.9.6\bin\mvn.cmd`
- Ghidra install: `F:\ghidra_12.1.2_PUBLIC`
- `tools.setup` delegates to Maven by default; set `TOOLS_SETUP_BACKEND=gradle` to route the same commands to Gradle
- Deploy handles: build, extension install, FrontEndTool.xml patching, Ghidra restart
- Migration plan: `docs/project-management/GRADLE_MIGRATION_CHECKLIST.md`

## Releases

Use `docs/releases/RELEASE_CHECKLIST.md` as the canonical release runbook. Do
not duplicate the whole checklist here; keep this file light enough to fit in
agent context.

Release floor before tagging or publishing:

```text
python -m tools.setup verify-version
python -m tools.setup build
pytest tests/unit/ -v --no-cov
python -m tools.setup deploy --ghidra-path F:\ghidra_12.1.2_PUBLIC --test release
```

Run UI-touching deploy/regression only after confirming the current Ghidra UI
state when modal dialogs may be present.

## Running the MCP Server

```bash
uv run bridge-mcp-ghidra                       # stdio (recommended for AI tools)
uv run bridge-mcp-ghidra --transport sse       # SSE (web/HTTP clients)
uv run python -m bridge_mcp_ghidra             # equivalent module form
uv sync --group debugger                       # optional debugger deps
uv run python -m debugger                      # standalone debugger server on :8099
```

The bridge is a package under `python/bridge_mcp_ghidra/` and ships as a wheel
(`ghidra_mcp_bridge`); installs expose the `bridge-mcp-ghidra` console script.

Ghidra HTTP endpoint: `http://127.0.0.1:8089`

## Adding New Endpoints

1. Add `@McpTool` + `@Param` method in the appropriate service class
2. AnnotationScanner auto-discovers it -- no bridge or registry changes needed
3. Add entry to `tests/endpoints.json` with path, method, category, description

For complex tools needing bridge-side logic (retries, multi-call orchestration), add a static `@mcp.tool()` in `python/bridge_mcp_ghidra/static_tools.py` (or `debugger.py`) and add the name to `STATIC_TOOL_NAMES` in `config.py`.

## Code Conventions

- All endpoints return JSON
- Transactions must be committed for Ghidra database changes
- Prefer batch operations over individual calls
- `@Param(value = "program")` defaults to `ParamSource.QUERY` -- POST endpoints must send `program` as URL query param, not in JSON body

## Convention Enforcement (Opinionated Tooling)

The longer this project was used across many versions and hundreds of thousands of functions, the less reliable prompt-only discipline became. Models drift, improvise, and skip conventions in much the same way people do.

The tools actively enforce RE documentation standards. This is intentional. v5.0 moves conventions into the tool layer so documentation stays readable, reusable, and consistent across both solo large-scale RE workflows and teams.

- **`NamingConventions.java`**: Centralized validation. All naming tools route through this.
- **Struct fields**: Auto-prefixed with correct Hungarian notation on `create_struct`, `add_struct_field`, `modify_struct_field`. The model doesn't need to know the prefix rules -- the tool handles it.
- **Function names**: `rename_function_by_address` warns on non-PascalCase, missing verbs, short names. Module prefixes (`UPPERCASE_`) are accepted and validated separately.
- **Globals/Labels**: `rename_or_label` warns if globals lack `g_` prefix or labels aren't snake_case.
- **Plate comments**: `batch_set_comments` warns on missing Algorithm/Parameters/Returns sections.
- **Type changes**: `set_local_variable_type` rejects `undefined` -> `undefined` (no-op protection).
- **Completeness scoring**: `analyze_function_completeness` returns budgeted scores with log-scaled deductions. Structural deductions are fully forgiven in effective_score.

When building new tools or modifying existing ones, wire validation through `NamingConventions` to maintain consistency.

## Testing

Three tiers by cost and prerequisites:

1. **Unit** (`pytest tests/unit/`) — pure Python, no Ghidra, no side effects. Covers bridge utils, debugger engine, setup CLI, catalog/schema consistency. Fast (<5s).
2. **Offline** — Java scanner/parity + Python regression tests that don't hit Ghidra on 8089. Fast (<10s).
3. **Integration** (`pytest tests/` + `mvn test`) — requires live Ghidra on port 8089 with a binary open. Slow and stateful.

### Match change → tests

Find the file(s) you edited below; run everything in that row. Always include the tier-1 Unit + Offline row as a floor unless noted.

| Change location | Run |
| --- | --- |
| `src/main/java/com/xebyte/core/*Service.java` (any service class) | Offline (Java) + Integration (Java) + `tests/integration/test_readonly_endpoints.py` |
| `src/main/java/com/xebyte/core/AnalysisService.java` — `/get_function_pcode` / `/get_language_metadata` (#192) | Offline (Java) + `tests/integration/test_readonly_endpoints.py::TestProgramInfo::test_get_language_metadata*` + `::TestFunctionAnalysis::test_get_function_pcode_*`. Requires live Ghidra with the new JAR deployed. |
| `src/main/java/com/xebyte/core/ServerManager.java` — UDS + TCP port advertising (#175) | Offline (Java) `ServerManagerPortTest` for `boundTcpPort` field; `tests/integration/test_readonly_endpoints.py::test_mcp_instance_info_on_tcp` for the live endpoint. |
| `src/main/java/com/xebyte/core/NamingConventions.java` | Offline (Java) — `NamingConventionsTest` covers function-name verb-tier rules + token-subset duplicate detection + global-name validator (`checkGlobalNameQuality`, `checkGlobalPlateComment`, `isAutoGeneratedGlobalName`). After deploy: `tests/integration/test_safe_write_endpoints.py` + `tests/integration/test_global_endpoints.py`. Also re-run fun-doc benchmark (`--mock --tier fast --compare`). |
| `src/main/java/com/xebyte/core/DataTypeService.java` — `audit_global` / `set_global` | Offline (Java) `NamingConventionsTest` for the helpers; `tests/integration/test_global_endpoints.py` for live endpoint behavior (post-deploy only — auto-skips when endpoints aren't registered). |
| `src/main/java/com/xebyte/core/SymbolLabelService.java` — `rename_data` / `rename_global_variable` validator hook | Offline (Java) `NamingConventionsTest` for the rule; `tests/integration/test_global_endpoints.py` for the structured-rejection round-trip. |
| Add/modify `@McpTool` / `@Param` annotation | Offline (Java) first — `EndpointsJsonParityTest` will fail if `tests/endpoints.json` is stale. Regenerate: `mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`. Then Integration (Java). |
| `src/main/java/com/xebyte/GhidraMCPPlugin.java` (HTTP routes) | Offline (Java) + `EndpointRegistrationTest` (integration) + `tests/performance/test_http_concurrency.py`. For UDS/TCP defaults + TCP port-range fallback (#175): manual verification with port 8089 occupied, expect bind on 8090; `/mcp/instance_info → tcp_port` should report the actual bound port. |
| `src/main/java/com/xebyte/headless/*` | Offline (Java) + `tests/unit/test_setup_ghidra.py` + Integration (Java) headless run |
| `python/bridge_mcp_ghidra/*` (bridge package) | `tests/unit/test_bridge_utils.py tests/unit/test_mcp_tools.py tests/unit/test_mcp_tool_functions.py tests/unit/test_response_schemas.py tests/unit/test_endpoint_catalog.py tests/unit/test_project_consistency.py`. For multi-candidate socket dir scan (#170): `TestGetSocketDirCandidates` + `TestDiscoverInstancesMultiDir`. For TCP port-range scanner (#175): `TestTcpPortScan`. For debugger-tool platform gating: `TestDebuggerEnabled` + `TestDebuggerToolRegistration`. Per-module size cap is 800 lines (`test_bridge_modules_stay_focused`). Mock-patch targets are module-qualified (e.g. `bridge_mcp_ghidra.dispatch.dispatch_get`, `bridge_mcp_ghidra.transport.do_request`); mutable globals live in `bridge_mcp_ghidra.state`. |
| `fun-doc/library_code_detector.py` — heuristic library-code classifier | `tests/performance/test_library_code_detector.py` (19-case unit suite) + `tests/performance/test_selector_invariants.py` (3 selector-skip cases). Live spot-check on a binary known to contain CRT/STL (e.g. anything compiled with MSVC `/MT`): confirm functions like `ParseSignedShort` classify but real user code (e.g. exported APIs) does not. |
| `fun-doc/fun_doc.py` — state, sessions, locking, selector, scoring | `tests/performance/test_state_atomicity.py tests/performance/test_state_lock_reentrant.py tests/performance/test_selector_invariants.py tests/performance/test_event_bus_drain.py` + fun-doc benchmark (`--mock --tier fast --compare`) |
| `fun-doc/fun_doc.py` — provider routing, prompt construction | `tests/performance/test_provider_selection.py tests/performance/test_ghidra_offline.py tests/performance/test_globals_worker.py` + fun-doc benchmark |
| `fun-doc/web.py` — worker loop, heartbeats, dashboard | `tests/performance/test_state_atomicity.py tests/performance/test_worker_watchdog.py tests/performance/test_dashboard_single_instance.py tests/performance/test_worker_config_snapshot.py` |
| `fun-doc/inventory_scorer.py` | `tests/performance/test_inventory_scorer.py` |
| `fun-doc/provider_pause.py` | `tests/performance/test_provider_pause.py` |
| `fun-doc/event_bus.py` / `event_log.py` | `tests/performance/test_event_bus_drain.py` |
| `fun-doc/audit/*` | `tests/performance/test_audit_rules.py tests/performance/test_audit_registry.py` |
| `fun-doc/benchmark/scorer.py` or `truth/*.yaml` or `src/*.c` | `tests/performance/test_benchmark_scorer.py tests/performance/test_benchmark_extract_truth.py tests/performance/test_benchmark_haiku_judge.py tests/performance/test_benchmark_ghidra_bridge.py` + rerun the benchmark itself |
| `debugger/*` | `tests/unit/test_address_map.py tests/unit/test_d2_conventions.py tests/unit/test_debugger_engine.py tests/unit/test_debugger_server.py tests/unit/test_windbg.py` |
| `tools/setup/*`, `build.gradle`, `pom.xml` | `tests/unit/test_setup_cli.py tests/unit/test_setup_ghidra.py tests/unit/test_gradle_tasks.py tests/unit/test_version_bump.py tests/unit/test_project_consistency.py` |
| `tests/endpoints.json` hand-edit | Offline (Java) — `EndpointsJsonParityTest` verifies every `@McpTool` is listed and hand-authored descriptions are preserved |
| CLI: `bridge-mcp-ghidra --transport` / `python -m bridge_mcp_ghidra`, `tools.setup` subcommands | `tests/unit/test_setup_cli.py` + manual invocation |

### Commands

**Unit (always cheap, run by default):**

```text
pytest tests/unit/ --no-cov
```

**Offline Java (scanner + endpoints.json parity, ~11 tests, <1s):**

```text
# Gradle
./gradlew test --tests 'com.xebyte.offline.*' -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC
# Maven
mvn test -Dtest='com.xebyte.offline.*Test'
```

**Offline Python (no Ghidra needed — the whole performance/ dir minus 4 integration-flavored files):**

```text
pytest tests/performance/ \
  --ignore=tests/performance/test_batch_scoring_consistency.py \
  --ignore=tests/performance/test_health_endpoint.py \
  --ignore=tests/performance/test_http_concurrency.py \
  --ignore=tests/performance/test_listing_consistency.py \
  --no-cov
```

(The four excluded files hit `http://127.0.0.1:8089` and need live Ghidra.)

**Integration (Ghidra running on 8089 with a binary open):**

```text
# Java
./gradlew test -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC   # or: mvn test
# Python — subset by marker
pytest tests/ -m readonly          # safe, no writes
pytest tests/ -m safe_write        # identity writes only
pytest tests/                      # full suite, includes mutating tests
```

### Catalog drift

If `EndpointsJsonParityTest` fails after `@McpTool` edits, regenerate `tests/endpoints.json` from the scanner (preserves hand-authored descriptions and hand-registered routes):

```text
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
```

## Key Gotchas

- **Ghidra overwrites FrontEndTool.xml on exit** -- deploy must patch AFTER Ghidra exits
- **Shared server renames not persisted by save_program** -- must checkin to persist
- **Max ~5 shared server programs open at once** -- opening 20+ crashes Ghidra
- **`switch_program` matches by name** -- for multi-version work, use the `program` query parameter on individual endpoints instead
- **Plate comment `\n` creates literal text**, not newlines -- use actual multi-line text
- **GUI operations from HTTP threads** must use `SwingUtilities.invokeAndWait()`

## Benchmark

`fun-doc/benchmark/` holds a reproducible regression harness for fun-doc's documentation quality. It re-documents a fixed set of functions against a ground-truth answer key (handcrafted C compiled into `Benchmark.dll`) and scores the result via a multi-level rubric plus structural signature/type checks, reporting quality and guardrail metrics.

**When to run.** Manual only — no automation fires it. Run `python fun-doc/benchmark/run_benchmark.py --mock --tier fast --compare` *before and after* any change that can affect documentation quality. The `--compare` flag diffs against the previous `runs/latest.json`. Commit the resulting `runs/*.json` + `runs/latest.json` along with the code change so `git blame` on `runs/latest.json` tells you exactly which commit moved a score.

**Files whose changes SHOULD trigger a rerun:**

- `fun-doc/fun_doc.py` — prompt construction, scoring, orchestration, provider invocation
- `fun-doc/web.py` — worker loop, pre-refresh, adaptive refresh, phase transitions
- `fun-doc/benchmark/scorer.py` — the scorer itself (validate the benchmark didn't drift with the rubric)
- `fun-doc/benchmark/truth/*.truth.yaml` — ground-truth semantic overlays
- `fun-doc/benchmark/src/*.c` — the baseline binary's source (requires `build.py` + `extract_truth.py` rerun first)
- `src/main/java/com/xebyte/core/NamingConventions.java` — any change to the validation cascade
- `src/main/java/com/xebyte/core/*.java` service changes that alter MCP tool behavior
- `tests/endpoints.json` — tool schema / description changes (affects what the worker calls)
- `python/bridge_mcp_ghidra/` — bridge-level prompt caching, tool orchestration, provider routing
- The provider client wrappers (minimax / gemini / claude / codex invocation paths)
- `priority_queue.json`'s `config.provider_models` — the benchmark tests whatever model table is live

**Status.** The fast tier's 5 archetype functions (CRC-16, state machine, strlen, struct mutator, recursion) are authored and ship as `Benchmark.dll`; the `--mock` path (reads pre-captured fixtures under `fixtures/`) is the only driver that works today. The `--real` path — which would invoke fun-doc against `Benchmark.dll` in Ghidra for real — is stubbed pending (1) install of VC6 SP6 to match D2 1.13d's toolchain (modern MSVC is the current placeholder), (2) a dedicated Ghidra project hosting `Benchmark.dll`, (3) a reset script that restores a pristine `.gzf` between suites. See `fun-doc/benchmark/README.md` for the full design and rollout plan.

## Auditing

Two independent systems both called "audit". They don't interact. Knowing which one's active for which problem saves hours.

### System-health audit watcher (Phase 1, always on)

Lives in [`fun-doc/audit/`](fun-doc/audit/). Subscribes to the bus (`ghidra_health`, `worker_started`, `worker_stopped`, `provider_timeout`, `run_logged`) and evaluates rules in [`rules.yaml`](fun-doc/audit/rules.yaml) every 30 s. When a rule fires:

- `audit.triggered` event → `logs/events.jsonl`
- Fire record appended to [`audit/queue.jsonl`](fun-doc/audit/queue.jsonl)
- Registry updated in [`audit/registry.json`](fun-doc/audit/registry.json) — tracks per-signature cooldowns (1-per-day default) and a global circuit breaker (3 fires in 10 min → halt all fires for 1 h)
- All rules currently pinned at `mode: report` — no agent action. Phase 3 will wire in a drain agent that acts on the queue.

The watcher has already earned its keep: the four deadlocked workers we debugged on 2026-04-24 were first flagged by the `bridge_counter_stall` rule 30+ min before py-spy confirmed the root cause. Treat fires as real signals even before Phase 3.

Reset procedure (when rules have false-positive fired and cooldowns are blocking fresh evidence):

```bash
# Archive today's fires, reset registry to armed state
mv fun-doc/audit/queue.jsonl fun-doc/audit/queue.jsonl.$(date +%Y-%m-%d)-archived
printf '' > fun-doc/audit/queue.jsonl
python -c "import json; open('fun-doc/audit/registry.json','w').write(json.dumps({'circuit_breaker':{'fires_window':[],'halt_until':None,'state':'armed','tripped_at':None},'signatures':{}}, indent=2))"
# Restart dashboard for the live watcher to re-read from disk (file edits don't hot-reload)
```

### Per-function audit (optional second-pass review)

After a worker documents a function, a different provider re-examines the result and fixes gaps. Configured in the dashboard's settings popout (or directly in `priority_queue.json`):

| Field | Values | Effect |
| --- | --- | --- |
| `config.audit_provider` | `null` / `claude` / `codex` / `minimax` / `gemini` | Which provider runs the second pass. `null` = off. |
| `config.audit_min_delta` | integer (default 5) | Skip audit if the worker already gained ≥ this many points. Lower = more audits. |

When enabled, every run writes an `audit_outcome` field into `logs/runs.jsonl` (`improved` / `regressed` / `no_change` / `skipped_good` / `skipped_delta`). The dashboard's "Audit:" line under run stats renders the aggregate. Current default pairing: **minimax** does the primary doc pass, **gemini** does audits (complementary family per model-routing memory).

## Cross-version doc archive (re-kb on bsim Postgres)

Stored at `re_kb.functions` on the bsim Postgres at `10.0.10.30:5432`. Exposed via the re-kb FastAPI service at `http://10.0.10.30:8422`. Source: `re-universe/services/re-kb/`. The system has six pieces:

1. **Schema** — `re_kb.functions` augmented with matching keys (`opcode_hash`, `bsim_signature LSHVECTOR`, shape stats), full doc payload (`locals`, `instruction_comments`, `referenced_data_types`, `referenced_globals`, `referenced_labels`, `equates_referenced` JSONB), and metadata. Companion tables: `doc_field_provenance` (per-field decision history), `doc_conflict_queue` (AI judge backlog), `doc_match_log` (lookup audit).
2. **REST API** (5 endpoints) — `POST /v1/doc_archive/upsert`, `POST /v1/doc_archive/match`, `GET /v1/doc_archive/{id}/full`, `GET /v1/doc_archive/conflicts`, `POST /v1/doc_archive/conflicts/{id}/resolve`.
3. **Heuristics** — `app/services/doc_heuristics.py` resolves field-level conflicts (longer plate wins, more typed params wins, etc.) without AI cost. 13 per-field strategies.
4. **MCP tools** — `archive_ingest_function(address, program)`, `archive_ingest_program(program)` in `DocumentationHashService.java`. Build payload from current Ghidra state, POST to archive's upsert endpoint.
5. **fun-doc hooks** — write hook in `process_function` after `save_program` calls `/archive_ingest_function`. Read hook before LLM checks `/v1/doc_archive/match`; on Q5-D gate pass (hash exact OR `BSim ≥0.9 AND score ≥80`), applies name + plate via existing MCP tools and skips LLM. `bus_emit("archive_pushed"|"archive_lookup"|"archive_applied"|"archive_apply_failed"|"archive_push_failed")` for dashboard visibility.
6. **AI conflict worker** — `re-kb-conflict-worker` docker container, polls `/v1/doc_archive/conflicts`, asks Claude Haiku for structured JSON decisions, POSTs back. Idle when queue empty.

Q1-Q6 design decisions are locked in; design rationale lives in commit history. Migration `003_function_doc_archive.sql` applied to bsim DB. Required env: `RE_KB_ARCHIVE_URL` (defaults to `http://10.0.10.30:8422`); empty disables both hooks.

**BSim signature backfill** is a one-shot Ghidra script — `C:\tmp\ghidra_recovery_scripts\Backfill_BSimSignatures.java` — run per binary from CodeBrowser to populate the `bsim_signature` column and unlock tier-2 LSH similarity matching. Tier 1 (opcode hash) works without it.

## Documentation

- Workflow: `docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md`
- Data types: `docs/prompts/DATA_TYPE_INVESTIGATION_WORKFLOW.md`
- Tool guide: `docs/prompts/TOOL_USAGE_GUIDE.md`
- String labels: `docs/prompts/STRING_LABELING_CONVENTION.md`
- Version history: see `CHANGELOG.md`

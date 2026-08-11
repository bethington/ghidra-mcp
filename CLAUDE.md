# Ghidra MCP - Claude Code Guide

## Overview

MCP server bridging Ghidra reverse engineering with AI tools. 253 MCP tools for binary analysis.

- **Package**: `com.xebyte` | **Version**: 7.0.0 | **Java**: 21 LTS | **Ghidra**: 12.1.2

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
- **Exception: `dependabot[bot]` PRs.** These are the repo's own configured automation, not community contributions — no person's work is at stake. The agent may comment (e.g. `@dependabot rebase`/`recreate`) and merge these autonomously once CI is green, without per-action go-ahead. This exception is scoped to PRs whose author is literally `dependabot[bot]`; it does not extend to any human contributor, even one proposing a similar dependency bump.
- A local `.claude/` hook (`block-community-github-writes.py`) enforces a slice of this by denying write-shaped `gh` commands (checking PR authorship to carve out the dependabot exception above); treat that as a backstop, not the boundary. The boundary is this section.

## Repository scope — what belongs here

This repo is the **Ghidra MCP server and its bridge**. Concretely, in
scope:

- `src/`, `python/bridge_mcp_ghidra/`, `debugger/` — the server, bridge, debugger
- `ghidra_scripts/`, `scripts/fid/` — Ghidra scripts and analysis tooling
- `tests/`, `tools/setup/`, `docs/`

**Out of scope: Diablo II game-side work.** Container/headless probes, mod
tooling, D2Debugger harnesses, renderer experiments and conformance proving
belong in the D2MOO repo (or their own), even when a session here produces them.
Sharing a subject matter is not the same as sharing a codebase.

This is written down because judgement alone did not hold: `scripts/d2probe/`
was committed here on 2026-08-02 *after* being explicitly identified as
out-of-scope in its own README, on the reasoning that the wrong repo beat no
repo. It was rescued from a temp folder, which was a real problem — but the fix
was to give it a home in D2MOO, not to attach 22 unrelated files to this
project's history. If something needs rescuing and does not fit the list above,
move it to the repo where it belongs.

Those 22 files were **removed on 2026-08-11** (919 lines). History was
deliberately not rewritten, so nothing is lost — recover the directory with:

```text
git log --all --diff-filter=D -1 --format=%H -- scripts/d2probe   # the deleting commit
git checkout <that-sha>^ -- scripts/d2probe                       # restore into a worktree
```

They still have no owning repo. Restoring them into D2MOO (or their own) is
the outstanding half of the fix; deleting them here only stopped this repo
from being the answer by default.

## Architecture

```
AI Tools <-> MCP Bridge (python/bridge_mcp_ghidra/) <-> Ghidra Plugin (GhidraMCPPlugin.jar)
```

- **Plugin**: `src/main/java/com/xebyte/GhidraMCPPlugin.java` -- HTTP server, delegates to services
- **Bridge**: `python/bridge_mcp_ghidra/` (package, split into focused modules: `config`, `state`, `server`, `validation`, `transport`, `discovery`, `schema`, `dispatch`, `registry`, `static_tools`, `debugger`, `cli`) -- dynamic tool registration from `/mcp/schema` + static tools (8 instance/tool-group/import: `list_instances`, `connect_instance`, `list_tool_groups`, `load_tool_group`, `unload_tool_group`, `check_tools`, `search_tools`, `import_file`; + 22 debugger proxy via `GHIDRA_DEBUGGER_URL`). Ships as the `ghidra-mcp-bridge` wheel; `bridge-mcp-ghidra` console script. Cross-module functions are called module-qualified (e.g. `transport.do_request`, `dispatch.dispatch_get`) and mutable runtime state lives in `state.py`, so each function has one canonical mock-patch target.
- **Service Layer**: `src/main/java/com/xebyte/core/` -- 14 service classes (~20K lines), `@McpTool`/`@Param` annotated. v5.4.0 adds `EmulationService` (P-code emulation), `DebuggerService` (TraceRmi wrapping — GUI-only)
- **Debugger (Python)**: `debugger/` -- standalone HTTP server on port 8099 (engine, protocol, tracing, address_map, d2/ conventions). Bridge proxies via `GHIDRA_DEBUGGER_URL` env var.
- **Headless**: `src/main/java/com/xebyte/headless/` -- standalone server without GUI. Includes `HeadlessManagementService` for program/project lifecycle.
- **fun-doc**: MOVED 2026-08-11 to the `d2-game-exe` repository, where it sits
  alongside the binary-reconstruction work it serves. It is no longer part of
  this repo's scope, tests or CI. It still consumes this server's HTTP API, so
  changes to the response envelope or to service endpoints can break it from a
  distance — the single-commit/single-CI relationship that used to catch that
  is gone, and that is the cost of the split.
- **Annotation Scanner**: `AnnotationScanner.java` discovers `@McpTool` methods, generates `/mcp/schema`

Services use constructor injection: `ProgramProvider` + `ThreadingStrategy`.
- FrontEnd mode: `FrontEndProgramProvider` + `DirectThreadingStrategy`
- Headless mode: `HeadlessProgramProvider` + `DirectThreadingStrategy`

## Tool Inventory

Do not try to keep the full tool list in this file.

- **Authoritative repo snapshot**: `tests/endpoints.json` (272 endpoints, categories, descriptions)
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
uv run bridge-mcp-ghidra                                  # stdio (recommended for AI tools)
uv run bridge-mcp-ghidra --transport streamable-http      # HTTP (web clients, MCP Inspector)
uv run bridge-mcp-ghidra --transport sse                  # SSE (deprecated compat only)
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
- **Function names**: `rename_function` warns on non-PascalCase, missing verbs, short names. Module prefixes (`UPPERCASE_`) are accepted and validated separately.
- **Globals/Labels**: `rename_symbol` warns if globals lack `g_` prefix or labels aren't snake_case.
- **Plate comments**: `batch_set_comments` warns on missing Algorithm/Parameters/Returns sections.
- **Type changes**: `set_variable_type` rejects `undefined` -> `undefined` (no-op protection).
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
| `src/main/java/com/xebyte/core/ProgramScriptService.java` — `open_program` | Offline (Java) `ProgramOpenFailureMessageTest` + a live round-trip: checkout → `open_program` → `close_program` → `undo_checkout` must return `checkout_undone` **on the first try, with no Ghidra restart**. `getDomainObject(tool, ...)` registers `tool` as a `DomainObject` consumer and `ProgramManager.openProgram` takes its OWN, so ours **must** be released in a `finally` — otherwise the DomainFile is permanently "in use", `undoCheckout` fails forever, and `close_program` reports `success: true, released_cache: false` because neither the ProgramManager nor the provider cache holds the stray reference. Measured 2026-08-10: a read-only verification sweep stranded **140 exclusive checkouts** on the shared project, clearable only by restarting Ghidra. Capture `getName()`/`getFunctionCount()` BEFORE the release — after it, the ProgramManager's consumer is the only thing keeping the Program alive. The release is unconditional on purpose: on a failure path nothing else holds it. `describeOpenFailure` must keep naming the remedy for a language-version refusal — a bare `Minor language change 4.6 -> 4.7` names the symptom, and this endpoint structurally cannot fix it (`okToUpgrade=false` + an upgrade needs an exclusive checkout), so the message points at `scripts/upgrade_project_language.py`. Do NOT decorate unrelated failures; a test pins that pass-through. |
| `src/main/java/com/xebyte/core/NamingConventions.java` | Offline (Java) — `NamingConventionsTest` covers function-name verb-tier rules + token-subset duplicate detection + global-name validator (`checkGlobalNameQuality`, `checkGlobalPlateComment`, `isAutoGeneratedGlobalName`). After deploy: `tests/integration/test_safe_write_endpoints.py` + `tests/integration/test_global_endpoints.py`. Also re-run fun-doc benchmark (`--mock --tier fast --compare`). |
| `src/main/java/com/xebyte/core/DataTypeService.java` — `audit_global` / `set_global` | Offline (Java) `NamingConventionsTest` for the helpers; `tests/integration/test_global_endpoints.py` for live endpoint behavior (post-deploy only — auto-skips when endpoints aren't registered). **"Untyped" has exactly ONE definition and it lives in THREE places that must move together**: `NamingConventions.isPlaceholderTypeName` (Java), `d2moo_types.PLACEHOLDERS` (Python), `conformance_dashboard._glob_is_untyped` (the inventory's `typed` flag). The set is `undefined*` + `code` + bare `pointer`/`pointer32`/`pointer64`. Until 2026-08-03 the Java side tested only `startsWith("undefined")`, so a `pointer *` global audited `issues: []`, `fully_documented: true` — the globals worker filed it `already_clean` AND clean-cached it, while the dashboard's types bar counted it untyped and told the operator to run that worker. The bar's count could not go down: 2 of PD2_EXT.dll's 5, ~180 corpus-wide. A one-sided edit here silently rebuilds that trap, and it presents as "starting a typing worker does nothing". **`set_global` must never clear a NAMED global out of existence** — `findEvictionVictims` + `NamingConventions.isEvictableSymbolName` gate the `clearCodeUnits` call and reject with `type_would_evict`, listing the casualties; `allow_evict=true` is the deliberate override. Clearing auto-generated labels (`DAT_*`, `LAB_*`) stays allowed — you cannot lay down an array otherwise. Before this guard, `clearCodeUnits` ran over the whole extent with its exception swallowed, so a type application deleted any global it overlapped **and still reported success**: measured 2026-08-03, three globals destroyed in one PD2_EXT.dll pass (a `float10` ate `g_dwPosInfBits` 8 bytes on; a `byte[256]` ate `g_abUppercaseCharTbl2_end`; three 4-byte writes destroyed the 128-byte `g_apfnApiSlots` they sat inside), and 541 globals corpus-wide sitting in that state. Both directions matter — a small write INSIDE an existing unit destroys the whole container, because `clearCodeUnits` works on whole code units. **All THREE clearing writers must go through `evictionRejection`** (`set_global`, `apply_data_type`, `apply_data_classification`): guarding only `set_global` made the guard advisory, and a worker hit its refusal four times then completed the identical write through `apply_data_type` + `rename_symbol` + `set_comment` — simply the next tool in the chain. **The refusal text must never name `allow_evict`** (`NamingConventions.evictionSuggestion` is tested for this): the first version ended "re-send with allow_evict=true", and within one turn a model read the suggestion, re-sent with the override, and destroyed `g_ldHalf`. The escape hatch is for a human who has decided the overlap is wrong; it is not a hint for the agent being constrained. |
| `src/main/java/com/xebyte/core/NamingConventions.java` — `plateStatedCount` / `plateExtentContradicts` (`plate_extent_mismatch`) | Offline (Java) `NamingConventionsTest`. Catches a type recording an extent the data does not support: when the eviction guard refuses, the easy way out is shrinking the type until it fits the free gap, which produced `g_apfnApiSlots : FARPROC[3]`, `issues: []`, `fully_documented: true` under a plate saying "Array of 32 FARPROC slots" — 3 is where the next label sat, not a fact about the binary. MEDIUM, so it blocks `fully_documented`. **The thresholds are calibration outputs, not choices** — measured against 6,434 live globals (PD2_EXT/D2Common/D2Client/Fog) across three passes: 153 findings with ~40% hand-reviewed false, then 83, then 69 (1.1%). Each abstention kills a MEASURED class and must not be removed: POINTER (`g_pInterpTable : double *` — the plate describes the pointee), SENTINEL (`*End`/`*_end` — the count describes the array it terminates), UNIT-MULTIPLE (`dword[510]` under "255 entries, 2 DWORDs each" — agreement in different units; only abstain when BOTH sides exceed 1, or a length of 1 divides everything), STRIDE ("8 bytes each" is an element size, not an extent), and SINGULAR nouns ("Roll 2 entry" is a proper noun). The stride look-behind must stay clause-bounded — a flat window made "32 slots, each a 4-byte pointer, 16 entries" drop the 16 and turn a two-count abstention into a confident wrong answer. |
| `src/main/java/com/xebyte/core/DataTypeService.java` — `auditGlobalAt`'s export gate (`is_export`) | Offline (Java) `NamingConventionsTest` for `isOrdinalExportName`; live `audit_global` on a named data export. **A NAMED export's name is the ABI contract and must never be audited into `g_` form** — the consuming loader resolves that exact string. Measured 2026-08-04 on PD2_EXT.dll, which is a `version.dll` PROXY: all 12 named exports are forwarder strings (`"version.VerFindFileW"`) and it has no real code exports at all. A globals pass renamed every one — `GetFileVersionInfoA` → `g_szImportNameGetFileVersionInfoA`, and `GetFileVersionInfoW` → `g_szVerFileVersionApi`, which does not even name the right export — plus mis-typed three of them (`char *` and `dword` on 24-byte strings). `list_exports` then showed both `Ordinal_1` and the invented global at one address. The model that first refused ("would destroy the canonical exported API identity") was RIGHT; nothing in the tool layer backed it, so a later pass did it anyway. **The exemption is name-only** — type and plate checks still fire, so a forwarder still needs its exact `char[N]`. **It must NOT be a blanket "exports are untouchable" rule**: D2's DLLs export almost everything by ORDINAL, Ghidra names those `Ordinal_10001`, and renaming them is the core workflow — `isOrdinalExportName` is the discriminator. Blast radius measured corpus-wide: 7,172 named *code* exports (unaffected, code-address guard) and 28 named *data* exports, of which 16 already had good `g_` names, so the rule's real effect is exactly the 12 forwarders — plus correctly protecting `g_dwNvOptimusEnablement` / `AmdPowerXpressRequestHighPerformance`, which drivers look up BY NAME. |
| `src/main/java/com/xebyte/core/DataTypeService.java` — `auditGlobalAt`'s interior detection | Offline (Java) + live `audit_global` on a known interior address. `audit_global` must keep distinguishing "no data here" from "swallowed by a unit that starts earlier" (`interior_to_data` + the `container` block). The difference is not cosmetic: **`/list_globals` resolves the CONTAINING data unit**, so it reports the EATER's type at a dead address and the dashboard renders a destroyed global as perfectly typed. On PD2_EXT.dll the types bar counted 1 untyped while `audit_global` counted 3; corpus-wide 540 of 541 damaged globals were invisible to every dashboard read. Severity is deliberately **soft** — `untyped` (hard) already fires for every interior global, and a second blocking issue would send the worker chasing a fix that needs a human judgement call (either the container's length is wrong or the interior symbol shouldn't exist). |
| `src/main/java/com/xebyte/core/SymbolLabelService.java` — `rename_symbol` / `rename_symbol` validator hook | Offline (Java) `NamingConventionsTest` for the rule; `tests/integration/test_global_endpoints.py` for the structured-rejection round-trip. |
| Add/modify `@McpTool` / `@Param` annotation | Offline (Java) first — `EndpointsJsonParityTest` will fail if `tests/endpoints.json` is stale. Regenerate: `mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`. Then Integration (Java). |
| `src/main/java/com/xebyte/GhidraMCPPlugin.java` (HTTP routes) | Offline (Java) + `EndpointRegistrationTest` (integration) + `tests/performance/test_http_concurrency.py`. For UDS/TCP defaults + TCP port-range fallback (#175): manual verification with port 8089 occupied, expect bind on 8090; `/mcp/instance_info → tcp_port` should report the actual bound port. |
| `src/main/java/com/xebyte/headless/*` | Offline (Java) + `tests/unit/test_setup_ghidra.py` + Integration (Java) headless run |
| `python/bridge_mcp_ghidra/*` (bridge package) | `tests/unit/test_bridge_utils.py tests/unit/test_mcp_tools.py tests/unit/test_mcp_tool_functions.py tests/unit/test_response_schemas.py tests/unit/test_endpoint_catalog.py tests/unit/test_project_consistency.py`. For multi-candidate socket dir scan (#170): `TestGetSocketDirCandidates` + `TestDiscoverInstancesMultiDir`. For TCP port-range scanner (#175): `TestTcpPortScan`. For debugger-tool platform gating: `TestDebuggerEnabled` + `TestDebuggerToolRegistration`. Per-module size cap is 800 lines (`test_bridge_modules_stay_focused`). Mock-patch targets are module-qualified (e.g. `bridge_mcp_ghidra.dispatch.dispatch_get`, `bridge_mcp_ghidra.transport.do_request`); mutable globals live in `bridge_mcp_ghidra.state`. |
| `src/main/java/com/xebyte/core/ListingService.java` — `/list_shadowed_globals` | Offline (Java) `EndpointsJsonParityTest` + `tests/performance/test_global_completeness.py` + live smoke against a binary with known shadowed globals (D2Common had 136). Exists because **`/list_globals` structurally cannot show this population**: it resolves the CONTAINING data unit, so a global swallowed by a neighbour reports the eater's type and renders as perfectly typed in every panel — 539 of 540 corpus-wide were invisible, each hard-capped at 79 by the untyped ceiling and unable to band COMPLETE_80+. Keep its symbol gates identical to `listGlobals` Pass 1: this count renders beside that one, and two views of "the globals in this binary" disagreeing on their denominator is the exact bug class it was built to expose. Auto-generated labels are skipped — their loss is not documentation loss, the same rule the eviction guard uses. **`formatGlobalSymbol` must take the type from `getDefinedDataAt`, never `symbol.getObject()`**: for a label inside a larger unit `getObject()` returns the CONTAINING Data, so the listing printed the covering neighbour's type at an address that has no type at all, and every consumer (types bar, globals inventory, `plate_scaffold`, the assess pass) read it as typed. It also contradicted its own caller — `type_filter` derives from `getDefinedDataAt`, so `type_filter=undefined` correctly SELECTED these while the printed line said they were typed. Fixing that one field is what actually closed the 540-global blind spot: PD2_EXT went from "bar says 1 untyped, `audit_global` says 3, 2 ghosts" to 2/2/**0 ghosts**, and the corpus sweep's `invisible to the dashboard` count went 539 → **0**. The separate endpoint answers a different question — not "is this untyped" (the listing now says so) but "what ate it". `isGlobalDataSymbol` is SHARED by both scanners, not copied: the first cut hand-copied the gates, which is the same two-code-paths-one-question shape as every other bug in this area, and the two counts render side by side. `tests/integration/test_readonly_endpoints.py::TestShadowedGlobalsConsistency` pins the subset relation live, and discovers a program that actually has shadowed globals rather than skipping on whatever is active (after a deploy that is the benchmark fixture, which has none). |
| `scripts/fid/build-vc6-fiddb.ps1`, `scripts/fid/CountFidMatches.java` | Manual A/B against a binary: import once with stock FID, once with `-preScript AttachFidDatabase.java`, diff `CountFidMatches` output. **The VC6 FidDb WORKS — measured 12→87 FID matches on `Benchmark.dll` (+75, 7×), 92% of library code identified with ZERO false claims against our 9 authored functions** (`ReportFidCoverage.java`). It adds nothing to D2Common (175→176) / D2Client (216→216) for a different reason than the one first recorded here: **D2's static CRT is not this LIBCMT**, NOT that the database is redundant with stock. Stock `vsOlder_x86.fidbf` finds only 12 of 151 in a binary built by this exact toolchain. **D2's CRT is VS2003 SP1, not VC6** — diagnosed 2026-08-02 two ways: (a) relocation-masked byte compare of known-CRT functions gives 6–18% against VC6 LIBCMT while the same method scores `_strlen`/`_memset` at **100.0%** on `Benchmark.dll`, so the method is sound; (b) the Rich header of D2Common/D2Client/D2Game/Fog/Storm contains **zero** VC6-compiler (`Utc12_*`) objects — every entry is a 710-series product at build **6030** = VS .NET 2003 SP1. VC6 SP6 is build 8804. So the benchmark's "VC6 SP6 compiler" premise is wrong (the linker half is right). **The VS2003 database is BUILT** (`vs2003_libcmt.fidb`, 1,049 sigs) and the diagnosis held at the byte level (`_qsort`/`_atol`/`_sprintf` 100.0%) — but the right library did NOT buy broad coverage: D2Common 175→204 (+29), D2Client/D2Game/Fog **+0**, because stock `vsOlder_x86.fidbf` already covers most VS2003-era CRT. Do NOT build a third CRT database expecting a different answer; what remains unidentified is game code or inlined CRT that hash-exact matching cannot reach. **Still open: the corpus was never re-analyzed** — both dbs sit in `FID.USER.ADDED`, which only affects analysis run *after* attaching, and D2Common still shows exactly 175 FID bookmarks live. Re-running the analyzer on documented programs can relabel fun-doc's work (`restore_fid_names.py` is the inverse). Always A/B a new database against `Benchmark.dll` first; it is the only binary with ground truth. Also: `analyzeHeadless` EXITS 0 when a script throws — scrape the log for `SCRIPT ERROR` and verify the artifact, or you will 'succeed' into an empty 671-byte .fidb. |
| `scripts/gen_conformance_protected.py` | Manual: `python -m scripts.gen_conformance_protected` (dry-run) against a live Ghidra instance with the PD2-S12 programs loaded; diff against the committed `conformance_protected.json` before `--apply`. Scoped to the `/Mods/PD2-S12/` path prefix, not `instance_info`'s `open` flag — that flag does not reliably indicate whether a program is queryable via `/search_functions_by_tag`. |
| `scripts/upgrade_project_language.py` | `tests/unit/test_upgrade_project_language.py` (offline) + a live dry run, then `--apply` on ONE folder before the corpus. **Ghidra records the SLEIGH language version a Program was built against, and a bump makes every older program open READ-ONLY** — measured 2026-08-09, the whole `diablo2` repo sat at `x86:LE:32:default` **4.6** against 12.1.2's **4.7**, and the symptom was "binaries open read-only and edits vanish". This is NOT the Ghidra DB schema version (`ProgramDB.DB_VERSION` was 32 on both sides, and `UPGRADE_REQUIRED_BEFORE_VERSION = 19` only gates *read-only* opens); the line that bites is `openMode == UPDATE && storedVersion < DB_VERSION`, and the language check is the parallel one in `LanguageVersionException`. A *minor* bump (4.6→4.7) returns a null `languageUpgradeTranslator` — no re-disassembly, no re-analysis, documentation safe; a *major* bump is a different operation this tool reports rather than performs. **`-commit` is load-bearing, not cosmetic**: `HeadlessAnalyzer` does `domFile.checkout(options.commit, ...)`, so without it the checkout is NON-exclusive, the upgrade cannot happen, and the run completes cleanly having upgraded nothing. `-noanalysis` is unconditional — auto-analysis over curated programs is the one irreversible mistake here. **The MCP server can never fix this itself**: every GUI-side open passes `okToUpgrade=false` (`FrontEndProgramProvider:452`, `ProgramScriptService:1815`), so it can only report `Minor language change 4.6 -> 4.7`; only `HeadlessProgramProvider` passes `true`. Three traps that each produced a silent no-op: a `ghidra://` URL sees **only versioned files** (9 private programs are unreachable and must not be counted as covered); Git Bash rewrites `--folder /Vanilla/1.01` into `C:\Program Files\Git\...`; and a check-in comment containing **parentheses** kills `analyzeHeadless.bat` with `"" was unexpected at this time` before the JVM starts. Files already checked out by the GUI project are skipped — headless is a separate project instance and cannot take an exclusive checkout on them. Credentials come from `<ghidra_dir>/.env` (`GHIDRA_SERVER_PASSWORD`), the same file `GhidraMCPAuthInitializer` reads; name outranks source, because an ambient `GHIDRA_PASS` holding a credential the server rejects otherwise beats it and presents as an auth outage. **It is NOT idempotent and `--apply` must not be used as its own verification** — `HeadlessAnalyzer` runs `if (canSave()) save()` then `commitProgram()` unconditionally, and `canSave()` is true for any checked-out file regardless of changes, so every pass writes a new server version for every file it touches; Ghidra logs *nothing* on a language upgrade, so the log cannot tell "upgraded" from "re-committed unchanged" (measured: a second full pass moved all 517 files up another version having upgraded none). A whole-project `--apply` therefore refuses within 24h of a previous one unless `--force`. **`--verify` is the verification step and leaks an exclusive checkout per probed program**: forcing a read-WRITE open needs a checkout, and `open_program` registers a `DomainObject` consumer nothing releases, so `undo_checkout` then fails `"<name> is in use"` forever — `close_program` reports `closed_count: 0, released_cache: false` and cannot help. Measured: a 152-program probe stranded 140 checkouts. Keep `--verify-sample` at 1-2; clear leftovers with a Ghidra restart then `--release-checkouts` (which only ever releases paths the tool recorded creating — undoing an arbitrary checkout discards whatever local work it held). Paths must be parsed with `(.+?)` and never `\S+`: `Diablo II.exe` (present in all 25 Vanilla folders) contains a space, which made the skip lines fail to match entirely and silently dropped the file from the tally. |
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

- **A Ghidra upgrade can silently make every program read-only** -- a SLEIGH language bump (e.g. x86 4.6 -> 4.7) leaves old programs openable read-only but refuses read-write, and on a shared project that compounds with "not checked out" into one indistinguishable symptom. Fix: `python scripts/upgrade_project_language.py` (dry run) then `--apply`. Check this FIRST after any Ghidra version change.
- **Ghidra overwrites FrontEndTool.xml on exit** -- deploy must patch AFTER Ghidra exits
- **Shared server renames not persisted by save_program** -- must checkin to persist
- **Max ~5 shared server programs open at once** -- opening 20+ crashes Ghidra
- **`switch_program` matches by name** -- for multi-version work, use the `program` query parameter on individual endpoints instead
- **Plate comment `\n` creates literal text**, not newlines -- use actual multi-line text
- **GUI operations from HTTP threads** must use `SwingUtilities.invokeAndWait()`

## Cross-version doc archive (optional re-kb service)

When explicitly configured, documentation is stored in `re_kb.functions` on a user-selected Postgres instance and exposed through a user-selected re-kb FastAPI service. Source: `re-universe/services/re-kb/`. The system has six pieces:

1. **Schema** — `re_kb.functions` augmented with matching keys (`opcode_hash`, `bsim_signature LSHVECTOR`, shape stats), full doc payload (`locals`, `instruction_comments`, `referenced_data_types`, `referenced_globals`, `referenced_labels`, `equates_referenced` JSONB), and metadata. Companion tables: `doc_field_provenance` (per-field decision history), `doc_conflict_queue` (AI judge backlog), `doc_match_log` (lookup audit).
2. **REST API** (5 endpoints) — `POST /v1/doc_archive/upsert`, `POST /v1/doc_archive/match`, `GET /v1/doc_archive/{id}/full`, `GET /v1/doc_archive/conflicts`, `POST /v1/doc_archive/conflicts/{id}/resolve`.
3. **Heuristics** — `app/services/doc_heuristics.py` resolves field-level conflicts (longer plate wins, more typed params wins, etc.) without AI cost. 13 per-field strategies.
4. **MCP tools** — `archive_ingest_function(address, program)`, `archive_ingest_program(program)` in `DocumentationHashService.java`. Build payload from current Ghidra state, POST to archive's upsert endpoint.
5. **fun-doc hooks** — write hook in `process_function` after `save_program` calls `/archive_ingest_function`. Read hook before LLM checks `/v1/doc_archive/match`; on Q5-D gate pass (hash exact OR `BSim ≥0.9 AND score ≥80`), applies name + plate via existing MCP tools and skips LLM. `bus_emit("archive_pushed"|"archive_lookup"|"archive_applied"|"archive_apply_failed"|"archive_push_failed")` for dashboard visibility.
6. **AI conflict worker** — `re-kb-conflict-worker` docker container, polls `/v1/doc_archive/conflicts`, asks Claude Haiku for structured JSON decisions, POSTs back. Idle when queue empty.

Q1-Q6 design decisions are locked in; design rationale lives in commit history. Migration `003_function_doc_archive.sql` applies to the selected BSim database. Archive exchange is disabled by default; set `RE_KB_ARCHIVE_URL` for fun-doc and `GHIDRA_MCP_ARCHIVE_URL` for the Java service to opt in.

**BSim signature backfill** is a one-shot Ghidra script — `ghidra_scripts/recovery/Backfill_BSimSignatures.java` — run per binary from CodeBrowser to populate the `bsim_signature` column and unlock tier-2 LSH similarity matching. Tier 1 (opcode hash) works without it.

## Documentation

- Workflow: `docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md`
- Data types: `docs/prompts/DATA_TYPE_INVESTIGATION_WORKFLOW.md`
- Tool guide: `docs/prompts/TOOL_USAGE_GUIDE.md`
- String labels: `docs/prompts/STRING_LABELING_CONVENTION.md`
- Version history: see `CHANGELOG.md`

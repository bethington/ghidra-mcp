# Changelog - Ghidra MCP Server

Complete version history for the Ghidra MCP Server project.

---

## Unreleased

### Added

- **Streamable HTTP transport** — `--transport streamable-http` is now documented and recommended for web/HTTP clients. SSE transport is deprecated. Added `ghidra-mcp-http` config example to `mcp-config.json`.
- **Engineering backlog** — Added `docs/project-management/BACKLOG.md` with prioritized roadmap items from competitive fork analysis (GitHub issues #109–#112).

### Fixed

- **read_memory OOM** (#107) — Capped read_memory allocation at 16 MB to prevent out-of-memory on malicious/large length values.
- **SSRF in connect_instance** (#106) — Wired `validate_server_url()` into `connect_instance` and `_auto_connect` TCP paths.

---

## v5.0.0 - 2026-04-03

GhidraMCP v5.0 marks a deliberate shift: from a passive Ghidra mirror to an **active enforcement layer**. Tools that write annotations now enforce naming conventions, reject no-ops, and auto-correct struct fields. At the scale of thousands of functions, multiple binary versions, and parallel AI + human workflows, conventions can't be suggestions — they must be in the tool.

This is a contract change. If you have scripts or prompts built against earlier versions, review the breaking changes below.

### Breaking Changes

| Tool / Behavior | Before | After (v5.0) |
|-----------------|--------|--------------|
| `batch_rename_variables` | endpoint name | **Renamed** to `rename_variables` — update all callers |
| `add_struct_field` | `insertAtOffset` (shifts subsequent fields) | `replaceAtOffset` — same call, different field layout |
| `set_local_variable_type` | accepted undefined→undefined silently | **Rejected with error** — type must actually change |
| Struct field names | passed through as-is | **Auto-prefixed** with Hungarian notation based on data type |

### Completeness Scoring Redesign
- **Log-scaled budget system**: Every per-count deduction category now has a fixed point budget with log-scaled penalties. No single category can dominate the score. Monster functions (5,000+ variables) no longer score 0%.
- **Tiered plate comment scoring**: Missing plate (-35pts), stub (-25pts), incomplete (-15pts), minor (-8pts), complete (0pts). Rewards quality, not just presence.
- **Effective score only counts fixable deductions**: Structural (unfixable) deductions are fully forgiven. Functions with only structural deductions score 100% effective.
- **Bulk stack-array heuristic**: Functions with 100+ undefined variables reclassify the excess as structural (impractical to fix via API).
- **Address-suffix name detection**: Functions ending with hex address suffixes (e.g., `_6FD93C30`) flagged as 20pt fixable deduction.
- **`__thiscall` ECX auto-param**: Correctly classified as structural/unfixable. `set_function_prototype` warns when `__thiscall` `this` type can't be changed.

### Naming Convention Enforcement
- **NamingConventions.java**: Centralized validation utility -- PascalCase function names, Hungarian variable prefixes, `g_` global prefixes, snake_case labels, plate comment structure.
- **Auto-fix struct field prefixes**: `create_struct`, `add_struct_field`, `modify_struct_field` automatically apply correct Hungarian prefixes based on field type.
- **Function name validation**: Warns on non-PascalCase, missing verb, too short. Module prefixes (`UPPERCASE_`) accepted and validated separately.
- **`set_local_variable_type` rejects undefined-to-undefined**: No-op type changes rejected with helpful error.

### New Tools
- **`/set_variables`**: Atomic type + rename in a single transaction. Sets types first, decompiles, then renames with Hungarian validation. Eliminates SSA churn.
- **`/check_tools`**: Verify if specific tools are callable. Returns `callable`, `not_loaded`, or `not_found` with fix suggestions.
- **`/rename_variables`**: Renamed from `/batch_rename_variables` for conciseness.

### Tool Improvements
- **`batch_set_comments`**: `decompiler_comments` and `disassembly_comments` arrays now optional (default `[]`). Omitting `plate_comment` leaves existing plate untouched.
- **`add_struct_field`**: Uses `replaceAtOffset` instead of `insertAtOffset` -- overlays undefined bytes without shifting subsequent fields. Off-by-one at struct boundary fixed.
- **`modify_struct_field`**: Accepts `offset:N` syntax (e.g., `offset:16` or `offset:0x10`) for unnamed fields.
- **`create_struct`**: Accepts flexible JSON key names (`field_name`, `fieldName`, `data_type`, etc.).
- **`get_function_variables`**: `limit` and `filter` params now optional with defaults.
- **`get_current_function` / `get_current_address`**: Now discovers CodeBrowser instances via ToolManager (was broken in FrontEnd mode). Returns JSON with program path.

### Plate Comment Validation
- **Summary line check**: First non-empty line must be >20 chars.
- **Parameter count cross-validation**: Compares Parameters section entries against function signature.
- **Returns/return-type match**: Catches void function with non-void docs and vice versa.
- **Source file reference**: Checks for `Source:` line.
- **Algorithm step substance**: Flags steps with <10 chars of content.
- **Parameter entry quality**: Flags entries lacking type + description.

### fun-doc Automation Engine
- **Codex SDK integration**: `AI_PROVIDER = "codex"` routes to OpenAI Codex Python SDK with MCP tools. Claude Code SDK also integrated.
- **Select mode (`-s`)**: Fetches current function from CodeBrowser, builds prompt. `--depth 2` recursively collects callers/callees.
- **Manual mode (`-m -s`)**: Single-keypress flow -- copies prompt, press any key for next function, `q` to quit.
- **State sync**: Pre-work and post-work sync points update `state.json` with live completeness data.
- **Short-circuit**: Functions at 95%+ with 0 fixable deductions auto-skip in auto mode (not manual).
- **Smart mode routing**: >= 100% VERIFY, >= 70% FIX, < 70% FULL. No smart promotion.

### Prompt V6 Improvements
- **Score removed from prompts**: Prevents models from coasting on high scores.
- **Consistency checklist**: Step 5 requires function name vs plate comment alignment check.
- **Module prefix decision**: 2-signal gate (Source file, behavior domain, callee family) before applying prefix.
- **Naming confidence rules**: Require evidence for semantic names. Placeholders (`dwUnknown1D0`) for unproven fields.
- **Struct creation gate**: Reuse-first, 3+ validated fields, 2+ code paths required. Otherwise comment-only.
- **Verification removed**: `analyze_function_completeness` no longer called inside prompts. Scoring handled externally.
- **Known module prefixes**: `prefixes.json` injected into every prompt.
- **Opportunistic checks in FIX mode**: Function name, prototype, plate comment, variable names.
- **`batch_set_comments` schema documented**: Exact JSON format in step-comments.md.
- **Non-ASCII sanitized**: All em dashes and arrows replaced with ASCII equivalents.

### Bridge Improvements
- **All tools loaded at startup** (`--lazy` default changed to False): Fixes Claude Code/Codex not seeing dynamically loaded tools.
- **`load_tool_group` returns tool names**: Response includes exact list of newly loaded tools.
- **TCP fallback in `list_instances()`**: Windows environments now show the active TCP connection (PR #90).
- **Program param optional on all tools**: Schema fixes from PR #92 -- omitting `program` uses active program.
- **Xref tools accept address directly**: `get_function_callers`/`get_function_callees` no longer require name-only lookup.

### Bug Fixes
- **`effective_score > max_achievable_score`**: Fixed -- effective score capped at max achievable.
- **`analyze_for_documentation` pre-fetch**: Was using `address` instead of `function_address` param. Fixed.
- **CodeBrowser detection**: `get_current_function`/`get_current_address` now search running CodeBrowser instances via ToolManager.
- **Callers/callees plain text parsing**: `fun_doc.py` now handles both JSON and text response formats from xref endpoints.

---

## v4.3.0 - 2026-03-09

### Annotation-Based Endpoints & Dynamic Bridge Registration

#### `@McpTool`/`@Param` Annotation Infrastructure
- All ~144 service methods across 12 service classes annotated with `@McpTool` and `@Param`
- `AnnotationScanner` discovers annotated methods via reflection and generates `EndpointDef` records
- `/mcp/schema` endpoint returns JSON schema describing all tools, parameters, types, and categories
- New endpoints are now a single step: annotate the service method and it's automatically discoverable

#### Dynamic Bridge Tool Registration
- Bridge fetches `/mcp/schema` from Ghidra HTTP server at startup and auto-registers ~170 MCP tools
- Reduced bridge from ~8,600 lines to ~2,400 lines (72% reduction)
- 22 complex tools with bridge-side logic (retries, local I/O, multi-call, Knowledge DB) remain as static `@mcp.tool()` functions
- `STATIC_TOOL_NAMES` set controls which tools skip dynamic registration
- `_make_tool_handler()` creates handlers with proper `inspect.Signature` for FastMCP introspection
- GET endpoints route all params as query string via `safe_get_json`
- POST endpoints separate query vs body params based on schema source field
- Graceful fallback: if Ghidra is not running, logs warning and starts with only static tools

#### Test Suite Updates
- Rewrote `test_mcp_tool_functions.py` for dynamic registration architecture
- Tests cover: schema type mapping, default conversion, handler creation, parameter routing, static tool availability
- Updated endpoint count assertions for static-only decorator count (15-50 range)

### Bug Fixes & Compatibility

- **Fixed POST endpoint data format** (#66): `safe_post()` was sending form-urlencoded data while the Java server expected JSON. Changed to send `json=data` instead of `data=data`, fixing `rename_function_by_address` and all other POST-based endpoints.
- **Added segment:offset address support** (#65): Bridge now accepts segment-prefixed addresses (e.g., `mem:20de`, `code:00169d`) used by non-x86/segmented architectures. Updated `sanitize_address()`, `validate_hex_address()`, and `normalize_address()` to pass through segment-qualified addresses without incorrect `0x` prefixing.
- **Relaxed Ghidra version compatibility check** (#64): Setup scripts (`ghidra-mcp-setup.ps1` and `ghidra-mcp-setup.sh`) now warn instead of error when deploying to a Ghidra installation with a different patch version (e.g., building with 12.0.3 and deploying to 12.0.4). Major.minor mismatches still block deployment.
- **Fixed Linux phantom process detection** (#63): Tightened `get_ghidra_pids()` regex in `ghidra-mcp-setup.sh` to match only the Java class name pattern (`ghidra.GhidraRun`/`ghidra.GhidraLauncher`), removing overly broad alternatives that caused false positives.
- **Fixed FrontEndProgramProvider multi-version bugs**: Fixed consumer reference leak on cache overwrite, `pathToName` not cleared in `releaseAll()`, and `getAllOpenPrograms()` deduplicating by name instead of identity (hiding same-named programs from different versions).
- **Reduced MCP response token usage ~30-40%**: Optimized JSON response payloads across service endpoints.

---

## v4.2.1 - 2026-03-06

### Documentation Completeness Improvements

#### `analyze_function_completeness` Enhancements
- Added **context-aware scoring** for compiler/runtime helper functions (e.g., CRT/SEH helpers) to reduce false penalties.
- Added **fixable vs structural deductions** in response payload:
  - `fixable_deductions`
  - `structural_deductions`
  - `max_achievable_score`
  - `deduction_breakdown` (verbose mode)
- Added **structured remediation output** (`remediation_actions`) with per-issue tool mapping, evidence samples, and estimated score gain.
- Added function context flags:
  - `is_stub`
  - `is_compiler_helper`
  - `documentation_profile`
- Improved plate comment validation with a **compact helper profile** (5-line minimum, Purpose/Origin + Parameters) for compiler/helper functions.
- Updated workflow recommendations to be **classification-aware** (compact helper workflow vs full workflow).

---
## v4.2.0 - 2026-03-02

### Knowledge Database Integration + BSim + Bug Fixes

#### Knowledge Database (5 new MCP tools)
- **`store_function_knowledge`** -- Store documented function data (name, prototype, comments, score) to PostgreSQL knowledge DB with fire-and-forget semantics
- **`query_knowledge_context`** -- Keyword search across documented functions using PostgreSQL `ILIKE`/`tsvector` full-text search. Returns relevant prior documentation to inform new function analysis
- **`store_ordinal_mapping`** -- Store ordinal-to-name mappings per binary version (e.g., D2Common.dll ordinal 10375 = GetUnitPosition)
- **`get_ordinal_mapping`** -- Look up known ordinal names by binary, version, and ordinal number
- **`export_system_knowledge`** -- Generate markdown export of documented functions grouped by game system, suitable for book chapters and content creation
- **Graceful degradation**: All knowledge tools return `{"available": false}` when DB is unreachable. Circuit breaker disables DB after 3 consecutive failures for the session. RE loop proceeds without knowledge DB.
- **Connection pool**: `psycopg2.ThreadedConnectionPool` with configurable DB host/port/credentials via `.env` file
- **Schema**: 3 new tables (`ordinal_mappings`, `documented_functions`, `propagation_log`) with full-text search indexes and `updated_at` triggers

#### BSim Cross-Version Matching (4 new Ghidra scripts)
- **`BSimIngestProgram.java`** -- Ingest all functions from current program into BSim PostgreSQL DB. One-time per binary version.
- **`BSimQueryAndPropagate.java`** -- Query BSim for cross-version matches of a specific function, returns JSON sorted by similarity score
- **`BSimBulkQuery.java`** -- Bulk query all undocumented (FUN_*) functions against BSim DB for batch propagation
- **`BSimTestConnection.java`** -- Verify BSim PostgreSQL connectivity and return DB metadata
- **3-tier matching cascade** in RE loop: exact opcode hash (fastest) -> BSim LSH similarity (medium) -> fuzzy instruction pattern (slowest)

#### Bug Fixes
- **Fix #44**: Enum value parsing -- Gson parses JSON integers as `Double` (0 -> 0.0), causing `Long.parseLong("0.0")` to fail silently. Replaced hand-rolled parser with `JsonHelper.parseJson()` + `Number.longValue()`. Hex strings (`0x1F`) now also accepted.
- **Improved error messages**: Enum creation with empty/invalid values now returns descriptive errors instead of silent failures

#### Dead Code Cleanup
- Removed ~243KB of deprecated workflow modules superseded by the RE loop skill
- Deleted deprecated slash commands (`auto-document.md`, `improve-cycle.md`, `fix-issues.md`, `improve.md`)

#### Migration Scripts
- **`scripts/apply_schema.py`** -- Apply knowledge DB schema to PostgreSQL (idempotent, handles "already exists" gracefully)
- **`scripts/migrate_learnings.py`** -- One-time migration from flat files (learnings.md, loop_state.json, community_names.json) to knowledge DB tables

#### Counts
- 193 MCP tools, 175 GUI endpoints, 183 headless endpoints

---

## v4.1.0 - 2026-03-01

### Parallel Multi-Binary Support

#### Universal `program` Parameter
- **Every program-scoped MCP tool now accepts an optional `program` parameter** -- Pass `program="D2Client.dll"` to any tool to target a specific open program without calling `switch_program` first
- **Eliminates race conditions** -- Parallel requests targeting different programs no longer contend on shared `currentProgram` state
- **Backward compatible** -- Omitting `program` falls back to the current/default program, preserving existing workflows
- **Full stack coverage**: Bridge helpers (5), 136 MCP tools, 130+ GUI endpoints, 130+ headless endpoints, and all 9 service classes updated

#### Service Layer Changes
- All service methods now accept `String programName` and resolve via `getProgramOrError(programName)`
- Backward-compatible overloads (`method(args)` delegates to `method(args, null)`) preserve internal callers
- Services updated: FunctionService, CommentService, DataTypeService, SymbolLabelService, XrefCallGraphService, DocumentationHashService, AnalysisService, MalwareSecurityService, ProgramScriptService

#### Bridge Changes
- `safe_get`, `safe_get_json`, `safe_post`, `safe_post_json`, `make_request` all accept `program=` kwarg
- GET helpers inject `program` into query params; POST helpers append `?program=X` to URL
- `switch_program` docstring updated: now documented as setting the default fallback, with explicit `program=` recommended for parallel workflows

#### Counts
- 188 MCP tools, 169 GUI endpoints, 173 headless endpoints

---

## v4.0.0 - 2026-02-28

### Major Release -- Service Layer Architecture Refactor

#### Architecture Refactor
- **Monolith decomposition**: Extracted shared business logic from `GhidraMCPPlugin.java` (16,945 lines) into 12 focused service classes under `com.xebyte.core/`
- **Plugin reduced 69%**: `GhidraMCPPlugin.java` went from 16,945 to 5,273 lines (server lifecycle, HTTP wiring, and GUI-only endpoints remain)
- **Headless reduced 67%**: `HeadlessEndpointHandler.java` went from 6,452 to 2,153 lines by delegating to the same shared services
- **Zero breaking changes**: All HTTP endpoint paths, parameter names, and JSON response formats are unchanged. The MCP bridge and all clients work without modification

#### New Service Classes
- `ServiceUtils` -- shared static utilities (escapeJson, paginateList, resolveDataType, convertNumber)
- `ListingService` -- listing/enumeration endpoints (list_methods, list_functions, list_classes, etc.)
- `FunctionService` -- decompilation, rename, prototype, variable management, batch operations
- `CommentService` -- decompiler/disassembly/plate comments
- `SymbolLabelService` -- labels, data rename, globals, external locations
- `XrefCallGraphService` -- cross-references, call graphs
- `DataTypeService` -- struct/enum/union CRUD, validation, field analysis
- `AnalysisService` -- completeness analysis, control flow, similarity, analyzers
- `DocumentationHashService` -- function hashing, cross-binary documentation
- `MalwareSecurityService` -- anti-analysis detection, IOCs, malware behaviors
- `ProgramScriptService` -- program management, scripts, memory, bookmarks, metadata

#### New Feature
- **Auto-analyze on open_program**: `open_program` endpoint now accepts optional `auto_analyze=true` parameter to trigger Ghidra's auto-analysis after opening a program (inspired by PR #42 from @heeen)

#### Counts
- 184 MCP tools, 169 GUI endpoints, 173 headless endpoints

#### Design Decisions
- Instance-based services with constructor injection (`ProgramProvider` + `ThreadingStrategy`)
- GUI mode uses `GuiProgramProvider` + `SwingThreadingStrategy`; headless uses `HeadlessProgramProvider` + `DirectThreadingStrategy`
- Services return JSON strings (same as before); `Response` sealed interface deferred to v5.0
- Existing `createContext()` endpoint registration pattern preserved (grep-friendly, proven)

---

## v3.2.0 - 2026-02-27

### Bug Fixes + Version Management

#### Bug Fixes (Cherry-picked from PR #38)
- **Fixed trailing slash in DEFAULT_GHIDRA_SERVER** -- `urljoin` path resolution was broken when the base URL ended with `/`
- **Fixed fuzzy match JSON parsing** -- `find_similar_functions_fuzzy` and `bulk_fuzzy_match` now use `safe_get_json` instead of `safe_get`, which was splitting JSON responses on newlines and destroying structure
- **Fixed OSGi class cache collisions for inline scripts** -- Inline scripts now use unique class names (`Mcp_<hex>`) per invocation instead of the fixed `_mcp_inline_` prefix, which caused the OSGi bundle resolver to cache stale classloaders

#### Bug Fixes
- **Fixed multi-window port collision (#35)** -- Opening a second CodeBrowser window no longer crashes with "Address already in use". The HTTP server is now a static singleton shared across all plugin instances, with reference counting for clean shutdown

#### Completeness Checker Improvements
- **New `batch_analyze_completeness` endpoint** -- Analyze multiple functions in a single call, avoiding per-function HTTP overhead. Accepts JSON array of addresses, returns all scores at once
- **Thunk comment density fix** -- Thunk stubs are no longer penalized for low inline comment density (thunks are single JMP instructions with no code to comment)
- **Thunk comment density recommendations** -- `generateWorkflowRecommendations` no longer suggests adding inline comments to thunk functions
- **Ordinal_ auto-generated name detection** -- `isAutoGeneratedName()` helper now covers FUN_, Ordinal_, thunk_FUN_, thunk_Ordinal_ prefixes across all checker endpoints
- **Callee-based ordinal detection** -- `undocumented_ordinals` now uses `func.getCalledFunctions()` instead of text scanning, eliminating false positives from self-references and caller mentions in plate comments
- **Thunk variable skip** -- Thunks with no local variables skip all body-projected decompiler artifacts
- **Relaxed thunk plate comment validation** -- Thunks only need to identify as forwarding stubs, not include full Algorithm/Parameters/Returns sections

#### Infrastructure
- **Fixed ENDPOINT_COUNT** -- Corrected from 146 to 149 to match actual `createContext` registration count
- **Centralized version in extension.properties** -- Description now uses `${project.version}` Maven filtering instead of hardcoded version string
- **Expanded bump-version.ps1** -- Now covers 11 files (up from 7): added README badge, AGENTS.md, docs/releases/README.md. Extension.properties is now Maven-dynamic.
- **Version consistency audit** -- Fixed stale 3.0.0 references across ghidra-mcp-setup.ps1, tests/endpoints.json, README.md, AGENTS.md, and docs/releases/README.md

---

## v3.1.0 - 2026-02-26

### Feature Release -- Server Control Menu + Completeness Checker Fixes

#### New Features
- **Tools > GhidraMCP server control menu** -- Start/stop/restart the HTTP server from Ghidra's Tools menu with status indicator
- **Deployment automation** -- TCD auto-activation patches tool config for plugin auto-enable; AutoOpen launches project on Ghidra startup; ServerPassword auto-fills server auth dialog
- **Batch workflow improvements** -- Strengthened dispatch prompt with explicit storage type resolution instructions; added practical note for p-prefix pointer pattern

#### Bug Fixes
- **Completeness checker: register-only SSA variables** -- Variables with `unique:` storage that can't be renamed/retyped via Ghidra API are now tracked as unfixable, boosting `effective_score` accordingly
- **Completeness checker: ordinal PRE_COMMENT detection** -- Ordinals documented via `set_decompiler_comment` appear on the line above the code in decompiled output; checker now checks previous line for PRE_COMMENT
- **Completeness checker: Hungarian notation types** -- Added `dword`/`uint` (dw), `word`/`ushort` (w), `qword`/`ulonglong` (qw), `BOOL` (f) to expected prefix mappings
- **CI Help.jar fix** -- Added Help.jar dependency to all CI workflow configurations (build.yml, release.yml, tests.yml)
- **Dropped Python 3.8/3.9** -- CI matrix now targets Python 3.10+ only

---

## v3.0.0 - 2026-02-23

### Major Release Ã¢â‚¬â€ Headless Server Parity + New Tool Categories

#### Ã°Å¸â€“Â¥Ã¯Â¸Â Headless Server Expansion
- **Full headless parity**: Ported 50+ endpoints from GUI plugin to headless server
- All analysis, batch operation, and documentation endpoints now available without Ghidra GUI
- Script execution (`run_ghidra_script`, `run_script_inline`) works headlessly via `GhidraScriptUtil`
- New `exitServer()` endpoint for graceful headless shutdown

#### Ã°Å¸â€œÂ Project Lifecycle (New Category)
- `create_project` Ã¢â‚¬â€ create a new Ghidra project programmatically
- `delete_project` Ã¢â‚¬â€ delete a project by path
- `list_projects` Ã¢â‚¬â€ enumerate Ghidra projects in a directory
- `open_project` / `close_project` Ã¢â‚¬â€ now exposed as MCP tools

#### Ã°Å¸â€”â€šÃ¯Â¸Â Project Organization (New Category)
- `create_folder` Ã¢â‚¬â€ create folders in project tree
- `move_file` / `move_folder` Ã¢â‚¬â€ reorganize project contents
- `delete_file` Ã¢â‚¬â€ remove domain files from project

#### Ã°Å¸â€â€” Server Connection (New Category)
- `connect_server` / `disconnect_server` Ã¢â‚¬â€ manage Ghidra Server connections
- `server_status` Ã¢â‚¬â€ check server connectivity
- `list_repositories` / `create_repository` Ã¢â‚¬â€ repository management

#### Ã°Å¸â€œÅ’ Version Control (New Category)
- `checkout_file` / `checkin_file` Ã¢â‚¬â€ file version control operations
- `undo_checkout` / `add_to_version_control` Ã¢â‚¬â€ checkout management

#### Ã°Å¸â€œÅ“ Version History (New Category)
- `get_version_history` Ã¢â‚¬â€ full version history for a file
- `get_checkouts` Ã¢â‚¬â€ active checkout status
- `get_specific_version` Ã¢â‚¬â€ open a specific historical version

#### Ã°Å¸â€˜Â¤ Admin (New Category)
- `terminate_checkout` Ã¢â‚¬â€ admin checkout termination
- `list_server_users` Ã¢â‚¬â€ enumerate server users
- `set_user_permissions` Ã¢â‚¬â€ manage user access levels

#### Ã¢Å¡â„¢Ã¯Â¸Â Analysis Control (New Category)
- `list_analyzers` Ã¢â‚¬â€ enumerate available Ghidra analyzers
- `configure_analyzer` Ã¢â‚¬â€ enable/disable and configure analyzers
- `run_analysis` Ã¢â‚¬â€ trigger analysis programmatically

#### Ã°Å¸â€Â§ Infrastructure
- **`bump-version.ps1`**: Single-command version bump across all 7 project files
- **`tests/unit/`**: New unit test suite Ã¢â‚¬â€ endpoint catalog consistency, MCP tool functions, response schemas
- **`.markdownlintrc`**: Markdown lint config for CI quality gate
- **`mcp-config.json`**: Fixed env key to match bridge (`GHIDRA_SERVER_URL`)
- Tool count: 179 MCP tools (up from 110), 147 GUI endpoints, 172 headless endpoints

#### Ã°Å¸â€Å’ GUI Plugin Additions
- `/get_function_count` Ã¢â‚¬â€ quick function count without full listing
- `/search_strings` Ã¢â‚¬â€ regex/substring search over defined strings, returns JSON
- `/list_analyzers` Ã¢â‚¬â€ enumerate all analyzers with enabled/disabled state
- `/run_analysis` Ã¢â‚¬â€ trigger Ghidra auto-analysis programmatically
- `get_function_count` MCP bridge tool added

---

## v2.0.2 - 2026-02-20

### Patch Release - Ghidra 12.0.3 Support, Pagination for Large Functions

#### Ã°Å¸Å¡â‚¬ Ghidra 12.0.3 Support (PR #29)
- **Full compatibility** with Ghidra 12.0.3 (released Feb 11, 2026)
- Updated `pom.xml` target version
- Updated Docker build configuration
- Updated all GitHub Actions workflows
- Updated documentation and setup scripts
- Fixes issue #14 for users on latest Ghidra

#### Ã°Å¸â€œâ€ž Pagination for Large Functions (PR #30)
- **New `offset` and `limit` parameters** for `decompile_function()` and `disassemble_function()`
- Prevents LLM context overflow when working with large functions
- Pagination metadata header shows total lines and next offset
- Backward compatible Ã¢â‚¬â€ only applies when parameters are specified
- Fixes issue #7

**Example usage:**
```python
# Get first 100 lines
code = decompile_function(address='0x401000', offset=0, limit=100)

# Get next chunk
code = decompile_function(address='0x401000', offset=100, limit=100)
```

**Response includes metadata:**
```c
/* PAGINATION: lines 1-100 of 523 (use offset=100 for next chunk) */
```

---

## v2.0.1 - 2026-02-19

### Patch Release - CI Fixes, Documentation, PowerShell Improvements

#### Ã°Å¸â€Â§ CI/Build Fixes
- **Fixed CI workflow**: Ghidra JARs now properly installed to Maven repository instead of just copied to lib/ (PR #23)
- **Proper Maven dependency management**: Works correctly with pom.xml changes from v2.0.0
- **Version as single source of truth**: `ghidra.version` now uses Maven filtering from pom.xml (PR #20)
- **Endpoint count updated**: Correctly reports 144 endpoints

#### Ã°Å¸â€œÂ Documentation
- **New troubleshooting section**: Comprehensive guide for common setup issues (PR #22)
- **Verification steps**: Added curl commands to verify server is working
- **Better error guidance**: Covers 500 errors, 404s, missing menus, and installation issues

#### Ã°Å¸â€“Â¥Ã¯Â¸Â PowerShell Setup Script
- **Fixed version sorting bug**: Now uses semantic version sorting instead of string sorting (PR #21)
- **Correct Ghidra detection**: Properly selects `ghidra_12.0.2_PUBLIC` over `ghidra_12.0_PUBLIC`
- Fixes issue #19

#### Ã°Å¸ÂÂ³ Docker Integration
- Added as submodule to [re-universe](https://github.com/bethington/re-universe) platform
- Enables AI-assisted analysis alongside BSim similarity matching

---

## v2.0.0 - 2026-02-03

### Major Release - Security, Ghidra 12.0.2, Enhanced Documentation

#### Ã°Å¸â€â€™ Security
- **Localhost binding**: HTTP server now binds to `127.0.0.1` instead of `0.0.0.0` in both GUI plugin and headless server Ã¢â‚¬â€ prevents accidental network exposure on shared networks
- Addresses the same concern as [LaurieWired/GhidraMCP#125](https://github.com/LaurieWired/GhidraMCP/issues/125)

#### Ã¢Å¡â„¢Ã¯Â¸Â Configurable Decompile Timeout
- New optional `timeout` parameter on `/decompile_function` endpoint
- Defaults to 60s Ã¢â‚¬â€ no behavior change for existing callers
- Allows longer timeouts for complex functions (e.g., `?timeout=300`)

#### Ã°Å¸ÂÂ·Ã¯Â¸Â Label Deletion Endpoints
- **New `delete_label` tool**: Delete individual labels at specified addresses
- **New `batch_delete_labels` tool**: Efficiently delete multiple labels in a single atomic operation
- Essential for cleaning up orphan labels after applying array types to pointer tables

#### Ã°Å¸â€Â§ Environment Configuration
- New `.env.template` with `GHIDRA_PATH` and other environment-specific settings
- Deploy script reads `.env` file Ã¢â‚¬â€ no more hardcoded paths
- Auto-detection of Ghidra installation from common paths
- Python bridge respects `GHIDRA_SERVER_URL` environment variable

#### Ã°Å¸Å¡â‚¬ Ghidra 12.0.2 Support
- Updated all dependencies and paths for Ghidra 12.0.2
- Updated library dependency documentation (14 required JARs)

#### Ã°Å¸â€ºÂ Ã¯Â¸Â Tool Count
- **Total MCP Tools**: 110 fully implemented
- **Java REST Endpoints**: 133 (includes internal endpoints)
- **New tools added**: 2 (delete_label, batch_delete_labels)

#### Ã°Å¸â€œÅ¡ Documentation
- Complete README rewrite with full tool listing organized by category
- Added architecture overview, library dependency table, and project structure
- Reorganized API documentation by category
- Added comprehensive contributing guidelines

#### Ã°Å¸Â§Âª Testing
- New unit tests for bridge utilities (`test_bridge_utils.py`)
- New unit tests for MCP tools (`test_mcp_tools.py`)
- Updated CI workflow to latest GitHub Actions versions

#### Ã°Å¸Â§Â¹ Cleanup
- Removed superseded files: `cross_version_matcher.py`, `cross_version_verifier.py` (replaced by hash index system in v1.9.4)
- Removed stale data files: `hash_matches_*.json`, `string_anchors.json`, `docs/KNOWN_ORDINALS.md`
- Refactored workflow engine (`continuous_improvement.py`, `ghidra_manager.py`)

---

## v1.9.4 - 2025-12-03

### Function Hash Index Release

#### Ã°Å¸â€â€” Cross-Binary Documentation Propagation
- **Function Hash Index System**: Hash-based matching of identical functions across different binaries
- **New Java Endpoints**:
  - `GET /get_function_hash` - Compute SHA-256 hash of normalized function opcodes
  - `GET /get_bulk_function_hashes` - Paginated bulk hashing with filter (documented/undocumented/all)
  - `GET /get_function_documentation` - Export complete function documentation (name, prototype, plate comment, parameters, locals, comments, labels)
  - `POST /apply_function_documentation` - Import documentation to target function
- **New Python MCP Tools**:
  - `get_function_hash` - Single function hash retrieval
  - `get_bulk_function_hashes` - Bulk hashing with pagination
  - `get_function_documentation` - Export function docs as JSON
  - `apply_function_documentation` - Apply docs to target function
  - `build_function_hash_index` - Build persistent JSON index from programs
  - `lookup_function_by_hash` - Find matching functions in index
  - `propagate_documentation` - Apply docs to all matching instances

#### Ã°Å¸Â§Â® Hash Normalization Algorithm
- Normalizes opcodes for position-independent matching across different base addresses
- **Internal jumps**: `REL+offset` (relative to function start)
- **External calls**: `CALL_EXT` placeholder
- **External data refs**: `DATA_EXT` placeholder
- **Small immediates** (<0x10000): Preserved as `IMM:value`
- **Large immediates**: Normalized to `IMM_LARGE`
- **Registers**: Preserved (part of algorithm logic)

#### Ã¢Å“â€¦ Verified Cross-Version Matching
- Tested D2Client.dll 1.07 Ã¢â€ â€™ 1.08: **1,313 undocumented functions** match documented functions
- Successfully propagated `ConcatenatePathAndWriteFile` documentation across versions
- Identical functions produce matching hashes despite different base addresses

#### Ã°Å¸â€ºÂ  Tool Count
- **Total MCP Tools**: 118 (112 implemented + 6 ROADMAP v2.0)
- **New tools added**: 7 (4 Java endpoints + 3 Python index management tools)

---

## v1.9.3 - 2025-11-14

### Documentation & Workflow Enhancement Release

#### Ã°Å¸â€œÅ¡ Documentation Organization
- **Organized scattered markdown files**: Moved release files to proper `docs/releases/` structure
- **Created comprehensive navigation**: Added `docs/README.md` with complete directory structure
- **Enhanced release documentation**: Added `docs/releases/README.md` with version index
- **Streamlined project structure**: Moved administrative docs to `docs/project-management/`

#### Ã°Å¸â€Â§ Hungarian Notation Improvements
- **Enhanced pointer type coverage**: Added comprehensive double pointer types (`void **` Ã¢â€ â€™ `pp`, `char **` Ã¢â€ â€™ `pplpsz`)
- **Added const pointer support**: New rules for `const char *` Ã¢â€ â€™ `lpcsz`, `const void *` Ã¢â€ â€™ `pc`
- **Windows SDK integration**: Added mappings for `LPVOID`, `LPCSTR`, `LPWSTR`, `PVOID`
- **Fixed spacing standards**: Corrected `char **` notation (removed spaces)
- **Array vs pointer clarity**: Distinguished stack arrays from pointer parameters

#### Ã°Å¸Å½Â¯ Variable Renaming Workflow
- **Comprehensive variable identification**: Mandated examining both decompiled and assembly views
- **Eliminated pre-filtering**: Attempt renaming ALL variables regardless of name patterns
- **Enhanced failure handling**: Use `variables_renamed` count as sole reliability indicator
- **Improved documentation**: Better comment examples for non-renameable variables

#### Ã°Å¸â€ºÂ  Build & Development
- **Fixed Ghidra script issues**: Resolved class name mismatches and deprecated API usage
- **Improved workflow efficiency**: Streamlined function documentation processes
- **Enhanced type mapping**: More precise Hungarian notation type-to-prefix mapping

---

## v1.9.2 - 2025-11-07

### Documentation & Organization Release

**Focus**: Project organization, documentation standardization, and production release preparation

#### Ã°Å¸Å½Â¯ Major Improvements

**Documentation Organization:**
- Ã¢Å“â€¦ Created comprehensive `PROJECT_STRUCTURE.md` documenting entire project layout
- Ã¢Å“â€¦ Consolidated `DOCUMENTATION_INDEX.md` merging duplicate indexes
- Ã¢Å“â€¦ Enhanced `scripts/README.md` with categorization and workflows  
- Ã¢Å“â€¦ Established markdown naming standards (`MARKDOWN_NAMING.md`)
- Ã¢Å“â€¦ Organized 40+ root-level files into clear categories

**Project Structure:**
- Ã¢Å“â€¦ Categorized all files by purpose (core, build, data, docs, scripts, tools)
- Ã¢Å“â€¦ Created visual directory trees with emoji icons for clarity
- Ã¢Å“â€¦ Defined clear guidelines for adding new files
- Ã¢Å“â€¦ Documented access patterns and usage workflows
- Ã¢Å“â€¦ Prepared 3-phase reorganization plan for future improvements

**Standards & Conventions:**
- Ã¢Å“â€¦ Established markdown file naming best practices (kebab-case)
- Ã¢Å“â€¦ Defined special file naming rules (README.md, CHANGELOG.md, etc.)
- Ã¢Å“â€¦ Created quick reference guides and checklists
- Ã¢Å“â€¦ Documented directory-specific naming patterns
- Ã¢Å“â€¦ Set up migration strategy for existing files

**Release Preparation:**
- Ã¢Å“â€¦ Created comprehensive release checklist (`RELEASE_CHECKLIST_v1.9.2.md`)
- Ã¢Å“â€¦ Verified version consistency across project (pom.xml 1.9.2)
- Ã¢Å“â€¦ Updated all documentation references
- Ã¢Å“â€¦ Prepared release notes and changelog
- Ã¢Å“â€¦ Ensured production-ready state

#### Ã°Å¸â€œÅ¡ New Documentation Files

| File | Purpose | Lines |
|------|---------|-------|
| `PROJECT_STRUCTURE.md` | Complete project organization guide | 450+ |
| `DOCUMENTATION_INDEX.md` | Consolidated master index | 300+ |
| `ORGANIZATION_SUMMARY.md` | Documentation of organization work | 350+ |
| `MARKDOWN_NAMING.md` | Quick reference for naming standards | 120+ |
| `.github/MARKDOWN_NAMING_GUIDE.md` | Comprehensive naming guide | 320+ |
| `scripts/README.md` (enhanced) | Scripts directory documentation | 400+ |
| `RELEASE_CHECKLIST_v1.9.2.md` | Release preparation checklist | 300+ |

#### Ã°Å¸â€Â§ Infrastructure Updates

- Ã¢Å“â€¦ Version consistency verification across all files
- Ã¢Å“â€¦ Build configuration validated (Maven 3.9+, Java 21)
- Ã¢Å“â€¦ Plugin deployment verified with Ghidra 11.4.2  
- Ã¢Å“â€¦ Python dependencies current (`requirements.txt`)
- Ã¢Å“â€¦ All core functionality tested and working

#### Ã¢Å“â€¦ Quality Metrics

- **Documentation coverage**: 100% (all directories documented)
- **Version consistency**: Verified (pom.xml 1.9.2 is source of truth)
- **Build success rate**: 100% (clean builds passing)
- **API tool count**: 111 tools (108 analysis + 3 lifecycle)
- **Test coverage**: 53/53 read-only tools verified functional

#### Ã°Å¸â€œÅ  Organization Achievements

**Before November 2025:**
- 50+ files cluttered in root directory
- 2 separate documentation indexes (duplicate)
- Unclear file categorization
- No scripts directory documentation
- Difficult navigation and discovery

**After November 2025:**
- 40 organized root files with clear categories
- 1 consolidated master documentation index
- Complete project structure documentation
- Comprehensive scripts README with categorization
- Task-based navigation with multiple entry points
- Visual directory trees for clarity
- Established naming conventions and standards

#### Ã°Å¸Å¡â‚¬ Production Readiness

- Ã¢Å“â€¦ **Build System**: Maven clean package succeeds
- Ã¢Å“â€¦ **Plugin Deployment**: Loads successfully in Ghidra 11.4.2
- Ã¢Å“â€¦ **API Endpoints**: All 111 tools functional
- Ã¢Å“â€¦ **Documentation**: 100% coverage with cross-references
- Ã¢Å“â€¦ **Testing**: Core functionality verified
- Ã¢Å“â€¦ **Organization**: Well-structured and maintainable

---

## v1.8.4 - 2025-10-26

### Bug Fixes & Improvements - Read-Only Tools Testing

**Critical Fixes:**
- Ã¢Å“â€¦ **Fixed silent failures in `get_xrefs_to` and `get_xrefs_from`**
  - Previously returned empty output when no xrefs found
  - Now returns descriptive message: "No references found to/from address: 0x..."
  - Affects: Java plugin endpoints (lines 3120-3167)

- Ã¢Å“â€¦ **Completed `get_assembly_context` implementation**
  - Replaced placeholder response with actual assembly instruction retrieval
  - Returns context_before/context_after arrays with surrounding instructions
  - Adds mnemonic field and pattern detection (data_access, comparison, arithmetic, etc.)
  - Affects: Java plugin getAssemblyContext() method (lines 7223-7293)

- Ã¢Å“â€¦ **Completed `batch_decompile_xref_sources` usage extraction**
  - Replaced placeholder "usage_line" with actual code line extraction
  - Returns usage_lines array showing how target address is referenced in decompiled code
  - Adds xref_addresses array showing specific instruction addresses
  - Affects: Java plugin batchDecompileXrefSources() method (lines 7362-7411)

**Quality Improvements:**
- Ã¢Å“â€¦ **Improved `list_strings` filtering**
  - Added minimum length filter (4+ characters)
  - Added printable ratio requirement (80% printable ASCII)
  - Filters out single-byte hex strings like "\x83"
  - Returns meaningful message when no quality strings found
  - Affects: Java plugin listDefinedStrings() and new isQualityString() method (lines 3217-3272)

- Ã¢Å“â€¦ **Fixed `list_data_types` category filtering**
  - Previously only matched category paths (file names like "crtdefs.h")
  - Now also matches data type classifications (struct, enum, union, typedef, pointer, array)
  - Added new getDataTypeName() helper to determine type classification
  - Searching for "struct" now correctly returns Structure data types
  - Affects: Java plugin listDataTypes() and getDataTypeName() methods (lines 4683-4769)

### Testing
- Systematically tested all **53 read-only MCP tools** against D2Client.dll
- **100% success rate** across 6 categories:
  - Metadata & Connection (3 tools)
  - Listing (14 tools)
  - Get/Query (10 tools)
  - Analysis (12 tools)
  - Search (5 tools)
  - Advanced Analysis (9 tools)

### Impact
- More robust error handling with descriptive messages instead of silent failures
- Completion of previously stubbed implementations
- Better string detection quality (fewer false positives)
- Type-based data type filtering now works as expected
- All read-only tools verified functional and returning valid data

---

## v1.8.3 - 2025-10-26

### Removed Tools - API Cleanup
- Ã¢ÂÅ’ **Removed 3 redundant/non-functional MCP tools** (108 Ã¢â€ â€™ 105 tools)
  - `analyze_function_complexity` - Never implemented, returned placeholder JSON only
  - `analyze_data_types` - Superseded by comprehensive `analyze_data_region` tool
  - `auto_create_struct_from_memory` - Low-quality automated output, better workflow exists

### Rationale
- **analyze_function_complexity**: Marked "not yet implemented" for multiple versions, no demand
- **analyze_data_types**: Basic 18-line implementation completely replaced by `analyze_data_region` (200+ lines, comprehensive batch operation with xref mapping, boundary detection, stride analysis)
- **auto_create_struct_from_memory**: Naive field inference produced generic field_0, field_4 names without context; better workflow is `analyze_data_region` Ã¢â€ â€™ manual `create_struct` with meaningful names

### Impact
- Cleaner API surface with less confusion
- Removed dead code from both Python bridge and Java plugin
- No breaking changes for active users (tools were redundant or non-functional)
- Total MCP tools: **105 analysis + 6 script lifecycle = 111 tools**

---

## v1.8.2 - 2025-10-26

### New External Location Management Tools
- Ã¢Å“â€¦ **Three New MCP Tools** - External location management for ordinal import fixing
  - `list_external_locations()` - List all external locations (imports, ordinal imports)
  - `get_external_location()` - Get details about specific external location
  - `rename_external_location()` - Rename ordinal imports to actual function names
  - Enables mass fixing of broken ordinal-based imports when DLL functions change

### New Documentation
- Ã¢Å“â€¦ **`EXTERNAL_LOCATION_TOOLS.md`** - Complete API reference for external location tools
  - Full tool signatures and parameters
  - Use cases and examples
  - Integration with ordinal restoration workflow
  - Performance considerations and error handling
- Ã¢Å“â€¦ **`EXTERNAL_LOCATION_WORKFLOW.md`** - Quick-start workflow guide
  - Step-by-step workflow (5-15 minutes)
  - Common patterns and code examples
  - Troubleshooting guide
  - Performance tips for large binaries

### Implementation Details
- Added `listExternalLocations()` method to Java plugin (lines 10479-10509)
- Added `getExternalLocationDetails()` method to Java plugin (lines 10511-10562)
- Added `renameExternalLocation()` method to Java plugin (lines 10567-10626)
- Added corresponding HTTP endpoints for each method
- Fixed Ghidra API usage for ExternalLocationIterator and namespace retrieval
- All operations use Swing EDT for thread-safe Ghidra API access

**Impact**: Complete workflow for fixing ordinal-based imports - essential for binary analysis when external DLL functions change or ordinals shift

---

## v1.8.1 - 2025-10-25

### Documentation Reorganization
- Ã¢Å“â€¦ **Project Structure Overhaul** - Cleaned and reorganized entire documentation
  - Consolidated prompts: 12 files Ã¢â€ â€™ 8 focused workflow files
  - Created `docs/examples/` with punit/ and diablo2/ subdirectories
  - Moved structure discovery guides to `docs/guides/`
  - Created comprehensive `START_HERE.md` with multiple learning paths
  - Updated `DOCUMENTATION_INDEX.md` to reflect new structure
  - Removed ~70 obsolete files (old reports, duplicates, summaries)

### New Calling Convention
- Ã¢Å“â€¦ **__d2edicall Convention** - Diablo II EDI-based context passing
  - Documented in `docs/conventions/D2CALL_CONVENTION_REFERENCE.md`
  - Applied to BuildNearbyRoomsList function
  - Installed in x86win.cspec

### Bug Fixes
- Ã¢Å“â€¦ **Fixed DocumentFunctionWithClaude.java** - Windows compatibility
  - Resolved "claude: CreateProcess error=2" 
  - Now uses full path: `%APPDATA%\npm\claude.cmd`
  - Changed keybinding from Ctrl+Shift+D to Ctrl+Shift+P

### New Files & Tools
- Ã¢Å“â€¦ **ghidra_scripts/** - Example Ghidra scripts
  - `DocumentFunctionWithClaude.java` - AI-assisted function documentation
  - `ClearCallReturnOverrides.java` - Clean orphaned flow overrides
- Ã¢Å“â€¦ **mcp-config.json** - Claude MCP configuration template
- Ã¢Å“â€¦ **mcp_function_processor.py** - Batch function processing automation
- Ã¢Å“â€¦ **scripts/hybrid-function-processor.ps1** - Automated analysis workflows

### Enhanced Documentation
- Ã¢Å“â€¦ **examples/punit/** - Complete UnitAny structure case study (8 files)
- Ã¢Å“â€¦ **examples/diablo2/** - Diablo II structure references (2 files)
- Ã¢Å“â€¦ **conventions/** - Calling convention documentation (5 files)
- Ã¢Å“â€¦ **guides/** - Structure discovery methodology (4 files)

### Cleanup
- Ã¢ÂÅ’ Removed obsolete implementation/completion reports
- Ã¢ÂÅ’ Removed duplicate function documentation workflows
- Ã¢ÂÅ’ Removed old D2-specific installation guides
- Ã¢ÂÅ’ Removed temporary Python scripts and cleanup utilities

**Impact**: Better organization, easier navigation, reduced duplication, comprehensive examples

**See**: Tag [v1.8.1](https://github.com/bethington/ghidra-mcp/releases/tag/v1.8.1)

---

## v1.8.0 - 2025-10-16

### Major Features
- Ã¢Å“â€¦ **6 New Structure Field Analysis Tools** - Comprehensive struct field reverse engineering
  - `analyze_struct_field_usage` - Analyze field access patterns across functions
  - `get_field_access_context` - Get assembly/decompilation context for specific field offsets
  - `suggest_field_names` - AI-assisted field naming based on usage patterns
  - `inspect_memory_content` - Read raw bytes with string detection heuristics
  - `get_bulk_xrefs` - Batch xref retrieval for multiple addresses
  - `get_assembly_context` - Get assembly instructions with context for xref sources

### Documentation Suite
- Ã¢Å“â€¦ **6 Comprehensive Reverse Engineering Guides** (in `docs/guides/`)
  - CALL_RETURN_OVERRIDE_CLEANUP.md - Flow override debugging
  - EBP_REGISTER_REUSE_SOLUTIONS.md - Register reuse pattern analysis
  - LIST_DATA_BY_XREFS_GUIDE.md - Data analysis workflow
  - NORETURN_FIX_GUIDE.md - Non-returning function fixes
  - ORPHANED_CALL_RETURN_OVERRIDES.md - Orphaned override detection
  - REGISTER_REUSE_FIX_GUIDE.md - Complete register reuse fix workflow

- Ã¢Å“â€¦ **Enhanced Prompt Templates** (in `docs/prompts/`)
  - PLATE_COMMENT_EXAMPLES.md - Real-world examples
  - PLATE_COMMENT_FORMAT_GUIDE.md - Best practices
  - README.md - Prompt documentation index
  - OPTIMIZED_FUNCTION_DOCUMENTATION.md - Enhanced workflow

### Utility Scripts
- Ã¢Å“â€¦ **9 Reverse Engineering Scripts** (in `scripts/`)
  - ClearCallReturnOverrides.java - Clear orphaned flow overrides
  - b_extract_data_with_xrefs.py - Bulk data extraction
  - create_d2_typedefs.py - Type definition generation
  - populate_d2_structs.py - Structure population automation
  - test_data_xrefs_tool.py - Unit tests for xref tools
  - data-extract.ps1, data-process.ps1, function-process.ps1, functions-extract.ps1 - PowerShell automation

### Project Organization
- Ã¢Å“â€¦ **Restructured Documentation**
  - Release notes Ã¢â€ â€™ `docs/releases/v1.7.x/`
  - Code reviews Ã¢â€ â€™ `docs/code-reviews/`
  - Analysis data Ã¢â€ â€™ `docs/analysis/`
  - Guides consolidated in `docs/guides/`

### Changed Files
- `bridge_mcp_ghidra.py` (+585 lines) - 6 new MCP tools, enhanced field analysis
- `src/main/java/com/xebyte/GhidraMCPPlugin.java` (+188 lines) - Struct analysis endpoints
- `pom.xml` (Version 1.7.3 Ã¢â€ â€™ 1.8.0)
- `.gitignore` - Added `*.txt` for temporary files

**See**: Tag [v1.8.0](https://github.com/bethington/ghidra-mcp/releases/tag/v1.8.0)

---

## v1.7.3 - 2025-10-13

### Critical Bug Fix
- Ã¢Å“â€¦ **Fixed disassemble_bytes transaction commit** - Added missing `success = true` flag assignment before transaction commit, ensuring disassembled instructions are properly persisted to Ghidra database

### Impact
- **High** - All `disassemble_bytes` operations now correctly save changes
- Resolves issue where API reported success but changes were rolled back

### Testing
- Ã¢Å“â€¦ Verified with test case at address 0x6fb4ca14 (21 bytes)
- Ã¢Å“â€¦ Transaction commits successfully and persists across server restarts
- Ã¢Å“â€¦ Complete verification documented in `DISASSEMBLE_BYTES_VERIFICATION.md`

### Changed Files
- `src/main/java/com/xebyte/GhidraMCPPlugin.java` (Line 9716: Added `success = true`)
- `pom.xml` (Version 1.7.2 Ã¢â€ â€™ 1.7.3)
- `src/main/resources/extension.properties` (Version 1.7.2 Ã¢â€ â€™ 1.7.3)

**See**: [v1.7.3 Release Notes](V1.7.3_RELEASE_NOTES.md)

---

## v1.7.2 - 2025-10-12

### Critical Bug Fix
- Ã¢Å“â€¦ **Fixed disassemble_bytes connection abort** - Added explicit response flushing and enhanced error logging to prevent HTTP connection abort errors

### Documentation
- Ã¢Å“â€¦ Comprehensive code review documented in `CODE_REVIEW_2025-10-13.md`
- Ã¢Å“â€¦ Overall rating: 4/5 (Very Good) - Production-ready with minor improvements identified

**See**: [v1.7.2 Release Notes](V1.7.2_RELEASE_NOTES.md)

---

## v1.7.0 - 2025-10-11

### Major Features
- Ã¢Å“â€¦ **Variable storage control** - `set_variable_storage` endpoint for fixing register reuse issues
- Ã¢Å“â€¦ **Ghidra script automation** - `run_script` and `list_scripts` endpoints
- Ã¢Å“â€¦ **Forced decompilation** - `force_decompile` endpoint for cache clearing
- Ã¢Å“â€¦ **Flow override control** - `clear_instruction_flow_override` and `set_function_no_return` endpoints

### Capabilities
- **Register reuse fixes** - Resolve EBP and other register conflicts
- **Automated analysis** - Execute Python/Java Ghidra scripts programmatically
- **Flow analysis control** - Fix incorrect CALL_TERMINATOR overrides

**See**: [v1.7.0 Release Notes](V1.7.0_RELEASE_NOTES.md)

---

## v1.6.0 - 2025-10-10

### New Features
- Ã¢Å“â€¦ **7 New MCP Tools**: Validation, batch operations, and comprehensive analysis
  - `validate_function_prototype` - Pre-flight validation for function prototypes
  - `validate_data_type_exists` - Check if types exist before using them
  - `can_rename_at_address` - Determine address type and suggest operations
  - `batch_rename_variables` - Atomic multi-variable renaming with partial success
  - `analyze_function_complete` - Single-call comprehensive analysis (5+ calls Ã¢â€ â€™ 1)
  - `document_function_complete` - Atomic all-in-one documentation (15-20 calls Ã¢â€ â€™ 1)
  - `search_functions_enhanced` - Advanced search with filtering, regex, sorting

### Documentation
- Ã¢Å“â€¦ **Reorganized structure**: Created `docs/guides/`, `docs/releases/v1.6.0/`
- Ã¢Å“â€¦ **Renamed**: `RELEASE_NOTES.md` Ã¢â€ â€™ `CHANGELOG.md`
- Ã¢Å“â€¦ **Moved utility scripts** to `tools/` directory
- Ã¢Å“â€¦ **Removed redundancy**: 8 files consolidated or archived
- Ã¢Å“â€¦ **New prompt**: `FUNCTION_DOCUMENTATION_WORKFLOW.md`

### Performance
- **93% API call reduction** for complete function documentation
- **Atomic transactions** with rollback support
- **Pre-flight validation** prevents errors before execution

### Quality
- **Implementation verification**: 99/108 Python tools (91.7%) have Java endpoints
- **100% documentation coverage**: All 108 tools documented
- **Professional structure**: Industry-standard organization

**See**: [v1.6.0 Release Notes](docs/releases/v1.6.0/RELEASE_NOTES.md)

---

## v1.5.1 - 2025-01-10

### Critical Bug Fixes
- Ã¢Å“â€¦ **Fixed batch_set_comments JSON parsing error** - Eliminated ClassCastException that caused 90% of batch operation failures
- Ã¢Å“â€¦ **Added missing AtomicInteger import** - Resolved compilation issue

### New Features
- Ã¢Å“â€¦ **batch_create_labels endpoint** - Create multiple labels in single atomic transaction
- Ã¢Å“â€¦ **Enhanced JSON parsing** - Support for nested objects and arrays in batch operations
- Ã¢Å“â€¦ **ROADMAP v2.0 documentation** - All 10 placeholder tools clearly marked with implementation plans

### Performance Improvements
- Ã¢Å“â€¦ **91% reduction in API calls** - Function documentation workflow: 57 calls Ã¢â€ â€™ 5 calls
- Ã¢Å“â€¦ **Atomic transactions** - All-or-nothing semantics for batch operations
- Ã¢Å“â€¦ **Eliminated user interruption issues** - Batch operations prevent hook triggers

### Documentation Enhancements
- Ã¢Å“â€¦ **Improved rename_data documentation** - Clear explanation of "defined data" requirement
- Ã¢Å“â€¦ **Comprehensive ROADMAP** - Transparent status for all placeholder tools
- Ã¢Å“â€¦ **Organized documentation structure** - New docs/ subdirectories for better navigation

---

For older release details, see the [docs/releases/](docs/releases/) directory.

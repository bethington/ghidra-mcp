# Release Documentation Index

This directory contains version-specific release documentation for the Ghidra MCP project.

For the full version history, see [CHANGELOG.md](../../CHANGELOG.md) in the project root.

For the release preparation runbook, see
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).

## Current Releases

### v5.15.0 (Latest) — headless GZF/GAR round-trip + debugger write primitives

Minor release. Headless program (`.gzf`) and project (`.gar`) archive
round-trip endpoints — `/export_program`, `/import_program`,
`/archive_project`, `/restore_project` — with two rounds of path-safety
hardening (traversal rejection, ambiguous-name resolution, exact-name
program lookup, non-destructive overwrite, post-restore verification).
Docker's Jython extension now auto-unpacks for Ghidra 12.1+. The
standalone debugger server gained `write_memory` / `write_registers`
primitives for driving controlled execution of inlined code fragments.
255 tools.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.14.1 — community-driven tools: /get_current_selection + GUI /open_project

Minor release. Two new endpoints filed/scoped by community feedback,
plus a quiet headless parity fix that surfaced while writing the
parity test. 245 tools.

- **`/get_current_selection` (GUI-only)** — closes the "where am I?"
  family alongside `/get_current_address` and `/get_current_function`.
  Returns the CodeBrowser listing's current selection as
  `{program, is_empty, ranges, min_address, max_address, num_addresses}`.
  Reads from `CodeViewerService.getCurrentSelection()` — the canonical
  Ghidra API for the listing's highlight state. Returns "Code viewer
  service not available" when no CodeBrowser is up, matching the
  sibling tools' error shape so AI clients see one consistent fall-
  through path for the whole family. Filed by @I-Knight-I on issue #153.
- **GUI plugin `/open_project`** with optional `headless=true` (default
  true) and optional `program` body params. The headless server has
  had `/open_project` since v4.x; the GUI plugin previously had no
  programmatic way to point Ghidra at a different project. The new
  route saves and closes the active project, opens the requested one
  via `ProjectManager.openProject(locator, ...)`, calls
  `AppInfo.setActiveProject`, and only when `headless=false` and
  `program` is set — auto-launches a CodeBrowser for that DomainFile.
  Same project already active is a no-op success (`already_open: true`)
  so accidental re-opens don't blow away CodeBrowser state. All
  FrontEnd mutations run on the EDT via `SwingUtilities.invokeAndWait`.
- **Headless `/server/admin/terminate_all_checkouts` parity fix** — the
  GUI plugin has registered this route since v5.6 but the headless
  server didn't. Added the `safeContext` registration plus the
  `terminateAllCheckouts()` implementation on `GhidraServerManager`.
  Also accepts `checkout_id` alias on
  `/server/admin/terminate_checkout` to match the cataloged param.
- **7 new offline tests** pin the new endpoints at the source level:
  route registrations, helper signatures, EDT marshaling, the
  `AppInfo.setActiveProject` call, and the catalog `params` drift
  guards.

Backward compatibility: every change is additive. Existing endpoint
behavior unchanged.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.11.4 — automatic ghidratrace install for the debugger launcher

Patch release with one targeted fix: the deploy flow now auto-installs
the matching `ghidratrace` wheel into the launcher Python during
`install-ghidra-deps` / `ensure-prereqs`, so the same
`VersionMismatchError: Front-end 12.1, back-end 12.0` that surfaced
three times in this release cycle cannot recur after a Ghidra version
bump. 244 tools, no functional API changes.

- **New helper `install_ghidratrace_for_debugger()`** resolves the
  launcher Python via the same precedence the live test uses
  (`GHIDRA_DEBUGGER_PYTHON` env var → `<repo>/.env` → `shutil.which("python")`),
  then `pip install --force-reinstall`s the wheel from
  `<ghidra>/Ghidra/Debug/Debugger-rmi-trace/pypkg/dist/`. Protobuf
  `>=6.31.0` (the floor `ghidratrace.setuputils` enforces) is upgraded
  first.
- **Wired into `install_ghidra_dependencies`** so `tools.setup
  ensure-prereqs` and `install-ghidra-deps` keep the launcher Python's
  `ghidratrace` aligned with the installed Ghidra every time they run.
  Best-effort: a pip failure here does NOT block the main JAR
  dependency setup (most users don't run the live debugger).
- **CI tests-on-Linux fix** — debugger-live unit tests stub
  `_terminate_processes_by_name` so the function's `finally:` clause
  doesn't spawn `taskkill` on the Linux runner and mask the test's
  actual outcome (previously caused a pytest INTERNALERROR with
  "cannot instantiate WindowsPath on your system").
- **5 new unit tests** pin the install helper's contract:
  env-var precedence, dotenv fallback, no-op when no wheel is
  bundled, dry-run doesn't invoke pip, and live invocation passes
  `--force-reinstall` + the bundled wheel path.

Backward compatibility: every change is additive. Existing
deployments unchanged until the next `ensure-prereqs` /
`install-ghidra-deps` run.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.11.3 — deploy/audit hardening + contributor recognition

Patch release closing several small papercuts: a recurring deploy bug,
a release-test environmental flake, a year-running audit false
positive, and a long-overdue contributor credit. 244 tools, no
functional API changes.

- **#217 fixed — deploy no longer over-patches sibling Ghidra user
  dirs.** `patch_ghidra_user_configs` globbed `*/FrontEndTool.xml`
  under the user-config base, stamping the new plugin's INCLUDE
  into every Ghidra version's user dir (12.0.4, 11.4.2, …) even
  when the deploy was targeting 12.1. Observed twice in this
  release cycle's logs. Function now takes an explicit
  `target_user_dir`; `deploy_to_ghidra` passes the result of
  `resolve_ghidra_user_dir(ghidra_path)`. Four new regression
  tests pin the target-only contract.
- **Release-tier deploy: debugger-live test now skips on missing
  prerequisites** instead of failing the whole release gate. New
  `DebuggerLiveTestSkipped` sentinel exception covers
  non-Windows hosts, absent `BenchmarkDebug.exe`, and known-
  environmental launch errors (no WDK, ghidratrace version
  mismatch, dbgeng backend missing). Five new unit tests pin the
  skip/raise classification.
- **Audit watcher: `bridge_counter_stall` false-positive fixed.**
  The rule polls `/api/_diag_bridge` for tool-call counters, but
  the endpoint didn't exist — the fetcher caught the 404,
  returned `{}`, and every counter read as 0. Result: 24
  identical fires between 2026-04-25 and 2026-05-21, exactly one
  per day at the 30-minute stall threshold. New endpoint
  surfaces real counters wired off the bus; four new tests pin
  the shape + monotonic-increment contract. Stale registry +
  queue archived during the cut.
- **README updates** — `@huehuehuehueing` joins `@heeen` in Core
  Contributors for address-space prefix support (#84) and the
  optional `program` parameter / schema fixes (#92). Discussions
  badge swapped from `shields.io/github/discussions` (broken
  with "unable to select next GitHub token from pool" — a
  shields.io rate-limit issue, not ours) to a static
  "discussions → join" badge that always renders.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.11.2 — customizable convention enforcement

Feature release opening the v5.0 enforcement layer to per-project
customization without weakening the strict-by-default posture. 244
tools.

- **`.ghidra-mcp/conventions.json` per-project config** — five sections
  (`strict_mode`, `function_naming`, `hungarian`, `global_naming`,
  `plate_comments`) cover every previously-hardcoded knob: verb
  whitelist add/remove, verb tier overrides, weak-noun add/remove,
  function-name min length, struct-field auto-Hungarian toggle,
  `g_` prefix requirement toggle, descriptor min length, plate-
  comment validation toggle, required-section list, first-line word
  count. Defaults reproduce pre-v5.11.2 hardcoded behavior exactly.
- **Per-call `strict_mode` parameter** on five enforcement endpoints
  (`rename_function_by_address`, `apply_data_type`, `set_global`,
  `rename_or_label`, `rename_global_variable`). Values:
  `enforce` / `warn` / `off`. Defaults to null = "use the global
  setting" so existing callers don't change.
- **Plate-comment validation gate** finally toggleable — closes the
  longstanding always-reject gap from v5.6.0.
- **fun-doc workers** now surface `no_eligible_candidates` on empty
  exits — workers spawned on a binary with nothing left to do are
  distinguishable from real failures in the dashboard.
- **Deploy hardening** — pinned `protobuf>=6.31.0` in
  `requirements-debugger.txt` and documented the manual
  `ghidratrace` wheel install. Both are required to keep the Ghidra
  TraceRmi debugger backend in sync with the front-end after a
  Ghidra version bump (a stale 12.0 ghidratrace shadow installed
  during the 12.0.4 → 12.1 upgrade caused
  `VersionMismatchError: Front-end 12.1, back-end 12.0`).
- **Docs**: [`docs/prompts/CUSTOMIZING_CONVENTIONS.md`](../prompts/CUSTOMIZING_CONVENTIONS.md)
  with the full schema, three-layer precedence table, and a worked
  non-Hungarian C++ project example.

Backward compatibility: every change is additive. No config file +
no `strict_mode` param = identical behavior to v5.11.1.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.11.1 — deploy hardening, coverage, attribution

Patch release bundling the post-v5.11.0 deploy hardening and test
coverage backfill discovered while shipping Ghidra 12.1 support. 244
tools, no functional API changes.

- **Plugin `endpoint_count` no longer drifts from `/mcp/schema`** —
  the version banner field was hardcoded at 177 while the scanner
  registered 196. Now set dynamically after registration completes.
- **Deploy warns when an old Ghidra is still running** — process
  detection split so a Ghidra running from a *different* install
  path is no longer invisible (it used to intercept post-start
  smoke checks bound to MCP port 8089).
- **Apache 2.0 attribution self-contained** — `LICENSE` copyright
  line filled in (LaurieWired + project contributors), new `NOTICE`
  file, README acknowledgment of the upstream project.
- **16 new tests** covering deploy-setup paths and MCP-readiness:
  open-form `<PACKAGE NAME="Utility">` patching,
  `patch_frontend_tool_config` idempotency,
  `mark_extension_known_in_tool_config`, `patch_ghidra_user_configs`,
  the DEV+PUBLIC user-config dir coexistence scenario (#217), plus
  version-vs-pom matching, schema floor, endpoint-count consistency,
  and ghidra-version well-formedness.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.11.0 — Ghidra 12.1 + community fixes

Minor release retargeting at Ghidra 12.1 and rolling up four
community-reported fixes plus the gemini-cli-sdk reconciliation.
244 tools.

- **#211 — Ghidra 12.1 support** (@firefart, PR #213 by @synthol).
  pom bumped 12.0.4 → 12.1; CI / release / Docker download metadata
  pointed at the Ghidra 12.1 20260513 upstream asset; setup docs,
  examples, defaults, and compatibility tests refreshed for
  `ghidra_12.1.2_PUBLIC`. Documents the 12.1 shared-server requirement
  (clients on 12.1 need server 12.1 or 12.0.5+) and that Jython is
  optional in 12.1 (install via File → Install Extensions if you run
  `.py` Ghidra scripts).
- **#212 — bridge tool registration aborted on one malformed schema
  entry** (@killerra, PR #214 by @synthol). Dynamic registration now
  skips only the failing tool, keeps loading later valid tools, and
  writes a stderr diagnostic with the bad tool name and exception.
  Tests cover both the connect-time eager and the lazy group-load
  paths.
- **#209 — bridge auto-analysis crash on un-analyzed programs**
  (@s-b-repo). `runAutoAnalysisAndPersistFlags` wrapped in
  `startTransaction`/`endTransaction` so writing analyzers no longer
  hit `db.NoTransactionException`.
- **#207 — fun-doc tool parameter mismatches** (@dalen). Three
  silent-failing internal calls fixed (archive-apply rename, archive-
  apply plate, library-code plate) + one latent fallback. New AST-
  driven parity test (`test_fundoc_endpoint_param_parity.py`) makes
  param drift a CI failure. Broader API-wide naming inconsistency
  tracked in #210.
- **#201 — Gemini SDK reconciliation** (@dalen). The working SDK
  lives at `bethington/gemini-agent-sdk` (renamed to de-conflict
  with the unrelated PyPI `gemini-cli-sdk`); fun-doc vendors it at
  `fun-doc/vendored/gemini_agent_sdk/` so the Gemini provider works
  with no extra install step.
- **#119 — structured headless diagnostics** (@j4s0n, @t0xk).
  `/load_program_from_project` failure responses now carry
  `project_server_bound`, `available_program_paths`, and a
  `suggestion`; `/get_project_info` surfaces server binding state.
  The "checked out but can't open" failure mode is now self-
  diagnosing. (Full shared-project endpoint still tracked in #119.)
- **#204 dashboard follow-up** — All Functions table gains a `Src`
  column showing each row's `name_source` and flagging propagation
  rows the selector will skip. Mirrors the selector gates exactly
  via a shared `compute_skip_reason` helper, regression-pinned by
  `test_compute_skip_reason.py`.
- **Security policy** (@dodge1218, #215). `SECURITY.md` published
  with the private-vulnerability-reporting path; GitHub PVR enabled
  for the repository.
- `/search_instructions` always echoes `mnemonic_filter` /
  `operand_filter` (Gson was dropping the null values).

**Upgrade note** — this release retargets the project at Ghidra 12.1.
Users on 12.0.4 should upgrade their Ghidra install; shared-server
setups need Ghidra Server 12.1 or 12.0.5+. Jython is optional in
12.1.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.10.0 — operations + propagation provenance + community features

Minor release rolling up a community feature (#172), two operational
hardening passes, and the propagation-provenance gate (#204) that
closes the v5.9.x worker token-leak on cross-version hash-propagated
CRT/STL. 243 → 244 tools.

- **`/search_instructions`** (#172, @Gaok1) — operand-pattern
  instruction search. Complement to `/search_byte_patterns`
  (byte-level); this matches after Ghidra has parsed instructions,
  so callers can search for `mov` + `[ecx+0xD0]` without knowing the
  encoding. Optional `function=` scope, `limit=` cap with
  truncation reporting.
- **Name-source provenance** (#204) — three new columns on
  `functions_workflow` (`name_source`, `name_source_binary`,
  `name_confidence`) tracking where each function name came from.
  The selector now skips `name_source = 'propagation'` rows with
  `name_confidence < 0.5` (tunable via
  `FUN_DOC_PROPAGATION_CONFIDENCE_THRESHOLD`) unless pinned. Closes
  the v5.9.x failure mode where cross-version hash propagation gave
  plausible D2-style names to statically-linked CRT/STL/iostream —
  ~10M input tokens burned on the top 7 such misidentifications in
  BH.dll's last 24h before the gate. Includes a backfill CLI
  (`scripts/backfill_name_source.py`) to mark existing rows by
  regex or JSON manifest. Migration `0003_name_source.sql` applied
  automatically on first dashboard start.
- **Log rotation** (`fun-doc/log_rotation.py`) — single
  `write_jsonl_rotating()` helper wraps the three operational JSONL
  logs (`ghidra_http.jsonl`, `runs.jsonl`, `events.jsonl`). Default
  200 MB × 5 backups = ~1.2 GB hard cap per series. Pre-rotation,
  `ghidra_http.jsonl` was unbounded and hit 1.03 GB in three weeks
  on the user's main workspace.
- **Storage backend loud-fail** — post-v5.9.1 follow-up: the
  import-time guard caught "sqlalchemy missing"; this commit extends
  the guard so post-import failures (Postgres unreachable, bad URL,
  schema migration broken, SQLite path unwritable) also `sys.exit(1)`
  with an actionable diagnostic instead of silently falling back to
  legacy `state.json`.
- **Legacy CLI tools archived** — `tools/scan_undocumented_functions.py`,
  `tools/scan_functions_mcp.py`, `tools/document_function.py` moved
  to `docs/archive/legacy-tools/` (gitmv-preserved history). All
  three predated `fun-doc/` by ~7 months and were last touched
  2025-10-10; everything they did is now better-handled by the
  worker + dashboard. Files still work against the stable v5.9.1
  HTTP API.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.9.1 — community fixes + fun-doc reliability

Patch release rolling up four community fixes (#200, #201, #202, #205)
plus three internal reliability fixes that landed during v5.9.0 worker
review. No new endpoints; existing `/disassemble_bytes` gains an
instruction-text payload (back-compat preserved). 243 tools.

- **Strict-naming toggle now preserves struct field names** (#200/#202,
  @1ndahaus3) — `create_struct`, `add_struct_field`, `modify_struct_field`
  no longer auto-prefix when the built-in naming convention is disabled.
- **`/disassemble_bytes` returns instruction text** (#205, @larrynz) —
  new optional `include_instructions` (default `true`) and
  `max_instructions` (default `1000`) POST params; each entry carries
  `address`, `mnemonic`, `operands`, `length`, `bytes` (lowercase hex).
- **Friendlier `gemini-cli-sdk` ImportError** (#201, @dalen) — message
  quotes the actual import error, names three working alternatives
  (minimax / claude / codex), and points at the pin-to-source workaround.
- **fun-doc loud-fail on missing sqlalchemy** — refuses to start instead
  of silently falling back to legacy `state.json`.
- **Library-code detector catches `_Setgloballocale` / `_Atexit` / TLS
  callbacks** — plugging a v5.9.0 miss where the worker burned 92K
  tokens on locale init.
- **Migration script carries `library_code` fields** — was dropping
  them on `state.json → state.db` folds.
- **Block-reason capture** — `_log_run_once` now extracts the reason
  text after recognized markers instead of dropping it.
- **Test fixture stopped wiping `fun-doc/state.db`** — autouse fixture
  refuses to delete files over 512 KB.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.9.0 — community fixes + P-code endpoints + library-code detector

Bundles three community-reported bug fixes (#170, #175, #192) plus an
internal fun-doc improvement (library-code auto-classification). 241 → 243 tools.

- **Multi-instance discovery on macOS** (#170, PR #195) — bridge now
  scans every plausible socket directory (`XDG_RUNTIME_DIR`,
  `$TMPDIR`, `/var/folders/*/*/T/`, `/private/var/folders/*/*/T/`,
  `/tmp`, `%TEMP%`).
- **Windows TCP port collisions** (#175, PR #196) — UDS enabled by
  default on all platforms; TCP port-range fallback scans
  `8089..8104` when the configured port is taken; actual bound port
  surfaced via `/mcp/instance_info → tcp_port`.
- **P-code endpoints** (#192, PR #197) — `/get_function_pcode` (basic
  + high granularity, full HighFunction graph with SSA flags),
  `/get_language_metadata` (SLEIGH facts, register relations,
  default symbols).
- **Library-code auto-classification (fun-doc)** (PR #198) — heuristic
  detector trips on canonical CRT names + CRT-only callees;
  conservative tuning for `/GS` stack-cookie helpers.

- See [CHANGELOG.md](../../CHANGELOG.md) for full details.

### v5.8.0 — fun-doc SQL storage migration (PR1)

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

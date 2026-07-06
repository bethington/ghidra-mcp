# Changelog - Ghidra MCP Server

Complete version history for the Ghidra MCP Server project.

---

## Unreleased

### Added

- **Coverage gates and baselines across all test tiers.**
  - CI unit job now runs with coverage and a `--cov-fail-under=46` ratchet
    (baseline 53%); the offline fun-doc job adds `--cov=fun-doc` with a floor of
    26 (baseline 29%). Both upload to Codecov. The floor is a ratchet — it sits
    a few points below the measured baseline to absorb platform/version skew;
    raise it as coverage improves, never lower it.
  - JaCoCo wired into Maven (`jacoco-maven-plugin` 0.8.13, report on every
    `mvn test`, `-Djacoco.skip=true` to disable) — first-ever Java coverage
    baseline (6.5% line, offline tier). CI uploads the report artifact.
  - New `python-tests-windows` CI job runs the unit suite on windows-latest so
    both halves of every `os.name == "nt"` branch (AF_UNIX gating, drive sweep)
    execute on each PR; wired into `build-status`.

### Fixed

- **WOW64 exception-filter gaps found in review of #366/#367.** #366 and #367
  shipped with no test coverage of `_on_exception`, `_our_bp_addrs`, or the
  fast path, and their design docs assumed contradictory models of how a
  planted breakpoint's INT3 is delivered on WOW64 (first-chance EXCEPTION vs.
  the separate BREAKPOINT event) with no live run confirming either. Added
  `TestOnExceptionFilter`/`TestDetachClearsBreakpointBookkeeping` in
  `tests/unit/test_debugger_engine.py` pinning the fast path, WX86 code
  handling, ret_catch recognition, and fault capture, so a future change
  can't silently regress either PR's fix. Also fixed two real bugs the
  contradiction surfaced: (1) `_on_exception`'s address match now queries
  dbgeng's *live* breakpoint list (`_live_bp_addrs()`) instead of the
  `_our_bp_addrs` shadow set, which went stale the moment a oneshot
  breakpoint fired (dbgeng auto-drops the object with no
  `remove_breakpoint()` call to clean up the shadow entry) — a later real
  exception at the reused address would otherwise be misclassified as ours
  and hidden from the target; (2) `detach()` now clears
  `_our_bp_addrs`/`_bp_id_to_addr`/`_call_guard`/`_stepping`, which
  previously survived a detach and could misclassify the next attached
  process's exceptions. **Live-verified end to end on genuine WOW64
  (2026-07-05)**: compiled a synthetic, disposable x86 process (confirmed
  PE machine type 0x14C) looping on `kernel32!SleepEx`. Passive path:
  `go_wait` reported repeated genuine hits under the merged filter even
  without registering `events.breakpoint()` — dbgeng halts execution at a
  recognized breakpoint independent of the interest mask, so the fast path
  does not swallow ordinary passive-capture breakpoints. Guarded-call path:
  with the thread stopped at that hit, `call_function` (defaulted
  `ret_catch`) returned cleanly (`returned_to == ret_catch`, not faulted),
  and passive capture kept working afterward with no run-control poisoning.
  See the docstring on `_on_exception` and the `reference-debugger-sim-runs`
  memory.
- **fun-doc storage bootstrap race.** `_get_storage_repo()` was an unlocked
  check-then-build singleton and `db/migrate.py` recorded schema versions
  with a bare INSERT, so two threads bootstrapping the same fresh SQLite
  (worker/watchdog + main) could die with `UNIQUE constraint failed:
  schema_versions.version`. Now double-check-locked, with
  `INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` version recording. `migrate()`
  is additionally serialized with a module-level lock: the PRAGMA-based
  `ADD COLUMN` skip can't win a cross-connection TOCTOU race (two threads both
  read an empty schema and race the same `ALTER TABLE ADD COLUMN`, the loser
  dying with "duplicate column name"), so the lock lets the second caller
  observe the first's committed schema and no-op. 3 race-regression tests in
  `test_migrate_sqlite_idempotent.py`.
- **libclang/clang version mismatch.** The `clang` bindings (21.x) had outrun
  the `libclang` DLL wheel (18.1.1, the newest published on PyPI), breaking
  `benchmark/extract_truth.py` with `clang_getOffsetOfBase not found`. Both are
  now pinned to LLVM 18.1.x (`clang>=18.1.8,<19`, `libclang>=18.1.1,<19`); the
  3 erroring extract-truth tests pass.
- **Windows cross-drive UDS discovery + AF_UNIX fallback.** On Windows the
  plugin's socket-dir fallback (`/tmp`, drive-relative) resolved against the
  JVM's working drive (e.g. `F:\tmp` when Ghidra runs from F:) while the bridge
  scanned its own drive's `\tmp`, so `list_instances` always reported "No
  running Ghidra instances" and the bridge never auto-connected after a Ghidra
  restart. Three-part fix:
  - Plugin: `ServerManager.getSocketDir()` now falls back to `java.io.tmpdir`
    (honors `%TEMP%`) before the literal `/tmp`, giving both sides an absolute,
    agreed-on location.
  - Bridge: `get_socket_dir_candidates()` sweeps every mounted drive root for
    `<drive>:\tmp\ghidra-mcp-<user>` (backward compat with older JARs).
  - Bridge: on Windows CPython, which doesn't expose `socket.AF_UNIX`
    (python/cpython#77589), discovery enriches socket-file hits with
    project/programs/url fetched over the plugin's TCP listener (joined by PID),
    and `connect_instance` / startup auto-connect / post-restart reconnect all
    route the connection over that TCP url instead of failing the UDS handshake.
  - Tests: real-socket transport tests (`test_transport_network.py`) and bridge
    CLI / DNS-rebinding tests (`test_bridge_cli.py`), plus
    `ServerManagerSocketDirTest.java` for the plugin fallback.

### Changed

- **Bridge restructured into a package + uv-native packaging.** The historical
  single-file `bridge_mcp_ghidra.py` (~2,270 lines) is split into a focused-module
  package under `python/bridge_mcp_ghidra/` (`config`, `state`, `server`,
  `validation`, `transport`, `discovery`, `schema`, `dispatch`, `registry`,
  `static_tools`, `debugger`, `cli`). Behavior is unchanged; cross-module calls
  are module-qualified and mutable runtime state lives in `state.py`.
- **uv is now the Python toolchain.** A root `pyproject.toml` + `uv.lock` define
  the shippable `ghidra-mcp-bridge` wheel (console script `bridge-mcp-ghidra`)
  and PEP 735 dependency groups (`test`, `debugger`, `fun-doc`, `dev`). The
  `requirements*.txt` files and `pytest.ini` were removed (folded into
  `pyproject.toml`); `tools.setup` installs deps via `uv sync` and deploys the
  built wheel.
- **CI builds and attaches a wheel.** Release / pre-release workflows build the
  bridge wheel with `uv build` and publish `ghidra_mcp_bridge-X.Y.Z-py3-none-any.whl`
  as the GitHub Release asset instead of the raw bridge script. Test/lint jobs run
  through uv.
- **Run the bridge with** `uv run bridge-mcp-ghidra` or `python -m bridge_mcp_ghidra`
  (the old `python bridge_mcp_ghidra.py` invocation is gone).

---

## v5.15.0 - 2026-07-02 (minor: headless GZF/GAR round-trip + debugger write primitives)

Minor release adding headless program/project archive endpoints (with two
rounds of path-safety hardening), Docker Jython support for Ghidra 12.1, and
live-process memory/register write primitives to the standalone debugger.

### Added

- **Headless GZF program and GAR project round-trip endpoints.** `POST
  /export_program` and `POST /import_program` pack/unpack a single Ghidra Zip
  File (`.gzf`) without a full project tarball, for both in-memory and
  project-based programs. `POST /archive_project` and `POST /restore_project`
  do the same for a whole Ghidra project as a `.gar` archive. All four accept
  overwrite protection and work from headless scripts and CI without a GUI.
- **`saveAllOpenPrograms` reports the total open program count** and surfaces
  a specific error when a program isn't attached to a writable project (a
  transient `DomainFileProxy`), instead of a generic save failure.
- **The `ANALYZED` flag is persisted after `/run_analysis`** via
  `GhidraProgramUtilities.markProgramAnalyzed(program)` inside the write
  transaction, so a re-opened program isn't silently re-prompted for analysis
  in the GUI.
- **Docker: the Jython extension is auto-unpacked for Ghidra 12.1+** during
  image build, restoring Jython script support in the containerized runtime.
- **Debugger: `write_memory` and `write_registers` primitives.** New
  `POST /debugger/write_memory` and `POST /debugger/write_registers` on the
  standalone debugger server let a caller drive controlled execution of a
  code fragment (set EIP + input registers/stack, then step) — enabling
  emulation-style capture of inlined arithmetic that has no standalone
  function to emulate statically (e.g. D2's to-hit / damage macros). Both
  require the target stopped; Ghidra-address translation reuses the existing
  mapper. Not yet exposed as MCP tools — callable directly against the
  debugger server's HTTP API.

### Fixed

- **Headless GZF/GAR endpoints reject path traversal.** Caller-supplied
  names (`output_name` on `/export_program` + `/archive_project`,
  `project_name` on `/restore_project`) are validated to be plain filenames
  (no `/`, `\`, or `..`), and the resolved output path is canonicalised and
  confirmed to stay inside its target directory via `HeadlessPaths`, the
  single validation choke point (covered offline by `HeadlessPathsTest`).
- **`/import_program` validates the caller-supplied `target_name`** before
  the project tree is touched, and the import-folder resolver rejects
  `.`/`..` path segments.
- **`/export_program` refuses to guess on an ambiguous bare name**, failing
  loud with a listed match count instead of silently packing the first hit
  from a folder walk, and resolves the live program to pack by exact (then
  case-insensitive) name instead of fuzzy substring match.
- **`/restore_project` verifies the project actually materialised on disk**
  after `RestoreTask` returns, instead of trusting headless GUI auto-open to
  have succeeded silently.
- **`/import_program` overwrite is no longer destructive on failure.** The
  existing `DomainFile` is renamed aside to a `.bak-<ts>` backup and only
  deleted after the new file is created; a failed import restores the
  original. Overwriting a program currently loaded in memory is rejected up
  front with a structured error.
- **File-loaded programs are materialised into the project** so
  `/save_all_programs` and `/export_program` work on them — `loadProgramFromFile`
  now passes the active project to `AutoImporter` and saves the result,
  turning a transient `DomainFileProxy` into a real `DomainFile`. Reloading
  the same name reopens the existing file instead of throwing
  `DuplicateNameException`.
- **`tests/endpoints.json` `total_endpoints` reconciled to 255**, matching
  the endpoint array length and the offline scanner/parity suite
  (`EndpointsJsonParityTest`), which had drifted stale after merging catalog
  changes from multiple branches.

---

## v5.14.2 - 2026-06-27 (patch: TCP fallback + PIC/GOT fixes)

Patch release fixing Windows UDS/TCP fallback regression and decompiler output accuracy for PIC binaries.

### Added

- **Parameter aliases for API naming consistency** (Issue #210): endpoints now accept alternative
  parameter names alongside their canonical names, enabling a standardized API while maintaining
  backward compatibility. Example: `/rename_data` accepts both `new_name` (canonical) and `newName`
  (legacy camelCase), with only `new_name` advertised in `/mcp/schema` to guide new callers toward
  consistent naming. Canonical names: `function_address` for function operations, `address` for
  data operations, `new_name` / `old_name` for rename operations (snake_case). Legacy names like
  `newName`, `oldName`, `function_address` (in data contexts) are recognized at runtime but not
  in schema, with optional deprecation logging per alias hit (configurable). Non-breaking change:
  all existing API calls continue to work unchanged.
  
  **Comprehensive Audit & Standardization Complete (v5.14.1)**: 
  - Audited all 251 endpoints across 14 service classes (~20K lines)
  - 99%+ parameter naming compliance achieved (most services already compliant)
  - FunctionService standardized: `/rename_variable`, `/set_local_variable_type`, 
    `/set_parameter_type`, `/set_function_this_type`, `/mark_no_return`
  - All remaining services verified 100% compliant with snake_case standard
  - Parameter resolution: canonical name first, then aliases in order, full backward compatibility
  - Zero breaking changes: legacy camelCase parameters continue to work at runtime
  - Verification: 259/260 offline tests passing, 397/400 Python unit tests passing

- **Strict program routing in the bridge** (`GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS`): set the env
  var to `1` and the bridge refuses any program-scoped call that omits a program selector,
  returning a clear error instead of letting the call ride the server's shared "current
  program" (the one `switch_program` and the active GUI tab move). Catches a forgotten selector
  as a loud failure on the first bad call instead of a silent write to the wrong binary. Covers
  every selector that picks an open program: plain `program=` plus the cross-program tools'
  `source_program`/`target_program` and `program_a`/`program_b` (which the server otherwise
  resolves to the current program when left empty). Useful when several programs are open at
  once, especially when more than one client shares a server. Off by default: with the variable
  unset the bridge sends calls unchanged. Tools with no program selector (`open_program` and
  `close_program` take `path`/`name`) are unaffected.

### Fixed

- **TCP fallback for projectless Windows UDS discovery** (#344): the headless server's UDS socket
  discovery on Windows was attempting a fallback to TCP only after the entire UDS socket dir scan
  had exhausted the system temp path and project paths, leaving many users with live instances
  unreachable until the UDS dir expanded. Discovery now checks UDS *and* TCP in parallel on first
  attempt, listing both protocol results and letting the caller choose, so a UDP-only Ghidra
  instance is immediately visible alongside any UDS instances. Fixes discovery hangs on clean
  Windows systems where UDS dirs are sparse.
- **PIC/GOT-indirected named globals rendered as `DAT_`** (#319): `decompile_function` and every
  other decompiler-backed operation constructed a bare `new DecompInterface()` and never applied
  `DecompileOptions`. A fresh `DecompileOptions` leaves *"Respect Read-Only Flags"* OFF (the C++
  decompiler-core default), so a read-only GOT/relocation slot stayed an opaque `DAT_<addr>`
  constant instead of being folded to the named global it points at (e.g. `param_1 * 9.0 *
  DAT_001e9ebc` rather than `... * ModSlashThickness`). This silently misled ports on PIC binaries
  (observed on an ARM32 target). All 11 decompiler construction sites in `FunctionService` and
  `DataTypeService` now route through a shared `ServiceUtils.createConfiguredDecompiler(program)`
  factory that applies `DecompileOptions.grabFromProgram(program)` before `openProgram`, exactly
  matching the Ghidra GUI / analysis decompiler. `force_decompile`, which was previously
  byte-identical to the broken output (a cache refresh with the same bare options), now also
  resolves the named global. 251 tools.
- **fun-doc selector blacklist flags now persist through SQL** (H22):
  `recovery_pass_done`, `decompile_timeout`, and `not_a_function` were set on
  the in-memory func dict but dropped by `_state_func_to_row`, so the selector
  re-picked pathological functions forever (forced-recovery giants, 60s
  decompile timeouts, data-not-code addresses). Migration `0004_selector_flags`
  adds the columns with backfill from `decompile_timeout_at` / `last_result`.
- **fun-doc `refresh_candidate_scores` writes to the SQL backend** (H23): the
  save block called `_atomic_write_state` which targets the legacy `state.json`
  the runtime no longer reads, so dashboard "Refresh Top N" and adaptive-refresh
  computed fresh scores into a dead file. Now routes through
  `_update_function_via_repo`, and clears blacklist flags with explicit
  `False`/`None` so the cleared values reach the columns.
- **fun-doc globals worker uses the subprocess watchdog** (H24):
  `process_global` called `_invoke_provider_direct` (no subprocess isolation,
  no deadline+terminate guard), so a single hung provider call stalled the
  continuous-mode globals worker indefinitely. Now routes through
  `invoke_claude` → `_invoke_provider_with_watchdog`, matching the function
  worker. Also brings the globals-worker `last_heartbeat_at` writes under
  `self._lock`.
- **fun-doc worker watchdog no longer self-heartbeats** (H25): `_watchdog_loop`
  wrote `last_heartbeat_at = now` on every tick, so `stale_sec` was always
  ≈`HEARTBEAT_INTERVAL_SEC` and the stall-kill path was unreachable for any
  worker that was ever healthy — the same failure mode as the 2026-04-24
  four-deadlocked-workers incident the watchdog was added for. The heartbeat
  write now lives in the worker loop (and the quota-pause wait loop); the
  watchdog only observes.
- **`migrate_state_to_sql.py` is idempotent for the `runs` table** (H26): the
  runs loader issued plain INSERTs into a table with only an autoincrement PK,
  so re-running the migration doubled every row. Now refuses with exit code 2
  unless `--truncate-runs` is passed, which wipes-then-reloads.
- **`test_worker_watchdog.py` fixture isolates from the real backend**: the
  `fast_watchdog_env` fixture reloaded `web` without isolating the storage
  repo, so module import resolved the live SQL backend and crashed on
  environmental data before any test ran.

---

## v5.13.1 - 2026-06-08 (patch: launch-noise fix + class-member listing)

Patch release.

### Fixed

- **Module.manifest launch error** (#265): the shipped `Module.manifest` used
  `GHIDRA_MODULE_NAME=` / `GHIDRA_MODULE_DESC=` lines, which aren't valid Ghidra
  module-manifest syntax, so Ghidra logged `Module manifest file error on line 2 of file:
  .../Extensions/GhidraMCP/Module.manifest` on every launch. Emptied it to match Ghidra's
  Skeleton extension template (the name/description/version already come from
  `extension.properties`).

### Added

- **`/list_class_members`** (#275): list the member functions of a C++ class. A function
  counts as a member if it lives in the class's namespace (e.g. after `set_function_this_type`
  re-parents it) or its implicit `this` parameter types as `<class> *`; each result reports how
  it matched (`namespace` / `this_type` / `both`). Replaces the manual "search `__thiscall`
  functions, then read each signature" workflow. 249 tools.

---

## v5.13.0 - 2026-06-08 (audit hardening: correctness, resilience, test coverage)

Minor release packaging a large project-audit hardening pass — service-layer threading and
transaction correctness, clearer address/variable error handling, a bounded on-demand program
cache that ends the long-run Ghidra out-of-memory stalls, graceful offline/provider handling in
the fun-doc dashboard, CI gates, and ~77 new offline tests. ~248 tools.

### Fixed

- **Service-layer threading/transactions** (#276): `DataTypeService` and `AnalysisService`
  mutations now route through the injected `ThreadingStrategy` (EDT marshaling in GUI mode, the
  global write lock in headless) instead of hand-rolled `invokeAndWait` + `startTransaction`. Fixes
  off-EDT GUI writes (`create_enum`, `apply_data_type`, `run_analysis`) and the headless
  write-lock bypass.
- **`recreate_struct` no longer loses data on partial failure** (#276): it captures a restorable
  copy of the original type before the destructive delete and re-adds it if the re-create fails.
- **Address parsing** (#278): a multi-address string (`addr1;addr2;...`) in a single `address`
  field now fails fast with a clear hint pointing at the comment-list arrays, instead of the old
  misleading "try `<space>:<hex>`" suggestion that produced a contradictory "Unknown address
  space" loop. A bad offset under a valid space now reports the offset, not the space.
- **`set_local_variable_type`** (#279): when a decompiler default name (`uVarN`/`puVarN`) is
  missing and none remain, the error explains the variables were renamed / are register-resident
  and points to `set_variables`, instead of repeating an unrecoverable failure.
- **fun-doc resilience**: workers back off and poll for recovery on `ghidra_offline` instead of
  spinning the queue and parking functions (#284); the on-demand program cache is now LRU-bounded
  (`GHIDRA_MCP_MAX_CACHED_PROGRAMS`, default 8) so long multi-binary runs no longer exhaust
  Ghidra's memory and drop it offline for hours (#286).
- **Security hardening** (#276): GUI `/import_file` now enforces `GHIDRA_MCP_FILE_ROOT`;
  non-idempotent bridge POSTs are no longer blindly retried (double-apply safety); `provider_pause`
  writes use an interprocess lock + Windows `PermissionError` retry; the dashboard's SocketIO CORS
  is scoped to the localhost origin instead of `*`.
- **Catalog accuracy** (#280): removed 4 stale `tests/endpoints.json` entries (old names of
  renamed tools) and corrected the advertised tool count (252 → 248).

### Changed

- **fun-doc provider timeout** default lowered 900s → 300s (#286); a hung/slow provider call now
  frees a worker in 5 min instead of 15–25 (complex/massive functions still get +300/+600).
- **fun-doc `ghidra_http.jsonl`** logs errors/timeouts only by default (#285), with
  `FUN_DOC_HTTP_LOG_VERBOSE=1` to record every call — cutting the ~1 GB success-event bulk.
- **pytest coverage** now measures the real Python (`bridge_mcp_ghidra` / `tools` / `debugger`)
  instead of the Java-only `src/` tree.

### Added

- **~77 offline tests**: validation + graceful-degradation suites for every previously-untested
  service (#281, #282), address-parser regressions, the variable-type recovery hint, the
  program-cache eviction logic, and a behavioral `set_function_this_type` integration test.
- **CI**: a `python-offline-regression` job runs the fun-doc offline tier on PRs; the
  release/pre-release paths are gated on offline tests before building; `ServiceUtilsAddressTest`
  moved into the offline tier; a reverse catalog-parity check catches orphaned `endpoints.json`
  entries.
- **Docs/tooling**: a Ghidra 12.1 deprecation backlog, a structural/tech-debt backlog, and a
  server health-check script.

The following entries were already on `main` since 5.12.0 and ship in this release:

### Security

- **`/load_program` now enforces the `GHIDRA_MCP_FILE_ROOT` allow-list.**
  The endpoint accepts an absolute filesystem path; when
  `GHIDRA_MCP_FILE_ROOT` is configured the path is canonicalized through
  `SecurityConfig.resolveWithinFileRoot(...)` (resolving symlinks and
  `..`) and rejected with `Access denied` when it escapes the root,
  before any disk access. The rejection message is generic (the
  configured root is logged server-side, not echoed to the caller, to
  avoid disclosing the filesystem layout). Previously the allow-list
  helper existed but was never wired to this endpoint, so an operator
  who set the root expecting path-traversal protection could still
  have the agent read any file on disk. With no root configured the
  behavior is unchanged.

- **Headless GZF/GAR endpoints reject path traversal.** Caller-supplied
  names (`output_name` on `/export_program` + `/archive_project`,
  `project_name` on `/restore_project`) are validated to be plain
  filenames — no `/`, `\`, or `..` — and the resolved output path is
  canonicalised and confirmed to stay inside its target directory. The
  default `.gzf` / `.gar` name is derived from the program/project
  basename so a project path like `/Vanilla/1.13d/D2Common.dll` can no
  longer leak separators into the written filename. `..` is rejected
  segment-by-segment (catching leading, middle, and trailing `..`
  segments such as `a/..`, not only the `../` prefix), and the
  containment check compares canonical paths element-wise via
  `java.nio.file.Path.startsWith` instead of a string prefix (so a
  sibling like `exports-evil` is no longer accepted under `exports`).
  New helper `HeadlessPaths` is the single validation choke point;
  covered offline by `HeadlessPathsTest`.

- **`/import_program` validates the caller-supplied `target_name`.** The
  optional program name is now checked as a plain filename (rejecting
  `/`, `\`, and `..` segments) before the project tree is touched, and
  the import-folder resolver rejects `.`/`..` path segments, closing a
  traversal vector that could place or overwrite a program outside the
  intended folder. Covered offline by `GzfExportImportTest`.

### Added

- **`/load_program` accepts optional `language` and `compiler_spec`.**
  Raw firmware blobs with no recognizable header (e.g. ARM Cortex-M
  `.mem` dumps) can now be imported as raw binary with an explicit
  processor by passing `language` (e.g. `ARM:LE:32:Cortex`) and
  optionally `compiler_spec`; when `language` is omitted the loader
  auto-detects the format as before. Both values are trimmed before
  the `LanguageID` / `CompilerSpecID` lookup so doc-copied inputs like
  `" ARM:LE:32:Cortex "` resolve instead of failing the lookup. The
  success response now also echoes the resolved `language`.

### Fixed

- **Headless: `/export_program` refuses to guess on an ambiguous bare
  name.** When a program name is given without a folder and the same
  filename exists in several project folders, the resolver now fails
  with an explicit "ambiguous" error listing how many matches were found
  and asking for a full project path, instead of silently packing the
  first match found by the folder walk. An exact / leading-slash path
  still resolves directly.

- **Headless: `/restore_project` verifies the project materialised on
  disk.** `HeadlessArchiveBridge.restore` no longer relies on Ghidra's
  headless GUI auto-open step being swallowed; after `RestoreTask`
  returns it asserts the project marker / directory exists and fails
  loud with an `IOException` otherwise, so a corrupt or partially
  extracted archive is reported instead of returning a false success.
  Offline validation branches covered by `GarArchiveRestoreTest`.

- **`tests/endpoints.json` total reconciled to 252.** Merging the
  upstream removal of 4 stale catalog entries with the 4 new headless
  GZF/GAR endpoints left `total_endpoints` at the pre-merge `256` while
  the array held 252, breaking `EndpointsJsonParityTest`. The field and
  the tool-count references in the docs are back in sync at 252.

- **Headless: `/export_program` resolves the live program by an exact
  name.** GZF export now looks the open program up by an exact (then
  case-insensitive) match instead of the fuzzy substring lookup, so a
  request for `Common.dll` can no longer pack a different open program
  such as `D2Common.dll`. Program idempotency on re-open is scoped to
  the project root rather than a recursive name search, avoiding
  reopening a same-named file from an unintended folder. Covered offline
  by `GzfExportImportTest`.

- **Headless: file-loaded programs are materialised into the project so
  `/save_all_programs` and `/export_program` work.** `loadProgramFromFile`
  and `loadProgramFromFileWithLanguage` now pass the active project to
  `AutoImporter` and call `save(monitor)` on the result, turning the
  transient `DomainFileProxy` into a real `DomainFile`. A same-named
  re-load reopens the existing file (idempotent) instead of throwing
  `DuplicateNameException`. With no project open the loader degrades to
  the previous in-memory behaviour.

- **Headless: the ANALYZED flag is persisted after `/run_analysis`.**
  `GhidraProgramUtilities.markProgramAnalyzed(program)` is invoked inside
  the write transaction so a re-opened program is not re-analyzed from
  scratch.

- **`/import_program` overwrite is no longer destructive on failure.**
  With `overwrite=true` the existing `DomainFile` is renamed aside to a
  `.bak-<ts>` backup and only deleted after the new file is created.
  If the import fails (corrupt `.gzf`, I/O error) the original is renamed
  back, so a failed overwrite never loses the prior program. An explicit
  pre-check rejects overwriting a program that is currently loaded in
  memory with a structured error before the project tree is touched,
  instead of relying on a `FileInUseException` mid-rename.

- **Headless: `/run_ghidra_script` and `/run_script_inline` crashed
  with `NullPointerException`** at
  `JavaScriptProvider.getScriptInstance()` because
  `GhidraScriptUtil.bundleHost` is never initialized outside the GUI
  (in GUI mode `GhidraScriptMgrPlugin` does it). The headless server
  now calls `GhidraScriptUtil.acquireBundleHostReference()` at startup
  and `releaseBundleHostReference()` at shutdown when
  `GHIDRA_MCP_ALLOW_SCRIPTS` is enabled (via
  `SecurityConfig.areScriptsAllowed()`), then ensures the user script
  directory is registered as an enabled `GhidraSourceBundle` so
  `JavaScriptProvider.loadClass()` can resolve compiled scripts.
  Gated on the existing opt-in flag to keep the ~hundreds-of-ms Felix
  OSGi startup cost off the default path.

- **Docker runtime image switched from `eclipse-temurin:21-jre` to
  `eclipse-temurin:21-jdk`.** Ghidra's `GhidraScript` OSGi loader
  invokes `javax.tools.ToolProvider.getSystemJavaCompiler()` to
  compile `.java` scripts on the fly; that returns `null` on a JRE,
  surfacing as `AssertException: Can't find java compiler` for any
  Java script run inside the container.

- **`ProgramScriptService` now surfaces OSGi build/activate output**
  when script execution fails. The `StringWriter` capturing
  `JavaScriptProvider.activateAll()` output is appended to the error
  response under `--- BUILD/ACTIVATE OUTPUT ---`, so Felix compile
  errors are visible to the caller instead of being silently dropped.
  The capturing `PrintWriter` is flushed before the buffer is read so
  the surfaced text is complete, and the output is bounded to its last
  16 KB (with a truncation notice) so a verbose compiler failure can't
  blow up the response payload.

- **Headless script init no longer registers a placeholder bundle when
  the user script directory can't be created.** `acquireBundleHostReference()`
  registers `GhidraScriptUtil.USER_SCRIPTS_DIR` itself, so a local temp-dir
  fallback wouldn't change the path it registers and the missing canonical
  directory would still become a `GhidraPlaceholderBundle`. The server now
  ensures the canonical user script directory is a real, writable directory
  (creating it if needed) and short-circuits BundleHost acquisition entirely
  when it isn't (script execution stays disabled, the server keeps running)
  instead of acquiring on a missing path and crashing later with
  `ClassCastException: GhidraPlaceholderBundle cannot be cast to
  GhidraSourceBundle`.

---

## v5.12.0 - 2026-05-23 (community-driven tools: /get_current_selection + GUI /open_project)

Minor release. Two new endpoints filed/scoped by community feedback
(@I-Knight-I on #153, plus an internal "open project without launching
a CodeBrowser" workflow request), plus a quiet headless parity fix
that surfaced while writing the parity test. 245 tools.

### Added

- **`/get_current_selection`** (GUI-only). Closes the "where am I?"
  tool family alongside `/get_current_address` and
  `/get_current_function`. Returns the CodeBrowser listing's current
  selection as `{program, is_empty, ranges, min_address, max_address,
  num_addresses}`. Reads from `CodeViewerService.getCurrentSelection()`
  — the canonical Ghidra API for the listing's highlight state. Like
  its siblings, returns "Code viewer service not available" when no
  CodeBrowser is up, so AI clients see one consistent error shape for
  the whole family. Filed by @I-Knight-I on issue #153.
- **GUI plugin `/open_project`** with optional `headless=true` (default
  true) and optional `program` body params. The headless server has
  had `/open_project` since v4.x; the GUI plugin previously had no
  programmatic way to point Ghidra at a different project. The new
  route closes (saves) the active project, opens the requested one
  via `ProjectManager.openProject(locator, ...)`, calls
  `AppInfo.setActiveProject`, and — only when `headless=false` and
  `program` is set — auto-launches a CodeBrowser for that DomainFile.
  Same project already active is a no-op success (`already_open: true`)
  so accidental re-opens don't blow away CodeBrowser state. All
  FrontEnd mutations run on the EDT via `SwingUtilities.invokeAndWait`.

### Fixed

- **Headless server now registers `/server/admin/terminate_all_checkouts`**
  for GUI parity. The GUI plugin has registered this route since v5.6
  but the headless server didn't, causing
  `test_manual_gui_headless_shared_endpoints_do_not_drift` to fail on
  CI when /get_current_selection was added (the parity test enumerates
  all `server.createContext` and `safeContext` registrations). Also
  accepts `checkout_id` as an alias for `checkoutId` on
  `/server/admin/terminate_checkout` to match the cataloged param name.

### Tests

- **OpenProjectGuiEndpointTest** (4 source-level invariants) — route
  registration, helper signature, EDT marshaling, `AppInfo.setActiveProject`
  call, and the catalog `params` drift guard.
- **GetCurrentSelectionEndpointTest** (3 source-level invariants) —
  route registration, helper uses `CodeViewerService.getCurrentSelection()`,
  catalog entry exists with empty `params: []`.

### Notes

`/open_project` is shared between the GUI and headless servers. The
catalog entry now lists `path`, `headless`, and `program`; the
headless server's `@McpTool` annotation still consumes only `path`
(headless mode has no CodeBrowser to launch), and
`EndpointsJsonParityTest` tolerates extra catalog params over what's
scanned. The shared path appears in neither `gui_only_expected` nor
`headless_only_expected` because the annotation also lives in the
`headless/` package and the parity check subtracts the annotated set.

---

## v5.11.4 - 2026-05-22 (automatic ghidratrace install for debugger launcher)

Targeted patch release. One real change: the deploy flow now keeps
the launcher Python's `ghidratrace` wheel aligned with the installed
Ghidra version, so the `VersionMismatchError: Front-end 12.1,
back-end 12.0` that surfaced three times in this release cycle
cannot recur on the next Ghidra version bump. 244 tools, no
functional API changes.

### Fixed

- **Auto-install matching `ghidratrace` into the launcher Python.**
  When Ghidra upgrades major/minor (e.g., 12.0.4 → 12.1), the
  `ghidratrace` wheel bundled at
  `<ghidra>/Ghidra/Debug/Debugger-rmi-trace/pypkg/dist/` bumps with
  it. The TraceRmi launcher imports `ghidratrace` from whichever
  Python `GHIDRA_DEBUGGER_PYTHON` (in `.env`) points at — and any
  stale `ghidratrace` pip-installed in that Python from the previous
  Ghidra version silently shadows the bundled source via
  `sys.path.append()`'s end-of-path insertion. New helper
  `install_ghidratrace_for_debugger()` resolves that exact Python
  (env var → dotenv → `shutil.which("python")`), upgrades protobuf
  to `>=6.31.0` (the `ghidratrace.setuputils` floor), then
  `pip install --force-reinstall`s the bundled wheel. Wired into
  `install_ghidra_dependencies` so `tools.setup ensure-prereqs` and
  `install-ghidra-deps` cover it on every run. Best-effort: a pip
  failure here does NOT block the main JAR-install dependency
  setup (most users don't run the live debugger).
- **CI tests-on-Linux unblock for debugger-live unit tests.** The
  monkeypatched-Windows tests hit the function's `finally:` clause,
  which called `_terminate_processes_by_name` → `subprocess.run
  (["taskkill", ...])` → `FileNotFoundError` on the Linux runner.
  The error escaped the test and pytest crashed during
  failure-report formatting with `cannot instantiate WindowsPath
  on your system`. Stub the terminator in the two affected tests
  so the body's outcome surfaces cleanly.

### Added

- **5 new unit tests for `install_ghidratrace_for_debugger`**:
  env-var precedence, dotenv fallback, no-op when no wheel is
  bundled (older Ghidra installs without the wheel layout),
  dry-run does not invoke pip, and live invocation passes
  `--force-reinstall` + the bundled wheel path.

### Notes

This is the third occurrence of the
`VersionMismatchError: Front-end 12.1, back-end 12.0` symptom in
this release cycle. The first two were patched out-of-band by
manually installing `ghidratrace` into a Python — but both manual
fixes hit the wrong interpreter (`C:\Python313` and the project
venv) because `GHIDRA_DEBUGGER_PYTHON` actually pointed at a
third Python (Microsoft Store 3.12) where a stale 12.0 wheel was
still pip-installed. The new helper resolves the launcher Python
via the same precedence the live test uses, so the install can
never miss again.

---

## v5.11.3 - 2026-05-22 (deploy + audit hardening, contributor recognition)

Patch release closing four small papercuts: a recurring deploy bug
re-observed in the v5.11.2 cut, a release-test environmental flake,
a year-running audit false positive, and a long-overdue contributor
credit. 244 tools, no functional API changes.

### Fixed

- **#217 — deploy no longer over-patches sibling Ghidra user dirs.**
  `patch_ghidra_user_configs` globbed `*/FrontEndTool.xml` and
  `*/tools/*.tcd` under the entire user-config base, stamping the
  new plugin's INCLUDE into every Ghidra version's user dir
  (12.0.4, 11.4.2, …) even when targeting 12.1. Observed twice in
  this release cycle's deploy logs. Function now takes an explicit
  `target_user_dir`; `deploy_to_ghidra` passes the result of
  `resolve_ghidra_user_dir(ghidra_path)`. The no-arg form is kept
  for back-compat with direct callers + existing tests.
- **Release-tier deploy: debugger-live test now skips on missing
  prerequisites** instead of failing the whole `--test release`
  gate. New `DebuggerLiveTestSkipped` sentinel exception covers
  non-Windows hosts, absent `BenchmarkDebug.exe`, and known-
  environmental launch errors (no WDK, ghidratrace version
  mismatch, dbgeng backend missing — all observed in this
  session's deploys on dev machines).
- **Audit watcher: `bridge_counter_stall` false-positive fixed.**
  The rule polls `/api/_diag_bridge` for tool_call / tool_result /
  model_text counters, but the endpoint didn't exist — the fetcher
  caught the 404, returned `{}`, and every counter read as 0
  indefinitely. Result: 24 identical fires between 2026-04-25 and
  2026-05-21, exactly one per signature per day at the 30-min stall
  threshold the rule was configured for. Dashboard now exposes the
  endpoint with real counters wired off the bus; stale registry +
  queue archived during the cut so phase-3 work starts clean.

### Added

- **README — `@huehuehuehueing` recognized in Core Contributors** for
  address-space prefix support (PR #84, closes #65 — added the
  `<space>:<hex>` syntax to address parsing across every endpoint)
  and the optional `program` parameter + required-param schema
  fixes (PR #92). The `mem:1000` / `code:ff00` syntax mentioned in
  half the endpoint docstrings is their work.
- **9 new offline tests**: 4 pin the #217 target-only patching
  contract, 5 cover the debugger-live skip classification.
- **4 new performance tests** for the `/api/_diag_bridge` endpoint:
  endpoint exists + correct payload shape, counters increment on
  matching bus events, unrelated events don't bump the counters,
  monotonic-increment guarantee.

### Changed

- **README Discussions badge** swapped from
  `shields.io/github/discussions/...` (rendering "unable to select
  next GitHub token from pool" due to a shields.io rate-limit
  issue) to a static "discussions → join" badge. Same destination
  link; just doesn't depend on shields.io's discussions endpoint
  staying up.

---

## v5.11.2 - 2026-05-22 (customizable convention enforcement)

Feature release introducing per-project customization of the v5.0
convention-enforcement layer. The enforcement that used to be
"hardcoded constants in `NamingConventions.java`" is now driven by a
`ConventionConfig` object loaded from
`<ghidra-project>/.ghidra-mcp/conventions.json`. Defaults reproduce
exactly the pre-v5.11.2 hardcoded behavior, so projects with no config
file see zero behavior change.

### Added

- **`.ghidra-mcp/conventions.json` per-project config** — five sections
  (`strict_mode`, `function_naming`, `hungarian`, `global_naming`,
  `plate_comments`) covering every previously-hardcoded knob: verb
  whitelist add/remove, verb tier overrides (1/2/3), weak-noun
  add/remove, function-name min length, struct-field auto-Hungarian
  toggle, `g_` prefix requirement toggle, descriptor min length, plate-
  comment validation toggle, required-section list, first-line word
  count. See [`docs/prompts/CUSTOMIZING_CONVENTIONS.md`](docs/prompts/CUSTOMIZING_CONVENTIONS.md)
  for the full schema + a worked non-Hungarian C++ example.
- **Per-call `strict_mode` parameter** on the five enforcement
  endpoints (`rename_function_by_address`, `apply_data_type`,
  `set_global`, `rename_or_label`, `rename_global_variable`). Values:
  `enforce` / `warn` / `off`. Default null = "use the project/global
  setting" so existing callers don't change behavior. Plumbed via a
  thread-local override on `NamingPolicy` and the
  `scopedRequestMode(...)` AutoCloseable helper so the override clears
  even if the body throws.
- **Plate-comment validation gate** — `checkGlobalPlateComment()`
  previously always-rejected; now consults the active
  `plate_comments.validate` flag. This closes the longstanding gap
  flagged in the v5.6.0 design (the strict-mode toggle was wired
  everywhere else but bypassed plate-comment).
- **Project doc**: [`CUSTOMIZING_CONVENTIONS.md`](docs/prompts/CUSTOMIZING_CONVENTIONS.md)
  with schema reference, three-layer precedence table, and a worked
  example for non-Hungarian C++ projects.

### Changed

- `NamingPolicy` now holds a full `ConventionConfig` rather than a
  bare boolean. The existing
  `setStrictNamingEnforcement(boolean, source)` setter still works —
  it flips just the mode bit and preserves all other config sections.
- `NamingConventions.getVerbTier()`, `isWeakNoun()`,
  `countSpecifierTokens()`, `validateFunctionName()`,
  `validatePlateCommentStructure()`, `checkGlobalPlateComment()`, and
  `checkGlobalNameQuality()` now consult the active config. With no
  config file present, all behavior is unchanged.
- The five enforcement endpoints' MCP signatures grow one optional
  `strict_mode` body parameter (`tests/endpoints.json` regenerated).

### Backward compatibility

Every change is additive. No config file = identical behavior to
v5.11.1. The legacy `Strict Naming Enforcement` Ghidra Tool Option
still works and still wins over the config file's `strict_mode` field,
so the GUI-toggle workflow keeps working.

### Also included

- **fun-doc workers now surface `no_eligible_candidates` on exit** —
  previously a worker that spawned on a binary with nothing left to do
  (everything at-or-above `good_enough_score`, library-code-skipped,
  retry-budget-exhausted) silently exited with status "finished" and 0
  progress, indistinguishable from a real failure. The dashboard now
  renders "finished — no eligible candidates" with 5 regression tests
  pinning the contract.

### Tests

27 new offline Java tests in `ConventionConfigTest` covering defaults,
JSON parsing of each section, file loading, weak-noun / verb-tier /
plate-comment / global-naming config consumption, and per-call
override lifecycle (thread-local scoping + cleanup-on-throw). 5 new
Python tests in `test_worker_exit_reason.py` for the worker exit
reason. `tests/endpoints.json` regenerated to capture the new params.

---

## v5.11.1 - 2026-05-21 (deploy hardening, coverage, attribution)

Patch release bundling the post-v5.11.0 deploy hardening and test
coverage backfill discovered while shipping Ghidra 12.1 support. 244
tools, no functional API changes.

### Fixed

- **Plugin: `endpoint_count` no longer drifts from `/mcp/schema`** —
  The version banner's `endpoint_count` field was a hardcoded constant
  (177) while the AnnotationScanner had grown to register 196. The
  plugin now sets `VersionInfo.setEndpointCount(scanner.getEndpoints()
  .size())` after registration so `/get_version` reflects ground truth.
  Verified by a new integration smoke test that pins schema == version
  banner count.
- **Deploy: warn when an old Ghidra install is still running** —
  Process detection was lumping install-path matching with enumeration;
  a Ghidra running from a *different* install path was silently
  invisible, then intercepted post-start smoke checks bound to MCP port
  8089. Split into `_enumerate_*` (every Ghidra) → `_find_matching_*` /
  `_find_mismatched_*` partitions; deploy now logs PIDs + command lines
  for mismatched Ghidras before continuing. (`d8cb60e`)
- **Tests: `test_set_global_rejects_bad_name` was broken on the day it
  landed** — used `DAT_1234` as the bad-name fixture, but per design
  auto-generated globals are intentionally exempt from
  `checkGlobalNameQuality` (renaming back to a Ghidra default is the
  documented "revert" affordance). Replaced with a plain non-`g_`-
  prefixed identifier so the test actually exercises the
  `missing_g_prefix` path it describes.

### Added

- **16 new unit + integration tests** covering deploy-setup paths that
  had no coverage before: open-form `<PACKAGE NAME="Utility">`
  patching, `patch_frontend_tool_config` idempotency,
  `mark_extension_known_in_tool_config` (4 cases),
  `patch_ghidra_user_configs` (5 cases including dry-run, missing base,
  stale tcd cleanup, idempotency), and the DEV+PUBLIC user-config dir
  coexistence scenario behind the v5.10→v5.11 deploy snag (#217).
- **Integration smoke tests for MCP readiness**: plugin version matches
  `pom.xml` (catches stale-jar deploys), `/mcp/schema` meets the v5.x
  150-tool floor, `endpoint_count` agreement, and `ghidra_version`
  well-formedness.
- **Synthetic `_OLD_PUBLIC` / `_NEW_PUBLIC` markers** in process-
  detection tests so an auto-linter cannot silently rewrite "old
  version" to "new version" and erase the test invariant.

### Licensing

- **`LICENSE` copyright line filled in** with both upstream (LaurieWired)
  and current-project (Ben Ethington + contributors) attribution.
  Previously the Apache 2.0 placeholder `Copyright [yyyy] [name of
  copyright owner]` had been left as-is — inherited from upstream.
- **New `NOTICE` file** documenting the upstream origin (LaurieWired/
  GhidraMCP, August 2025) and the Apache-2.0 attribution.
- **README acknowledgment** of the upstream project alongside existing
  contributor credits.

These are housekeeping items to make the repo's attribution
self-contained, independent of the GitHub fork pointer, before the
fork is converted to a standalone repository.

---

## v5.11.0 - 2026-05-21 (Ghidra 12.1 + community fixes)

Minor release rolling up Ghidra 12.1 support (#211), bridge tool-
registration resilience (#212), the bridge auto-analysis crash fix
(#209), fun-doc's wrong-param bug (#207), the gemini-cli-sdk
reconciliation (#201), the headless server-binding diagnostics
(#119), and the dashboard name-source column (#204 follow-up).
244 tools.

**Ghidra 12.1 upgrade note** — this release retargets the project at
Ghidra 12.1. Users on 12.0.4 should upgrade their Ghidra install;
shared-server setups need Ghidra Server 12.1 (or 12.0.5+ where the
compatibility matrix permits). Jython is optional in 12.1; install
the Jython extension from File → Install Extensions if you run
`.py` Ghidra scripts.

### Fixed

- **#211 — Ghidra 12.1 compatibility** (@firefart). Updated the
  project Ghidra dependency version, CI/release/Docker download
  metadata, setup defaults, examples, and compatibility tests from
  Ghidra 12.0.4 to the latest official Ghidra 12.1 release. Added
  12.1-specific shared-server guidance, Jython-extension documentation,
  preflight messaging for configured shared servers, and a clearer
  `.py` script-provider error when Jython is not installed.

- **#212 — bridge tool registration aborted on one malformed schema
  entry** (@killerra, PR #214 by @synthol). Dynamic registration now
  skips only the failing tool, keeps loading later valid tools during
  both connect-time registration and lazy group loading, and writes a
  compact stderr diagnostic with the bad tool name and exception.

- **#207 — fun-doc called Ghidra endpoints with wrong parameter
  names** (@dalen). Audited every `ghidra_get`/`ghidra_post` call in
  `fun_doc.py` against the endpoint catalog. Three real bugs + one
  latent, all in fun-doc's internal helper paths (archive-apply,
  library-code stamp) that fail silently:
  - `/rename_function_by_address` was sent `address` (endpoint wants
    `function_address`) with the body params in the query string —
    every archive-hit rename silently no-op'd.
  - `/batch_set_comments` (archive-apply) used a dead
    `items=[{address,type,text}]` payload shape — plate write no-op'd.
  - `/batch_set_comments` (library-code stamp) sent `function_address`
    where the param is `address` — the generic plate never landed.
  - `/get_function_variables` address-fallback passed the address as
    `function_name` instead of using the `address` param.
  `fix-prototype.md` prompt example corrected
  (`set_function_prototype` → `function_address` + `prototype`). New
  `test_fundoc_endpoint_param_parity.py` AST-checks every fun-doc call
  against `endpoints.json` so param drift is a CI failure. The
  API-wide param inconsistency (`address` vs `function_address` etc.)
  is tracked separately in #210.

- **#209 — bridge auto-analysis crashed on un-analyzed programs**
  (@s-b-repo). `runAutoAnalysisAndPersistFlags` ran
  `AutoAnalysisManager.startAnalysis` with no open DB transaction, so
  `FunctionStartAnalyzer` threw `db.NoTransactionException` on any
  program not already fully analyzed. Wrapped the analysis sequence in
  `startTransaction`/`endTransaction`, matching the sibling
  `set_image_base` and `HeadlessProgramProvider.runAnalysis` paths.

- **#201 — Gemini worker SDK** (@dalen). The working SDK now ships
  from GitHub (`bethington/gemini-agent-sdk`) and is vendored into
  `fun-doc/vendored/gemini_agent_sdk/`, so the Gemini provider works
  with no install step. Renamed from `gemini-cli-sdk` (distribution
  *and* import package) to de-conflict with the unrelated PyPI
  `gemini-cli-sdk` — the import-name collision was the root cause of
  the original `ImportError`.

- **`/search_instructions` always echoes filter values** — Gson
  dropped null map values, so `mnemonic_filter`/`operand_filter` were
  silently absent from the response when the filter was empty. They
  are now always present as plain strings (empty = no filter).

### Added

- **#119 — structured diagnostics for `/load_program_from_project`**
  (@j4s0n, @t0xk). Failure responses now carry a `diagnostics` block
  (`project_server_bound`, `available_program_paths`, `suggestion`)
  and `/get_project_info` surfaces server-binding state, so the
  "checked out but can't open" failure mode is self-diagnosing.

- **Dashboard name-source column** (#204 follow-up) — the All
  Functions table shows each row's `name_source` and flags
  propagation rows the selector will skip.

---

## v5.10.0 - 2026-05-15 (operations + propagation provenance + community features)

Minor release rolling up a community feature (#172), two operational
hardening passes (log rotation, storage loud-fail), and the
propagation-provenance gate (#204) that closes the v5.9.x worker
token-leak on cross-version hash-propagated CRT/STL. Plus the
legacy-CLI archive and the AUR README link from the post-v5.9.1
hygiene sweep.

243 → 244 tools. Schema migration `0003_name_source.sql` applied
automatically on first dashboard start.

### Added

- **`/search_instructions`** — operand-pattern instruction search. Complement to
  `/search_byte_patterns` (byte-level): this matches after Ghidra has parsed
  instructions, so callers can search for `mov` + `[ecx+0xD0]` without knowing
  the encoding. Mnemonic match is case-insensitive exact; operand pattern is
  case-insensitive substring on the joined operand string. Optional
  `function=` scope restricts to a single function's body. Closes the gap
  raised in #172.
- **fun-doc — log rotation** (`fun-doc/log_rotation.py`) — single
  `write_jsonl_rotating()` helper that wraps the three operational JSONL logs
  (`ghidra_http.jsonl`, `runs.jsonl`, `events.jsonl`). Default 200 MB per file
  × 5 backups = ~1.2 GB hard cap per log series, tunable via
  `FUN_DOC_LOG_MAX_BYTES` / `FUN_DOC_LOG_BACKUPS` env vars. Pre-rotation the
  `ghidra_http.jsonl` log was unbounded and hit 1.03 GB in three weeks on the
  user's main workspace.
- **fun-doc — name-source provenance (#204)** — three new columns on
  `functions_workflow`:
  - `name_source` TEXT — `'scan'` (default) / `'manual'` / `'propagation'` /
    `'pdb'` / `'archive'`
  - `name_source_binary` TEXT — when source = propagation, the binary the name
    came from
  - `name_confidence` REAL — 0.0–1.0 archive/BSim-gate signal (nullable)

  The selector now skips functions where `name_source = 'propagation'` and
  `name_confidence < 0.5` (env-tunable via
  `FUN_DOC_PROPAGATION_CONFIDENCE_THRESHOLD`), unless pinned. Closes the
  v5.9.x failure mode where cross-version hash propagation gave plausible
  D2-style names (`DATATBLS_*`, `ROOM_*`, `CLIENT_*`, `NET_*`, `GAME_*`) to
  statically-linked CRT/STL/iostream code — ~10M input tokens burned on the
  top 7 such misidentifications in BH.dll's last 24h before the gate landed.
  Existing rows default to `name_source = 'scan'`; mark propagated names
  retroactively with `python -m scripts.backfill_name_source --program X
  --name-pattern '^(DATATBLS|ROOM|CLIENT|NET|GAME)_' --source-binary Y
  --apply`.

  Migration: `0003_name_source.sql` (Postgres) + `0003_name_source.sqlite.sql`
  (SQLite). Auto-applied by `db.migrate` runner on first dashboard start.

### Changed

- **fun-doc — storage backend open failures now loud-fail** (post-v5.9.1
  follow-up). The v5.9.1 import-time guard caught "sqlalchemy missing";
  this commit extends the guard so post-import failures (Postgres
  unreachable, bad URL, schema migration broken, SQLite path unwritable)
  also `sys.exit(1)` with an actionable diagnostic instead of silently
  falling back to legacy `state.json`. The test-fixture override path
  (`_storage_repo_failed = True`) is preserved so
  `test_state_atomicity.py`'s legacy-fallback regression coverage stays
  intact.
- **fun-doc — `_append_run_log` no longer serializes behind `_state_lock`.**
  The log-rotation rewire moved file-I/O ownership to per-path RLocks in
  `log_rotation.py`. Storage writes that previously queued behind a long
  run-log append now run independently.
- **CHANGELOG/tool counts** — endpoint count goes from 243 to 244 with
  `/search_instructions`. Docs (README, CLAUDE.md, AGENTS.md) get the
  bump at next release tag via `tools.setup bump-version`.

### Removed

- **`tools/scan_undocumented_functions.py`,
  `tools/scan_functions_mcp.py`, `tools/document_function.py`** —
  archived to `docs/archive/legacy-tools/` with a README mapping each
  to its `fun-doc/` replacement. They predated `fun-doc/` by ~7 months
  and were last touched on 2025-10-10; everything they did is now
  better-handled by the worker + dashboard. Files still work against
  the stable v5.9.1 HTTP API; they're unmaintained going forward.

---

## v5.9.1 - 2026-05-14 (community fixes + fun-doc reliability)

Patch release rolling up four community fixes (#200, #201, #202, #205)
plus three internal reliability fixes that landed during v5.9.0 worker
review. No new endpoints over v5.9.0; existing `/disassemble_bytes`
gains an instruction-text payload (back-compat preserved). 243 tools.

### Fixed

- **#200 / #202**: Disabling **Strict Naming Enforcement** now also
  preserves agent-provided struct field names. `create_struct`,
  `add_struct_field`, and `modify_struct_field` no longer auto-add
  Hungarian prefixes when the built-in naming convention is disabled.
  Community fix from @1ndahaus3. (PR #202)

- **fun-doc — silent state.json fallback when sqlalchemy is missing**:
  if `sqlalchemy` wasn't importable, `fun_doc.py` quietly fell back to
  legacy `state.json` and accumulated worker output that never reached
  `state.db`. Hit the same user twice on v5.9.0 release day after
  launching the dashboard from `C:\Python313\python.exe` (no
  sqlalchemy installed) instead of the project venv. New loud-fail
  guard at startup imports sqlalchemy early and `sys.exit(1)`s with
  the actual `sys.executable` path and the venv + pip-install fix
  commands. (PRs #203, cherry-pick 3657e77)

- **fun-doc — library-code detector missed `_Setgloballocale` /
  `_Atexit` / TLS callbacks**: a real v5.9.0 case where the worker
  explicitly wrote `"Source: Visual Studio 2019 Release (msvcp*.dll)"`
  in its plate but still burned 92K tokens because the detector
  didn't catch `_Setgloballocale`. Added `_Atexit`,
  `_Setgloballocale`, `_Getcoll`, `_Getfac`, `_Getfmt`,
  `__dyn_tls_init`, `__dyn_tls_dtor`, `__tlregdtor` to
  `HARD_CALLEE_NAMES`. Detector unit suite 19 → 21 cases. (PR #203)

- **fun-doc — migration script dropped library_code fields**:
  `scripts/migrate_state_to_sql.py` was silently discarding
  `library_code`, `library_code_at`, and `library_code_reasons` when
  folding `state.json` back into `state.db`. Surfaced when the user's
  state.json had 65 functions correctly flagged but state.db showed
  zero after migration. Added the fields to `_DIRECT_FIELDS` and
  `_RENAMED_FIELDS`. (PR #203)

- **fun-doc — block-reason empty on 1431 runs**:
  `_log_run_once(result)` on the main worker output-parsing branch
  was discarding the reason text the model wrote after recognized
  markers (`BLOCKED:`, `NEEDS REDO:`, rate-limit phrases). New
  `_extract_marker_reason()` helper pulls the first non-empty line
  after the marker and plumbs `result_reason` through to the run
  log. Other early-exit paths already passed explicit `reason=`
  strings. (PR #203)

- **tests — autouse fixture was wiping the developer's live
  `fun-doc/state.db`**: `tests/performance/conftest.py` was
  unconditionally `unlink()`ing `state.db` before and after every
  test. Correct in clean-repo / CI contexts but in a developer
  environment this destroyed the 124 MB user database. Real
  incident: 65 library_code flags + 36k+ runs lost; recovered only
  by re-running the migrator against `state.json`. New
  `_safe_clean_state_db()` checks file size and refuses to delete
  anything over 512 KB (fresh bootstrap is ~50-150 KB). Tests that
  genuinely need a fresh DB should construct one under `tmp_path`.
  (commit e031c3c, also in PR #203)

- **#201 — friendlier error when `gemini-cli-sdk` import fails**
  (@dalen): the published `gemini-cli-sdk` 0.1.0 on PyPI lacks the
  `GeminiCli` class fun_doc.py uses (working version lives in a
  local source tree that hasn't been republished). The bare
  `ImportError` was unactionable. New error message quotes the
  actual import error, explains the situation, links to issue #201,
  lists three working alternative providers
  (minimax / claude / codex), and mentions the pin-to-source
  workaround. Doesn't fix the root cause — that requires republishing
  the SDK to PyPI — but stops new users from filing the same issue.
  (PR #206)

### Added

- **#205 — instruction text in `/disassemble_bytes`** (@larrynz): the
  endpoint already disassembled a byte range but returned only a
  success summary. Callers building custom processor definitions had
  no way to read back what Ghidra actually produced without a follow-
  up `/disassemble_function` call. Two new optional POST params:
  - `include_instructions` (default `true`) — include the
    disassembled instruction list in the response.
  - `max_instructions` (default `1000`) — cap on returned
    instructions; the response sets `truncated=true` and
    `instructions_total` when exceeded.

  Each instruction entry has `address`, `mnemonic`, `operands`
  (joined like the GUI listing), `length`, and `bytes` (lowercase
  hex). Walks the listing via `InstructionIterator` over the address
  set the disassembly was just applied to, after the transaction
  succeeds — exactly what Ghidra parsed, no second pass needed.
  Back-compat: two helper overloads on the public
  `disassembleBytes(...)` signature so `HeadlessEndpointHandler` /
  `EndpointRegistry` callers keep working unchanged. (PR #206)

---

## v5.9.0 - 2026-05-12 (community fixes + P-code endpoints + library-code detector)

Bundles three community-reported bug fixes (#170, #175, #192) plus an
internal fun-doc improvement (library-code auto-classification). Net
result: cleaner multi-instance discovery, fewer surprise port collisions,
new endpoints for downstream P-code tooling, and no more LLM tokens wasted
on statically-linked CRT.

### Fixed

- **#170**: macOS bridge spawned by Claude Desktop couldn't find Ghidra
  instances. Root cause: Claude Desktop spawned the bridge without
  forwarding `$TMPDIR`, so the bridge fell back to `/tmp/ghidra-mcp-<user>`
  while the plugin (with `$TMPDIR` set to a `/var/folders/<2>/<rand>/T/`
  path) wrote its socket elsewhere. Fix: `bridge_mcp_ghidra.py` now scans
  every plausible socket directory (`XDG_RUNTIME_DIR`, `/run/user/<uid>`,
  `$TMPDIR`, `/var/folders/*/*/T/...`, `/private/var/folders/*/*/T/...`,
  `/tmp`, `%TEMP%`) via `get_socket_dir_candidates()` and deduplicates by
  absolute path. Backwards-compatible: `get_socket_dir()` still returns
  the primary candidate. (PR #195)

- **#175**: On Windows, two Ghidra instances couldn't run simultaneously
  because both tried to bind TCP `8089` and the second failed with
  "Address already in use: bind". Two-part fix:
  1. **UDS enabled by default on all platforms** (Win10 1803+ has
     `AF_UNIX`; older Windows falls through to the TCP path). Per-PID
     socket file names mean no port competition for UDS users.
  2. **TCP port-range fallback** in `GhidraMCPPlugin`: when the
     configured port is taken, the plugin scans the next 15 ports and
     binds the first that's free. The actual bound port is surfaced via
     `/mcp/instance_info → tcp_port` (now served on both UDS and TCP
     transports), and the bridge's new `_scan_tcp_for_project()` walks
     `8089..8104` probing for the matching project. Project-mismatch
     refusal: the bridge no longer silently connects to a wrong-project
     instance — if UDS finds instances but none match the requested
     project, it returns a clear error rather than guessing a TCP port.
     (PR #196)

### Added

- **#192 — decompiler P-code endpoints** for downstream tooling that needs
  the raw graph rather than the C decompile (P-code emulators, alternative
  decompilers, ML pipelines):
  - `/get_function_pcode?function_address=...&granularity={basic|high}`:
    dumps HighFunction P-code. `basic` returns the basic-block iter only
    (PcodeOps in program order, lighter payload). `high` (default) adds
    the full HighFunction PcodeOp graph from `hf.getPcodeOps()`. Each op
    carries mnemonic, opcode, varnode inputs/output with space/offset/size
    and SSA flags (`is_register`, `is_constant`, `is_unique`, `is_addrtied`,
    `is_hash`, `is_persistent`, `merge_group`). Basic blocks carry start/
    stop addresses via the shared `ServiceUtils.addressToJson` helper.
  - `/get_language_metadata?include_registers=true&include_default_symbols=true`:
    SLEIGH-level program facts — language ID, processor, endian, size,
    variant, default space, default data space, program counter, full
    address-space list, register list (with parent/child relations,
    description, aliases, bit length), default symbol set (with
    end_offset, byte_size, is_entry/is_primary/is_volatile flags).

  Endpoint count: 241 → 243. (PR #197)

- **PDB import helper** (`scripts/ghidra/ImportMSDLPDB.java`): user-
  installable Ghidra script that reads the program's `PdbInformation`
  (GUID / age) and kicks the PDB Universal Analyzer to fetch + apply
  matching symbols from Microsoft's symbol server. Authoritative names
  for everything MSVCRT / VC-runtime / MFC. Skip-with-reason JSON when
  the binary has no PDB metadata. Install per
  `scripts/ghidra/README.md`.

- **Library-code auto-classification (fun-doc)**: heuristic detector at
  `fun-doc/library_code_detector.py` runs after decompile and before LLM
  invocation. Trips on canonical CRT names (`??2@YAPAXI@Z`, `_strtoi64@4`,
  `std::_*`) or CRT-only callees (`__SEH_prolog4`, `_Xinvalid_argument`,
  `_CxxThrowException`). Detected functions get a generic plate stamped
  and `library_code=True` set on the workflow row, excluding them from
  future selector picks until refresh. Motivating case: 729K tokens
  burned on `ParseSignedShort @ 10052ba0` in BH.dll — code that doesn't
  exist in BH source. Conservative tuning: `/GS` stack-cookie helpers are
  SOFT signals (they appear in user code too) so a single `__security_check_cookie`
  hit doesn't trip the gate. New `skip_library_code` config flag (default
  `True`) for disable. Storage migration `0002_library_code.sql` adds
  three columns; 19-case detector unit suite + 3 selector regression
  tests. (PR #198)

### Test coverage notes

- **Bridge size cap** bumped from 2100 → 2250 lines to absorb the multi-
  candidate socket-dir scan + TCP port-range scanner. The cap is a soft
  signal per its docstring; both contributions pull weight (real bug
  fixes with docstrings + unit coverage).
- **New unit/integration test files:**
  - `tests/unit/test_bridge_utils.py` — `TestGetSocketDirCandidates`
    (3 cases), `TestDiscoverInstancesMultiDir` (2 cases), `TestTcpPortScan`
    (7 cases), plus three macOS-layout tests using `Path.exists`/`Path.glob`
    mocks.
  - `src/test/java/com/xebyte/offline/ServerManagerPortTest.java` —
    3-case Java unit suite for `boundTcpPort` (default value, persistence,
    volatile thread-visibility).
  - `tests/integration/test_readonly_endpoints.py` — new readonly tests
    for `/mcp/instance_info` (TCP), `/get_function_pcode` (basic + high
    granularity), and `/get_language_metadata` (with/without heavy
    sections).
  - `tests/performance/test_library_code_detector.py` — 19-case detector
    unit suite.

---

## v5.8.0 - 2026-05-11 (fun-doc SQL storage migration — PR1)

Major release: fun-doc's per-function workflow state moves out of `state.json`
(~106 MB single file, swapped per-binary by hand) into a SQL-backed
repository abstraction. The default backend is SQLite at
`fun-doc/state.db`; users with a Postgres instance can point
`FUN_DOC_DB_URL=postgresql://...` to use it instead. Schema applies
to `fun_doc.*` (Postgres) or the equivalent tables (SQLite). No
endpoint changes — endpoint count unchanged at 241.

This is **PR1** of the storage migration. **PR2** (v5.9.0) adds the
re-kb FastAPI gateway so users running the re-universe Docker stack
can have fun-doc state served from a shared remote service rather
than a local file. PR2 is not in this release.

### Added — storage abstraction (`fun-doc/storage/`)

- **`storage/__init__.py`** — backend factory. Reads `FUN_DOC_DB_URL`
  env var; SQLite (`sqlite:`) and Postgres (`postgresql:`) URLs are
  both supported. Default when unset: SQLite at `fun-doc/state.db`.
- **`storage/models.py`** — SQLAlchemy Core schema for
  `functions_workflow`, `runs`, `inventory`, `global_inventory`,
  `sessions`, `meta`. Hot fields (`run_count`, `audit_count`,
  `escalation_count`, `last_run_at`, etc.) denormalized onto
  `functions_workflow` rows so dashboard reads stay O(1).
- **`storage/repository.py`** — CRUD layer. Single source of truth for
  function-state reads/writes, run-row inserts, inventory rollups.
- **`storage/slow_query_log.py`** — structured logging for queries
  above the 100 ms threshold; logger name `fun_doc.storage.slow_query`.

### Added — schema migrations

- **`fun-doc/db/migrate.py`** — schema runner; idempotent.
- **`fun-doc/db/migrations/0001_initial.sql`** — Postgres schema.
- **`fun-doc/db/migrations/0001_initial.sqlite.sql`** — SQLite mirror
  (`BIGSERIAL` → `INTEGER PRIMARY KEY AUTOINCREMENT`, `TIMESTAMPTZ` →
  `TEXT` ISO-8601).

### Added — migration tooling

- **`fun-doc/scripts/migrate_state_to_sql.py`** — one-shot import:
  `state.json` + `runs.jsonl` + `inventory.json` +
  `global_inventory.json` → SQL store. Idempotent; safe to re-run.
- **`fun-doc/scripts/verify_migration.py`** — zero-diff verifier
  comparing SQL row counts and field values against the JSON sources.
  Required pre-merge gate per the locked plan.

### Added — pre-release smoke runbook

- **`fun-doc/scripts/v58_smoke.py`** — single-command driver for the
  migrate → pre-verify → worker spawn → check → post-verify cycle.
  Subcommands: `prep`, `check`, `verify`, `post-verify`, `reset`.
  Default backend: SQLite at `C:/tmp/v58-smoke.db` (disposable).
  Caches pre-smoke counts to a snapshot for post-verify diffing.

### Added — tier-2 doc-quality regression (`fun-doc/benchmark/bh/`)

- **`fun-doc/benchmark/bh/grade.py`** — grades fun-doc's BH.dll
  documentation against the upstream
  [Project-Diablo-2/BH](https://github.com/Project-Diablo-2/BH)
  source (Apache 2.0, license-compatible) as the ground-truth oracle.
  Pulls each mapped function's current name, plate, signature, and
  variables from a live Ghidra MCP server; scores against the truth;
  emits per-function table + corpus aggregate + JSON for trend
  tracking. `--compare` flag diffs two runs for regression-spotting.
- **`fun-doc/benchmark/bh/mapping.yaml`** — 14 entries: 9 BH.dll
  exports + 5 string-anchored internal-function placeholders.
- **`fun-doc/benchmark/bh/runs/2026-05-10-baseline.json`** — baseline
  corpus score 0.442 across 6 resolvable exports.
- **`fun-doc/benchmark/bh/runs/2026-05-11-post-smoke.json`** — post-smoke
  score 0.442 (no regression).

### Changed

- **fun-doc workers** read function state through `storage.repository`
  instead of parsing `state.json` directly. The persistence-layer
  swap is transparent to users — `load_state()` and `save_state()`
  in `fun_doc.py` keep the same shapes; the backend changes underneath.
- **Dashboard** (`fun-doc/web.py`) reads from the repository for all
  function-listing, sessions, inventory, and stats endpoints. Same
  rendered output; sub-100 ms per query on warmed indexes.
- **`fun-doc/inventory_scorer.py`** rolls up to the repository instead
  of writing `inventory.json` directly.
- **`runs.jsonl`** is preserved as an append-only audit log for
  back-compat and external tooling; the canonical source of truth is
  now the SQL `runs` table.

### Fixed (caught during smoke)

- **`_invoke_provider_direct` minimax branch wraps through
  `_wrap_result()`** so an early-exit return-None (missing API key,
  missing `openai` package, etc.) yields a clean `(None, meta)` tuple
  instead of crashing the caller's `text, meta = result` unpack with
  TypeError. Same latent bug existed on v5.7.2; cherry-picked here.

### Known follow-ups (not v5.8.0 blockers)

- **Globals worker run-write path is JSON-only** — `process_global`
  appends to `runs.jsonl` but doesn't call `repo.record_run()`. Affects
  globals worker only; function workers are wired correctly.
- **`runs.model` persists as `'unknown'`** — model name lookup
  during the run-row insert isn't capturing the live model. Cosmetic
  data-fidelity issue.
- **`functions_workflow.run_count` denorm doesn't tick** on completed
  runs. Denorm callback wiring incomplete.
- **`/api/stats` slow** (~30 s on 61k function dataset). Aggregation
  needs profiling.
- **`tools/setup` doesn't auto-install the new SQLAlchemy + psycopg
  dependencies** — users may need a manual `pip install -r
  fun-doc/requirements.txt` after pulling.

### Migration path

For existing fun-doc users:

```bash
# 1. After updating to v5.8.0, install new deps:
pip install -r fun-doc/requirements.txt

# 2. Run the one-shot migration (idempotent; preserves state.json):
python fun-doc/scripts/migrate_state_to_sql.py \
    --state fun-doc/state.json \
    --runs fun-doc/logs/runs.jsonl \
    --inventory fun-doc/inventory.json \
    --global-inventory fun-doc/global_inventory.json

# 3. Verify zero-diff:
python fun-doc/scripts/verify_migration.py [same args]

# 4. Restart the dashboard. fun-doc/state.db (SQLite) is the new
#    canonical store. state.json stays put as a back-compat copy.
```

For users with Postgres:

```bash
export FUN_DOC_DB_URL='postgresql://user:pass@host:5432/dbname'
# then run the same migrate + verify + restart sequence
```

### Verification

- Tier-0: 295 unit tests + 29 storage abstraction tests (SQLite +
  cross-backend) pass; 17 PG-specific tests skip without Docker.
- Tier-1 (mechanical smoke): post-migrate verifier zero-diff,
  function-worker SQL write path confirmed end-to-end on BH.dll
  (`ParseSignedShort @ 10052ba0`, score 0→37, atomic
  `functions_workflow` + `runs` row update).
- Tier-2 (BH grader): corpus score 0.442, identical to baseline —
  no doc-quality regression.

---

## v5.7.2 - 2026-05-10 (critical bridge fix + Linux/Nix compat + toggle extension)

Patch release bundling one critical bridge fix that affected all v5.7.0/v5.7.1
users, two Linux/Nix setup compatibility fixes, and an extension of the
v5.7.1 naming-enforcement toggle to cover global name-quality gates. No
endpoint count change (still 241).

### Fixed

- **Bridge `_fetch_and_register_schema()` raised "duplicate parameter name:
  'dry_run'" on startup, preventing tool registration.** Affected every
  v5.7.0/v5.7.1 user whose Ghidra plugin exposed any endpoint that already
  declared `dry_run` in its `@McpTool` schema (e.g.
  `archive_ingest_function`, `archive_ingest_program`); the bridge was
  unconditionally adding a synthetic `dry_run` parameter to every POST
  endpoint, colliding with the schema-declared one. The bridge now skips
  the synthetic injection when a schema-declared `dry_run` is present and
  preserves the schema's declared `source` (`query` vs `body`). Includes
  regression tests for synthetic, schema-declared-query, and
  schema-declared-body variants. Closes
  [#187](https://github.com/bethington/ghidra-mcp/issues/187) (community —
  @synthol, [#193](https://github.com/bethington/ghidra-mcp/pull/193)).

- **`tools.setup` pip discovery failed on Nix-managed Python
  environments.** Setup invoked pip as `python -m pip` everywhere, but on
  Nix the active interpreter can't import pip even though `pip` exists on
  PATH. Reported by @Molkars
  ([#190](https://github.com/bethington/ghidra-mcp/issues/190)), confirmed
  by @letsjustfixit on Debian. New `pip_command(python_executable)` helper
  probes `python -m pip` first (safer, venv-aware) and falls back to a
  bare `pip` on PATH only when the module form fails; result is cached per
  interpreter. Six new unit tests cover the matrix (Windows/Mac happy
  path, Nix fallback, neither-form-works, caching, isolation across
  interpreters, integration with `install_requirements_file`). Closes
  [#190](https://github.com/bethington/ghidra-mcp/issues/190).

- **`tools.setup deploy` failed on Linux because
  `find_ghidra_executable` preferred `ghidraRun.bat` first.** Ghidra
  release zips ship both `ghidraRun` (shell script) and `ghidraRun.bat`
  (Windows batch) regardless of host OS, so `is_file()` returned the
  Windows batch on Linux too; `subprocess.Popen` then tried to exec
  `cmd.exe` and failed with `FileNotFoundError`. Candidate order is now
  platform-aware. Reported and diagnosed by @Molkars
  ([#191](https://github.com/bethington/ghidra-mcp/issues/191)). Closes
  [#191](https://github.com/bethington/ghidra-mcp/issues/191).

### Changed

- **Strict Naming Enforcement now covers global name-quality gates.**
  The existing Ghidra Tool Option remains strict by default, but when
  disabled it now downgrades the hard name-quality rejects in
  `rename_data`, `rename_global_variable`, `set_global`, and the
  `apply_data_type` prefix/type guard to warnings, matching
  `rename_function_by_address`'s behavior since v5.7.1. The legacy
  **Strict Function Name Enforcement** Tool Option value is migrated
  automatically. No endpoint schema changes. Community —
  @Hummer12007, [#188](https://github.com/bethington/ghidra-mcp/pull/188).

### Tests

- Bridge soft-line-count cap raised from 2000 → 2100 to absorb the
  `#187` fix's added conditional logic plus prior legitimate growth.
  The cap remains a signal against gratuitous bloat — bump deliberately
  on future trips, not reflexively (commit
  [a0afe77](https://github.com/bethington/ghidra-mcp/commit/a0afe77)).

## v5.7.1 - 2026-05-08 (community contributions + post-release triage)

Patch release bundling five community-contributed PRs that landed on `main`
in the 48 hours after v5.7.0 shipped, plus three post-release bug fixes
diagnosed by users on the issue tracker. No breaking changes; endpoint
count grows 231 → 241.

### Added

- **Function tags** (community — chompie1337, [#179](https://github.com/bethington/ghidra-mcp/pull/179))
  — 10 new MCP endpoints for tagging functions with program-wide labels:
  `add_function_tag`, `remove_function_tag`, `get_function_tags`,
  `search_functions_by_tag`, `create_function_tag`, `delete_function_tag`,
  `set_function_tag_comment`, `list_function_tags`,
  `batch_add_function_tags`, `batch_remove_function_tags`. Tags
  auto-create on first use, are stored in the Ghidra DB so they persist
  across save/checkin, and cover the "carve curated subsets across
  long analysis sessions" pattern (e.g. `crypto`, `parser`, `reviewed`).
  See `docs/prompts/TOOL_USAGE_GUIDE.md` for the sweep-and-curate worked
  example.
- **`isThunk` / `isExternal` filters in `search_functions_enhanced`**
  (community — c8rri3r, [#178](https://github.com/bethington/ghidra-mcp/pull/178))
  — every result now carries `isThunk` and `isExternal` boolean fields,
  and the endpoint accepts `is_thunk=true|false` and
  `is_external=true|false` query parameters for filtering. Closes
  [#177](https://github.com/bethington/ghidra-mcp/issues/177).
- **GUI-configurable function-name enforcement** (community — Hummer12007,
  [#171](https://github.com/bethington/ghidra-mcp/pull/171)) — the
  **Strict Function Name Enforcement** Ghidra Tool Option controls
  whether `rename_function_by_address` hard-rejects names that fail the
  verb-tier or token-subset gates. The default remains strict. When
  disabled, the rename proceeds while returning the same issues as
  warnings. No endpoint schema change is required.

### Fixed

- **Headless server crashes on startup with "cannot add context to list"**
  ([#180](https://github.com/bethington/ghidra-mcp/issues/180), originally
  diagnosed by @MMOStars). `/create_folder` and `/delete_file` were
  registered both via `@McpTool` annotations on `ProgramScriptService`
  and manually in `GhidraMCPHeadlessServer.registerEndpoints()`,
  tripping `HttpServerImpl.createContext` with
  `IllegalArgumentException`. Removed the duplicate manual
  registrations; updated `countEndpoints()` -2.
- **Address-space name lowercasing breaks 8051 and other uppercase-space
  architectures** ([#184](https://github.com/bethington/ghidra-mcp/issues/184),
  reported by @Artem-B). `bridge_mcp_ghidra.py::sanitize_address` was
  lowercasing the space-name component (`CODE:123` → `code:123`), but
  Ghidra's `AddressFactory` is case-sensitive and 8051 declares
  `RAM`/`CODE`/`INTMEM`/`EXTMEM` uppercase. Fix: pass the space name
  through unchanged. Three regression tests added covering the 8051
  spaces. Two unrelated pre-existing test scaffolding bugs cleaned up
  in the same commit (camelCase param key, missing mock kwarg) — test
  file goes 18 → 21 passing tests.
- **Docker build can't resolve Ghidra Maven artifacts**
  ([#183](https://github.com/bethington/ghidra-mcp/issues/183), reported
  by @RocketMaDev). `Dockerfile` `GHIDRA_VERSION` ARG defaulted to
  `12.0.3` from the v5.6.0 era but `pom.xml` bumped to `12.0.4` in
  v5.7.0. The build downloaded 12.0.3 and stamped JARs as
  `ghidra:*:12.0.3`, then Maven failed to resolve `ghidra:*:12.0.4`.
  Bumped to `12.0.4` + `GHIDRA_DATE=20260303` and added a comment
  marking this as a release-time sync point with `pom.xml`.
- **Maven `OSError` on Windows when `M2_HOME` is set** (community —
  deckbsd, [#176](https://github.com/bethington/ghidra-mcp/pull/176)).
  `tools/setup/maven.py::candidate_maven_commands` was always adding
  both `<M2_HOME>/bin/mvn` (shell script) and `<M2_HOME>/bin/mvn.cmd`
  (Windows wrapper) as candidates. On Windows the shell script
  triggered an `OSError` when the discovery code tried to exec it.
  Now adds only the platform-appropriate executable.

### Changed

- Endpoint catalog: 231 → 241 endpoints. Tool-count references in
  `README.md`, `CLAUDE.md`, `AGENTS.md`, `docs/NAMING_CONVENTIONS.md`,
  `MANIFEST.MF`, and `extension.properties` updated to match.

---

## v5.7.0 - 2026-05-05 (globals quality, scope guard, archive integration)

Release headline is bringing global variables up to the same documentation
bar as functions: a four-axis "properly documented" standard
(name + type + bytes formatted + plate comment) enforced at three layers
(prompt + scorer + validator), three new MCP endpoints replacing the
fragile 4-tool fix chain with a single atomic write, and a binary-wide
bulk auditor mirroring the function inventory scorer pattern.

Three additional themes added during release prep:

- **Project-folder scope guard** — opt-in two-layer guard preventing
  multi-version reverse-engineering from accidentally writing to the
  wrong binary. Layer 1 fun-doc Python validation, Layer 2 Ghidra Java
  `FrontEndProgramProvider` + `SecurityConfig.isPathInProjectScope`.
  Off by default (env var `GHIDRA_MCP_PROJECT_FOLDER`); general users
  see no behavior change.
- **Cross-version doc archive integration** — fun-doc now mirrors
  documented functions to a re-kb FastAPI service and reads from it
  before invoking the LLM. On Q5-D gate pass (hash-exact OR BSim≥0.9
  AND score≥80) it applies the archived name + plate via existing
  MCP tools and skips the LLM. Two new MCP tools
  (`archive_ingest_function`, `archive_ingest_program`).
- **state.json truncation hardening** — root-caused and fixed an
  incident where a duplicate `load_state()` in `web.py` raced a writer
  for >3 retries, returned an empty stub, and saved that stub over
  the real ~110 MB state.json. Now delegates to `fun_doc.load_state`
  (5 retries → `.bak` fallback → raise) and uses `_atomic_write_state`
  with a guardrail refusing to overwrite a populated state with an
  empty-functions dict.

### Added

#### MCP endpoints

- **`audit_global`** — read-only inspector. Returns address, name, type,
  length, plate comment, xref count, and a structured `issues` list
  (`generic_name`, `untyped`, `unformatted_bytes_length_mismatch`,
  `unformatted_bytes_should_be_string`, `missing_plate_comment`,
  `plate_comment_too_short`).
- **`audit_globals_in_function`** — per-function bulk auditor. Walks
  the function's instructions, collects unique data-reference targets,
  audits each via the shared `auditGlobalAt` helper, and returns
  `{function, globals: [...], summary: {total, fully_documented,
  with_issues, issue_histogram}}`. The killer per-function pre-flight
  tool — one MCP call instead of N.
- **`set_global`** — atomic single-transaction write that applies type,
  optional `array_length`, name, and plate comment as a unit. Pre-flight
  validation rejects on naming/type/format failures with a structured
  error (`status: "rejected"`, `error`, `issue`, `suggestion`). No
  partial writes — either everything applies or nothing does. Replaces
  the four-tool chain (`apply_data_type` → `rename_data` →
  `batch_set_comments` → `create_label`).

#### Per-function scorer deductions

Four new categories surface bad globals in the work queue at scoring
time, capped at -20 aggregate per function:

- `untyped_global` -8 — referenced global has `undefined*` type.
- `unformatted_global_bytes` -5 — wrong byte layout (length mismatch
  or string-as-char).
- `generic_global_name` -5 — auto-generated remnant or fails
  `checkGlobalNameQuality`.
- `missing_global_plate_comment` -3 — empty or `<4-word` first line.

#### Binary-wide bulk scorer

- **`fun-doc/global_scorer.py`** — opt-in idle-time daemon that walks
  every binary in the Ghidra project tree, audits every global symbol,
  and tallies per-binary `total_documentable` / `fully_documented`
  counts. Mirrors `inventory_scorer.py`'s architecture: single-thread,
  cooperative pause when doc workers run, session-only blacklist after
  3 strikes, persisted to `fun-doc/global_inventory.json`. Most-globals-
  with-issues-first ordering, reverse-alpha tiebreak.
- **Dashboard "Global Inventory" panel** — per-binary table with coverage
  bar, fully_documented / total / with_issues counts, percent, status,
  last scan, and a Retry button on blacklisted rows. Live updates via
  `global_inventory_status` WebSocket event.
- **New endpoints** — `GET /api/global_inventory/status`,
  `POST /api/global_inventory/toggle`,
  `POST /api/global_inventory/clear_blacklist`.
- **`global_inventory_enabled`** added to `DEFAULT_QUEUE_CONFIG` (default
  False; opt-in via the dashboard toggle).

#### Naming + plate-comment helpers

- **`NamingConventions.checkGlobalNameQuality(name, type)`** — structured
  global-name validator. Enforces `g_` prefix + Hungarian matching type +
  ≥2-char descriptor + reject auto-generated remnants (`g_DAT_*`,
  `g_PTR_*`, `g_FUN_*`, `g_LAB_*`, `g_SUB_*`, `g_<prefix>_<hex>`).
  Conservative placeholders (`g_dwField1D0`, `g_pUnk20`) are accepted
  per CLAUDE.md's underclaim convention.
- **`NamingConventions.isAutoGeneratedGlobalName`** — recognizer for
  Ghidra's auto-generated global symbols.
- **`NamingConventions.checkGlobalPlateComment`** — shared helper used
  by both `audit_global` and `set_global` so they apply the same
  ≥4-word first-line rule.
- **`DataTypeService.auditGlobalAt`** — public static helper; the
  shared per-global audit routine called by `audit_global`,
  `audit_globals_in_function`, and the new scorer deductions.

#### Prompt

- **`prompts/step-globals.md`** — new step module loaded by FULL and
  recovery prompt builders. Documents the four-axis bar, the
  Hungarian-vs-type table, the canonical `audit_globals_in_function` →
  `set_global` workflow, and how to handle structured rejections.
- **`prompts/hungarian-table.md`** — canonical single-source-of-truth
  Hungarian prefix → type table, referenced by all the other globals
  prompts (`step-globals.md`, `worker-globals.md`, `fix-hungarian.md`)
  instead of being restated in each.
- **`prompts/worker-globals.md`** — globals worker prompt covering the
  Q1–Q12 design (process_global pre-audit short-circuit, completed/
  no_change/regressed classification, runs.jsonl row shape with
  `mode="globals"`).

#### Globals worker

- **`process_global`** in `fun_doc.py` — single-function globals
  documentation entrypoint. Pre-audit short-circuits when the global
  is already fully_documented; classifies completed/no_change/regressed
  based on issue-list deltas; writes `runs.jsonl` rows with
  `mode="globals"` for dashboard tracking.
- **`run_globals_worker_pass`** — count-capped worker loop with
  continuous-mode binary rotation and stop_flag interruption.
- **`WorkerManager` mode dispatch** — recognizes `mode="globals"`,
  requires a `binary` parameter, and rejects a second launch on the
  same binary (Q11 per-binary lock prevents concurrent writes).

#### Project-folder scope guard

- **`SecurityConfig.isPathInProjectScope(domainFilePath)`** — collision-
  safe equals-or-startsWith path matcher (a path "P/A" inside scope
  "/P" must NOT match scope "/PA"). Reads `GHIDRA_MCP_PROJECT_FOLDER`
  env var; null/unset disables the guard so general users see no
  behavior change.
- **`FrontEndProgramProvider.getProgram(name)`** — wraps existing
  resolution with a scope check, returning a clear error if the
  resolved DomainFile is outside the configured project folder.
- **`scripts/launch-ghidra-scoped.ps1`** — convenience wrapper that
  sets `$env:GHIDRA_MCP_PROJECT_FOLDER` then launches `ghidraRun.bat`.

#### Cross-version doc archive integration

- **`archive_ingest_function(address, program)`** — MCP tool in
  `DocumentationHashService.java`. Builds the archive payload from the
  current Ghidra state (locals, instruction comments, referenced data
  types/globals/labels, equates, opcode hash, BSim signature when
  available) and POSTs to the re-kb FastAPI service's
  `/v1/doc_archive/upsert` endpoint.
- **`archive_ingest_program(program)`** — bulk variant; iterates every
  documented function in the program.
- **fun-doc write hook** — after `save_program` in `process_function`,
  pushes the freshly-documented function to the archive.
- **fun-doc read hook** — before invoking the LLM, checks
  `/v1/doc_archive/match`. On Q5-D gate pass (hash-exact OR BSim≥0.9
  AND score≥80) applies the archived name + plate via existing MCP
  tools and skips the LLM. Bus events `archive_pushed`,
  `archive_lookup`, `archive_applied`, `archive_apply_failed`,
  `archive_push_failed` for dashboard visibility.
- Required env: `RE_KB_ARCHIVE_URL` (defaults to
  `http://10.0.10.30:8422`); empty disables both hooks.

### Changed

- **`rename_data` / `rename_global_variable` validator gates** — hard-
  reject names failing `checkGlobalNameQuality` with structured errors:
  `{"status": "rejected", "error": "name_quality", "issue": ...,
  "rejected_name": ..., "current_type": ..., "message": ...,
  "suggestion": ...}`. Function unchanged on rejection. The model
  retries informed by the error rather than ignoring soft warnings.
- **`set_global` array bounds validation** — added pre-flight rejection
  for `array_length < 0` (`invalid_array_length`), `array_length > 0`
  with empty `type_name` (`array_length_requires_type`), zero-length
  element types (`invalid_element_size`), and overflow / sane-cap
  exceedance (`array_too_large`, 16 MiB cap). Previously these slipped
  through with misleading "success" responses or silent overflow.
- **`web.py` state I/O hardening** — `load_state()` now delegates to
  `fun_doc.load_state` (5 retries → `.bak` fallback → raise on corrupt),
  and `_save_state_inline()` uses `_atomic_write_state` with a guardrail
  refusing to overwrite a populated state.json with an empty-functions
  stub. Eliminates the silent-truncation race that nuked ~110 MB of
  state during the 2026-05-03 incident.

### Fixed

Three commits targeting silent-failure modes the production log audit
surfaced; pairs with the v5.7.0 globals work since the same patterns
were biting the globals worker:

- **`set_variables` empty-map success** — now returns success (not
  error) when the variables map is empty; matches `batch_set_comments`
  semantics and lets prompts pass `{}` to mean "no-op." (`8a6b58d`)
- **`set_local_variable_type` SSA-churn awareness** — type changes that
  trigger re-decompilation surface a churn-aware error directing the
  worker to call `get_function_variables` and retry via `set_variables`,
  rather than failing opaquely. (`c9b1381`)
- **Chained-rename worker redirect** — workers that previously chained
  `rename_data` → `apply_data_type` → `batch_set_comments` are pushed
  to use `set_global` instead, eliminating partial-application risk.
  (`3f8e904`)
- **`set_global` / `rename_or_label` / `rename_global_variable` name
  idempotency** — same name on re-run is a no-op success, not a
  `DuplicateNameException`. (`16840c8`)
- **Three high-impact silent-error patterns** from prod log audit
  hardened across the worker tools. (`56808c9`)

### Tests

- **17 new offline JUnit tests** for `NamingConventions.checkGlobalNameQuality`
  + `checkGlobalPlateComment` (53 total — was 47, +6 plate-comment).
- **19 new offline Python tests** for `global_scorer.py` (ordering,
  blacklist, pause-gate, persistence shape, threaded-class behavior).
- **18 new live integration tests** in `tests/integration/test_global_endpoints.py`
  exercising every rejection code, the no-partial-application contract
  on `set_global`, the per-function bulk auditor's response shape, and
  endpoint-catalog parity. Auto-skip with a clear "deploy first"
  message when the live plugin doesn't have the new endpoints.
- **`docs/releases/v5.7.0-VERIFY.md`** — manual verification checklist
  walking the rejection table by hand for spot-checks.

The fragile 4-tool fix chain still works for non-global data items;
globals are encouraged to use `set_global` exclusively via the prompt.
The validator + bulk scorer + per-function deductions provide three
independent ways for sloppy globals to surface in the worker's
attention.

---

## v5.6.0 - 2026-04-25 (release regression + fun-doc workflow)

Release covering deploy/regression safety, live benchmark coverage, debugger
endpoint validation, and a substantial fun-doc workflow upgrade: per-worker
config freezing, quota-aware provider pause/resume, a continuously-running
background inventory scorer, and verb-tier function-name quality
enforcement at the rename layer.

### Added

#### Deploy / regression / debugger

- **Live deploy release regression** — deploy can opt into benchmark-backed
  read/write, multi-program, negative-contract, and debugger-live regression
  tiers via `--test ...` or local `GHIDRA_MCP_DEPLOY_TESTS`.
- **Benchmark debugger fixture** — `fun-doc/benchmark` now builds
  `BenchmarkDebug.exe` alongside `Benchmark.dll` so debugger MCP endpoints
  can be exercised against a real launched process.
- **Scoped prompt policy endpoint** — `/prompt_policy` temporarily handles a
  narrow allow-list of known Ghidra automation dialogs during
  deploy/regression runs while leaving normal interactive prompts
  untouched.

#### fun-doc workflow

- **Worker config snapshot** — workers freeze the dashboard's policy fields
  (`good_enough_score`, `audit_provider`, `audit_min_delta`,
  `complexity_handoff_provider`, `complexity_handoff_max`, per-provider
  `provider_max_turns` + `provider_models`) at start and read from the
  snapshot for the rest of their life. Mid-run live-config edits no longer
  affect a running worker — restart-to-change semantics. Snapshot is
  persisted to `events.jsonl` via a `worker.started` event so post-hoc log
  analysis can join run records to the exact config under which they ran.
  Dashboard shows a per-worker config sub-line and fires a toast when
  saving the queue config diverges from any running worker's snapshot.
- **Provider model + max-turns defaults backfill** — `priority_queue.json`
  now backfills missing per-provider entries from a module-level
  `DEFAULT_PROVIDER_MODELS` (gemini, claude, codex, minimax). Fresh
  installs and partial configs get fully populated dashboard inputs
  without manual setup.
- **Background inventory scorer** — opt-in daemon that fills missing
  `analyze_function_completeness` scores across every binary in the Ghidra
  project tree. Idle-time backfill (yields when any doc worker is active),
  most-missing-first ordering with reverse-alpha tiebreak, single-thread,
  cooperative pause at chunk boundaries, session blacklist after 3
  strikes, dedicated `fun-doc/inventory.json` persistence. Dashboard
  widget plus an Inventory panel with sortable per-binary table (coverage
  bar, scored, total, missing, %, status, last scan).
- **Quota-aware provider pause/resume** — when a provider returns a quota-
  wall error (gemini's "exhausted your capacity", claude's "credit balance
  is too low", codex's "insufficient_quota", minimax's quota messages),
  fun-doc parses the reset duration, installs a per-(provider, model)
  pause in `fun-doc/provider_pauses.json`, and parks every worker on that
  model until the timer fires. Soft rate limits (<5 min) stay in retry
  logic; hard walls (≥5 min) install a pause. Dashboard surfaces a
  `quota_paused` worker state with a live wake-time countdown. Manual
  override via `POST /api/provider_pauses/clear`.
- **Function-block visual** — per-function worker output is wrapped in a
  three-sided gold bracket (top + left + bottom, open right). Header is
  the function's start name; footer is the post-rescore name (so renames
  are visible). Body indented; blank lines stripped within a block; one
  blank line of breathing room between blocks. Worker abandon mid-function
  emits a synthetic `(interrupted)` footer so headers never go orphaned.
- **Three-column worker grid** — dashboard now shows 3 worker panes per
  row instead of 2, fitting ~50% more workers without scrolling.

#### Naming-quality enforcement

- **Verb-tier function-name quality** — `NamingConventions` gains Tier 1 /
  Tier 2 / Tier 3 verb classification, a weak-noun denylist, PascalCase
  tokenization, and a `checkFunctionNameQuality` API returning structured
  rejection (`vague_verb`, `weak_noun_only`, `missing_specifier`). Tier 3
  verbs (`Process`, `Handle`, `Manage`, …) require ≥2 specifier tokens
  after the verb; weak nouns (`Data`, `Info`, `Stuff`, …) don't count as
  specifiers.
- **Token-subset duplicate detection** —
  `NamingConventions.findTokenSubsetCollision` flags function-name
  collisions where one name's tokens are a strict subset of another's
  within the same module-prefix scope (e.g., `SendStateUpdate` ⊂
  `SendStateUpdateCommand`).
- **Three new completeness deductions** — `low_name_quality` (-8),
  `name_collision` (-10), `missing_module_prefix` (-5; fires when name has
  no `UPPERCASE_` prefix and ≥3 callees share one). Surfaces existing bad
  legacy names in the work queue with point pressure to fix them.

#### New endpoints

- `GET /api/inventory/status`, `POST /api/inventory/toggle`,
  `POST /api/inventory/clear_blacklist` — background scorer surface.
- `GET /api/provider_pauses`, `POST /api/provider_pauses/clear` —
  quota-pause surface.

### Changed

- **Deploy lifecycle** — deploy now saves all open programs, attempts
  graceful Ghidra exit, force-kills matching leftovers when needed,
  installs the extension, starts Ghidra, waits for MCP/project readiness,
  and runs schema smoke checks.
- **Benchmark project reset** — benchmark tiers reset `/testing/benchmark`
  in the active project, import both benchmark binaries, auto-analyze
  them, and clear restored benchmark tool state before startup.
- **`rename_function_by_address` validator gate** — hard-rejects names
  failing the verb-tier rules or token-subset uniqueness with a structured
  error: `{"status": "rejected", "error": …, "issue": …,
  "rejected_name": …, "conflicts_with": …, "message": …, "suggestion": …}`.
  Function is unchanged on rejection; the model retries with a better
  name. Auto-generated names are exempt. `step-prototype.md` documents the
  verb tiers, weak-noun list, a worked-example pass/fail table, and a
  rejection round-trip guide.
- **Complexity-handoff fall-through** — when handoff can't fire (no
  provider configured, cap reached, or target walled), the worker now
  continues with primary instead of skipping the function. Removes a
  silent `consecutive_fails` increment on healthy functions for
  config/transient reasons.
- **Worker title color treatment** — provider/id token in the worker pane
  header is now white (`text-primary`); the active function name is gold
  (`accent-gold`) so the eye lands on what you're tracking.
- **Audit / handoff under quota wall** — when the target provider+model is
  walled, audits log `audit_outcome: quota_paused` and skip; handoffs
  pre-empt and stick with primary. No `consecutive_fails` bump.

### Fixed

- **`list_functions_enhanced` thunk parity** — `isThunk` now uses the same
  `AnalysisService.classifyFunction` path as
  `analyze_function_completeness`, so single-jump thunk heuristics agree
  across both tools. Thanks to PR #165 by c8rri3r.
- **`create_struct` tool guidance** — MCP schema/catalog descriptions now
  spell out the expected `fields` JSON array format, optional decimal
  `offset`, accepted alternate field keys, and valid type sources so agents
  stop trying C-like struct strings or CSV bodies.
- **Gemini quota errors silently swallowed** — `_invoke_gemini`'s retry-
  exhaust path now propagates `provider_error` / `provider_error_type`
  into the run record so the dashboard and `runs.jsonl` show the actual
  message ("exhausted your capacity, quota will reset after Xh") instead
  of `output: null` / `error: null`.
- **State lock reentrancy** — `_state_lock` switched from `Lock` to
  `RLock` so `load_state` can be called from within a `with _state_lock:`
  block without deadlocking.

### Tests

- 28 offline tests for the inventory scorer (ordering, blacklist,
  pause-gate, scored definition, JSON shape stability).
- 34 offline tests for the provider-pause module (parser, per-provider
  detectors, threshold, manager round-trip, callback semantics).
- 13 offline tests for the worker config snapshot (shape, freeze
  guarantees, fall-through, conditional banner).
- 31 offline tests for `NamingConventions` (tokenize, verb tiers,
  specifier counting, all rejection codes, token-subset collision in
  both directions, module-prefix scoping, exact-match exemption).
- Updated `test_provider_selection.py` to cover the new
  `DEFAULT_PROVIDER_MODELS` backfill behavior.

## v5.5.0 - 2026-04-23 (maintenance)

Maintenance release focused on cleanup and release readiness after the
v5.4.1 security hardening work.

### Fixed

- **`FunctionService` decompiler lifetime handling** — closes owned
  `DecompInterface` instances on all relevant success, early-return, and
  exception paths to avoid leaking decompiler subprocesses during
  decompilation and variable-update workflows.
- **Claude/CAPI tool-name compatibility in the Python bridge** —
  `bridge_mcp_ghidra.py` now enforces the stricter `^[a-zA-Z0-9_-]{1,64}$`
  constraint when sanitizing and collision-suffixing tool names, matching
  client expectations instead of emitting overlong names.
- **Bundled Ghidra script resource ownership** — script-side
  `DecompInterface` usage now follows scoped `try/finally` disposal in the
  affected batch, export, survey, and audit helpers.
- **Claude subprocess lifetime in bundled scripts** — the Claude-invoking
  scripts now drain and close readers with try-with-resources and use
  bounded `waitFor(timeout, TimeUnit.SECONDS)` handling with terminate/kill
  fallback instead of unbounded waits.

- **fun-doc logging diagnostics** - provider watchdog workers now inherit
  per-run debug context, early exits are recorded in `runs.jsonl`, Ghidra
  HTTP failures write structured diagnostics, and debug analyzers count
  normalized provider error statuses.

### Docs

- **Release metadata refreshed to `5.5.0`** across Maven, plugin/headless
  fallbacks, manifest metadata, endpoint catalog, operator docs, and the
  release index.
- **`CONTRIBUTING.md`** — added a concise resource-ownership checklist for
  services and bundled scripts, covering disposable helpers,
  transactions, child-process lifecycle, and timeout expectations.

## v5.4.1 - 2026-04-18 (security)

Security + operational-readiness release on top of v5.4.0. Addresses the
findings from a full production-readiness audit: unauthenticated HTTP
surface, ungated RCE-class endpoints, silent `--bind 0.0.0.0`, broken CI
after the debugger merge, stale metadata, and an empty v5.4.0 release
page.

### Breaking change

- **`/run_script_inline` and `/run_ghidra_script` are now off by default.**
  These endpoints execute arbitrary Java against the running Ghidra
  process. Set `GHIDRA_MCP_ALLOW_SCRIPTS=1` (or `true`/`yes`) to restore
  v5.4.0 behavior. Error message surfaced to callers names the env var
  and explains why.

### Security — opt-in hardening (default = pre-v5.4.1 localhost behavior)

New [`com.xebyte.core.SecurityConfig`](src/main/java/com/xebyte/core/SecurityConfig.java)
— read-once, thread-safe snapshot of three env vars:

- **`GHIDRA_MCP_AUTH_TOKEN`** — when set, every HTTP request must carry
  `Authorization: Bearer <token>`. Constant-time byte comparison resists
  timing attacks. `/mcp/health`, `/health`, `/check_connection` are
  always-exempt read-only pings. Enforced in the GUI plugin's
  `safeHandler()` wrapper and the new headless
  `safeContext(path, handler)` registration helper (replaces bare
  `server.createContext` at all 32 sites).
- **`GHIDRA_MCP_ALLOW_SCRIPTS`** — see Breaking change above.
- **`GHIDRA_MCP_FILE_ROOT`** — when set, filesystem-path endpoints
  canonicalize input and require it to fall under the configured root.
  Mechanism + helper (`SecurityConfig.resolveWithinFileRoot()`) shipped
  in this release; per-endpoint wiring for `/import_file`,
  `/delete_file`, `/open_project`, etc. follows in v5.4.2.

### Security — bind hardening

- Headless `startServer()` now calls
  `SecurityConfig.requireAuthForNonLoopbackBind(bindAddress)` before
  binding. Non-loopback binds (`0.0.0.0`, explicit external IP) now
  refuse to start unless `GHIDRA_MCP_AUTH_TOKEN` is configured. Error
  message names the env var.

### CI

- **All four workflows now install the three Ghidra Debugger JARs**
  (`Debugger-api`, `Framework-TraceModeling`, `Debugger-rmi-trace`) —
  every build on main since the v5.4.0 debugger merge had been failing
  because these weren't in the `mvn install:install-file` blocks.
  Release workflow re-ran successfully after the fix; v5.4.0 release
  page now has attached artifacts (was empty at tag time).
- **Offline Java tests run in CI.** The 11 annotation-scanner + catalog
  parity tests (~3 s) were previously only run on developer machines;
  they now gate every push/PR on `main` and `develop`. Integration
  tests (which require live Ghidra on port 8089) remain excluded.

### Fixed

- **Python debugger startup + target query flow on Windows** — the
  debugger backend now validates `WINDBG_DIR` before importing `pybag`,
  falls back to a Microsoft Store WinDbg cache when the Windows Kits
  debugger directory is incomplete, stops double-waiting after
  `AttachProcess`, parses `pybag` module tuples correctly, and reads
  x64 register sets (`RAX`-`R15`/`RIP`) instead of returning empty
  register output on 64-bit targets.
- **WOW64 register context** — when attached to 32-bit processes under
  WOW64, debugger register reads now switch dbgeng's effective
  processor to x86 so the API returns `EAX`/`ECX`/`ESP`/`EIP` instead of
  the host-side 64-bit `R*` context. The same x86 view is used for
  stack-context reads that depend on those registers.

### Docs

- **`CHANGELOG.md`** — v5.4.0 entry backfilled (was missing at tag
  time). This v5.4.1 entry.
- **`README.md`** — version badge `5.3.2 → 5.4.0 → 5.4.1`, tool-count
  references refreshed to 219 (5+ occurrences), new `## 🔒 Security`
  section documenting the three env vars with a worked LAN-exposure
  example and a migration note for the script-gate breaking change,
  Dynamic Analysis features subsection covering emulation + debugger,
  GUI/headless endpoint counts corrected.
- **`CLAUDE.md`** — version + tool count, Architecture section updated
  for `EmulationService`, `DebuggerService`, `debugger/` Python
  package on port 8099 via `GHIDRA_DEBUGGER_URL`, and
  `HeadlessManagementService`.
- **`tests/endpoints.json`** — `version` field `5.2.0 → 5.4.1` (had
  been stale since v5.3).
- **`src/main/resources/META-INF/MANIFEST.MF`** — `Plugin-Version`
  `4.4.0 → 5.4.1` (very stale).
- **`src/main/resources/extension.properties`** — tool count
  `199 → 219`; dynamic-analysis capabilities noted.
- **`GhidraMCPHeadlessServer.java`** — `VERSION` string
  `5.3.2-headless → 5.4.1-headless`.

### Hygiene

- **Deprecated-API warning suppressed** in
  `HeadlessEndpointHandler.batchSetComments` — Ghidra 12's deprecated
  `Listing.setComment(Address, int, String)` + `CodeUnit` int
  constants. Silences the "Some input files use or override a
  deprecated API" warning that appeared on every clean build.
- **`requirements.txt:8`** — bumped `requests` floor to `>=2.32.0`
  per CVE-2024-35195 (certificate-verification bypass).
- **`.playwright-mcp/`** added to `.gitignore` — Playwright MCP
  scratch directory was appearing in `git status` after every browser
  test.
- **Per-function escalation + audit tracking (fun-doc)** — when a
  worker auto-escalates mid-function to a stronger provider, or when
  the post-function audit pass runs, the function record is now
  stamped with `escalation_count` / `last_escalated` /
  `last_escalation_from` / `last_escalation_to` /  `audit_count` /
  `last_audited` / `last_audit_provider` / `last_audit_delta`.
  `/api/stats` surfaces two new counters (`audited`, `escalated`).

### Known gaps (follow-ups to v5.4.2)

- **Per-endpoint file-path root check.** The `SecurityConfig`
  mechanism is ready, but individual endpoints (`/import_file`,
  `/delete_file`, `/open_project`, `/load_program`, etc.) still
  accept raw paths. Wire-up in next patch.
- **Debugger endpoints are still live-untested.** 17 Java + 22 Python
  bridge tools compile, pass offline tests, and fail gracefully when
  no debug session is attached, but haven't been exercised against a
  running target. v5.4.2 or v5.5.0 will ship with live-validation
  logs.
- **Three placeholder endpoints** (`/detect_crypto_constants`,
  `/find_dead_code`, `auto_decrypt_strings`) still in the schema with
  "Not yet implemented" responses.

---

## v5.4.0 - 2026-04-18

Feature release. Three new service domains land together: P-code emulation,
live debugger integration, and PCode-graph data flow analysis. Plus headless
catalog fixes, fun-doc UI improvements, and a `--use-venv` setup flag. Tool
count rises from 199 → 219 on main.

### Added

- **P-code emulation** (#127) — [`EmulationService.java`](src/main/java/com/xebyte/core/EmulationService.java)
  exposes two new endpoints backed by Ghidra's `EmulatorHelper`:
  - `POST /emulate_function` — run a function with user-supplied register
    and memory state; returns the final register values. Memory regions
    accept base64 (`data`), hex, or `string` forms, wrapped under
    `{"regions": [...]}` in the JSON body.
  - `POST /emulate_hash_batch` — brute-force API hash resolution. Iterates
    a candidate list, writes each string into scratch memory, runs the
    hash function, and compares the result register against a target hash.
    Returns all matches (collision-safe) plus a `best_match` convenience
    field.

  Live-verified against D2Common.dll: a two-instruction leaf
  (`MOV EAX, [ECX+4]; RET`) round-trips `0xDEADC0DE` through the emulator,
  and `/emulate_hash_batch` correctly isolates a single matching
  candidate from a three-item list using a contrived hash target.

- **Live debugger integration** (#128) — two-part addition:
  - Java side: [`DebuggerService.java`](src/main/java/com/xebyte/core/DebuggerService.java)
    exposes 17 `/debugger/*` endpoints (`status`, `traces`, `resume`,
    `interrupt`, `step_{into,over,out}`, `{set,remove,list}_breakpoint`,
    `registers`, `read_memory`, `stack_trace`, `modules`,
    `{static,dynamic}_to_{dynamic,static}`, `launch_offers`) wrapping
    Ghidra's `DebuggerTraceManagerService`,
    `DebuggerLogicalBreakpointService`, and `TraceRmiLauncherService`.
    Supports whatever backend Ghidra's TraceRmi framework provides
    (`dbgeng` for Windows PE targets, `gdb`/`lldb` otherwise). GUI-only —
    not wired into the headless server because `DebuggerService` requires
    a `PluginTool`.
  - Python side: new [`debugger/`](debugger/) package with a standalone
    HTTP server on port 8099 (engine, protocol, tracing, address_map,
    D2-specific convention parser). `bridge_mcp_ghidra.py` registers 22
    static MCP tools (`debugger_attach`, `debugger_continue`,
    `debugger_step_*`, `debugger_registers`, `debugger_read_memory`,
    `debugger_stack_trace`, `debugger_trace_*`, `debugger_watch_*`) that
    proxy to the server via the `GHIDRA_DEBUGGER_URL` env var.

  Compile + offline tests pass for both layers. Live-session testing is
  pending an attached debug target.

- **Data flow analysis** (#125, closes #111) — `GET /analyze_dataflow`
  traces value propagation through a function using the decompiler's
  PCode graph. Backward mode walks producers via `Varnode.getDef()`;
  forward mode walks consumers via `Varnode.getDescendants()`.
  Terminates at constants, function inputs, call boundaries, or
  `max_steps`. Phi (`MULTIEQUAL`) nodes are summarized as single steps
  rather than recursed. Anchor resolution accepts register names
  (`EAX`), HighVariable names (`param_1`, `local_14`), or empty for the
  first PcodeOp output at the address. Live-verified against
  `ANIM_GetFrameData` in D2Common.dll: the backward chain reproduces the
  decompiler output `*(byte *)(pUnit->dwField50 + 0x10 + nAnimIndex)`
  step-for-step.

- **Headless program/project management** (#121, #122, #123) — the eight
  headless-specific endpoints (`/load_program`, `/close_program`,
  `/create_project`, `/open_project`, `/close_project`,
  `/load_program_from_project`, `/get_project_info`, `/server/status`)
  were previously registered manually and invisible to `/mcp/schema`,
  so `list_tool_groups` omitted them. New
  [`HeadlessManagementService.java`](src/main/java/com/xebyte/headless/HeadlessManagementService.java)
  moves them into the annotation scanner. Parity test extended to
  scan the headless-only service so catalog drift in these endpoints
  now fails at `mvn test` time.

- **`--use-venv` flag for Linux setup** (#120) — the legacy Linux setup flow
  can now install Python deps into a local `.venv` instead of the
  system Python, required on Ubuntu 24.04+ where system Python is
  externally-managed.

### Changed

- **`tests/endpoints.json`** regenerated via `RegenerateEndpointsJson`
  — 199 → 219 entries. The `version` field, stale at `5.2.0`, is bumped
  to `5.4.0`. Categories list adds `emulation` and `headless`.
- **fun-doc UI** (#126) — layer filter dropdown (matches dashboard BFS
  computation), 7 sortable column headers replacing the previous
  dropdown sort, `Layer` column replacing `Callers`, 500-row table cap
  removed, `Focus` button on worker panes + banner wired to
  `/api/navigate`, `Stop All Workers` button with visibility logic,
  runs-today counter reads the full log file, auto-escalate to stronger
  provider when score < `good_enough`. Live smoke-tested via Playwright
  against the running dashboard.
- **`tests/endpoints.json` catalog corrections** (#123) — three headless
  endpoint params had been miscatalogued (`/load_program`: `path` →
  `file`; `/close_program`: `program` → `name`;
  `/load_program_from_project`: two params → one). Catalog is now
  authoritative and validated by the offline parity test.

### Fixed

- **Intermediate varnode rendering in `/analyze_dataflow`** (second
  commit on #125) — Ghidra's `HighVariable` returns the literal string
  `"UNNAMED"` for anonymous intermediates. The initial implementation
  rendered these as `"UNNAMED"` instead of falling through to the
  `unique:<id>` labeling. Fixed by skipping the placeholder and
  surfacing the unique varnode id, giving traceable dependency chains.

### Security

- No security-relevant changes in v5.4.0. The unchanged default state
  — unauthenticated HTTP endpoints with the option to bind `0.0.0.0`
  in headless mode — applies here as before. **A v5.4.1 security
  release is planned** to address auth, bind hardening, script-endpoint
  gating, and path canonicalization on file-handling endpoints.

### Known gaps

- **Debugger endpoints are live-untested.** All 17 Java endpoints and
  22 Python bridge tools compile, pass offline annotation-parity tests,
  and fail gracefully when no debug session is attached, but they have
  not been exercised against a running target. v5.4.1 or v5.5.0 will
  ship with live-validation logs.
- **Three placeholder endpoints** remain in the schema with "Not yet
  implemented" responses: `/detect_crypto_constants`, `/find_dead_code`,
  `auto_decrypt_strings`. These will either be implemented or switched
  to returning an error in a subsequent release.

---

## v5.3.2 - 2026-04-15 (hotfix)

Second hotfix on the v5.3.x line, shipped after a multi-hour overnight
test session exposed three bugs that v5.3.1 didn't catch. Each was
reproducible and live-verified fixed. No new features, no breaking
changes. Semver PATCH bump.

### fun-doc

#### Fixed

- **Pass 2 (`FULL:comments`) never ran for codex or claude** — [fun_doc.py:3960](fun-doc/fun_doc.py#L3960)
  gated the two-pass flow on `tool_calls_made > 0`. Both providers use
  `_wrap_result` which sets `tool_calls: -1` ("unknown, trust run") since
  neither the codex nor the claude SDKs report per-turn tool counts.
  `-1 > 0` was False, so Pass 2 was skipped on every codex/claude run.
  Pass 2 is the phase that adds plate comments and EOL markers, which is
  typically what pushes a function from ~55-65% to 80%+. Without it,
  both providers plateaued and re-entered the selector forever.
  Changed the gate to `!= 0`.

  Live verification (2026-04-15 14:18–14:23, 5 runs across both providers):
  ```
  InitializeVideoState            codex   59→100  (+41)  FULL:comments  completed
  ResetNpcMenuState               claude  59→100  (+41)  FULL:comments  completed
  CreateMissileCheckingSkillFlags codex   61→100  (+39)  FULL:comments  completed
  InitializeExpansionAudio        claude  61→ 92  (+31)  FULL:comments  completed
  ReinitializeExpansionAudio      codex   61→ 91  (+30)  FULL:comments  completed
  ```
  Average delta: **+36.4%** vs. yesterday's +13-25%. Five for five reached
  the `good_enough_score` (80) on the first attempt.

- **Infinite re-pick loops on no-progress runs** — Selector had no
  mechanism to blacklist a function that keeps completing with zero
  progress. Observed pattern on 2026-04-15:
  ```
  RenderResourceBarProgress       codex  ×46 runs, all +0%
  CLIENT_UpdateUnitDisplayEffects codex  ×68 + claude ×18, all +0%
  IsPathTargetMonsterBoss         codex  ×24 runs, 23 at +0% then +10
  UpdateRoomLevelTracker          claude ×28 runs, pattern [+0,-7,+7,+0×25]
  CheckNetworkSessionTimeout      claude ×27 runs, pattern [-8,+8,+0×25]
  CLIENT_UpdateUnitDisplayEffects claude ×18 runs, all +0%
  ```
  Guard #2 (no-progress downgrade) requires `tool_calls_made == 0`, so
  `-1` from codex/claude never triggered it. `consecutive_fails` only
  tracks hard failures, not stagnant completions. `partial_runs >= 3`
  only deprioritizes 10× — still pickable when nothing else is available.
  `recovery_pass_done` only fires for `complexity_tier == "massive"`.

  Fix: new `stagnation_runs` counter in [fun_doc.py:4256](fun-doc/fun_doc.py#L4256),
  incremented on `(completed|partial) and delta <= 1` (covers +0%, +1%,
  and all regressions). Reset on `delta >= 5`. Selector excludes funcs
  with `stagnation_runs >= 3` unless pinned. Cleared by `scan --refresh`,
  `refresh_candidate_scores` (dashboard "Refresh Top N"), or pinning.

- **Claude false `BLOCKED:` false-positive from ToolSearch confusion** —
  The `_invoke_claude` system prompt at [fun_doc.py:3105](fun-doc/fun_doc.py#L3105)
  instructed the agent to "Use ToolSearch to load the ghidra-mcp MCP
  tools if they are not yet available". But `ToolSearch` is for *deferred*
  tools (ones listed in `<system-reminder>` but not loaded). ghidra-mcp
  tools are statically registered via `~/.claude.json` → `mcpServers.ghidra`
  and are **immediately callable** under `mcp__ghidra-mcp__<name>`. They
  never appear as deferred.

  Following the old prompt, claude would burn 5-12 turns trying
  `ToolSearch` with various queries, get empty results each time, then
  declare "BLOCKED: the required MCP tools are not available in this
  runtime". Observed 11 false-positive `BLOCKED:` results out of 213
  claude runs (≈5%) on 2026-04-15. Score deltas on those runs were
  typically 0% or negative (because a rename had landed but the follow-up
  type/prototype work gave up).

  Fix: new system-prompt append tells claude the tools are already
  registered and to call them directly by the short or fully-qualified
  name, and explicitly says *do not* use ToolSearch for ghidra-mcp tools.
  Prevents the whole class of false-BLOCKED outcomes.

### Test coverage

- **3 new selector invariant tests** for `stagnation_runs`:
  - `test_stagnation_runs_excluded_at_threshold` (checks `== 3` and `> 3`)
  - `test_stagnation_runs_bypassed_by_pin`
  - `test_stagnation_runs_does_not_affect_unflagged` (0, 1, 2, missing)
- **Total offline test count**: 27 Python + 25 Java (was 24 + 25 in v5.3.1)

### Why this release exists

The v5.3.1 release was shipped in the afternoon with confidence that it
covered all the observed issues. It didn't. The codex Pass-2 bug was
live during v5.3.1 and triggered the multi-hour loops on codex workers
that same evening. v5.3.2 is the real "stable multi-provider workloads
finish successfully" release.

**Provider parity**: before v5.3.2, only minimax could reliably reach
`good_enough_score` on `use_two_pass`-eligible functions because only
minimax reported tool counts truthfully. After v5.3.2, all three
providers (minimax, codex, claude) reach good_enough_score on the first
attempt for the same class of function. Live-measured average score
delta parity: minimax ≈ +20%, codex ≈ +36%, claude ≈ +36% in the post-fix
session.

---

## v5.3.1 - 2026-04-14 (hotfix)

Stability and observability hotfix on top of v5.3.0. Ships after a multi-hour live test session that uncovered several issues the v5.3.0 release didn't fully address. All three AI providers (minimax, codex, claude) verified under concurrent 6-worker load; zero failures across 63 runs in the final test session.

### Ghidra Plugin

#### Fixed

- **`decompileFunctionNoRetry` cap lowered to 12 s** (was 60 s) — `FunctionService` now uses `NO_RETRY_DECOMPILE_TIMEOUT_SECONDS = 12` on all scoring/analysis code paths. Math: composite handlers like `/analyze_for_documentation` chain up to 4 sequential decompiles (primary → nested `analyze_function_completeness` → `validateParameterTypeQuality` fallback), so 4 × 12 = 48 s worst case, comfortably under the 60 s client HTTP timeout and well below Ghidra's 20 s Swing-deadlock threshold per individual call. Pathological functions exceeding 12 s are treated as "too complex to score" and blacklisted via the new fun-doc one-shot flag — an acceptable trade since they would otherwise pin the HTTP thread pool.

- **Four more MCP handler call sites routed through `decompileFunctionNoRetry`** — v5.3.0 only wired one path (`batch_analyze_completeness`). Remaining retry-wrapped callers discovered and fixed:
  - `AnalysisService.analyzeFunctionComplete` at line 2058
  - `AnalysisService.validateParameterTypeQuality` fallback at line 3607 (reachable from `analyze_function_completeness` when the primary decompile fails)
  - `AnalysisService.analyzeForDocumentation` primary decompile at line 3953
  - `DocumentationHashService.getFunctionDocumentation` at line 359

  Under v5.3.0 these paths still escalated 60 → 120 → 180 s per call. A single pathological function could pin an HTTP thread for up to 6 minutes and leak `DecompInterface` contexts on abandoned retries. Live test confirmed: zero `Decompilation attempt` log lines and zero `UnableToSwingException: Timed-out waiting for Swing thread lock` errors across a 125-minute 6-worker session with 35,653 completed tasks.

### fun-doc

#### Fixed

- **Opus empty-output parser trust** — When opus runs on massive-complexity functions it sometimes burns its entire output-token budget on `tool_use` blocks and never emits a trailing text block with a `DONE:` marker. The work is committed to Ghidra, but fun-doc's parser saw the empty `output` string, hit the `else: result = "failed"` branch at [fun_doc.py:3827](fun-doc/fun_doc.py#L3827), and re-queued the function — paying the cost twice. Observed ~$15/function of wasted opus invocations before the fix. Parser now treats `empty output + tool_calls_made >= 5` as `completed` and lets Guard #2b (score regression check) catch genuine no-ops.

- **Recovery-pass one-shot flag (`recovery_pass_done`)** — Massive-complexity functions receive exactly one complexity-forced recovery pass; the flag is set on completion and the selector excludes flagged functions from future picks until an explicit refresh clears it. Stops the "re-queue forever below `good_enough_score`" loop. Cleared by `scan --refresh`, dashboard's `Refresh Top N`, or manual pinning.

- **Decompile-timeout one-shot flag (`decompile_timeout`)** — Complement to the Java 12 s cap. When a decompile-heavy Ghidra endpoint hits a read timeout, `fetch_function_data` sets `func.decompile_timeout = True` and the selector skips it. Turns three `consecutive_fails` cycles (~180 s wasted per pathological function) into one 60 s miss. Implemented via a new `threading.local` tracker inside `ghidra_get`/`ghidra_post` that flags `ReadTimeout` specifically.

- **Bridge empty-string schema-default filter** — Codex's MCP client passes schema default values (including empty strings) to every tool call. Ghidra handlers treat empty strings as "missing" and fail on required params. Bridge now filters `v is None or v == ""` from kwargs. Matches minimax's direct-HTTP behavior. Bundled as hygiene; not the primary cause of codex failures (see codex config fix below).

- **ContextVar debug logging** — Replaced `threading.local()` with `contextvars.ContextVar[dict]` in the debug module. Defensive refactor: `ContextVar` propagates correctly across `asyncio` tasks, generators, and `asyncio.to_thread` executor boundaries where `threading.local` can silently break. Offline E2E test verifies cross-context propagation.

- **Claude `ToolResultBlock` capture** — `_invoke_claude`'s message-handler loop only iterated `AssistantMessage.content` blocks. Per `claude_agent_sdk._internal.message_parser`, `ToolResultBlock` arrives in `UserMessage.content` (the Anthropic API convention is "user sends tool results back"). The existing `ToolResultBlock` handler inside `AssistantMessage` was dead code, so `_debug_log_tool_call()` was never reached on the claude path. Refactored to iterate both `AssistantMessage` and `UserMessage` content blocks; TextBlock capture stays gated on AssistantMessage (UserMessage text is the outgoing prompt). Live-verified with a real claude session: 2 tool calls captured end-to-end with correct correlation and JSONL output.

- **Dashboard worker pane reconnect** — On page refresh the local `workerPanes` map starts empty. The `worker_status` event fires on reconnect with the server-authoritative list but the old handler did `if (!pane) return` — updating existing panes only. Result: running workers reappeared with title `? #abcde` instead of `codex #abcde`. Fix: `worker_status` now calls `getOrCreatePane(w.id, w.provider, w.binary)` for unknown workers and refreshes the title on existing panes.

### Codex configuration

- **`~/.codex/config.toml` tool approval list** — Not a code change, but critical for codex to work with the Ghidra MCP at all. The user's codex config had `approval_mode = "approve"` for only 37 tools; the other 162 Ghidra MCP tools defaulted to `ask` which in headless/SDK mode = reject. This caused a silent 35% failure rate on codex runs (observed: all 7 `get_function_callers` failures in one session). Session fix added entries for the remaining tools. Future installs should either populate the full approval list or use a newer codex SDK with wildcard approval.

### Test coverage

- **6 new selector invariant tests** in `tests/performance/test_selector_invariants.py`:
  - `test_recovery_pass_done_excluded_when_not_pinned`
  - `test_recovery_pass_done_bypassed_by_pin`
  - `test_recovery_pass_done_does_not_affect_unflagged_functions`
  - `test_decompile_timeout_excluded_when_not_pinned`
  - `test_decompile_timeout_bypassed_by_pin`
  - `test_decompile_timeout_does_not_affect_unflagged`

- **24 Python + 25 Java offline tests** all green on every commit in this release.

### Live verification (final test session)

```
63 runs across 6 parallel workers (4×minimax, 1×codex, 1×claude)
  minimax: 37 runs, +20.9% avg score delta, 0 failures
  codex:   18 runs, +24.6% avg score delta, 0 failures
  claude:   8 runs, +16.1% avg score delta, 0 failures

Ghidra pool: 3/3 active, 0 queued, 35,653 completed tasks over 125 min uptime
Memory:      255/592 MB, healthy GC (heap grew and shrank, no leak)
Retries:     0 since test start (v5.3.0 baseline: hundreds per pathological function)
SLOW:        0 warnings since test start
Deadlocks:   0 since test start
```

---

## v5.3.0 - 2026-04-14

### Ghidra Plugin

#### Added

- **`/mcp/health` endpoint** — Returns HTTP server pool stats, uptime, memory, and active request count. Used by the fun-doc dashboard and by regression tests to observe server saturation.
- **HTTP thread pool (pool size = 3)** — `GhidraMCPPlugin` now uses a fixed thread pool for HTTP request handling instead of the default single-threaded executor. Size 3 is a deliberate compromise: large enough that a slow write doesn't block every read, small enough to avoid saturating Ghidra's Event Dispatch Thread (sizes ≥ 8 triggered `Swing.runNow` deadlocks via `ToolTaskManager.taskCompleted`).
- **Annotation scanner offline test suite** — `src/test/java/com/xebyte/offline/` adds 11 pure-reflection tests that run without Ghidra: schema generation shape, path uniqueness, HTTP method validity, `tests/endpoints.json` parity (scanner ⊆ catalog), param parity, and `total_endpoints` consistency. Partial implementation of #112.
- **`RegenerateEndpointsJson` utility** — Opt-in test (`mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`) that rewrites `tests/endpoints.json` from the annotation scanner, preserving hand-authored descriptions and hand-registered routes like `/mcp/health` and `/check_connection`.

#### Fixed

- **`AnalysisService.batch_analyze_completeness` partial-results bug** — When one function's decompile timed out, the batch threw and discarded every successful result in the same request. Now inserts an error marker for the failed function and continues the loop. `PER_CHUNK_TIMEOUT_SEC` raised to 90 s to give the 60 s internal decompile cap a 30 s buffer.
- **`FunctionService.decompileFunctionNoRetry`** — New single-attempt decompile helper used by the scoring path. The retry-wrapped `decompileFunction` escalated 60 → 120 → 180 s and leaked `DecompInterface` contexts when the scoring timeout fired mid-retry, eventually OOMing the JVM.
- **`tests/endpoints.json` drift** — The annotation scanner catalog parity test found and fixed 5 missing endpoints (`/analysis_status`, `/import_file`, `/reanalyze`, `/set_image_base`, `/set_variables`), 10 HTTP method mismatches, ~50 missing `@Param` entries, and a missing `/mcp/health` row. `total_endpoints`: 193 → 199.

### fun-doc

#### Added

- **Priority queue system** — Replaces the old pin-one-at-a-time model. `priority_queue.json` stores a FIFO work queue. Auto-dequeues functions when they hit `good_enough_score` (configurable per-binary, default 80). Dashboard surfaces the queue with scan progress, handoff counter, and stale-skip counter.
- **Complexity handoff** — Workers can hand a function to a more capable provider when the current model's completeness plateaus. Default cascade: minimax → claude (disabled by default, set `complexity_handoff_max`).
- **Debug mode** — Per-function JSONL tool-call logs under `fun-doc/debug/<function_key>.jsonl`. Captures every MCP call, its truncated args, and result. Ship with `fun-doc/analyze_debug.py` CLI for post-hoc pattern analysis (consecutive same-tool runs, failed retries, repeated args).
- **Atomic state writes** — `_atomic_write_state()` uses temp + fsync + `os.replace` + `.bak` rotation. Fixes the lost-update race where multiple workers saving whole-state from their in-memory copies clobbered each other's per-function updates.
- **`update_function_state(key, func)`** — Per-function atomic read-modify-write under `_state_lock`. Replaces every per-function `save_state(state)` call in the processing path.
- **Pagination-aware function list fetch** — `_fetch_function_list` now pages through `list_functions_enhanced` in 10k chunks. Previously silently truncated binaries above 10,000 functions (`glide3x.dll`, `libcrypto-1_1.dll`).
- **Regression test suite** under `tests/performance/` — 30 tests across selector invariants, state atomicity, HTTP concurrency contract, listing consistency, batch scoring consistency, and `/mcp/health` shape. Most skip gracefully without a live Ghidra server; `test_selector_invariants.py` and `test_state_atomicity.py` run fully offline.

#### Fixed

- **fun-doc run/debug log provenance** — `runs.jsonl` now records `run_id`, requested vs effective provider, provider chain, `tool_calls_known`, prompt size, token metadata, and the concrete debug log path. Debug traces are now one file per run attempt instead of co-mingling multiple providers in a single per-function file, and tool names are normalized across Gemini/Claude/Codex/MiniMax while preserving the raw provider-specific name.
- **fun-doc dashboard + handoff analysis follow-up** — provider cards now compute average tool counts from known samples only, explicitly count unknown tool-call runs, surface handoff/provider-chain summaries, ship a dedicated `fun-doc/analyze_runs.py` CLI for requested→effective provider analysis, and move the live complexity handoff target from Codex to Gemini.
- **Cold-start lane infinite re-processing loop** — `_sync_func_state` didn't stamp `last_processed`, so the selector kept re-picking already-scored functions. Worst seen: SafeDelete stuck at 83% across hundreds of iterations.
- **"Stale at X%" misleading message** — The cached score was captured after `_sync_func_state` had already overwritten it, so the log always showed the live value. Captures `original_cached_score` before sync now.
- **`RETRY_SIZE` vs client timeout math** — Retry batch was 10 × 90 s = 900 s > 600 s client budget. Reduced to `RETRY_SIZE = 3` (270 s, fits with 330 s margin).
- **`tests/conftest.py` IPv6 fallback** — Default base URL changed from `http://localhost:8089` to `http://127.0.0.1:8089`. Windows dual-stack `localhost` resolution tries IPv6 first, times out after exactly 2 s, then falls back to IPv4 — adding ~2000 ms to every test request.

### Docs

- `CLAUDE.md` Testing section now documents offline vs. integration test commands and the `RegenerateEndpointsJson` escape hatch.
- Tool count updated: 193 → 199 (README, CLAUDE.md, endpoints.json).

---

## v5.2.0 - 2026-04-11

### Ghidra Plugin

#### Added

- **Request serialization in MCP bridge** — Added `threading.Lock` around all Ghidra HTTP calls in `bridge_mcp_ghidra.py` to prevent JSON-RPC stdout corruption when multiple MCP tool calls arrive concurrently (#91).
- **Dry-run mode for mutating endpoints** — Pass `dry_run=true` query parameter to any POST endpoint to preview changes without committing to the Ghidra database. Implemented via nested transaction rollback in `AnnotationScanner` — no service code changes needed. All dynamic MCP tools for POST endpoints now include an optional `dry_run` parameter (#110).
- **Composable completeness scoring** — Added `include_completeness` flag to `analyze_function_complete` endpoint. When enabled, includes full completeness scoring in the same response, eliminating the need for a separate `analyze_function_completeness` call (#109).

---

## v5.1.0 - 2026-04-10

### fun-doc: Multi-Provider Dashboard & Worker System

The fun-doc automation engine was substantially rebuilt. It now ships a real-time web dashboard, supports parallel workers across multiple AI providers, and includes quality guards that catch common AI documentation mistakes.

#### Added

- **Real-time WebSocket dashboard** — `python fun_doc.py` (no args) launches a web UI with live activity feed, progress charts, and control panel. EventBus architecture pushes updates via WebSocket.
- **Multi-provider worker system** — Run up to 4 parallel workers across Claude, Codex, and MiniMax providers simultaneously. Per-worker output panes in a 2×2 grid.
- **Continuous mode** — Workers fetch and document functions one-at-a-time in a continuous loop.
- **MiniMax AI provider** — Added MiniMax-M2.7 as a low-cost first-pass documentation option with dedicated hardening: Hungarian notation audit (Guard #4), complexity gating, `<think>` tag stripping, partial tracking, dynamic max_tokens, reasoning preservation.
- **Codex provider** — Added OpenAI Codex (gpt-5.3-codex) to the provider dropdown.
- **Quality guards** — Evidence-based documentation workflow with Guards #1–5, score-delta validation, and variable reconciliation in step-verify prompt.
- **Classification-aware prompting** — `_inject_classification_directives()` automatically limits wrapper/stub functions (≤10 code lines) to minimal plate comments (Summary, Parameters, Returns, Source only), preventing over-documentation with struct layouts and disassembly comments.
- **Phantom variable hints** — Functions with phantom variables (`in_EAX`, `in_EDX`, `extraout_*`) get a pre-prompt directive to attempt `set_function_prototype` before documenting.
- **Guard #5: magic number EOL reconciliation** — Catches models that document magic numbers in the plate comment but skip EOL comments at instruction addresses. Downgrades to partial for requeue when ≥2 undocumented magic numbers remain in non-wrapper functions.
- **Source section enforcement** — Guard #3 now validates plate comment structural completeness (missing Source line, etc.) using the scorer's `plate_issues` field. Step-comments and fix-plate-comment prompts explicitly mark Summary, Source, Parameters, and Returns as required sections.
- **Verify checklist expansion** — Step-verify prompt adds name-vs-behavior contradiction detection (rename if name contradicts actual code behavior) and magic number EOL coverage verification.
- **Folder & binary selector** — Dashboard discovers all project binaries from Ghidra, supports per-binary scan with persistent state filtering.
- **Cross-binary progress view** — Phase 3 folder switcher shows documentation progress across all binaries in a project.
- **ROI queue** — Dashboard control panel with ROI-prioritized function queue and deduction breakdown.
- **Claude agent-sdk migration** — Migrated from deprecated `claude-code-sdk` to `claude-agent-sdk`.

#### Fixed

- **Score-delta guard** — No longer falsely triggered for Claude when `tool_calls=-1`; relaxed to accept +0% when tools made changes.
- **State file race condition** — Fixed concurrent write corruption of `state.json` during parallel worker operation.
- **Page size limit** — All Functions table capped at 200 entries to prevent 24 MB pages.
- **Per-binary scan stats** — Rescan now scores unscored functions and no longer reports other binaries as removed.
- **Batch scoring** — Falls back to individual scoring when batch endpoint fails; increased timeout and added progress reporting.

### Ghidra Plugin

#### Added

- **Streamable HTTP transport** — `--transport streamable-http` is now documented and recommended for web/HTTP clients. SSE transport is deprecated. Added `ghidra-mcp-http` config example to `mcp-config.json`.
- **Engineering backlog** — Added `docs/project-management/BACKLOG.md` with prioritized roadmap from competitive fork analysis (GitHub issues #109–#114).
- **Gradle build** — Added Gradle-based Ghidra extension build as an alternative to Maven (`build.gradle`, `settings.gradle`).

#### Fixed

- **read_memory OOM** (#107) — Capped `read_memory` allocation at 16 MB to prevent out-of-memory on malicious/large length values.
- **SSRF in connect_instance** (#106) — Wired `validate_server_url()` into `connect_instance` and `_auto_connect` TCP paths.
- **urlparse import** (#113) — `validate_server_url()` used `urlparse` but it was only imported inside `tcp_request()`. The bare `except` silently swallowed the `NameError`, causing all connections to fail. Moved import to module scope.
- **LoadResults.save() signature** — Corrected to match Ghidra 12.0.3 API (takes `TaskMonitor` only). Fixes Docker build and compilation errors (#103, #104).
- **Program param standardization** — All `@Param("program")` annotations now use `QUERY` source consistently. Fixes batch operations that failed when `program` was sent in POST body.
- **import_file "Database is closed"** — Fixed race condition in program import flow.
- **Batch rename variables** — Fixed `programName` not passed through in fallback paths.
- **batch_analyze_completeness** — Now passes program param to per-function calls correctly.

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
- **Relaxed Ghidra version compatibility check** (#64): The legacy setup flow now warns instead of error when deploying to a Ghidra installation with a different patch version (e.g., building with 12.0.3 and deploying to 12.0.4). Major.minor mismatches still block deployment.
- **Fixed Linux phantom process detection** (#63): Tightened the legacy Linux setup process detection regex to match only the Java class name pattern (`ghidra.GhidraRun`/`ghidra.GhidraLauncher`), removing overly broad alternatives that caused false positives.
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
- **Expanded version bump workflow** -- Now covers 11 files (up from 7): added README badge, AGENTS.md, docs/releases/README.md. Extension.properties is now Maven-dynamic.
- **Version consistency audit** -- Fixed stale 3.0.0 references across setup/config files, tests/endpoints.json, README.md, AGENTS.md, and docs/releases/README.md

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
- **Version bump workflow**: Single-command version bump across all 7 project files
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

### Patch Release - CI Fixes, Documentation, Setup Workflow Improvements

#### Ã°Å¸â€Â§ CI/Build Fixes
- **Fixed CI workflow**: Ghidra JARs now properly installed to Maven repository instead of just copied to lib/ (PR #23)
- **Proper Maven dependency management**: Works correctly with pom.xml changes from v2.0.0
- **Version as single source of truth**: `ghidra.version` now uses Maven filtering from pom.xml (PR #20)
- **Endpoint count updated**: Correctly reports 144 endpoints

#### Ã°Å¸â€œÂ Documentation
- **New troubleshooting section**: Comprehensive guide for common setup issues (PR #22)
- **Verification steps**: Added curl commands to verify server is working
- **Better error guidance**: Covers 500 errors, 404s, missing menus, and installation issues

#### Ã°Å¸â€“Â¥Ã¯Â¸Â Setup Workflow
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
- Ã¢Å“â€¦ **hybrid function processor workflow** - Automated analysis workflows

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
  - data extraction and function-processing helpers - automation utilities used during that release cycle

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

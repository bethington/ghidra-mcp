# VulnAnalysisService (Phase 1) — Design

**Date:** 2026-06-17
**Status:** Approved (pending implementation)
**Branch:** `feature/vuln-analysis-service`
**Scope:** Phase 1 — foundation, source/sink catalog, attack-surface enumeration,
and four intra-function PCode vuln-pattern detectors. Inter-procedural taint
(`find_taint_paths`) is deferred to a separate Phase-2 spec.

## Problem

ghidra-mcp's existing security tooling (`MalwareSecurityService`) is
malware-IR oriented — it answers *"what does this hostile binary do?"*
(`detect_malware_behaviors`, `extract_iocs_with_context`,
`find_anti_analysis_techniques`, `detect_crypto_constants`). Security /
vulnerability research asks the opposite question: *"where can I break this
benign binary?"* No tool today surfaces vulnerability candidates from the
decompiler's PCode.

`analyze_dataflow` (`AnalysisService.java:4544-4880`) already walks PCode
backward/forward inside one function, but stops at `CALL`/`CALLIND` and has
no notion of dangerous sinks. `detect_array_bounds` is xref-based, not
PCode-based. There is no catalog of sources/sinks and no Finding schema. The
`FUNDABLE_ROADMAP.md` milestones are infrastructure (native MCP, headless
parity, BSim corpus); none target vuln discovery.

## Architecture

A new `com.xebyte.core.vuln` package holding a service, a catalog, shared
PCode query helpers, a result record, and one small class per detector.

```
com.xebyte.core.vuln/
├── VulnAnalysisService.java     @McpTool endpoints; wires catalog + detectors
├── SinkCatalog.java             load catalog; resolve Function → CatalogEntry[]
├── Finding.java                 record: result schema (one row per hit)
├── PcodeQuery.java              shared PCode helpers (extracted from the
│                                 AnalysisService dataflow walker)
├── VulnDetector.java            interface
└── detectors/
    ├── FormatStringDetector.java
    ├── UnboundedCopyDetector.java
    ├── IntegerOverflowAllocDetector.java
    └── CommandInjectionDetector.java

resources/vuln_catalog.json      baked-in default catalog
```

**Service wiring.** `VulnAnalysisService(ProgramProvider, ThreadingStrategy,
FunctionService)` — same injection pattern `AnalysisService` already uses for
the decompile helper (`FunctionService.decompileFunctionNoRetry`). The
service is added to the `AnnotationScanner` constructor list; `@McpTool`
discovery is automatic (no bridge changes).

**`PcodeQuery` extraction.** Rather than duplicate `AnalysisService`'s private
`traceBackward` / `describeVarnode` / `mnemonic` helpers (~200 lines at
`AnalysisService.java:4674-4880`), lift the reusable pieces into a small
package-visible utility both services share. `analyze_dataflow` keeps its
public behavior unchanged and is switched to call the extracted helpers;
existing offline tests cover the no-regression guarantee.

### Approaches considered

| Approach | Verdict |
| --- | --- |
| **A. Detector-as-class with a registry** | **Chosen.** Mirrors `NamingConventions` centralization, keeps each detector ~150 lines and independently testable, avoids growing another 4900-line `AnalysisService`. |
| B. Monolithic `detectVulnPatterns()` switch | Rejected — exactly how `AnalysisService` got to 4900 lines; awkward per-detector tests. |
| C. Script-based detectors under `ghidra_scripts/vuln/` | Rejected — loses offline JUnit, can't reuse private PCode helpers, brittle script-compile path. |

## Endpoints (3 new `@McpTool`s)

- **`detect_vuln_patterns`** `(function?, classes?, write_bookmarks?, max_depth?)`
  — Scan one function (or, if `function` omitted, every function reachable
  from an attack-surface entry up to `max_depth`, default 3) with the selected
  detector classes. Returns `Finding[]` and optionally writes Ghidra
  bookmarks (`SEVR/<vuln_class>`).
- **`enumerate_attack_surface`** `(max_depth?)` — Return functions ≤N
  call-graph hops from any catalog `source`, grouped by source class
  (`network` / `file` / `env` / `cli` / `ipc` / `ioctl`). Reuses
  `ExternalManager` (`ListingService.java:859-878`) + a callers-of walk.
- **`list_vuln_detectors`** — Introspection: detector ids, descriptions,
  catalog summary, override path in effect.

## Catalog (`resources/vuln_catalog.json`)

One JSON file, two top-level arrays. Each entry declares how to match a
function and which argument position carries the relevant data.

```json
{
  "sinks": [
    { "id": "memcpy",  "class": "copy",   "size_arg": 2, "dst_arg": 0,
      "match": { "import": ["memcpy","memmove","wmemcpy"],
                 "regex":  ["(?i).*memcpy.*","(?i).*memmove.*"],
                 "tag":    ["SINK_COPY_SIZED"] } },
    { "id": "strcpy",  "class": "copy",   "size_arg": null, "dst_arg": 0,
      "match": { "import": ["strcpy","strcat","wcscpy","lstrcpyA","lstrcpyW"],
                 "regex":  ["(?i).*strcpy.*","(?i).*strcat.*"],
                 "tag":    ["SINK_COPY_UNSIZED"] } },
    { "id": "printf",  "class": "format", "fmt_arg": 0,
      "match": { "import": ["printf","fprintf","sprintf","snprintf","vsnprintf","syslog"],
                 "regex":  ["(?i).*printf.*"], "tag": ["SINK_FORMAT"] } },
    { "id": "system",  "class": "exec",   "cmd_arg": 0,
      "match": { "import": ["system","popen","execl","execvp","CreateProcessA","CreateProcessW","ShellExecuteA"],
                 "regex":  ["(?i)^system$"], "tag": ["SINK_EXEC"] } },
    { "id": "malloc",  "class": "alloc",  "size_arg": 0,
      "match": { "import": ["malloc","calloc","realloc","HeapAlloc","operator new[]"],
                 "regex":  ["(?i).*alloc.*"], "tag": ["SINK_ALLOC"] } }
  ],
  "sources": [
    { "id": "recv",   "class": "network", "out_arg": 1,
      "match": { "import": ["recv","recvfrom","read","WSARecv"], "tag": ["SOURCE_NETWORK"] } },
    { "id": "fread",  "class": "file",    "out_arg": 0,
      "match": { "import": ["fread","ReadFile","fgets"], "tag": ["SOURCE_FILE"] } },
    { "id": "getenv", "class": "env",     "return": true,
      "match": { "import": ["getenv","GetEnvironmentVariableA"], "tag": ["SOURCE_ENV"] } },
    { "id": "argv",   "class": "cli",     "param": true,
      "match": { "regex": ["^main$","^wmain$","^WinMain$"], "tag": ["SOURCE_CLI"] } }
  ]
}
```

**Resolution.** `SinkCatalog.resolve(Function f)` returns matching entries by
checking, in order: (1) external-import label via `ExternalManager`,
(2) function name against each `regex`, (3) `f.getTags()` against each `tag`.
A function may match multiple entries.

**Override.** User catalog path: `${GHIDRA_MCP_VULN_CATALOG}` env var if set,
else `~/.ghidra-mcp/vuln_catalog.json`. If present, it **merges** over the
baked-in default (user entries win on `id` collision). Same env-var pattern
as `RE_KB_ARCHIVE_URL`.

**Why name-regex + tag (not behavioral signature).** Embedded/static targets
(e.g. the RTOS `Application1.elf` with overlay spaces) compile libc in and
rename it; import-name matching alone is useless there. Tags let fun-doc (or
the analyst) mark a function once (`SINK_COPY_SIZED`) and have every detector
pick it up — composing with the existing `add_function_tag` /
`search_functions_by_tag` tools. PCode behavioral fingerprints are deferred.

## Shared PCode primitives (`PcodeQuery.java`)

Extracted/adapted from `AnalysisService.java:4674-4880`:

| Helper | Returns | Used by |
| --- | --- | --- |
| `argVarnode(PcodeOp call, int idx)` | varnode feeding arg `idx` of a `CALL`/`CALLIND` | all detectors |
| `reachesConstantOnly(Varnode v, int maxSteps)` | true iff backward walk hits only constants / `COPY` / `CAST` | format-string, exec |
| `definingOps(Varnode v, int maxSteps)` | set of `PcodeOp` producers (transitive, intra-function) | int-overflow, copy |
| `hasDominatingCompare(Varnode v, HighFunction hf)` | true iff an `INT_LESS`/`INT_SLESS`/`INT_EQUAL` on `v` (or its def chain) dominates the use site | copy, int-overflow |
| `destBufferSize(Varnode dst, HighFunction hf)` | known byte size of `dst` if a stack local, typed global, or `PTRSUB` into a struct field; else `-1` | copy |
| `describe(Varnode v)` | human label (register / const / HighVariable name) | all (evidence) |

Pure functions over `HighFunction` / `Varnode`; offline-testable with mocked
PCode graphs the same way `ServiceUtilsAddressTest` mocks `AddressFactory`.

## Detector logic

**`FormatStringDetector`.** For each `CALL` whose callee resolves to a
`class:"format"` sink: take `argVarnode(call, fmt_arg)`; if
`!reachesConstantOnly(...)`, emit a Finding. Confidence `high` when the def
chain includes a function parameter or a `class:"source"` call return;
`medium` otherwise.

**`CommandInjectionDetector`.** Same shape, `class:"exec"` sink, `cmd_arg`
position. Confidence `high` when the def chain contains a string-concat
(`CALL` to `strcat`/`sprintf` or pointer arithmetic into a buffer that also
receives a constant prefix).

**`UnboundedCopyDetector`.** For each `class:"copy"` sink call:
- If `size_arg == null` (strcpy family) → hit when
  `destBufferSize(dst) > 0` (dest is a bounded local/field) AND the source
  varnode is not constant.
- If `size_arg != null` (memcpy family) → hit when
  `!hasDominatingCompare(sizeVarnode)` AND `destBufferSize(dst) > 0` AND the
  size varnode is not a constant ≤ dest size.

**`IntegerOverflowAllocDetector`.** For each `class:"alloc"` sink call: walk
`definingOps(sizeVarnode)`; flag when it contains `INT_MULT`/`INT_ADD` whose
inputs aren't both constant AND there is no dominating overflow check
(`INT_CARRY` / `INT_LESS` against the product). Also flag the sign-confusion
sub-pattern: an `INT_SLESS` (signed) compare on a varnode that later feeds a
size arg via `INT_ZEXT`.

Each detector is ≤ ~150 lines and depends only on `PcodeQuery` + `SinkCatalog`.

## `Finding` schema & output

```java
record Finding(
    String detectorId,      // "format_string"
    String vulnClass,       // "format" | "copy" | "alloc" | "exec"
    String address,         // call-site address (full form, overlay-aware via addressToJson)
    String function,        // containing function name
    String sink,            // catalog entry id that matched
    String confidence,      // "high" | "medium" | "low"
    List<String> evidence,  // human-readable PCode trace lines
    String why              // one-sentence explanation
) {}
```

`detect_vuln_patterns` returns
`{ "findings": [...], "scanned_functions": N, "detectors_run": [...] }`.
When `write_bookmarks=true`, each finding writes a Ghidra bookmark:
type `BookmarkType.ANALYSIS`, category `SEVR/<vulnClass>`,
comment `<detectorId>: <why>` — using the transaction pattern at
`ProgramScriptService.java:1792-1807`.

## Error handling

- Function fails to decompile → skipped, counted in `"decompile_failures": N`;
  scan continues.
- Catalog file malformed → fall back to baked-in default; warning in
  `"catalog_status"` field.
- No sinks resolved in the program → empty findings with
  `"note": "no catalog sinks resolved — consider tagging functions with SINK_* / SOURCE_*"`.
- All address output flows through `ServiceUtils.addressToJson` so overlay
  addresses round-trip correctly.

## Testing

| Tier | What | Where |
| --- | --- | --- |
| Offline Java | `SinkCatalog` load/merge/resolve (mocked `Function` / `ExternalManager`); `PcodeQuery` helpers on hand-built `PcodeOp`/`Varnode` mocks; one test per detector with a synthetic `HighFunction` that does/doesn't trigger | `src/test/java/com/xebyte/offline/vuln/*Test.java` |
| Catalog | `vuln_catalog.json` schema validity; every entry has ≥1 `match` key | `VulnCatalogSchemaTest` |
| Integration | `detect_vuln_patterns` against a fixture binary with planted bugs — extend `fun-doc/benchmark/src/*.c` with `vuln_format.c`, `vuln_copy.c`, `vuln_alloc.c`, `vuln_exec.c`; ground-truth in `truth/*.yaml` | `tests/integration/test_vuln_endpoints.py` (auto-skips without server) |
| Parity | `tests/endpoints.json` + `EndpointsJsonParityTest` for the 3 new endpoints | regenerate per CLAUDE.md |

## Scope guard / deferred

- **Phase 1 is intra-function.** Detectors do not cross `CALL` boundaries
  except to identify the callee as a sink/source. `find_taint_paths`
  (inter-procedural taint) is a separate Phase-2 spec that reuses
  `SinkCatalog` and `PcodeQuery`.
- **Not in Phase 1:** UAF/double-free (needs alias tracking), TOCTOU,
  lore/CVE lookup, findings-ledger persistence, PCode behavioral signatures
  for sink matching. All noted as follow-ups.
- No behavior change to `AnalysisService` endpoints; only helper extraction
  into `PcodeQuery` (with `analyze_dataflow` calling the extracted versions —
  covered by its existing tests).

## Decisions (from brainstorming)

1. **Scope:** Phase 1 = foundation + 4 intra-function detectors +
   `enumerate_attack_surface`. Inter-procedural taint is Phase 2.
2. **Sink matching:** import name ∪ name-regex ∪ Ghidra function tag
   (composes with `add_function_tag` and fun-doc's tagging).
3. **Detectors:** format-string, unbounded-copy, int-overflow→alloc/index,
   command/path injection.
4. **Architecture:** Approach A — detector-as-class with a registry, in a new
   `com.xebyte.core.vuln` package; catalog as JSON resource with
   env-var/user-file override.

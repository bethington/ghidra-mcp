# MCP Response Contract

**Status:** normative. This is what the Java-native `/mcp` endpoint implements,
and what `tests/conformance/` verifies.

Every tool returns JSON. No exceptions.

That rule was always the project's stated convention ("All endpoints return
JSON" — `CLAUDE.md`), but it was never enforced, and by 6.0.0 **33 of 86
surveyed tools returned plain text**. The inconsistency was found by the MCP
conformance sweep on 2026-07-25. `decompile_function` was inconsistent *with
itself*: JSON in bulk mode (`{"calc_crc16": "..."}`), plain text in single mode.

The contract is being fixed **before** the Java port rather than after, so the
port implements the intended design instead of faithfully reproducing an
accident.

---

## 1. Shapes

### 1a. List-shaped responses

A tool returning a collection returns an object with a **named plural key**,
plus metadata:

```json
{
  "segments": [
    {"name": ".text", "start": "10001000", "end": "1000d9ff", "size": 51712}
  ],
  "count": 7
}
```

Paginated tools additionally carry the paging frame:

```json
{
  "functions": [ ... ],
  "count": 100,
  "offset": 0,
  "limit": 100,
  "total": 5739
}
```

- `count` — items in **this** response.
- `total` — items available overall. Callers need this to know a result was
  truncated; `len(items)` cannot tell you that.
- A bare JSON array is **not** valid. It has nowhere to put `total`, so a
  truncated result is indistinguishable from a complete one.

### 1b. Single-entity responses

A tool describing one thing returns that thing as a bare object:

```json
{"type_name": "DWORD", "size": 4, "alignment": 4, "path": "/WinDef.h/DWORD"}
```

### 1c. Errors

```json
{"error": "No function at address: 0x10001000"}
```

In-band errors return HTTP 200 with an `error` key. This is deliberate: many
tools report "not found" as a normal, expected outcome rather than a transport
failure. Clients must check for the `error` key, not just the status code.

**Resolved (2026-07-26) — empty string arguments are now reachable.** An
argument passed as `""` used to be dropped before it bound, so Java received
`null` and `set_comment` could not clear a comment: `CommentService` only
rejected `comment == null`, but `comment: ""` arrived as exactly that and the
tool answered `{"error": "Comment text is required"}`. Parameters that need
`""` to be meaningful now declare `@Param(allowEmpty = true)`, and
`set_comment`'s `comment` parameter does; `set_comment(comment="")` returns
`{"status": "success", ...}` and actually clears the field. Deployed and
verified end to end (write → read-back), 26/26 write round-trips pass. Pinned
by `tests/conformance/corpus/write_roundtrips.yaml` (`clear_plate`,
`clear_eol`, `readback_cleared`).

### 1d. Text payloads

Content that is genuinely text (decompiled C, disassembly listings) is a
**string field inside** an object, never the whole response body:

```json
{"address": "10001000", "name": "calc_crc16", "decompiled": "ushort calc_crc16(...)\n{...}"}
```

---

## 2. Naming

- Keys are `snake_case`.
- The list key is the plural of the entity: `segments`, `functions`, `strings`,
  `data_types`, `entry_points`.
- Addresses are lowercase hex **without** an `0x` prefix in output
  (`"10001000"`), matching existing behavior. Input accepts either form.
- Absent values are omitted rather than emitted as `null`.

  **Resolved (2026-07-26):** `get_comment` now emits all five comment kinds
  (`plate`, `pre`, `eol`, `post`, `repeatable`) explicitly on every response --
  `null` for a kind that was never set, `""` for one explicitly cleared. This
  needed a kind-specific exception: the shared Gson instance (`JsonHelper`)
  deliberately drops null map values so every *other* endpoint gets
  absent-means-null, and changing that globally would have flipped the
  convention for dozens of tools. `get_comment` instead serializes with a
  locally-scoped Gson (`serializeNulls()`) and returns it through
  `Response.text` -- the contract's sanctioned use of that escape hatch for
  pre-serialized JSON, not a §3 prose-report violation. Deployed and verified
  live against `Benchmark.dll`. Pinned by
  `read_assertions_2.yaml::get_comment::curated_kinds_and_convenience_fields`.

- **Filter parameters must be optional.** `list_data_types` requires
  `category`, so there is no way to list every data type — the sibling
  `search_data_types` defaults its filter to empty and should be the model.

---

## 3. Enforcement

- `Response.text(...)` is the escape hatch that allowed the drift. After the
  migration it is reserved for pre-serialized JSON only; returning
  human-formatted text through it is a contract violation.
- `tests/conformance/` snapshots every tool's normalized response. Any shape
  change shows up as snapshot drift and must be accepted deliberately.
- `ParamTypeConsistencyTest` covers the request side: a parameter name must
  publish one type across all tools.

---

## 4. Migration status

Staged by category, each stage gated by re-running the conformance suite.

| Stage | Scope | Tools | Status |
| --- | --- | --- | --- |
| 1 | `list_*` | 13 | done |
| 2 | `get_*` | 13 | done |
| 3 | `decompile_function`, `disassemble_function` | 2 | done |
| 4 | `list_imports` into the envelope | 1 | done |
| 5 | validation/status returns -> err/success | 61 sites | done |
| 6 | StringBuilder prose reports (per-tool JSON design) | 55 sites | done |

Callers are migrated with their stage — fun-doc, `tests/`, `tools/setup`, and
the docs each parse these responses today, so a stage is not complete until its
callers are updated and the suite is green.

### Stage 5 scope (measured, not estimated)

The first four stages covered the tools that appeared in the read-tier
conformance snapshot. A source-level sweep for `Response.text` inside
`@McpTool` bodies found **35 registered tools still returning text**, dominated
by the datatype write surface:

```text
create_enum (11)  create_struct (8)   resolve_duplicate_type (7)
apply_data_type (6)  validate_data_type (5)  add_struct_field (4)
get_enum_values (4)  get_struct_layout (4)   ... and 27 more
```

Stage 5 converted 61 of those sites: validation errors became `Response.err`
and write acknowledgements became `Response.success(msg)` ->
`{"status": "success", "message": ...}`.

### Stage 6 (done 2026-07-26)

55 sites across `DataTypeService`, `FunctionService`, `ListingService`,
`ProgramScriptService`, and `AnalysisService` that emitted a StringBuilder
prose report (`result.toString()`, hand-concatenated JSON, generated-script
bodies) now return real, designed JSON shapes. Highlights, not an exhaustive
list — see git history on this date for the full per-tool diff:

- **`resolve_duplicate_type`** was 5 different ad-hoc `Response.text` prose
  branches; now always `Response.ok` with a `situation` enum
  (`no_stub_to_resolve | multiple_canonical | stub_only_no_canonical |
  stub_present_flag_required | resolved | deletion_failed`) plus
  `matches`/`canonical_types`/`demangler_stubs` arrays. Factored into a
  `resolveDuplicateTypeData()` helper so `delete_data_type`'s
  demangler-retry branch can embed it as a real nested object.
- **A real bug found and fixed along the way**: `delete_data_type`'s
  demangler-retry branch used to `Response.text(result.toString() + "\n" +
  resolved.toJson())` — string-concatenating a plain-text failure message
  with a *second, separately serialized* JSON blob on the next line. The
  response was neither valid JSON nor coherent text. Now a proper nested
  object: `{"status":"error","message":...,"resolve_duplicate_attempt":{...}}`.
- **Two real one-line bugs found by inspection**: `apply_data_type` and
  `validate_data_type` each had one branch that returned
  `Response.text(ServiceUtils.getLastParseError())` instead of
  `Response.err(...)` — inconsistent with every other branch in the same
  method (confirmed via repo-wide grep: every other of the ~60
  `getLastParseError()` call sites already used `Response.err`).
- **A real bug in `create_union`**: its exception handler used to append
  `"Error creating union: " + e.getMessage()` into the same StringBuilder as
  the success report, meaning an exception during union creation returned
  HTTP 200 with prose that merely *said* "Error" rather than a real
  `{"error": ...}`. Fixed alongside the shape design.
- **Dead code deleted, not migrated**: `DataTypeService.createUnionSimple` /
  `createUnionDirect` (no `@McpTool` annotation, zero callers anywhere,
  doc comment literally said "simplified approach for testing") and
  `ProgramScriptService.generateScriptContent`/`generateScriptName` + the 6
  `generateXxxScript` helpers (confirmed via full call-graph trace: no
  `@McpTool` annotation, no route registration, the only caller was an
  equally-dead private wrapper in `GhidraMCPPlugin.java` with zero callers of
  its own). Converting dead code's output shape has no value; deleting it
  does. `GhidraMCPPlugin.convertNumber` / `HeadlessEndpointHandler
  .convertNumber` (unrelated dead wrappers around `ServiceUtils
  .convertNumber`, found while reshaping `convert_number`) were removed the
  same way.
- **`ServiceUtils.convertNumber`** (deprecated, returned a formatted text
  block) replaced with `convertNumberData()` returning a `Map`; the 6
  computed representations (`decimal_unsigned`, `decimal_signed`,
  `hexadecimal`, `binary`, `octal`, `hex_padded`) are now real fields instead
  of lines in a string.
- **`list_data_items_by_xrefs`**: both its `format=text` branch (opaque
  newline-joined string) *and* its `format=json` branch (a bare array with no
  `count`/`offset`/`limit`/`total` — itself a §1a violation nobody had
  noticed) collapsed into one `ServiceUtils.paged(...)` envelope. `format` is
  now a no-op kept only for backward-compatible calls that still pass it.
- **`run_script_inline`/`run_ghidra_script`**: the shared `runGhidraScript`
  helper now returns `{"success": bool, "console_output": "<full
  transcript>"}` instead of the raw transcript text. This required a real
  code change beyond the shape, not just a caller update:
  `runGhidraScriptWithCapture` and `runScriptInline`'s own cleanup `finally`
  block both used to derive success by string-searching the serialized
  response for the literal marker `"SCRIPT COMPLETED SUCCESSFULLY"` — both
  now read the structured `success` field directly via `Response.Ok`
  pattern-matching instead.
- Five sites already emitted **valid, pre-serialized JSON** through the
  `Response.text` escape hatch (`DocumentationHashService.getFunctionSignature`,
  4 of `HeadlessManagementService`'s project-lifecycle tools) — refactored to
  `Response.ok(map)`/`JsonHelper.mapOf` for consistency and to shrink the
  grep-for-`Response.text` false-positive surface, not because the output was
  wrong. `HeadlessManagementService.serverStatus` and `GhidraServerManager
  .getStatus()` were left as-is — fixing that one requires touching
  `GhidraServerManager`'s broader hand-built-JSON convention, out of scope
  for this stage. `Response.text` is now down to 4 sites total: `get_comment`
  (sanctioned per §2), the two generic dry-run-wrapper sites in
  `AnnotationScanner`, and `serverStatus`.

**Verification**: 392/392 offline Java tests, full conformance suite
(`--tier all`) green against a freshly reset benchmark fixture, plus direct
live manual testing of every reshaped tool's success *and* error paths (the
automated corpus's auto-generated smoke cases mostly exercise validation-error
branches on a fixture that already has the relevant types from prior runs, so
they don't reliably reach the success branches that changed the most).

A caller-side audit (dedicated subagent research pass, not hand-grep — see
the "hand-grepping missed 14 sites" lesson below) found one real regression:
`fun-doc/ledger_apply.py`'s `_parse_layout` was regex-parsing
`get_struct_layout`'s old pipe-delimited ASCII table; the new JSON `fields`
array made it silently return `{}` for every struct (no crash, no error —
`reconcile()` would have classified every proven field offset as "absent").
Fixed to parse the JSON directly; its `_selftest()` fixture updated to match.
Every other caller across `fun-doc/*.py`, `tests/integration/*.py`,
`tests/performance/*.py`, and `tools/setup/ghidra.py` was already
shape-tolerant (`isinstance(x, dict)` guards, permissive substring
assertions, or `_ensure_mcp_ok`'s error-key-only check).

### Callers migrated so far

fun-doc (18 modules, via the `decompiled_text` / `disasm_text` /
`_envelope_items` helpers in `fun_doc.py`, plus `ledger_apply.py`'s
`_parse_layout` fixed in Stage 6), `tools/setup` (deploy smoke tests + the
YAML regression runner's "lines" assertion), and the offline test mocks.
`tests/integration` was migrated against real post-deploy failures rather than
by guesswork — one assertion needed changing across the readonly and safe_write
tiers, both of which are now green.

`tests/performance/test_response_contract_callers.py` guards the caller side: it
scans fun-doc for every reshaped endpoint's call sites and asserts each unwraps
the record. It exists because hand-grepping missed 14 sites, one of which failed
184 live worker runs before anyone noticed.

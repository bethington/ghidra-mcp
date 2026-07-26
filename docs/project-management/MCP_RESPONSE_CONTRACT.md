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
| 6 | StringBuilder prose reports (per-tool JSON design) | 55 sites | **open** |

Callers are migrated with their stage — fun-doc, `tests/`, `tools/setup`, and
the docs each parse these responses today, so a stage is not complete until its
callers are updated and the suite is green.

### Stage 5 scope (measured, not estimated)

The first four stages covered the tools that appeared in the read-tier
conformance snapshot. A source-level sweep for `Response.text` inside
`@McpTool` bodies found **35 registered tools still returning text**, dominated
by the datatype write surface:

```
create_enum (11)  create_struct (8)   resolve_duplicate_type (7)
apply_data_type (6)  validate_data_type (5)  add_struct_field (4)
get_enum_values (4)  get_struct_layout (4)   ... and 27 more
```

Stage 5 converted 61 of those sites: validation errors became `Response.err`
and write acknowledgements became `Response.success(msg)` ->
`{"status": "success", "message": ...}`.

**Stage 6 is what remains**: 55 sites that emit a StringBuilder prose report
(`result.toString()`, `report.toString()`, generated-script bodies). Each needs
a JSON shape designed around what its report actually contains — real design
work, not a mechanical swap, which is why they were left rather than converted
blind. `Response.text` can be deleted when they land; until then the contract is
a convention rather than a constraint.

### Callers migrated so far

fun-doc (18 modules, via the `decompiled_text` / `disasm_text` /
`_envelope_items` helpers in `fun_doc.py`), `tools/setup` (deploy smoke tests +
the YAML regression runner's "lines" assertion), and the offline test mocks.
`tests/integration` was migrated against real post-deploy failures rather than
by guesswork — one assertion needed changing across the readonly and safe_write
tiers, both of which are now green.

`tests/performance/test_response_contract_callers.py` guards the caller side: it
scans fun-doc for every reshaped endpoint's call sites and asserts each unwraps
the record. It exists because hand-grepping missed 14 sites, one of which failed
184 live worker runs before anyone noticed.

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
- Absent values are omitted rather than emitted as `null`, except where a
  caller distinguishes "absent" from "empty" (`get_comment` emits every comment
  kind, using `null` for absent, precisely so callers can tell the difference).

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

| Stage | Scope | Tools |
| --- | --- | --- |
| 1 | `list_*` | 13 |
| 2 | `get_*` | 14 |
| 3 | remainder (`decompile_function`, `disassemble_function`, `check_connection`, `force_decompile`, `search_data_types`, `validate_data_type`) | 6 |
| 4 | bare-array outliers brought into the envelope (`list_imports`, `list_external_locations`, `detect_crypto_constants`, `find_dead_code`) | 4 |

Callers are migrated with their stage — fun-doc, `tests/`, `tools/setup`, and
the docs each parse these responses today, so a stage is not complete until its
callers are updated and the suite is green.

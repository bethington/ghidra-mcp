# Ghidra MCP Tool Usage Guide

## Summary of Fixed Issues

The enhanced analysis prompt has been updated to use the **correct and reliable tool patterns** that work without retry loops.

### Issue Fixed: Type Application Pattern

**Previous approach (causes retries):**
```python
# ❌ PROBLEMATIC - create_and_apply_data_type has parameter format issues
create_and_apply_data_type(address, "PRIMITIVE", '{"type": "dword"}', "dwName", "comment")
# Error: type_definition must be JSON object/dict, got: String
```

**New approach (works first time):**
```python
# ✅ RELIABLE - Use separate, proven tools
apply_data_type(address, "dword")           # Step 1: Apply type
rename_symbol(address, "dwName")          # Step 2: Rename with Hungarian notation
set_comment(address, "comment", type='pre')  # Step 3: Add documentation
```

## Complete Workflow Pattern

### Type Application (Step 3)

```python
# Always use this three-step pattern:

# 1. Apply the data type
apply_data_type(address, type_name)

# 2. Rename with Hungarian notation
rename_symbol(address, hungarian_name)

# 3. Set documentation (in Step 6)
set_comment(address, documentation, type='pre')
```

### Supported Type Names for apply_data_type()

**Primitive Types:**
- `"dword"` - 32-bit unsigned integer
- `"word"` - 16-bit unsigned integer
- `"byte"` - 8-bit unsigned integer
- `"int"` - 32-bit signed integer
- `"short"` - 16-bit signed integer
- `"char"` - 8-bit signed character
- `"float"` - 32-bit IEEE 754 floating point
- `"double"` - 64-bit IEEE 754 floating point
- `"pointer"` - Generic pointer (32/64-bit depending on architecture)
- `"qword"` - 64-bit unsigned integer
- `"longlong"` - 64-bit signed integer
- `"bool"` - Boolean type

**String/Array Types:**
- `"char[N]"` - ASCII/ANSI string (e.g., `"char[6]"`, `"char[256]"`)
- `"word[N]"` - Array of 16-bit words
- `"dword[N]"` - Array of 32-bit dwords
- `"byte[N]"` - Array of bytes
- `"pointer[N]"` - Array of pointers

## Hungarian Notation Reference

Always use type prefixes in step 2 (rename_symbol):

| Type | Prefix | Examples |
|------|--------|----------|
| DWORD (unsigned 32-bit) | `dw` | `dwFlags`, `dwCount`, `dwUnitId` |
| WORD (unsigned 16-bit) | `w` | `wX`, `wY`, `wPort` |
| BYTE (unsigned 8-bit) | `b`, `by` | `bValue`, `byOpcode` |
| int (signed 32-bit) | `n` | `nCount`, `nIndex`, `nOffset` |
| short (signed 16-bit) | `n` | `nValue`, `nDelta` |
| char (signed 8-bit) | `c` | `cChar`, `cValue` |
| String (char[]) | `sz` | `szName`, `szPath`, `szGameName` |
| String (wchar_t[]) | `wsz`, `w` | `wszTitle`, `wName` |
| Pointer | `p` | `pData`, `pNext`, `pPlayerData` |
| Pointer (legacy) | `lp` | `lpBuffer`, `lpStartAddress` |
| Boolean (function-level) | `f` | `fEnabled`, `fIsActive` |
| Boolean (struct field) | `b` | `bActive`, `bVisible` |
| Function pointer | `fn` | `fnCallback`, `fnHandler` |
| Handle | `h` | `hFile`, `hThread`, `hModule` |
| Byte count | `cb` | `cbSize`, `cbBuffer` |

## Documentation Pattern

```python
# After apply_data_type() and rename_symbol() succeed:

documentation = """================================================================================
                    [TYPE] [Hungarian Name] @ [Address]
================================================================================
TYPE: [DataType] ([Size bytes]) - [Brief description]

VALUE: [Hex representation] ([Decimal if relevant])

PURPOSE:
[What this data represents and how it's used in 1-2 sentences]

[Additional relevant sections]
"""

set_comment(address, documentation, type='pre')
```

### Documentation Template Sections

**Mandatory:**
- `TYPE:` - Data type, size in bytes, brief description
- `VALUE:` - Hex and decimal values
- `PURPOSE:` - What the data represents and its primary usage

**Optional (add as relevant):**
- `SOURCE REFERENCE:` - Where data comes from (file, structure, etc.)
- `XREF COUNT:` - Number of cross-references
- `USAGE PATTERN:` - How/where the data is accessed
- `RELATED GLOBALS:` - Connected data items
- `INITIALIZATION:` - What function sets this
- `STRUCTURE LAYOUT:` - For pointer data
- `CONSTRAINTS:` - Value ranges, validation rules
- `EXAMPLES:` - Usage examples from decompiled code

## Complete Example

```python
# Address: 0x0040BC08, Data: "VIDEO" string (6 bytes)

# Step 3a: Apply type
apply_data_type("0x0040bc08", "char[6]")
# Returns: "Successfully applied data type 'char[6]' at 0x0040bc08 (size: 6 bytes)"

# Step 3b: Rename with Hungarian notation
rename_symbol("0x0040bc08", "szVideoSection")
# Returns: "Success: Renamed defined data at 0x0040bc08 to 'szVideoSection'"

# Step 6: Set documentation
set_comment(type='pre', "0x0040bc08", """================================================================================
                    STRING szVideoSection @ 0x0040BC08
================================================================================
TYPE: char[6] (6 bytes) - Null-terminated ASCII string

VALUE: "VIDEO" (0x56 0x49 0x44 0x45 0x4F 0x00)

PURPOSE:
INI section name used to read video configuration settings from D2Server.ini file.
Passed to GetPrivateProfileIntA/GetPrivateProfileStringA for retrieving video-related
configuration keys from the VIDEO section.

XREF COUNT: 2 references
- LoadVideoConfigurationFromIni (2 calls for boolean and integer INI values)
""")
# Returns: "Success: Set comment at 0x0040bc08"
```

## When to Use Which Tool

### For Primitives (1-8 bytes)
1. `apply_data_type()` with primitive type name
2. `rename_symbol()` with `dw`, `w`, `n`, or `b` prefix
3. `set_comment(type='pre')` with documentation

### For Strings
1. `apply_data_type()` with `"char[N]"` or `"wchar_t[N]"`
2. `rename_symbol()` with `sz` or `wsz` prefix
3. `set_comment(type='pre')` with documentation

### For Pointers
1. `apply_data_type()` with `"pointer"`
2. `rename_symbol()` with `p` or `lp` prefix
3. `set_comment(type='pre')` with documentation

### For Arrays
1. `apply_data_type()` with `"type[count]"` (e.g., `"dword[64]"`)
2. `rename_symbol()` with type prefix (e.g., `adwValues`)
3. `set_comment(type='pre')` with documentation

### For Structures
1. `create_struct()` to define the structure with fields
2. `apply_data_type()` with structure name
3. `rename_symbol()` with descriptive instance name
4. `modify_struct_field()` if fields need renaming/type changes
5. `set_comment(type='pre')` with documentation

## Error Prevention Checklist

- ✓ Use `apply_data_type()` with string type names (not dicts)
- ✓ Use `rename_symbol()` for naming (it auto-detects data vs code)
- ✓ Always include Hungarian notation prefix in names
- ✓ Use `char[N]` format for strings (not just `char`)
- ✓ Use hex sizes for padding: `_1[0x158]` not `_1[344]`
- ✓ Call `set_comment(type='pre')` AFTER type and name are set
- ✓ Include header banner and all mandatory sections in documentation

## Related Tools

**For structure creation:**
- `create_struct(name, fields)` - Create a new structure type
- `modify_struct_field(struct_name, field_name, new_type, new_name)` - Update fields
- `search_data_types(pattern)` - Search for structures by name pattern

**For analysis:**
- `analyze_data_region(address)` - Get data type and boundaries
- `inspect_memory_content(address, length)` - Read raw memory
- `get_bulk_xrefs(addresses)` - Get cross-references

**For validation:**
- `validate_data_type(type_name)` - Check if type exists
- `can_rename_at_address(address)` - Check what operation is appropriate

## Per-Program Storage: Options and Property Maps (v5.17.0+)

Two typed stores that live *inside* the Ghidra program database, so anything
written here travels with the `.gzf` and survives a re-open.

### Program options — per-program settings and metadata

Read or write any typed option in any group (Program Information, Analyzers,
Decompiler, …).

```text
list_option_groups(program="")                       -> group names
get_program_options(group, program="")               -> {name: value} in that group
set_program_option(group, name, value, type="", program="")
remove_program_option(group, name, program="")
```

`set_program_option` infers the type from an existing option when `type` is
omitted, accepts `string|int|long|double|float|boolean`, and creates custom
options on demand — which makes it a durable place to record project-level
facts (e.g. a curation pass version) without inventing a side file.

### Property maps — typed per-address key→value stores

Where a comment is prose, a property is data. Use these when you need
structured per-address values you can query back exactly.

```text
list_property_maps(program="")                       -> existing maps + types
create_property_map(name, type, program="")          -> type: int|long|string|void
set_property(name, address, value, program="")
get_property(name, address, program="")
list_properties(name, program="")                    -> every address carrying it
remove_property(name, address, program="")
delete_property_map(name, program="")
```

A `void` map is a pure marker set (address is either in it or not) — ideal for
"reviewed" / "needs-rework" flags. For richer records, store JSON in a
`string` map. Object maps are read-only: they require a registered `Saveable`
type that can't be created over HTTP.

**Gotcha:** as with every write endpoint, `program` is a *query* parameter.
Omitting it writes to whichever program is active, which is how per-program
data leaks into the wrong binary during multi-version work.

## Comments (any address)

`get_comment` / `set_comment` work at **any** address — data and undefined
bytes included, not just function entries — and cover all five Ghidra comment
types (`plate`, `pre`, `post`, `eol`, `repeatable`):

```text
get_comment(address, program="")
set_comment(address, comment, type="plate|pre|eol|post|repeatable", program="")
```

`type` also accepts the aliases `decompiler` (= `pre`) and `disassembly`
(= `eol`). In 7.0.0 this pair absorbed the function-only
`set_plate_comment` / `set_decompiler_comment` / `set_disassembly_comment` /
`get_plate_comment` tools, so it is now the only comment reader/writer you
need — including for the "every documented global carries a comment" rule.
Passing an empty `comment` clears that comment type at the address.

## Flow Repair (v5.17.0+)

```text
set_function_no_return(address, no_return, program="")
clear_flow_and_repair(address, program="")
```

`set_function_no_return` synchronizes the flag across every thunk hop and the
terminal target, and its response reports the verified `function_no_return` /
`terminal_no_return` state — trust that, not the request you sent.

When a function was *wrongly* marked no-return, clearing the flag alone does
not restore the call fallthrough that Ghidra already deleted. Run
`clear_flow_and_repair(address)` afterwards to rebuild the damaged flow
without a full re-analysis.

## Cross-Binary Documentation Propagation (v1.9.4+)

These tools enable documentation sharing across different versions of the same binary by matching functions based on their normalized opcode hashes.

### Function Hashing

```python
# Get hash for a single function
hash_info = get_function_hash("0x6FAB1234")
# Returns: {"hash": "abc123...", "instruction_count": 63, "has_custom_name": true}

# Get hashes for many functions (paginated)
result = get_bulk_function_hashes(offset=0, limit=500, filter="documented")
# filter options: "documented", "undocumented", "all"
```

### Documentation Export/Import

```python
# Export complete documentation from a well-documented function
docs = get_function_documentation("0x6FAB1234")
# Returns: name, prototype, plate_comment, parameters, locals, comments, labels

# Apply documentation to another function with matching hash
apply_function_documentation(
    target_address="0x6FAC0000",
    function_name="ProcessPlayerData",
    return_type="int",
    calling_convention="__fastcall",
    plate_comment="Processes player data structures.",
    parameters=[{"ordinal": 0, "name": "pPlayer", "type": "Player *"}]
)
```

### Index Management (High-Level Workflow)

```python
# Build index from documented functions across programs
build_function_hash_index(
    programs=["D2Client.dll 1.07", "D2Client.dll 1.08"],
    filter="documented",
    index_file="function_hash_index.json"
)

# Find functions matching a hash
matches = lookup_function_by_hash(hash="abc123...")
# Returns all programs/addresses with matching functions

# Propagate documentation to all matching functions
propagate_documentation(
    source_address="0x6FAB1234",
    target_programs=["D2Client.dll 1.08", "D2Client.dll 1.09"],
    dry_run=True  # Preview changes without applying
)
```

### Hash Normalization Details

The hash algorithm normalizes position-dependent values so identical functions at different addresses produce the same hash:

| Pattern | Normalization | Reason |
|---------|---------------|--------|
| Internal jumps | `REL+offset` | Relative to function start |
| External calls | `CALL_EXT` | Different addresses per binary |
| External data | `DATA_EXT` | Different addresses per binary |
| Small immediates (<0x10000) | `IMM:value` | Preserved (constants) |
| Large immediates | `IMM_LARGE` | May be addresses |
| Registers | Preserved | Part of algorithm logic |

## Dynamic Analysis Tools (v5.4.0+)

When static decompilation is ambiguous, three endpoint families run code or trace data flow directly. Use them as cross-checks, not replacements.

### `analyze_dataflow(address, variable, direction, max_steps=20, program="")`

Traces how a value propagates through a function using the decompiler's PCode graph.

- `direction="backward"` — walk producers via `Varnode.getDef()`. Shows where a return value or sink argument *came from*.
- `direction="forward"` — walk consumers via `Varnode.getDescendants()`. Shows every place a parameter or early-computed value *flows to*.
- `variable` — register name (`EAX`), HighVariable name (`param_1`, `local_14`, `iVar1`), or empty string for the output of the first PcodeOp at the address. Empty-string errors list candidate names from the address.
- Terminates at constants, function inputs, call boundaries, or `max_steps` (capped at 200).
- Phi (`MULTIEQUAL`) nodes summarized as single steps rather than recursed.

When to reach for it:

- A function returns a value and you need to name producers concretely (did it come from a syscall return? a table lookup? a masked parameter?).
- Forward-tracing a parameter to confirm every use is consistent with your PURPOSE claim (no hidden sink you missed).
- Reconstructing a candidate string list for `emulate_hash_batch` — the forward trace from the hash function's string parameter shows every call site that feeds it.

### `emulate_function(address, registers, memory, max_steps=10000, return_registers="", program="")`

Emulates a function through Ghidra's `EmulatorHelper`. No process, no syscalls, pure P-code execution.

- `registers` — JSON string: `{"ECX": "0x7FFE0000", "EDX": "0x10"}`
- `memory` — JSON string with `regions` wrapper: `{"regions": [{"address": "0x7FFE0004", "hex": "DEC0ADDE"}]}`. Regions accept `data` (base64), `hex`, or `string`.
- `return_registers` — comma-separated names to include in output (empty = all general-purpose)
- Returns `{success, function, entry_address, hit_return, final_pc, registers: {...}}`

Stack is auto-initialized at `0x7FFF0000` with a `0xDEADBEEF` return sentinel. `hit_return: true` means the function executed to RET without hitting `max_steps`.

Use for: hash functions, CRC/checksum leaves, bit-packing routines, anything that's pure computation with known inputs.

### `emulate_hash_batch(hash_function_address, string_register, result_register, target_hash, candidates, initial_registers="", wide_string=false, program="")`

Brute-force API-hash resolution. Iterates a candidate list through a hash function and returns all matches.

- `candidates` — JSON string array of candidate strings: `["CreateProcessW", "VirtualAlloc", ...]`
- Returns `{function, target_hash, total_candidates, tested, matches: [{api_name, computed_hash, iteration}], resolved, best_match}`
- `matches` lists **all** collisions. When two or more names hash to the target, check the full array; `best_match` is only the first in iteration order.

Workflow: locate the hash function (`search_byte_patterns`, `detect_crypto_constants`, or `search_functions`), identify input/output registers (`get_function_variables` or `analyze_dataflow`), supply a candidate list per suspected source DLL, feed the target hash from the call site.

### `debugger_*` families (GUI-only)

There are **two independent debugger tool families** with different backends. Pick by
platform/target. Both require a CodeBrowser with the **Window > Debugger** view open.

#### A. TraceRmi family — in-process, cross-platform (use this on Linux/macOS)

Server-side `@McpTool` endpoints (`/debugger/*` in `DebuggerService.java`) that drive
**Ghidra's own native debugger** via `TraceRmiLauncherService`. The launcher chosen at
launch time selects the backend:

- Linux ELF: `gdb`  ·  macOS Mach-O: `lldb`  ·  Windows PE: `dbgeng`

Tools: `debugger_launch`, `debugger_launch_offers`, `debugger_status`, `debugger_resume`,
`debugger_interrupt`, `debugger_step_{into,over,out}`, `debugger_{set,remove,list}_breakpoints`,
`debugger_registers`, `debugger_read_memory`, `debugger_stack_trace`, `debugger_modules`,
`debugger_traces`, `debugger_static_to_dynamic`, `debugger_dynamic_to_static`.

These ship with the plugin and need no extra processes — they appear in `/mcp/schema`
on every platform.

**gdb-on-Linux workflow:**

```text
1. In CodeBrowser: Window > Debugger  (one-time, GUI — TraceRmi is GUI-only)
2. debugger_launch_offers()                  # lists gdb local/remote/ssh launchers
3. debugger_launch(executable_path="...")    # starts the target under gdb
4. debugger_set_breakpoint(...) / debugger_registers() / debugger_read_memory(...)
5. debugger_step_into() / debugger_resume() / debugger_interrupt()
6. debugger_static_to_dynamic(...) maps a Ghidra (static) address to the live
   process; debugger_dynamic_to_static(...) goes the other way.
```

#### B. WinDbg proxy family — standalone dbgeng server (Windows only)

22 static bridge tools proxied to a standalone Python server via `GHIDRA_DEBUGGER_URL`
(default `http://127.0.0.1:8099`), which wraps **dbgeng/WinDbg via `pybag`** —
**Windows-only** (`pybag` requires `pywin32`). Adds dbgeng-specific capabilities the
TraceRmi family doesn't have: attach-by-process-name, ordinal resolution, argument
reads, and the trace/watch loops.

Tools: `debugger_attach`, `debugger_detach`, `debugger_continue`,
`debugger_resolve_ordinal`, `debugger_read_args`, `debugger_trace_{function,stop,log,list}`,
`debugger_watch_{memory,stop,log}` (plus dbgeng versions of status/step/breakpoint/
registers/memory/stack/modules).

**Registration is platform-gated** (`_debugger_enabled()` in the bridge): on non-Windows
hosts with a local `GHIDRA_DEBUGGER_URL` these tools are **not registered** (they could
never work), which also frees the shared `debugger_*` names for the TraceRmi family above.
They register when: running on Windows, `GHIDRA_DEBUGGER_URL` points at a remote
(Windows) host running the server, or `GHIDRA_DEBUGGER_TOOLS=1` forces them on.

> Naming note: where the two families share a name (e.g. `debugger_status`), only one
> can hold the clean name. On non-Windows the TraceRmi tool wins; on Windows (both
> active) the dbgeng proxy holds the clean name and the TraceRmi endpoint is suffixed
> `_2` (e.g. `debugger_status_2`).

Use either family for: ground-truth validation after static analysis. After emulation
resolves a hash, set a breakpoint on the resolved API and confirm the process calls it.

## Function Tagging

Lightweight per-function labels (program-wide tag definitions, attached to any function). Useful for carving curated subsets across long analysis sessions — e.g. `crypto`, `parser`, `reviewed`, `todo`, `imported-from-dll`. Tags are stored in the Ghidra DB so they roundtrip through save/checkin and survive across sessions.

Two layers:

- **Tag definitions** (program-wide): `create_function_tag`, `delete_function_tag`, `set_function_tag_comment`, `list_function_tags`.
- **Per-function attachment**: `add_function_tag`, `remove_function_tag`, `get_function_tags`, `search_functions_by_tag`. Attaching a tag by name auto-creates the definition if it doesn't already exist.

Batch variants: `add_function_tag` / `remove_function_tag` take an array of `{function, tags}` objects and run the whole set in one transaction. Use these when tagging a sweep result — single-call instead of N round-trips.

Worked pattern — sweep + curate:

```python
# After locating all crypto routines via detect_crypto_constants / search_byte_patterns,
# tag them with one batch call:
add_function_tag(assignments=[
    {"function": "0x401abc",  "tags": "crypto,aes"},
    {"function": "0x401d40",  "tags": "crypto,sha256"},
    # ...
])

# Later, recall the curated list:
search_functions_by_tag(tag="crypto")
# → returns {tag, total, functions: [{name, address}, ...]}
```

Tags are case-sensitive; `search_functions_by_tag` rejects unknown tag names (returns error rather than empty list) so you can detect typos.

## Security Environment Variables (v5.4.1+)

GhidraMCP defaults to localhost-unauthenticated — safe on a single-user dev box. Configure these before binding beyond loopback:

| Env var | Effect |
|---|---|
| `GHIDRA_MCP_AUTH_TOKEN` | When set, every HTTP request must carry `Authorization: Bearer <token>`. Timing-safe comparison. `/mcp/health`, `/health`, `/check_connection` are always exempt. |
| `GHIDRA_MCP_ALLOW_SCRIPTS` | Set to `1`, `true`, or `yes` to enable `/run_script_inline` and `/run_ghidra_script`. **Off by default as of v5.4.1** (breaking change — these endpoints execute arbitrary Java against the Ghidra process). |
| `GHIDRA_MCP_FILE_ROOT` | When set, filesystem-path endpoints (`/load_program`, `/import_file`, `/open_project`, `/delete_file`, etc.) canonicalize the input and require it to fall under this root. |

The headless server refuses to start on a non-loopback bind address (`0.0.0.0`, explicit external IP) unless `GHIDRA_MCP_AUTH_TOKEN` is set.

**The MCP bridge reads the same `GHIDRA_MCP_AUTH_TOKEN`** and attaches `Authorization: Bearer <token>` to every outbound call (UDS and TCP). Export the same token in the bridge's environment — otherwise it will hit `401 Unauthorized` on every tool call to an auth-enabled server. Unset = no header (matches the localhost default).

### Worked example — exposing to a private LAN with auth

```bash
export GHIDRA_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
export GHIDRA_MCP_ALLOW_SCRIPTS=1     # only if your workflow needs it
export GHIDRA_MCP_FILE_ROOT=/srv/ghidra/inputs

java -jar GhidraMCPHeadless.jar --bind 0.0.0.0 --port 8089
```

---

## Two Documentation Metrics: Hygiene vs Truth

`analyze_function_completeness` is a **hygiene** score: it verifies documentation is *present and well-formed* (name quality, plate sections, typed params). It is computed entirely from the documentation, so it cannot detect a claim that is confidently wrong — a plate describing an algorithm the code does not implement still scores 100.

The **truth** axis is falsifiability (`fun-doc/falsify.py`): mechanical, model-free checks that compare documentation claims against disassembly facts — declared calling convention vs the callee's actual `RET n`, plate-documented parameters vs the live signature, reader-verb names (`Get*`/`Is*`) on functions that write globals, plate/prototype return contradictions. Tier-1 (mechanically certain) findings mark the function `DOC_REFUTED`, stamp an idempotent `[AUDIT falsify:*]` plate flag, force an audit pass seeded with the contradiction, and keep the function in the work queue regardless of its score.

Operationally: treat a high completeness score as "the form is filled in", never as "the content is verified". When a plate carries an `[AUDIT falsify:*]` flag, resolving that contradiction — by correcting the documentation to match the disassembly, never the reverse — takes priority over any score-driven work.

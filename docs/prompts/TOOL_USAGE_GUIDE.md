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
| ------ | -------- | ---------- |
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
set_comment("0x0040bc08", """================================================================================
                    STRING szVideoSection @ 0x0040BC08
================================================================================
TYPE: char[6] (6 bytes) - Null-terminated ASCII string

VALUE: "VIDEO" (0x56 0x49 0x44 0x45 0x4F 0x00)

PURPOSE:
INI section name used to read video configuration settings from Server.ini file.
Passed to GetPrivateProfileIntA/GetPrivateProfileStringA for retrieving video-related
configuration keys from the VIDEO section.

XREF COUNT: 2 references
- LoadVideoConfigurationFromIni (2 calls for boolean and integer INI values)
""", type='pre')
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
- `find_data_types(pattern, kind="struct")` - Search for structures by name pattern

**For analysis:**

- `analyze_data_region(address)` - Get data type and boundaries
- `inspect_memory_content(address, length)` - Read raw memory
- `get_xrefs_to(addresses="a,b,c")` - Get cross-references to one or many addresses

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
get_program_options(program="")                       -> group names (no group given)
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
list_properties(program="")                          -> existing maps + types (no map given)
create_property_map(name, type, program="")          -> type: int|long|string|void
set_property(map, address, value, program="")
get_property(map, address, program="")
list_properties(map, program="")                     -> every address carrying it
remove_property(map, address, program="")
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
set_function_no_return(function_address, no_return, program="")
clear_flow_and_repair(start_address, end_address="", program="")
```

`set_function_no_return` synchronizes the flag across every thunk hop and the
terminal target, and its response reports the verified `function_no_return` /
`terminal_no_return` state — trust that, not the request you sent.

When a function was *wrongly* marked no-return, clearing the flag alone does
not restore the call fallthrough that Ghidra already deleted. Run
`clear_flow_and_repair(start_address)` afterwards to rebuild the damaged flow
without a full re-analysis.

## Cross-Binary Documentation Propagation (v1.9.4+)

These tools enable documentation sharing across different versions of the same binary by matching functions based on their normalized opcode hashes.

### Function Hashing

```python
# Get hash for a single function
hash_info = get_function_hash("0x6FAB1234")
# Returns: {"hash": "abc123...", "instruction_count": 63, "has_custom_name": true}

# Get hashes for many functions (paginated)
result = get_function_hash(offset=0, limit=500, filter="documented")  # omit `function` for bulk mode
# filter options: "documented", "undocumented"; omit for all
```

### Documentation Export/Import

```python
# Export complete documentation from a well-documented function
docs = get_function_documentation("0x6FAB1234")
# Returns: hash, function_name, return_type, calling_convention, plate_comment,
# parameters, local_variables, comments, labels

# Apply documentation to another function with matching hash
apply_documentation(
    address="0x6FAC0000",
    name="ProcessPlayerData",
    return_type="int",
    calling_convention="__fastcall",
    plate_comment="Processes player data structures.",
    parameters=[{"ordinal": 0, "name": "pPlayer", "type": "Player *"}]
)
# Or pass the export straight back: apply_documentation(**docs, target_address="0x6FAC0000")
# Many functions at once: apply_documentation(entries=[{"address": ..., "name": ...}, ...])
```

### Matching Across Programs

There is no persistent hash index and no reverse hash lookup. Hash both programs
in bulk, join the two listings on `hash`, and copy documentation one function at
a time:

```python
# Hash the documented functions in the source and everything in the target
src = get_function_hash(filter="documented", limit=500, program="example.dll 1.0")
dst = get_function_hash(limit=500, program="example.dll 1.1")
# Page with offset= until each listing is exhausted, then pair entries whose
# "hash" values are equal.

# For each pair, export from the source and apply to the target
doc = get_function_documentation(function="0x10001234", program="example.dll 1.0")
apply_documentation(**doc, target_address="0x10002000", program="example.dll 1.1")
```

When the two programs share addresses (a rescued copy of the same image),
`merge_program_documentation(source, target, dry_run=true)` copies everything
in one transaction instead. For functions that changed between versions, so
their hashes differ, `bulk_fuzzy_match(source_program, target_program)` pairs
them by similarity.

### Hash Normalization Details

The hash algorithm normalizes position-dependent values so identical functions at different addresses produce the same hash:

| Pattern | Normalization | Reason |
| --------- | --------------- | -------- |
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

Workflow: locate the hash function (`search_byte_patterns`, `detect_crypto_constants`, or `find_functions`), identify input/output registers (`get_functions` with `fields=parameters,locals`, or `analyze_dataflow`), supply a candidate list per suspected source DLL, feed the target hash from the call site.

### `debugger_*` families (GUI-only)

There are **two independent debugger tool families** with different backends. Pick by
platform/target. Both require a CodeBrowser with the **Window > Debugger** view open.

#### A. TraceRmi family — in-process, cross-platform (use this on Linux/macOS)

Server-side `@McpTool` endpoints (`/debugger/*` in `DebuggerService.java`) that drive
**Ghidra's own native debugger** via `TraceRmiLauncherService`. The launcher chosen at
launch time selects the backend:

- Linux ELF: `gdb`  ·  macOS Mach-O: `lldb`  ·  Windows PE: `dbgeng`

Tools: `debugger_launch`, `debugger_launch_offers`, `debugger_status`, `debugger_resume`,
`debugger_interrupt`, `debugger_step` (`kind="into"|"over"|"out"`), `debugger_set_breakpoint`,
`debugger_remove_breakpoint`, `debugger_list_breakpoints`,
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
5. debugger_step(kind="into") / debugger_resume() / debugger_interrupt()
6. debugger_static_to_dynamic(...) maps a Ghidra (static) address to the live
   process; debugger_dynamic_to_static(...) goes the other way.
```

#### B. WinDbg proxy family — standalone dbgeng server (Windows only)

22 static bridge tools proxied to a standalone Python server via `GHIDRA_DEBUGGER_URL`
(default `http://127.0.0.1:8099`). That server is not part of this repository. It wraps **dbgeng/WinDbg via `pybag`** —
**Windows-only** (`pybag` requires `pywin32`). Adds dbgeng-specific capabilities the
TraceRmi family doesn't have: attach-by-process-name, ordinal resolution, argument
reads, and the trace/watch loops.

Tools: `debugger_attach`, `debugger_detach`, `debugger_continue`,
`debugger_resolve_ordinal`, `debugger_read_args`, `debugger_trace_{function,stop,log,list}`,
`debugger_watch_{memory,stop,log}` (plus dbgeng versions of status/step/breakpoint/
registers/memory/stack/modules).

**These tools are off by default** (`_debugger_enabled()` in the bridge). They register
only when `GHIDRA_DEBUGGER_URL` is set to a loopback URL or `GHIDRA_DEBUGGER_TOOLS=1`;
`GHIDRA_DEBUGGER_TOOLS=0` keeps them off even with a URL set. Calls are only proxied to
loopback, so reach a server on another machine through a forwarded port.

> Naming note: where the two families share a name (e.g. `debugger_status`), both stay
> reachable. With the proxies off, the TraceRmi tool holds the clean name. With them on,
> the dbgeng proxy holds it and the TraceRmi tool is registered as `debugger_status_2`.
> The two families drive separate debuggers, so pick one per target: a process the
> TraceRmi debugger launched cannot also be attached by the dbgeng server.

Use either family for: ground-truth validation after static analysis. After emulation
resolves a hash, set a breakpoint on the resolved API and confirm the process calls it.

## Decompilation tree (v7.2.0+)

Materialise a program's decompilation into a partitioned on-disk tree, then search
it with the client's own `Grep` / `Read` / `Glob`. That turns corpus questions
("which functions touch this MMIO page", "where does this constant appear") into
one search instead of one MCP round trip per function.

### Workflow

```text
1. decompile_tree_create(program=..., root=..., exclusions=[...])   # registers; no sweep
2. decompile_tree_run(checkout=..., action="start")                # returns in ms with resource_uri
3. Poll decompile_tree_status(checkout=...) until phase=complete    # or read STATUS.md on disk
4. Grep / Read / Glob under <root>/modules/                   # the tree is the corpus
5. For a hit: read the file header's uri: ghidra://function/<program>/<address>
   then resources/read that URI for callers and call-site context
```

Create and start are separate on purpose: config changes must not silently launch
a multi-minute sweep. `decompile_tree_status` is READ_ONLY so it stays usable in plan
mode; the five write paths (`create` / `configure` / `start` / `stop` / `delete`)
are not.

`STATUS.md` in the tree root answers "is this tree trustworthy?" with **zero
Ghidra calls**. `state: clean` is exactly the last sweep's output; `spliced` has been
kept current block by block since that sweep (`spliced_since_sweep` counts the
rewritten blocks); `dirty` means a writer did not finish (crash, cancel, or still
running) — do not Grep a dirty tree as if it were complete; `stale` means the tree is
known to diverge from the program (`last_error` says why) — resweep.
`decompile_tree_status` reports `in_sync`: swept, not stale, and no change still
queued or being spliced in — the answer to "can I trust a grep right now". `pending_dirty`
says what is queued. (Modification numbers are reported but are not the test: they also
move for changes no block shows, and start over each time the program opens. STATUS.md names
the `session` the tree was built in, the program's `saved_time` and whether it
`includes_unsaved_edits`.)

**A tree outlives the server.** When a program opens, its trees on disk are adopted without
a `create` call: registered, observed, and reconciled against the program as it opened (a
tree from another session reports `previous_session: true`; edits lost with the old process
are taken back out). A tree is the program's when its `tree.json` names the same domain
path and `program_url` (the repository URL for a versioned file, the local project's URL
otherwise). A tree from before that field existed is adopted only from a root this server
created; one under the default root, whose parent every server on the machine shares, waits
for a `decompile_tree_create` call, which stamps it. `create` refuses a tree that names
another project's program.

**Every route ends at the same tree.** A tree that is `in_sync` is byte for byte what a fresh
sweep would write at that point, apart from the `dts` stamps, the status files and
the tree's own root and id, whether it got there by a sweep, by splices after edits, by a
full reconcile (`decompile_tree_refresh` with no addresses), by narrowing its exclusions,
or by adopting a tree someone copied. One packer lays out every compartment's files and one
renderer writes every index and README, from `index/by-address.tsv` and the grouping the
sweep kept in `index/partitions.json`. A full reconcile also repairs: a deleted or
hand-edited `.c` file, README, index or `AGENTS.md` comes back as the sweep wrote it (a block
whose text no longer matches its `// fp:` is rebuilt). A tree swept before
`partitions.json` existed cannot be reproduced without the sweep's own
work, so a full reconcile of one runs a sweep instead and says so (`sweep_queued`).
Re-partitioning is the one thing a reconcile does not do: functions added since the sweep
join the compartment that contains their address; resweep to regroup.

### Measured sweep cost

| Specimen | Functions | Time | Tree |
| --- | --- | --- | --- |
| blender ARM firmware | 677 | 4 s | 773 KB |
| `synaWudfBioUsb.dll` | 3,230 | 18–28 s | 5.6 MB |
| `ls` (static stripped ELF) | 25,231 | 669 s | 45 MB |

Excluding two library compartments on the DLL: 3,230 → 2,036 functions, ~7 MB →
5 MB, 28 s → 20 s. Prefer `tag:` / `partition:` exclusions after reading
`modules/index.md` over decompiling library code you will never Grep.

`decompile_timeout_seconds` is the wall-time knob. On `ls`, 8 pathological
functions each hit the 30 s timeout and accounted for 240 s of the 669 s total —
lowering the timeout bounds the damage; raising it does not make those functions
finish faster.

### The tree is the corpus; the resource is the microscope

Each function block carries everything `get_functions` returns for it: both are rendered
from the same facts, by the same decompiler settings, and a test holds them equal field for
field. The header is one `// key: value` line per fact, so each greps on its own; it ends at
`// ----`, after which comes the decompiler's C (whose own `//` lines are body):

```text
// fn: gpio_set @ 08004000 size=24
// signature: void gpio_set(uint * port, ushort pins)
// classification: leaf
// return_type: void                       (+ " (unresolved)" when it is undefined*)
// body: 08004000..08004017
// tags: gpio, hal
// plate: Sets pins.\nAlgorithm: ...        (newlines inside a value are written \n)
// plate_issue: missing Parameters section
// calls: read_status@08002000             (name@address, sorted, capped at 50 "+N more")
// callers: led_on@08005000
// refs: 0x08004100 0x40003c0c 0x40020000<0x08004100  (every address used; value<pool word)
// param: #0 uint * port @r0:4
// local: int extraout_r0 @r0 [phantom]
// label: +0x14 done (USER_DEFINED)
// comment: +0x4 eol BSRR write
// xref: 08005010 UNCONDITIONAL_CALL led_on
// jump: 08004014
// decompile_error: timed out              (only when there is no C)
// part / fp / dts / mod / uri / see       (where it sits; fp hashes the block itself)
// ----
void gpio_set(uint *port,ushort pins) { ... }
```

Typical greps: `// callers:.*led_on`, `// refs:.*0x40020000`, `// tags:.*hal`,
`// return_type:.*unresolved`. `call_context` is the one bundle field a block leaves out
(it costs a decompile per caller, and every caller's own block is in the tree);
`callgraph.tsv` lists every call edge by the same rule as the `calls:` lines.

Every address a function uses is on its `// refs:` line, however the C spells it: data
references, memory the decompiled code reads or writes (so a register reached as
base + offset, which the C prints as the base plus `0xc`, is there as itself), and the values
of literal-pool words, written `value<word`:

```text
// refs: 0x08016e58 0x40003c0c 0x40020000<0x08016e58
```

`grep -rn 0x40003c0c modules/` finds every function that touches that register; the nearest
`// fn:` line above a hit names it. `0x40020000<0x08016e58` says the base was loaded from
pool word `0x08016e58`, the word to retype or label. The list is not capped.

Addresses are bare hex in the program's default space and `space:hex` in any other
(`// fn: init @ OVL:00001000`), in the headers, the TSVs, the file names
(`OVL_00001000.c`) and the `uri:` line, the same spelling `get_functions` uses.

Grep finds the hit; the `uri:` line is how you pull call-site context afterwards. Do not
re-decompile via tools just to re-read what the block already holds.

The MCP resource `ghidra://decompile-tree/{tree_id}` is status/config prose (phase,
exclusions, compartment table, Glob/Grep incantations) — not a substitute for
searching the files.

### Two caveats an agent will otherwise hit

1. **Stripped binaries make name-based Grep useless.** `ls` has 12 real names out
   of 25,231 functions, so grepping for `__memmove_avx` finds nothing. Grep for
   **strings and constants** instead — that is also the signal the partitioner
   uses (`literal-locality` / string evidence in compartment READMEs).

2. **Peripheral / RAM addresses can be invisible in the C** when the code block is
   marked writable, which firmware loaders often do: the decompiler then treats each
   literal-pool load as a variable (`iVar2 = DAT_08016e58;`, the word holding
   `0x40020000`), so grepping the address finds nothing. Mark flash read-only first:
   `set_memory_block(block="ram", write=false)`, then resweep. Measured on a 339-function
   firmware: pool reads went from 1123 to 4, and the bases printed as constants or the
   labels at their targets (`(uint *)&GPIOC_CFGR`). A register reached as base + offset
   still prints as the base plus the offset; its own address is on the block's `// refs:`
   line, taken from the decompiled code. That needs the pool words read-only too: a writable
   word can change at run time, so the decompiler does not fold it.

## Shared projects: check out before you edit

On a project bound to a Ghidra Server, a versioned file that is not checked out opens as
an **in-memory copy** of its latest version. Edits apply, but there is nowhere to save
them, and they are gone when the program closes. The tools say so:

- `open_program` reports `read_only: true` with a `read_only_reason` naming the checkout.
- Every edit that succeeds on such a copy carries that reason in `warnings`.
- `save_program` refuses with the same reason. Ghidra's own message here is "Location
  does not exist for a save operation!".
- `close_program(save=true)` refuses rather than close and drop the edits. `save=false`
  discards them deliberately.

The workflow (the version-control tools are in the `server` group, `checkin_program`
included):

```python
server_version_control_checkout(path="/fw/a.dll", exclusive=False)
open_program(path="/fw/a.dll")      # read_only: false
# ... edits ...
save_program(program="/fw/a.dll")   # optional: checkin saves first
checkin_program(path="/fw/a.dll", comment="named the USB handlers", dry_run=True)  # preview
checkin_program(path="/fw/a.dll", comment="named the USB handlers")
```

A checkout of a file that is already open behaves like this:

- **The copy has no edits:** it is closed and reopened on the tree (`reopened: true`).
- **The copy has edits:** it is left alone and the response says `reopen_required`.
  Those edits cannot move into the checkout. Close the copy with `save=false`, reopen it,
  and redo them.
- **The file is already checked out:** the tree answers `already_checked_out`, not
  an error.

## Function Tagging

Lightweight per-function labels (program-wide tag definitions, attached to any function). Useful for carving curated subsets across long analysis sessions — e.g. `crypto`, `parser`, `reviewed`, `todo`, `imported-from-dll`. Tags are stored in the Ghidra DB so they roundtrip through save/checkin and survive across sessions.

Two layers:

- **Tag definitions** (program-wide): `delete_function_tag`, `set_function_tag_comment`, `list_function_tags`. There is no create call: attaching a tag creates its definition, and `tag_comments={"crypto": "..."}` on `add_function_tag` or `apply_documentation` gives a new one a description.
- **Per-function attachment**: `add_function_tag`, `remove_function_tag`, and `apply_documentation(tags=...)`, which adds tags alongside everything else you write about a function. Read them back with `get_functions(fields=tags)`, and find functions by tag with `find_functions(tag=...)`; every `find_functions` result lists its tags.

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
find_functions(tag="crypto")            # any of several: tag="crypto,parser"
# → returns {functions: [{name, address, tags, ...}, ...], total, ...}
```

Tags are case-sensitive; `find_functions(tag=...)` rejects unknown tag names (returns error rather than empty list) so you can detect typos.

## Security Environment Variables (v5.4.1+)

GhidraMCP defaults to localhost-unauthenticated — safe on a single-user dev box. Configure these before binding beyond loopback:

| Env var | Effect |
| --- | --- |
| `GHIDRA_MCP_AUTH_TOKEN` | When set, every HTTP request must carry `Authorization: Bearer <token>`. Timing-safe comparison. `/mcp/health` and `/check_connection` are always exempt. |
| `GHIDRA_MCP_ALLOW_SCRIPTS` | Set to `1`, `true`, or `yes` to enable `/run_script_inline` and `/run_ghidra_script`. **Off by default as of v5.4.1** (breaking change — these endpoints execute arbitrary Java against the Ghidra process). |
| `GHIDRA_MCP_FILE_ROOT` | When set, filesystem-path endpoints (`/import_file`, `/open_project`, `/delete_file`, etc.) canonicalize the input and require it to fall under this root. |

The headless server refuses to start on a non-loopback bind address (`0.0.0.0`, explicit external IP) unless `GHIDRA_MCP_AUTH_TOKEN` is set.

**The MCP bridge reads the same `GHIDRA_MCP_AUTH_TOKEN`** and attaches `Authorization: Bearer <token>` to every outbound call (UDS and TCP). Export the same token in the bridge's environment — otherwise it will hit `401 Unauthorized` on every tool call to an auth-enabled server. When an HTTP/SSE bridge binds beyond loopback, clients must also send that bearer token to the bridge; unauthenticated requests receive `401 Unauthorized`. Unset = no header (matches the localhost default).

### Worked example — exposing to a private LAN with auth

```bash
export GHIDRA_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
export GHIDRA_MCP_ALLOW_SCRIPTS=1     # only if your workflow needs it
export GHIDRA_MCP_FILE_ROOT=/srv/ghidra/inputs

# The jar does not bundle Ghidra; put both on the classpath, as docker/entrypoint.sh does
java -cp "GhidraMCP.jar:$GHIDRA_CLASSPATH" com.xebyte.headless.GhidraMCPHeadlessServer \r
    --bind 0.0.0.0 --port 8089
```

---

## Two Documentation Metrics: Hygiene vs Truth

`analyze_function_completeness` is a **hygiene** score: it verifies documentation is *present and well-formed* (name quality, plate sections, typed params). It is computed entirely from the documentation, so it cannot detect a claim that is confidently wrong — a plate describing an algorithm the code does not implement still scores 100.

The **truth** axis is falsifiability: mechanical, model-free checks that compare documentation claims against disassembly facts — declared calling convention vs the callee's actual `RET n`, plate-documented parameters vs the live signature, reader-verb names (`Get*`/`Is*`) on functions that write globals, plate/prototype return contradictions. These checks are not part of this server; an external documentation orchestrator can run them. When one does, a mechanically certain finding stamps an idempotent `[AUDIT falsify:*]` plate flag and keeps the function in its work queue regardless of its score.

Operationally: treat a high completeness score as "the form is filled in", never as "the content is verified". When a plate carries an `[AUDIT falsify:*]` flag, resolving that contradiction — by correcting the documentation to match the disassembly, never the reverse — takes priority over any score-driven work.

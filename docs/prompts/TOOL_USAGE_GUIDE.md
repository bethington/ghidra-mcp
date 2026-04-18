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
rename_or_label(address, "dwName")          # Step 2: Rename with Hungarian notation
set_decompiler_comment(address, "comment")  # Step 3: Add documentation
```

## Complete Workflow Pattern

### Type Application (Step 3)

```python
# Always use this three-step pattern:

# 1. Apply the data type
apply_data_type(address, type_name)

# 2. Rename with Hungarian notation
rename_or_label(address, hungarian_name)

# 3. Set documentation (in Step 6)
set_decompiler_comment(address, documentation)
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

Always use type prefixes in step 2 (rename_or_label):

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
# After apply_data_type() and rename_or_label() succeed:

documentation = """================================================================================
                    [TYPE] [Hungarian Name] @ [Address]
================================================================================
TYPE: [DataType] ([Size bytes]) - [Brief description]

VALUE: [Hex representation] ([Decimal if relevant])

PURPOSE:
[What this data represents and how it's used in 1-2 sentences]

[Additional relevant sections]
"""

set_decompiler_comment(address, documentation)
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
rename_or_label("0x0040bc08", "szVideoSection")
# Returns: "Success: Renamed defined data at 0x0040bc08 to 'szVideoSection'"

# Step 6: Set documentation
set_decompiler_comment("0x0040bc08", """================================================================================
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
2. `rename_or_label()` with `dw`, `w`, `n`, or `b` prefix
3. `set_decompiler_comment()` with documentation

### For Strings
1. `apply_data_type()` with `"char[N]"` or `"wchar_t[N]"`
2. `rename_or_label()` with `sz` or `wsz` prefix
3. `set_decompiler_comment()` with documentation

### For Pointers
1. `apply_data_type()` with `"pointer"`
2. `rename_or_label()` with `p` or `lp` prefix
3. `set_decompiler_comment()` with documentation

### For Arrays
1. `apply_data_type()` with `"type[count]"` (e.g., `"dword[64]"`)
2. `rename_or_label()` with type prefix (e.g., `adwValues`)
3. `set_decompiler_comment()` with documentation

### For Structures
1. `create_struct()` to define the structure with fields
2. `apply_data_type()` with structure name
3. `rename_or_label()` with descriptive instance name
4. `modify_struct_field()` if fields need renaming/type changes
5. `set_decompiler_comment()` with documentation

## Error Prevention Checklist

- ✓ Use `apply_data_type()` with string type names (not dicts)
- ✓ Use `rename_or_label()` for naming (it auto-detects data vs code)
- ✓ Always include Hungarian notation prefix in names
- ✓ Use `char[N]` format for strings (not just `char`)
- ✓ Use hex sizes for padding: `_1[0x158]` not `_1[344]`
- ✓ Call `set_decompiler_comment()` AFTER type and name are set
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
- `validate_data_type_exists(type_name)` - Check if type exists
- `can_rename_at_address(address)` - Check what operation is appropriate

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

### `debugger_*` family (22 tools, GUI-only)

Proxied to a standalone Python debugger server via `GHIDRA_DEBUGGER_URL` (default `http://127.0.0.1:8099`). Wraps Ghidra's `DebuggerTraceManagerService`, `DebuggerLogicalBreakpointService`, and `TraceRmiLauncherService`. Backend depends on the TraceRmi launcher chosen at attach time:

- Windows PE targets: `dbgeng` (WinDbg engine)
- Linux ELF: `gdb`
- macOS Mach-O: `lldb`

Covers: `debugger_attach`, `debugger_status`, `debugger_step_{into,over,out}`, `debugger_{set,remove,list}_breakpoints`, `debugger_registers`, `debugger_read_memory`, `debugger_stack_trace`, `debugger_modules`, `debugger_trace_{function,start,stop,log,list}`, `debugger_watch_{memory,stop,log}`, `debugger_resolve_ordinal`, `debugger_read_args`, `debugger_continue`, `debugger_detach`.

Use for: ground-truth validation after static analysis. After emulation resolves a hash, set a breakpoint on the resolved API and confirm the process actually calls it.

## Security Environment Variables (v5.4.1+)

GhidraMCP defaults to localhost-unauthenticated — safe on a single-user dev box. Configure these before binding beyond loopback:

| Env var | Effect |
|---|---|
| `GHIDRA_MCP_AUTH_TOKEN` | When set, every HTTP request must carry `Authorization: Bearer <token>`. Timing-safe comparison. `/mcp/health`, `/health`, `/check_connection` are always exempt. |
| `GHIDRA_MCP_ALLOW_SCRIPTS` | Set to `1`, `true`, or `yes` to enable `/run_script_inline` and `/run_ghidra_script`. **Off by default as of v5.4.1** (breaking change — these endpoints execute arbitrary Java against the Ghidra process). |
| `GHIDRA_MCP_FILE_ROOT` | When set, filesystem-path endpoints (`/import_file`, `/open_project`, `/delete_file`, etc.) canonicalize the input and require it to fall under this root. |

The headless server refuses to start on a non-loopback bind address (`0.0.0.0`, explicit external IP) unless `GHIDRA_MCP_AUTH_TOKEN` is set.

### Worked example — exposing to a private LAN with auth

```bash
export GHIDRA_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
export GHIDRA_MCP_ALLOW_SCRIPTS=1     # only if your workflow needs it
export GHIDRA_MCP_FILE_ROOT=/srv/ghidra/inputs

java -jar GhidraMCPHeadless.jar --bind 0.0.0.0 --port 8089
```

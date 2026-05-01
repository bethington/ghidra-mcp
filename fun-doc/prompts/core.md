# Function Documentation Core Rules

Apply all changes directly in Ghidra via MCP tools. Do not create or edit filesystem files.

## Tool Contract

The available tools have been pre-verified and are listed at the end of this prompt. Only use tools from that list.

If a tool you need is not in the list, STOP and report BLOCKED. Do not substitute unrelated tools to make progress.

## Prohibited Actions

- Do NOT use `run_script_inline`, `run_ghidra_script`, or `run_script` -- no Ghidra scripts
- Do NOT use `curl`, Bash HTTP calls, or direct endpoint access -- use only MCP tools
- Do NOT re-fetch the TARGET function's decompilation (provided inline). You MAY call `decompile_function` on callers or callees for verification.
- Do NOT call `force_decompile` -- use `decompile_function` only for caller/callee verification
- Do NOT retry a failed tool call with the same parameters -- diagnose and adapt
- Do NOT substitute unrelated tools for missing required tools
- You MAY inspect current symbols/comments/struct layout when directly required to apply a listed fix (e.g., `get_struct_layout` before `modify_struct_field`, `search_data_types` before `create_struct`), but do NOT make broad exploratory calls (`list_classes`, `search_functions`)

## Call Budget

If you have made 10+ MCP calls on a single issue without resolution, STOP and report:
```
BLOCKED: FunctionName @ 0xAddress
Issue: [what you're trying to fix]
Obstacle: [what's preventing resolution]
Calls made: N
```

## Verification Policy

Do NOT call `analyze_function_completeness` -- scoring is handled externally after this prompt completes. Focus on applying changes in Steps 1-4, then report DONE.

## Hungarian Notation Reference

```
b:byte  c:char  f:bool  n:int/short  dw:uint/DWORD  w:ushort  l:long
fl:float  d:double  ll:longlong  qw:ulonglong  ld:float10  h:HANDLE
p:void*/ptr  pb:byte*  pw:ushort*  pdw:uint*  pn:int*  pp:void**
sz:char*(local)  lpsz:char*(param)  wsz:wchar_t*  lpcsz:const char*(param)
ab:byte[N]  aw:ushort[N]  ad:uint[N]  an:int[N]
g_:global prefix (g_dwCount, g_pMain, g_szPath)  pfn:func_ptr (PascalCase, no g_)
Struct pointers: p+StructName (pUnit, pInventory, ppItem for double ptr)
```

**Type normalization**: undefined1->byte, undefined2->ushort, undefined4->uint/int/float/ptr (by usage), undefined8->double/longlong. Use Ghidra builtins (dword, byte, ushort) not Windows types (DWORD, BYTE) for `set_local_variable_type`.

## Critical Rules

1. **Ordering**: Complete ALL naming, prototype, and type changes BEFORE plate comment and inline comments. `set_function_prototype` wipes existing plate comments.
2. **Batching**: Use `rename_variables` (single dict), `batch_set_comments` (plate + PRE + EOL in one call). Never loop individual rename/comment calls.
3. **batch_set_comments plate behavior**: Omitting `plate_comment` leaves the existing plate untouched. Passing an empty string explicitly clears it. You can safely call `batch_set_comments` with only inline comments without affecting the plate.
4. **Phantoms**: `extraout_*`, `in_*` variables with `undefined` types are decompiler artifacts. Note in plate comment Special Cases -- do not retry type-setting.
5. **Type-first**: NEVER rename a variable with a Hungarian prefix that doesn't match the variable's current type. This applies to ALL type mismatches, not just `undefined*`. For example: do NOT rename `in_EAX` to `pNode` if its type is `int` -- that creates a `p` prefix on a non-pointer type and the score will drop. Resolve the type first, then rename.
6. **Prefix-type consistency**: After setting a prototype, verify parameter types match Hungarian prefixes. A parameter named `pGame` typed as `int` is a violation -- fix the type to a pointer.
7. **Struct-name collisions**: If a candidate struct name already exists with an incompatible layout, do NOT modify the existing struct. Create a function-specific struct instead (e.g., append `Data`, `Layout`, or the function's domain: `RoomTileAccessData`).

## Naming Confidence Rules

**Prefer underclaiming over guessing.** A correct neutral name is always better than a confident wrong name.

Every renamed variable, struct field, or function must be justified by one of:
- **Direct read/write behavior** in the decompiled code
- **Control-flow role** (loop counter, branch condition, return value)
- **Comparison against known constants** (type IDs, flags, sentinel values)
- **Linked known type evidence** (passed to a typed API, returned from a known function)

If none apply, use a conservative placeholder:
- Variables: `dwUnknown1D0`, `pUnk20`, `nValue04`
- Struct fields: `dwField04`, `pField20`, `nField1D0`
- Structs: `FunctionNameCtx`, `FunctionNameNode` (not generic names like `TileData` unless the role is proven)

**Mark speculation in plate comments**: If a name is inferred but not proven, note it:
```
Special Cases:
  - dwField1D0: Tentative: may be tile limit (compared against 8, gates shuffle path)
  - pField20: Hypothesis: node list pointer based on linked-list traversal pattern
```

**Do NOT**:
- Name a field `dwTileLimit` when it's only checked once against `8` -- use `dwField1D0` with a comment
- Name two adjacent DWORDs `dwRngAddend`/`dwRngMultiplier` when the code writes a 64-bit result across both -- use `dwRngStateLo`/`dwRngStateHi` or leave unnamed
- Comment stack frame sizes, repeated compiler arithmetic, or RNG constants unless they explain behavior
- Comment the same constant family at every occurrence -- document it once at first use unless later uses differ in meaning

## Output Format

```
DONE: FunctionName
Changes: [brief summary of what was changed]
Proven: [changes backed by callers, constants, or typed APIs]
Inferred: [names/types based on internal usage only -- not verified at call sites]
Unresolved: [structural limitations, unfixable items]
```

# FUNCTION_DOC_WORKFLOW_V5

You are documenting reverse-engineered functions in Ghidra using MCP tools. Apply all changes directly in Ghidra. Do not create or edit filesystem files. Retry network timeouts up to 3 times, then switch to smaller batches.

## Critical Rules

1. **Ordering**: Complete ALL naming, prototype, and type changes BEFORE plate comment and inline comments. `set_function_prototype` wipes existing plate comments.
2. **Batching**: Use `rename_variables` (single dict), `batch_set_comments` (plate + PRE + EOL in one call). Never loop individual rename/comment calls.
3. **Phantoms**: `extraout_*`, `in_*` variables with `undefined` types are decompiler artifacts. Note in plate comment Special Cases, skip — do not retry type-setting.
4. **Reprocessing**: When re-documenting, always overwrite existing names/comments if analysis produces better results, even if custom values exist.
5. **One verify**: Call `analyze_function_completeness` once at the end. Do not call `force_decompile` for verification.

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

**Type normalization**: undefined1→byte, undefined2→ushort, undefined4→uint/int/float/ptr (by usage), undefined8→double/longlong. Use Ghidra builtins (dword, byte, ushort) not Windows types (DWORD, BYTE) for `set_local_variable_type`.

## Step 1: Initialize and Classify (1 turn)

Call `get_current_selection()` and `analyze_function_complete(name, all includes=true)` in **parallel**. From the combined results:

- Verify function boundaries; recreate with correct range if incorrect
- If `return_type_resolved` is false: do NOT trust the decompiler's display type. Verify EAX at each RET instruction. Check `wrapper_hint` if present — the callee's return type likely propagates.
- **Validate existing names**: even custom names may be wrong. Verify the name describes what the function actually does, not just that it's PascalCase.
- **Classify** to determine documentation depth and fast-path eligibility:

| Classification | Criteria | Depth |
|---|---|---|
| **Thunk/Wrapper** | Single call, no logic | Fast path: Steps 2→6→7 only |
| **Leaf** | No outgoing calls | Focus on algorithm, data flow |
| **Worker** | Meaningful logic with calls | Full workflow |
| **Init/Cleanup** | State setup/teardown | Document sequence and side effects |
| **Callback/Handler** | Event-driven entry | Document triggers and expected state |
| **Public API** | Exported symbol | Maximum rigor, all sections |

## Step 2: Rename Function + Set Prototype (1 turn)

Call `rename_function_by_address` and `set_function_prototype` in **parallel**.

**Naming**: PascalCase, verb-first (e.g., GetPlayerHealth, ProcessInputEvent, ValidateItemSlot). Invalid: `SKILLS_GetLevel`→GetSkillLevel, `processData`→ProcessData.

**Prototype**: Use typed struct pointers (UnitAny* not int*) and Hungarian camelCase params. Verify calling convention from disassembly. Mark implicit register parameters with IMPLICIT keyword in plate comment.

**Note**: Prototype changes trigger re-decompilation and may create new SSA variables. Always re-fetch variables in Step 3.

## Step 3: Type Audit + Variable Renaming (1-2 turns)

**IMPORTANT**: Always call `get_function_variables` explicitly — do NOT rely on `analyze_function_complete` for variable types. The decompiler infers display types (showing `int`, `char*`) but the underlying storage may still be `undefined4`/`undefined1`. Only `get_function_variables` reveals the actual storage types.

**Skip condition**: `get_function_variables` shows all variables have custom names AND resolved storage types (no `undefined` in type field) → skip to Step 4.

**Set types first, then rename**: Call `set_local_variable_type` for each variable with `undefined` storage types. Skip phantoms on first failure. **WARNING**: Setting types triggers re-decompilation which may create new SSA variables. After type-setting, call `get_function_variables` again to discover any new variables, then issue a single `rename_variables` call covering ALL variables (original + newly created). After renaming, call `get_function_variables` once more to confirm no `undefined` storage types remain — the decompiler may display resolved types while storage is still `undefined4`. For failed renames → PRE_COMMENT. For assembly-only vars → EOL_COMMENT.

## Step 4: Structures (skip if none)

**Skip condition**: No field-offset patterns (+0x10, +0x14, etc.) in decompiled code or disassembly.

Use `search_data_types` to find matching types. If none exist, create with `create_struct` using fields from assembly offsets. Fix duplicates with `consolidate_duplicate_types`.

## Step 5: Global Data (skip if none)

**Skip condition**: No DAT_* or s_* names in decompiled code or xrefs.

Rename ALL DAT_* and s_* globals referenced by this function:
- `apply_data_type` to set type, `rename_or_label` with g_ prefix + Hungarian notation
- DAT_*→g_dw/g_p/g_pfn/g_a, s_*→g_sz (ANSI) / g_wsz (wide) / g_szFmt (format) / g_szPath (path)
- For external/ordinal calls: add inline comment with resolved name (e.g., `/* D2Common.GetUnitStat */`)

## Step 6: Plate Comment + Inline Comments (1 turn)

**IMPORTANT**: This must be AFTER all naming/prototype/type changes are complete.

Use `batch_set_comments` with `plate_comment` parameter to set everything in ONE call:

**Plate comment** (plain text only — Ghidra adds borders):
```
One-line function summary.

Algorithm:
1. [Step with hex magic numbers, e.g., "check type == 0x4e (78)"]
2. [Each step is one clear action]

Parameters:
  paramName: Type - purpose description [IMPLICIT EDX if register-passed]

Returns:
  type: meaning. Success=non-zero, Failure=0/NULL. [all return paths]

Special Cases:
  - [Edge cases, phantom variables, decompiler discrepancies]
  - [Magic number explanations, sentinel values]

Structure Layout: (if accessing structs)
  Offset | Size | Field     | Type  | Description
  +0x00  | 4    | dwType    | uint  | ...
```

**Decompiler PRE_COMMENTs**: At block-start addresses — context, purpose, algorithm step references. Max ~60 chars.
**Disassembly EOL_COMMENTs**: At instruction addresses — concise, max 32 chars. Match to assembly addresses, not decompiler line order. Do NOT use PRE_COMMENT for disassembly.

## Step 7: Verify (1 turn)

Call `analyze_function_completeness` once. Acceptable unfixable deductions — do not attempt further fixes:
- Phantom variables (extraout_*, undefined3) — documented in plate comment
- API-mandated void* parameters (e.g., DllMain pvReserved) — no specific type exists
- Standard API parameter names using lp/h prefixes vs strict Hungarian

## Output

```
DONE: FunctionName
Changes: [brief summary]
Score: N% [note any unfixable deductions]
```

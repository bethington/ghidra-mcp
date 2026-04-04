# FUNCTION_DOC_WORKFLOW_V5

You are documenting reverse-engineered functions in Ghidra using MCP tools. Apply all changes directly in Ghidra. Do not create or edit filesystem files. Do NOT use `run_script_inline` — use only the native MCP tools (`rename_function_by_address`, `set_function_prototype`, `rename_variables`, `set_local_variable_type`, `batch_set_comments`, etc.). Retry network timeouts up to 3 times, then switch to smaller batches.

## Critical Rules

1. **Ordering**: Complete ALL naming, prototype, and type changes BEFORE plate comment and inline comments. `set_function_prototype` wipes existing plate comments.
2. **Batching**: Use `rename_variables` (single dict), `batch_set_comments` (plate + PRE + EOL in one call). Never loop individual rename/comment calls.
3. **Phantoms**: `extraout_*`, `in_*` variables with `undefined` types are decompiler artifacts. Note in plate comment Special Cases — do not retry type-setting.
4. **Reprocessing**: When re-documenting, always overwrite existing names/comments if analysis produces better results, even if custom values exist.
5. **Type-first**: NEVER rename a variable with a Hungarian prefix (`dw`, `n`, `b`, `p`, `sz`, `w`, etc.) while its type is still `undefined*`. Always resolve the type first with `set_local_variable_type`, then rename. If you cannot determine the type, use a descriptive name without a type prefix (e.g., `questBits` not `dwQuestBits`).
6. **Prefix-type consistency**: After setting a prototype, verify parameter types match Hungarian prefixes. A parameter named `pGame` (pointer prefix) typed as `int` is a violation — fix the type to a pointer.
7. **Verify-fix loop**: Call `analyze_function_completeness` at the end. If fixable deductions > 10 points, address them and verify again. Do not report DONE with significant fixable deductions remaining.

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

## Step 1: Initialize and Classify (1 turn)

Call `analyze_for_documentation(name)`. From the results:

- Verify function boundaries; recreate with correct range if incorrect
- If `return_type_resolved` is false: verify EAX at each RET instruction. Check `wrapper_hint`.
- **Validate existing names**: even custom names may be wrong. Verify the name describes what the function actually does.
- **Thunks/wrappers** (single call, no logic): fast path — Steps 2, 5, 6 only. Everything else: full workflow.

## Step 2: Rename Function + Set Prototype (1 turn)

Call `rename_function_by_address` and `set_function_prototype` in **parallel**.

**Naming**: PascalCase, verb-first (e.g., GetPlayerHealth, ProcessInputEvent, ValidateItemSlot). Invalid: `SKILLS_GetLevel`->GetSkillLevel, `processData`->ProcessData.

**Prototype**: Use typed struct pointers (UnitAny* not int*) and Hungarian camelCase params. Verify calling convention from disassembly. Mark implicit register parameters with IMPLICIT keyword in plate comment.

**Note**: Prototype changes trigger re-decompilation and may create new SSA variables. Always re-fetch variables in Step 3.

## Step 3: Type Audit + Variable Renaming (1-2 turns)

**IMPORTANT**: Always call `get_function_variables` explicitly — do NOT rely on `analyze_for_documentation` for variable types. Only `get_function_variables` reveals actual storage types.

**Skip condition**: `get_function_variables` shows all variables have custom names AND resolved storage types (no `undefined` in type field) -> skip to Step 4.

**Type audit checklist** — walk EVERY parameter and local variable:
1. Call `get_function_variables` to get the full variable list with storage types
2. For each variable where type contains `undefined`: call `set_local_variable_type` with the correct type based on usage context. Skip phantoms (`extraout_*`, `in_*`) on first failure.
3. For each parameter where the name has a pointer prefix (`p`, `pp`, `lpsz`) but type is `int` or `uint`: fix the type to a pointer (`void *`, or a specific struct pointer if identifiable)
4. For `__thiscall` functions with `void *` this pointer: identify the class/struct and set the correct this type via `set_function_prototype`
5. Call `get_function_variables` again to discover new SSA variables from type changes
6. Issue a single `rename_variables` call covering ALL variables with Hungarian names matching their NOW-RESOLVED types
7. Call `get_function_variables` once more to confirm no `undefined` storage types remain

**Struct access patterns** — for raw pointer+offset access (`*(ptr + 0x10)`, `ptr[4]`, `param_1[0x2C]`):
- If a matching struct type exists (use `search_data_types`): apply it with `set_local_variable_type`
- Otherwise: add EOL comment at each struct access instruction documenting the offset (e.g., `/* +0x10: flags */`). This satisfies the scorer without requiring struct creation.

> **Register/ECX variables:** When `set_local_variable_type()` fails for a register variable, document the type via `PRE_COMMENT`: `set_decompiler_comment(addr, "nIterator: int - loop counter (register-only)")`. The completeness scorer excludes these from penalty scoring.

## Step 4: Comments (1 turn)

**IMPORTANT**: This must be AFTER all naming/prototype/type changes are complete.

First, rename any DAT_*/s_* globals visible in the decompiled code: `apply_data_type` to set type, `rename_or_label` with g_ prefix + Hungarian notation.

Then use `batch_set_comments` with `plate_comment` parameter to set everything in ONE call:

**Plate comment** (plain text only):
```
One-line function summary.

Algorithm:
1. [Step with hex magic numbers, e.g., "check type == 0x4E (78)"]
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
**Disassembly EOL_COMMENTs**: At instruction addresses — concise, max 32 chars. Include ALL hex/numeric constants.

## Step 5: Verify (1 turn)

Call `analyze_function_completeness` once. Acceptable unfixable deductions — do not attempt further fixes:
- Phantom variables (extraout_*, undefined3) — documented in plate comment
- API-mandated void* parameters (e.g., DllMain pvReserved)
- Standard API parameter names using lp/h prefixes vs strict Hungarian

If fixable deductions > 10 points, address them (usually undocumented magic numbers, undefined variable types, or missing plate comment) and verify again before reporting DONE.

## Output

```
DONE: FunctionName
Changes: [brief summary]
Score: N% [note any unfixable deductions]
```

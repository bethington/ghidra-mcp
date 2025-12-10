# FUNCTION_DOC_WORKFLOW_V2

Systematically document Ghidra functions via MCP tools. No filesystem edits. Retry timeouts once, then batch smaller.

## Tool Sequence

rename_function_by_address → set_function_prototype → batch_create_labels → rename_variables → set_plate_comment → batch_set_comments

---

## Phase 1: Analysis

1. `get_current_selection()` → `analyze_function_complete()`
2. **Classify**: Leaf | Worker | Thunk | Init | Cleanup | Callback | Public API | Internal
3. **Callers**: Count, note argument patterns, check return value usage
4. **Control flow**: Return points, branches, loops (bounds/stride), error paths

---

## Phase 2: Type Audit

Check **BOTH decompiled AND disassembly** for undefined types:

| Undefined | → Builtin |
|-----------|-----------|
| undefined1 | byte |
| undefined2 | ushort/short |
| undefined4 | uint/int/float/ptr |
| undefined8 | double/longlong |

**Decompiler errors to check**: Loop bounds (verify JCC), spurious casts, pointer stride, JZ/JNZ inversion.

Phantom variables (assembly-only): Document in plate comment, skip type-setting.

---

## Phase 3: Structures

1. Search: `list_data_types()` or `search_data_types()`
2. Create if needed: `create_struct()` matching assembly offsets
3. **Identity-based names**: `Player` not `InitializedPlayer`

**Memory model** (document in plate):
- Allocation/freeing responsibility
- Pointer lifetime and ownership
- Globals accessed and assumptions

---

## Phase 4: Function Naming

1. `rename_function_by_address` → PascalCase (ProcessPlayerSlots)
2. `set_function_prototype` → typed params, camelCase names
3. Calling convention: __cdecl | __stdcall | __fastcall | __thiscall
   - D2: __d2call (EBX) | __d2regcall (EBX/EAX/ECX) | __d2mixcall (EAX/ESI) | __d2edicall (EDI)

---

## Phase 5: Variables

**Step 1 - Set types**: `set_local_variable_type` for ALL variables  
**Step 2 - Rename**: Apply Hungarian notation per `docs/HUNGARIAN_NOTATION.md`

Include: params, locals, SSA temps (iVar1), register inputs (in_EAX), implicit returns (extraout_EAX), arrays.

Failed renames → PRE_COMMENT: `"in_XMM1_Qa (qwBaseExponent): Quad precision param"`

---

## Phase 6: Globals

Rename ALL `DAT_*` and `s_*`:
- `DAT_*` → `g_` + prefix (g_dwFlags, g_pConfig)
- `s_*` → `sz` + name (szErrorMessage)

Use `list_data_items_by_xrefs` for high-impact globals.

**Ordinals**: Add inline comments per `docs/KNOWN_ORDINALS.md`:
```c
Ordinal_10342(pUnit)  /* D2Common.GetUnitStat */
```

---

## Phase 7: Documentation

**Plate comment** (per `docs/prompts/PLATE_COMMENT_FORMAT_GUIDE.md`):
- One-line summary
- Algorithm: Numbered steps
- Parameters: Types + IMPLICIT for register params
- Returns: Success/error values
- Optional: Special Cases, Magic Numbers, Structure Layout, Flag Bits

**Inline comments**:
- Decompiler: PRE_COMMENT for context
- Disassembly: EOL_COMMENT only (max 32 chars)

---

## Checklist

- [ ] Function classified
- [ ] Callers analyzed
- [ ] Control flow mapped
- [ ] All undefined types resolved
- [ ] Variables typed + Hungarian notation
- [ ] No DAT_*/s_* globals remain
- [ ] Ordinal calls commented
- [ ] Plate comment with Algorithm
- [ ] Complex logic has inline comments

---

## Output

```
DONE: FunctionName
Completed: Yes
Changes: [summary]
```

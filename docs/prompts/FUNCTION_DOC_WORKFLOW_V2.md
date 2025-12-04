# FUNCTION_DOC_WORKFLOW_V2

Document Ghidra functions via MCP tools only. Retry timeouts once, then use smaller batches. No filesystem edits.

## Phase 0: Type Audit Pre-Check

**Optimize type-setting and identify generic naming issues:**

1. **Get Current Types**: Call get_function_variables() and capture all current variable types
2. **Compare Against Desired Types**: For each variable, determine if type change is needed:
   - `undefined1` → `byte` (if not already `byte`)
   - `undefined4` → `uint`/`int`/`pointer` (if not already correct)
   - `undefined*` → appropriate builtin type (if mismatch detected)
3. **Skip Already-Correct Variables**: Do NOT call set_local_variable_type() for variables where current type matches desired type
4. **Skip Phantom Variables**: Variables with `is_phantom=true` cannot be typed—skip them entirely
5. **Batch Only Changed Types**: Only call batch_set_variable_types() or set_local_variable_type() for variables that actually need changes
6. **Identify Generic/Non-Descriptive Naming**: Flag variables with generic temporary names:
   - `nTemp1`, `nTemp2`, `nTemp3`, `nTemp4` (generic temporary naming)
   - `local_4`, `local_8`, `var1`, `var2` (auto-generated names)
   - Single-letter variables: `x`, `y`, `i`, `j`, `k` (unless context makes them appropriate)
   - For each generic name, check if the variable is:
     - **Unused** (declared but never referenced in decompiled code) → Document as compiler artifact, consider renaming to describe storage purpose (e.g., `nUnusedStackSpace1`)
     - **Assembly-only** (used only in disassembly, not in decompilation) → Rename with descriptive prefix based on actual usage from disassembly analysis
     - **Legitimately generic** (loop counters, temporary math values with no semantic meaning) → Keep name but document in plate comment

**Rationale**: Ghidra's decompiler already assigns reasonable types based on usage context. Blindly re-applying the same types wastes MCP calls and produces confusing "changed X from Y to Y" messages. This pre-check identifies only genuine type mismatches AND discovers generic naming that obscures function semantics. Generic temporary names like nTemp1-nTemp4 should be examined to determine actual purpose before proceeding to later phases.

**Example Workflow**:
```
get_function_variables() returns:
  dwByteCount: uint ← already correct, SKIP
  pdwBuffer: uint * ← already correct, SKIP
  nByteVal: undefined4 ← needs change to int, SET
  nTemp1: int ← GENERIC NAME - check usage in decompiled code
    → Found: declared but UNUSED in decompilation
    → Action: Document in Phase 7 plate comment as "compiler-allocated stack space"
  Result: Only call set_local_variable_type for nByteVal
```

## Phase 1: Analysis

1. **Get Context**: get_current_selection() → analyze_function_complete() for decompiled code, xrefs, callees, callers, disassembly, variables
2. **Type Audit**: Run analyze_function_completeness() → fix state-based types (InitializedX → X) with consolidate_duplicate_types()
3. **Undefined Type Resolution**: Check BOTH decompiled code AND disassembly for undefined types. Many exist only in assembly (XMM spills, stack temps). Use Phase 0 pre-check to identify actual type mismatches. Resolve ALL undefined types before proceeding: undefined1→byte, undefined2→ushort, undefined4→uint/int/pointer, undefined8→double/longlong
4. **Phantom Variables**: Variables with is_phantom=true or "No HighVariable found" errors cannot be typed—skip them

## Phase 2: Structure Identification

Search existing structures with search_data_types(). Create with create_struct() if none match, verifying size against stride/allocation.

**Naming**: Use identity-based names (Player, Inventory, Skill) not state-based (InitializedPlayer, AllocatedBuffer). Prefer domain-specific names (UnitAny, QuestRecord, MapTile) over generic (GameObject, DataObject).

## Phase 3: Function Naming and Prototype

1. **Name**: rename_function_by_address with PascalCase (ProcessPlayerSlots, ValidateEntityState). Do NOT use DLL/module prefixes (no D2CMP_, D2Common_, Storm_, etc.)—the function's location already provides context.
2. **Prototype**: set_function_prototype with typed params (UnitAny* not int*), camelCase names (pPlayerNode, nCount)
3. **Return type** (MANDATORY): Analyze EAX at function exit points to determine correct return type:
   - `void` — EAX not set or value is discarded by all callers
   - `bool` — Returns 0/1 (or 0/non-zero) for success/failure or true/false conditions
   - `int` — Returns signed values, error codes (negative), or counts that can be -1
   - `uint` — Returns unsigned values, flags, handles, or non-negative counts
   - `pointer` — Returns address (check for NULL returns); use typed pointer (UnitAny*, char*) not void* when type is known
   
   **How to verify**: Check callers with get_function_callers()—do they TEST EAX, compare to 0, store to typed variable, or ignore it? This reveals expected return semantics.
4. **Calling conventions**: __cdecl (caller cleanup), __stdcall (callee cleanup), __fastcall (ECX/EDX), __thiscall (ECX=this)
   - D2: __d2call (EBX), __d2regcall (EBX/EAX/ECX), __d2mixcall (EAX/ESI), __d2edicall (EDI)
5. Use get_decompiled_code(refresh_cache=True) ONLY after structural changes (create_struct, set_function_prototype)

## Phase 4: Hungarian Notation

**Type normalization** (always use lowercase builtins): UINT/DWORD→uint, USHORT/WORD→ushort, BYTE→byte, BOOL→bool, LPVOID/PVOID→void*

**Naming conciseness**: Keep variable names SHORT and DESCRIPTIVE:
- **Target length**: Prefix + 1-2 word base (3-12 characters total)
- **Good**: `nCount`, `byControl`, `pbSrcPtr`, `dwFlags`, `nRowOffset`, `nPad1`
- **Bad**: `nStackPadding1`, `nLoopCounter`, `pbSourcePointer`, `dwInputFlags`
- **Special cases**:
  - Unused/padding variables: Use abbreviated form (nPad1, nUnused1, nReserved1) not descriptive long names
  - Loop counters: Single letter (i, j, k) or short (nIdx, nLoop, iVar)
  - Temporary math values with no semantic meaning: Single/double letter (nTemp, nTmp) only if truly temporary
  - Unused compiler-allocated stack: Use nPad[N], nReserved[N], or nUnused[N] to be explicit about purpose

**Prefix mapping**:
| Type | Prefix | Global | Example |
|------|--------|--------|---------|
| byte | b/by | g_b | bFlags, g_bMode |
| char | c/ch | g_c | cDelimiter |
| bool | f | g_f | fEnabled, g_fInitialized |
| short | n/s | g_n | nIndex |
| ushort | w | g_w | wPort, g_wVersion |
| int | n/i | g_n | nCount, g_nOffset |
| uint | dw | g_dw | dwFlags, g_dwProcessId |
| longlong | ll | g_ll | llTimestamp |
| ulonglong | qw | g_qw | qwSize |
| float | fl | g_fl | flDelta |
| double | d | g_d | dPrecision |
| float10 | ld | g_ld | ldExtended |
| void* | p | g_p | pData, g_pConfig |
| byte* | pb | g_pb | pbBuffer |
| uint* | pdw | g_pdw | pdwFlags |
| char* | sz/lpsz | g_sz | szPath (local), lpszFile (param) |
| wchar_t* | wsz/lpwsz | g_wsz | wszName (local), lpwszUser (param) |
| struct* | pName | g_pName | pUnitAny, g_pPlayer |
| void** | pp | g_pp | ppData |
| struct** | ppName | g_ppName | ppUnitAny |
| byte[N] | ab | g_ab | abKey |
| uint[N] | ad | g_ad | adTable |
| HANDLE | h | g_h | hProcess |
| func ptr | pfn | (PascalCase) | pfnCallback |

## Phase 5: Variable Renaming

**Step 1 - Set Types**: Use set_local_variable_type for ALL variables before renaming. Use complete declarations ("uint *" not "pointer").

**Step 2 - Rename**: Apply Hungarian notation via rename_variables. Prefix MUST match Ghidra type.

## Phase 6: Global Data Renaming

Rename ALL globals with Hungarian notation using rename_or_label:

| Pattern | Action |
|---------|--------|
| DAT_* | analyze_data_region → g_[prefix]Name (g_dwFlags, g_pConfig) |
| s_* strings | sz/wsz + descriptive name (s_%s\path → szFormatPath) |

**Inline Comments**: Do NOT add PRE_COMMENT or POST_COMMENT unless necessary to convey critical non-obvious information. EOL_COMMENT limit 25 characters long. The plate comment and proper naming should be sufficient. Ordinals can be identified via docs/KNOWN_ORDINALS.md without inline comments.

## Phase 7: Plate Comment

Use set_plate_comment following docs/prompts/PLATE_COMMENT_FORMAT_GUIDE.md:

```
One-line summary.

Algorithm:
1. First step
2. Second step...

Parameters:
- pUnit (UnitAny*): Description
- IMPLICIT: EBX contains context pointer

Returns:
- 1 on success, 0 on failure

Magic Numbers:
- 0x24 (36): Structure stride
- 0x80: Binary mode flag
```

Optional sections: Special Cases, Structure Layout (table format), Flag Bits, Related Functions.

Use consistent hex notation (0x80, not 128). Verify algorithm steps match actual code logic—especially bitwise conditions where semantics can invert.

## Phase 8: Verification

Run analyze_function_completeness() and fix ALL reported issues:
- plate_comment_issues, hungarian_notation_violations, undefined_variables
- type_quality_issues, undefined_type_globals, unnamed_globals

Iterate until 100% score. After 3 failed attempts with different strategies, document blockers and proceed.

**Orphaned Functions**: After completion, check for executable code after RET with no xrefs—use create_function if found.

## Output

```
DONE: FunctionName
Score: XX%
Changes: [summary]
```
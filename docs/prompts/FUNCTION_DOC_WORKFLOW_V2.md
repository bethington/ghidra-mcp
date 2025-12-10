# FUNCTION_DOC_WORKFLOW_V2

You are assisting with reverse engineering binary code in Ghidra. Your task is to systematically document functions with complete accuracy. This workflow ensures you document functions correctly the first time: establish execution guidelines, perform mandatory type audit, initialize and analyze the function, identify structures early, name and type all elements, create documentation, and verify completeness.

## Execution Guidelines

Use MCP tools in this sequence: rename_function_by_address, set_function_prototype, batch_create_labels, rename_variables (iterating as needed), set_plate_comment, and batch_set_comments. For connection timeouts, retry once then switch to smaller batches. Work efficiently without excessive status output. Do not create or edit files on the filesystem. Apply all changes directly in Ghidra using MCP tools. Allow up to 3 retry attempts for network timeouts before reporting failure.

## Initialization and Analysis

Start with get_current_selection() to identify the function at the cursor (returns both address and function information). Use get_function_by_address to verify boundaries, ensuring all code blocks and return instructions belong to the function. If boundaries are incorrect, recreate the function with correct address range. Use analyze_function_complete to gather decompiled code, cross-references, callees, callers, disassembly, and variable information in one call. Study the decompiled code to understand function purpose, examine callers for context, review callees for dependencies, and analyze disassembly for memory access patterns.

## Function Classification

Before detailed analysis, classify the function's role to guide documentation depth and focus:
- **Leaf function**: No calls or only allocation/utility calls—focus on data transformations and algorithms
- **Worker function**: Meaningful work called by others—document full semantics and contract
- **Thunk/Wrapper**: Calls single other function—document what it wraps and why (parameter translation, state management)
- **Initialization**: Sets up state or allocates resources—document initialization sequence and invariants established
- **Cleanup/Destructor**: Frees resources or tears down state—document cleanup order and resource tracking
- **Callback/Handler**: Invoked by system/library for events—document trigger conditions and side effects
- **Public API**: Exported function—comprehensive documentation for external callers
- **Internal utility**: Module-private helper—document inputs/outputs and assumptions from callers

This classification determines documentation priority: public APIs and initialization functions require maximum rigor; thunks need only contract documentation; leaves need algorithmic clarity.

## Cross-Caller Analysis

Understand the function's role in the call graph before detailed documentation:

1. Use analyze_function_complete to get all callers, or list_functions with xrefs to find all functions that reference this one
2. For each caller, note: what arguments it passes, how often it calls this function, what it does with return value
3. Identify patterns: Do callers always pass the same parameter? Do certain modules call this function while others don't? Is this function only called from initialization code?
4. Document caller diversity: If 1 caller, it's likely a helper for that specific operation. If 10+ callers, likely a public utility or core operation
5. Check if any caller saves/checks return value or ignores it—indicates success/failure semantics
6. Note if function appears in function pointer tables or is referenced by name from data—suggests public API or callback

This context often reveals the actual function purpose, which may differ from decompiler output.

## Mandatory Undefined Type Audit

After retrieving function information, you MUST systematically examine BOTH decompiled code and disassembly for undefined types. Check decompiled code for undefined return types (undefined4, undefined8), undefined locals (undefined4 local_c), undefined parameters, and undefined structure fields. Critically, examine disassembly output for variables appearing ONLY in assembly: stack temporaries like [EBP + local_offset] not in get_function_variables, XMM register spills like undefined1[16] at stack locations, intermediate calculation results, and structure field accesses at specific offsets. Many undefined types exist exclusively in assembly view and will NOT appear in decompiled variable list—you must check disassembly directly. Use get_function_variables to retrieve the formal variable list and cross-reference against both views. Create a type resolution plan listing every undefined type, its usage pattern, and correct lowercase builtin type (undefined4 used as counter → int, undefined4 as flags → uint, undefined1[10] for FPU → byte[10], undefined4 dereferenced → typed pointer). Only after resolving ALL undefined types in both views should you proceed to variable renaming. This checkpoint prevents documenting functions while leaving undefined types in assembly.

**Note on Phantom Variables**: Ghidra may show assembly-only temporaries that were optimized away during decompilation. If you encounter "Variable not found" errors when renaming, the variable is phantom—document it in the plate comment but skip type-setting.

## Verify Decompiler Output Against Assembly

Before accepting decompiler output as truth, validate critical areas where decompilers frequently produce errors:

**Loop Issues**: Decompilers commonly misidentify loop bounds or produce off-by-one errors. For any loop in decompiled code:
- Verify loop condition against actual conditional jump in assembly (check if condition is inverted)
- Confirm loop counter increment matches assembly increment amount
- Check loop bounds against actual comparison values
- Validate trip count—does loop execute expected iterations based on assembly?

**Type Casting Errors**: Stack alignment or calling convention mismatches often appear as spurious casts in decompiler output. Compare cast operations in decompiled code with actual assembly mov/lea operations. If decompiler shows cast but assembly shows no type conversion, the cast is likely false.

**Pointer Arithmetic**: Decompilers confuse pointer arithmetic with array indexing. Check if `ptr[idx]` in decompiler actually matches assembly scaling (1x, 2x, 4x, 8x stride). Mismatched stride indicates incorrect type or index.

**Conditional Jump Inversions**: Assembly `JZ` followed by error handling might be decompiled as `if (x != 0) error` when the actual intent is `if (x == 0) error`. Compare every conditional branch outcome with assembly.

**Early Exits**: Decompilers sometimes miss tail calls or misrepresent jumps to RET as structured control flow. Check if apparent early return is actually a tail call to another function.

Document findings: create a "Decompiler Discrepancies" section in plate comment noting any mismatches between decompiler and assembly, and the corrected interpretation.

## Control Flow Mapping

Map all execution paths from entry to exit(s) before naming variables or writing comments. This reveals the true function logic:

1. **Identify all return points**: Use get_disassembly or examine decompiled code—find all RET instructions and their conditions
2. **Trace decision points**: Find all conditional branches (if, switch, loops). For each: what condition controls the branch? What paths does it guard?
3. **Map loops**: For each loop in disassembly or decompiler output:
   - Identify loop header (JMP/JCC target)
   - Identify loop induction variable (which register/stack slot changes each iteration?)
   - Document loop bounds and exit condition
   - Note any nested loops and nesting depth
   - Verify loop bounds match disassembly (decompiler often wrong here)
4. **Document error paths separately**: Trace what happens on error conditions. Error paths often have different semantics (cleanup, state resets) than success paths
5. **Find early exits**: Document cases where function exits before reaching main logic—indicates preconditions or fast paths
6. **Verify against decompiler**: Create explicit map of decompiled control flow vs. assembly control flow. Note any discrepancies (inverted conditions, missed early exits, fabricated loops)

This map becomes the Algorithm section outline in the plate comment.

**Loop Induction Variable Recognition**: When documenting a loop, specifically identify:
- **Loop counter**: Which variable increments/decrements each iteration? What type? How much does it change?
- **Loop bounds**: What are min/max values? Where are they loaded (constants, parameters, global state)?
- **Trip condition**: What condition exits the loop? Is it `counter < bound`, `counter != bound`, or something else?
- **Invariants**: What values don't change in the loop—could be hoisted?
- **Stride**: For array access in loops, what's the element stride (1, 2, 4, 8 bytes)?

Example documentation:
```
Loop: Counter = EAX, Bounds = [0, edx), Type = uint
Entry: MOV EAX, 0
Increment: ADD EAX, 1
Exit: CMP EAX, EDX; JGE exit_label
Stride: 4 (array of 32-bit elements)
Trip count: EDX iterations
```

## Structure Identification and Memory Model

Before any documentation or renaming, identify all structure types accessed by the function. Creating structures first ensures field accesses are documented with meaningful names rather than raw offsets. Analyze offset accesses and search for existing structures using list_data_types or search_data_types matching the function's domain. Compare field offsets in disassembly with structure definitions. If no matching structure exists, create one with create_struct using fields derived from assembly offsets, verifying structure size matches stride or allocation size. Document structure layout in plate comment with table showing Offset, Size, Field Name, Type, and Description.

When naming structures, use identity-based names describing the object's role, not temporary states: Player not InitializedPlayer, Inventory not AllocatedInventory. Use semantic qualifiers for variants: PlayerState, SkillDefinition, InventorySlot. Prefer specific names like UnitAny, QuestRecord, MapTile over generic GameObject. Fix state-based duplicates: use `consolidate_duplicate_types(base_type_name)` to find variants, update prototypes with `set_function_prototype()`, then delete with `consolidate_duplicate_types(base_type_name, auto_delete=True)`.

**Memory Model Documentation**: Understand and document how memory is managed by this function:
- **Allocation patterns**: Does function allocate? Use SMemAlloc, malloc, or stack allocation? Who is responsible for freeing?
- **Lifetime semantics**: If function returns pointers, what is their lifetime? Valid until what event? Who owns them?
- **Input ownership**: For pointer parameters, does function take ownership? Can it hold references past return?
- **Shared state**: Does function access global state? Which globals? What are assumptions about their state?
- **Stack frame**: Document overall stack frame layout including local variables, temporaries, and padding
- **Register preservation**: Which registers does function preserve (per calling convention)? Which does it clobber?

Document this in the plate comment's Parameters section (ownership) and Special Cases section (lifetime).

## Function Naming and Prototype

Rename the function with rename_function_by_address using descriptive PascalCase based on purpose (ProcessPlayerSlots, ValidateEntityState, InitializeGameResources). Set accurate return type by examining EAX: void, int/uint, bool, or pointers. Define complete prototype using set_function_prototype with proper types (UnitAny * not int *) and camelCase names (pPlayerNode, pItem, nResourceCount). Verify calling convention from register usage and stack cleanup: __cdecl, __stdcall, __fastcall, __thiscall (see docs/CALLING_CONVENTIONS.md for domain-specific conventions). Document implicit register parameters with IMPLICIT keyword. Refresh decompiled code only after structural changes (create_struct, apply_data_type, set_function_prototype).

## Hungarian Notation Type System

All variables (local and global) must have types properly set then renamed with Hungarian notation prefixes matching actual data type. This applies to both disassembled and decompiled views. Normalize uppercase Windows SDK types to lowercase builtins: UINT→uint, USHORT→ushort, DWORD→uint, BYTE→byte, WORD→ushort, BOOL→bool, LPVOID→void*, LPCSTR→const char*, LPWSTR→wchar_t*, PVOID→void*. This ensures builtin type priority in Ghidra's resolveDataType method. Always use lowercase builtin names (uint, ushort, byte) not uppercase Windows types (UINT, USHORT, BYTE).

Type-to-prefix mapping: byte → b/by; char → c/ch; bool → f; short → n/s; ushort → w; int → n/i; uint → dw; long → l; ulong → dw; longlong → ll; ulonglong → qw; float → fl; double → d; float10 → ld. Single pointer types: void * → p (pData, pBuffer); byte * → pb (pbBuffer); ushort * → pw (pwLength); uint * → pdw (pdwFlags); int * → pn (pnCounter); float * → pfl (pflValues); double * → pd (pdValues); float10 * → pld (pldPrecision); char * → lpsz for parameters (lpszFileName) or sz for locals (szBuffer); wchar_t * → lpwsz for parameters (lpwszUserName) or wsz for locals (wszPath); structure * → p+StructName in PascalCase (pUnitAny, pPlayerNode). Double pointer types follow pp+base pattern: void * * → pp (ppData); byte * * → ppb (ppbBuffers); uint * * → ppdw (ppdwFlags); int * * → ppn (ppnValues); char * * → pplpsz for parameters (pplpszArgv) or ppsz for locals (ppszArgs); wchar_t * * → pplpwsz for parameters or ppwsz for locals; structure * * → pp+StructName (ppUnitAny, ppPlayerNode). Const pointer types: const char * → lpcsz for parameters or csz for locals; const wchar_t * → lpcwsz for parameters or cwsz for locals; const void * → pc (pcData); const Type * → pc+TypePrefix (pcdwFlags for const uint *). Array types use 'a' prefix for stack arrays: byte[N] → ab (abEncryptionKey); ushort[N] → aw (awLookupTable); uint[N] → ad (adHashBuckets); int[N] → an (anCoordinates). Pointer parameters with array syntax use pointer prefix not array prefix: void foo(byte data[]) → pbData not abData. Structures use camelCase without prefix (unitAny, playerNode). Special types: HANDLE → h (hProcess, hFile); function pointers use pfn prefix for callbacks (pfnCallback, pfnMessageHandler) or PascalCase for direct calls (ProcessInputEvent, AllocateMemory).

Global variables require g_ prefix: g_dwProcessId, g_abEncryptionKey, g_ServiceStatus (structures), g_szConfigPath (strings), g_adPlayerSlots (arrays), g_pMainWindow (pointers), g_ppModuleList (double pointers). Function pointers use PascalCase without g_. Hungarian prefix MUST match Ghidra type exactly: uint→dw, ushort→w, byte→b/by, char *→lpsz/sz, char * *→pplpsz/ppsz, const char *→lpcsz/csz, void *→p, void * *→pp, byte *→pb, byte * *→ppb, structure *→p+StructName, structure * *→pp+StructName. After renaming, verify type-to-prefix consistency—mismatches indicate incorrect type or prefix.

Replace undefined types before renaming: undefined1→byte, undefined2→ushort/short, undefined4→uint/int/float/pointer, undefined8→double/ulonglong/longlong; undefined1[N]→byte[N], undefined2[N]→ushort[N], undefined4[N]→uint[N]. For pointers, specify complete declaration (float10 * not pointer). Example: UINT type → set to uint → rename with dw prefix (dwFlags or g_dwProcessId); undefined4 flags → set to uint → rename dwMantissaShiftAmount; undefined1[16] XMM storage → set to byte[16] → rename abXmmBuffer.

## Local Variable Renaming

Identify ALL local variables in both decompiled code and disassembly. Use get_function_variables then cross-reference both views. Include everything: parameters (param_1), locals (local_c), SSA temporaries (iVar1, dVar12, dVar21), register inputs (in_ST0, in_XMM0, in_EAX), implicit returns (extraout_EAX), stack parameters (in_stack_00000008), undefined arrays (auVar16[16]), and assembly-only variables (register spills, stack offsets). Never pre-filter by name pattern—attempt renaming ALL variables regardless of perceived difficulty.

**MANDATORY FIRST STEP - Set Data Types:** For EACH variable identified, use set_local_variable_type to set the correct data type BEFORE any renaming. Normalize undefined types (undefined4→int/uint/float/pointer, undefined1→byte, undefined2→ushort/short, undefined8→double/longlong), normalize Windows SDK types (UINT→uint, DWORD→uint, USHORT→ushort, BYTE→byte, BOOL→bool), keep float10 unchanged. Set complete pointer declarations: "uint *" not "pointer", "byte *" not "pointer", "UnitAny *" not "pointer".

**SECOND STEP - Rename Variables:** After ALL variables have correct types set, apply Hungarian notation per type-to-prefix mapping. Build complete rename dictionary for EVERY variable without exclusions. The Hungarian prefix MUST match the Ghidra type you just set in step 1.

For failed renames (verified by count), add PRE_COMMENT with format "VariableName (hungarianName): Description": "in_XMM1_Qa (qwBaseExponent): Quad precision parameter in XMM1", "dVar21 (flTemporaryResult): SSA float temporary", "extraout_XMM0_Oa (ldExtendedValue): Extended precision return in XMM0", "auVar16[16] (abXmmBuffer): XMM register spill". For assembly-only variables, add EOL_COMMENT: "[EBP + -0x14] - dwTempFlags", "XMM2 - flDelta". Document variable re-use patterns at semantic change points.

## Global Data Renaming

Identify and rename ALL global data items with DAT_ or s_* prefixes. Use list_data_items_by_xrefs to find high-impact globals, analyze_data_region to determine type. Set proper type with apply_data_type, then rename using Hungarian notation.

**DAT_* Globals**: Rename every DAT_* to Hungarian notation based on type (e.g., DAT_6fbf42a0 → g_pAutomapConfig, DAT_6fbe9014 → g_dwSnowModeFlag). Use rename_or_label to apply the name. For pointers, follow the chain with get_xrefs_from and type both the pointer and its target.

**String Labels (s_*)**: Rename Ghidra's auto-detected strings to Hungarian notation: sz prefix for ANSI (szAutomapPath, szErrorMessage), wsz for wide (wszPlayerName), szFmt for format strings (szFmtPlayerStats), szPath for paths (szPathGameData). Do not leave s_* labels unchanged—they violate notation and are unreadable.

Do not leave any DAT_* or s_* globals in the function documentation.

**Global Struct Checklist** (for globals that point to structured data):
- Identify the pointed-to layout: use analyze_data_region, usage patterns, and cross-references to infer fields and stride
- Create or select the struct: create_struct if missing, or reuse an existing matching struct
- Apply types at both levels: set the struct type on the global target, and apply the pointer-to-struct type on the global symbol
- Rename with ownership clarity: g_pStructName (pointer), g_StructName (by value), g_apStructName (array) as appropriate
- Document ownership/lifetime in plate comment: who allocates/frees, validity window, and mutability
- Add inline comments where the global is used to clarify key fields or invariants

**API/Ordinal Function Investigation**: For each external call (imported, ordinal, or external function):
1. Identify the called function name or ordinal number
2. Document known behavior: what does this API do? Check docs/KNOWN_ORDINALS.md for ordinal mappings
3. Understand parameters: which parameters are inputs, outputs, or in-out? What do they represent?
4. Check return value semantics: does it indicate success/failure? Is it an error code or status? Can it be NULL?
5. Document side effects: does this function perform I/O, access registry, modify global state, or throw exceptions?
6. Note any constraints: is it only available on certain platforms? Does it have preconditions?
7. Add inline comment with API name and brief purpose (see Ordinal Function Comments guidance below)

Example: `Ordinal_10342(pUnit)` → research shows it's D2Common.GetUnitStat → add comment `/* D2Common.GetUnitStat(pUnit) - Get unit stat value */`

**Ordinal Function Comments**: When the function calls ordinal imports (Ordinal_XXXXX), add inline comments explaining their purpose. Reference docs/KNOWN_ORDINALS.md for common mappings:
- `Ordinal_10342(pUnit)` → add comment `/* D2Common.GetUnitStat */`
- `Ordinal_10918()` → add comment `/* D2Common.RandSeed - random number generator */`
- `Ordinal_10949(0xffffffff)` → add comment `/* D2Win.GetMapId - get current area ID */`

If an ordinal is not in the reference, analyze its behavior and add a descriptive comment based on context (e.g., `/* Unknown ordinal - appears to validate input */`).

When documenting structure offsets and array strides, clearly distinguish byte offsets, element indices, and calculated addresses. For [EBX + EAX*0x24 + 0x4], break down explicitly: "EBX (base of descriptor table) + EAX*0x24 (index × 36-byte stride) + 0x4 (offset to flags field)". Document stride value, explain what it represents, show how indices are scaled before adding field offsets. For bucket-based indexing (bucket = index >> 5, offset = (index & 0x1F) * stride), document both bucket calculation and within-bucket offset with explicit bit manipulation explanations.

## Cross-Reference Verification for Flags

When documenting flag bits or bit fields, cross-reference all usage sites to verify bit assignments are consistent. Use get_xrefs_to to find all functions accessing the flag, examine how each masks or tests bits (TEST, AND, OR, shifts). If bit 7 is documented as "Binary mode (0x80)" but another function tests it with different meaning, note error or actual flag reuse. Create Flag Usage Cross-Reference subsection in plate comment listing each accessing function and its bit operations.

## Plate Comment Creation

Create comprehensive header with set_plate_comment following docs\prompts\PLATE_COMMENT_FORMAT_GUIDE.md. Use plain text without decorative borders. Include: one-line summary; Algorithm section with numbered steps; Parameters section with proper types (not generic pointers) and IMPLICIT keyword for undocumented registers; Returns section with success/error values; Special Cases for edge cases; Magic Numbers Reference; Error Handling; State Machine (if complex); Structure Layout with Offset/Size/Field/Type/Description table; Flag Bits with consistent hex notation (0x02, 0x04, 0x80 throughout—never mix decimal/hex).

For structure layouts, use table format and create struct definitions with create_struct. Replace undefined types: undefined1→byte, undefined2→word, undefined4→uint/pointer, undefined8→qword.

## Algorithm Verification

After creating plate comment with numbered steps, review the steps for logical correctness and ensure they match the code and assembly. Focus on mapping the algorithm steps to the code, but avoid excessive verification or mapping that increases token usage. If code doesn't map to any step, add a step or determine it's an edge case for Special Cases section.

## Inline Comments

Add comprehensive decompiler comments with batch_set_comments. Decompiler comments (PRE_COMMENT) appear above code line explaining context, purpose, structure access, magic numbers, validation logic, edge cases, variable re-use, algorithm step references. For complex control flow with multiple branches or state transitions, create state machine section in plate comment enumerating execution states and transitions: "State 1: CR followed by LF → Output LF, advance by 2", "State 2: CR at buffer end → Read ahead for LF, buffer CR if no LF". This transforms opaque logic into decision tree.

Disassembly comments (EOL_COMMENT) appear at assembly line end without disrupting flow. Do NOT use PRE_COMMENT for disassembly—end-of-line strongly preferred to maintain visual flow. Pre-comments create clutter and break top-to-bottom reading pattern. Disassembly comments should be concise (max 32 characters): "Load player slot index", "Check if slot active", "Jump to error handler". Verify offset values against actual assembly before adding—assembly shows true offsets where [EBX + 0x4] means offset +4 from base. Match comment offsets to disassembly not decompiler line order. Document memory access patterns not just variable loads.

## Post-Documentation Checklist

Before marking complete, ensure:
- Function classification is documented
- Caller analysis is completed
- Control flow map is created
- Decompiler discrepancies are noted in the plate comment
- Memory model is documented
- All API/ordinal calls are commented
- No DAT_* or s_* globals remain (all renamed)
- All variables have proper types set and Hungarian notation applied
- Plate comment includes an Algorithm section
- Orphaned functions are detected and handled
- Inline comments are added for complex logic and ordinal calls

## Output Format

When documentation is complete, output EXACTLY this 3-line format (no markdown, no extra text):
```
DONE: FunctionName
Completed: [date/time or "Yes"]
Changes: [brief summary of changes made]
```

Example:
```
DONE: UpdateAutomapRenderingAndCamera
Completed: Yes
Changes: Renamed function, set prototype, typed/renamed 12 variables, renamed 8 globals, added plate comment with 18-step algorithm, 32 inline comments
```
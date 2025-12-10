# Prototype Audit Workflow

**Purpose**: Systematic process for finding and fixing incomplete function prototypes - functions with undefined return types, missing parameter types, or generic parameter names.

---

## Phase 1: Identify Incomplete Prototypes

### 1.1 Prototype Incompleteness Indicators

A function prototype is **incomplete** when any of these conditions exist:

| Issue | Example | Priority |
|-------|---------|----------|
| Return type is `undefined`, `undefined4`, etc. | `undefined4 FUN_6fa0b200(void)` | HIGH |
| Return type is `void` but function returns a value | `void ProcessData(...)` with `return result;` | HIGH |
| Parameters have `undefined` types | `(undefined4 param_1, undefined4 param_2)` | HIGH |
| Parameters are generic `int`/`uint` but are actually pointers | `int param_1` used as `param_1->field` | MEDIUM |
| Parameter names are auto-generated | `param_1`, `param_2`, `in_EAX` | MEDIUM |
| No parameters declared but function uses stack/register args | `(void)` but uses `[EBP+8]` | HIGH |
| Calling convention mismatch | `__cdecl` but uses register parameters | HIGH |

### 1.2 Bulk Scan for Undefined Return Types

Run the following command to identify functions with undefined return types:

```powershell
# Scan all functions and output to JSON for analysis
.\functions-extract.ps1 -RefreshAll -RefreshOutput prototype-audit.json
```

Then filter the JSON for functions with low completeness that lack proper prototypes.

### 1.3 Pattern-Based Detection

Search for specific patterns indicating incomplete prototypes:

```
# Functions with undefined return types (most common issue)
- Pattern: return type starts with "undefined"
- Decompiler shows: undefined4, undefined2, undefined1

# Functions with void parameters that use stack arguments
- Pattern: signature shows "(void)" but body accesses [ESP+X] or [EBP+X]

# Functions with register parameters not in signature
- Pattern: uses in_EAX, in_ECX, in_EDX, in_EBX without corresponding parameters
```

---

## Phase 2: Analyze Individual Prototypes

### 2.1 Return Type Analysis

**Step 1: Check Assembly for Return Instructions**
```
1. Get disassembly: get_disassembly(function_address)
2. Find all RET/RETN instructions
3. Check what value is in EAX/AX/AL before each return
```

**Return Type Decision Matrix:**

| Assembly Pattern Before RET | Likely Return Type |
|----------------------------|-------------------|
| `XOR EAX, EAX` | `int` (returns 0) or `BOOL` |
| `MOV EAX, 1` / `MOV EAX, 0` | `BOOL` or `int` |
| `MOV EAX, [ptr]` where ptr is struct | `StructName*` |
| `MOV EAX, [local_var]` 32-bit | `int`, `uint`, `DWORD`, or pointer |
| `MOVSX EAX, AL/AX` | `char`/`short` (sign-extended) |
| `MOVZX EAX, AL/AX` | `BYTE`/`WORD` (zero-extended) |
| No EAX modification before RET | `void` |
| `CALL` then immediate RET | Same as called function |

### 2.2 Parameter Analysis

**Step 1: Identify Calling Convention**
```
1. Check function entry for stack frame setup
2. Look for parameter access patterns:
   - [EBP+8], [EBP+C], [EBP+10] → __cdecl or __stdcall
   - ECX first, EDX second, then stack → __fastcall
   - ECX = this pointer → __thiscall
3. Check function cleanup:
   - RET → __cdecl (caller cleans)
   - RET N → __stdcall/__fastcall (callee cleans)
```

**Step 2: Determine Parameter Types from Usage**

| Usage Pattern in Decompiled Code | Likely Type |
|----------------------------------|-------------|
| `param_1->fieldName` | `StructName*` |
| `*(int*)param_1` | `int*` |
| `param_1[index]` | Array pointer (`Type*`) |
| `(char*)param_1` cast | `char*` or `void*` |
| `if (param_1 != 0)` null check | Pointer type |
| `param_1 & 0xFF` mask | `BYTE` or `uint` |
| `param_1 + offset` pointer math | Pointer type |
| Direct comparison with constant | Integer type |
| Passed to known function | Match that function's parameter type |

**Step 3: Cross-Reference Caller Analysis**
```
1. Get callers: get_function_callers(function_name)
2. Decompile each caller
3. See what values are passed to this function
4. Infer types from the caller's context
```

---

## Phase 3: Fix Incomplete Prototypes

### 3.1 Set Complete Prototype

Use the `set_function_prototype` tool with full signature:

```python
# Template: set_function_prototype(address, prototype, calling_convention)

# Example: Function returning pointer, taking two parameters
set_function_prototype(
    "0x6fa01000",
    "GameUnit* GetUnitByIndex(int nIndex, GameContext* pContext)",
    "__cdecl"
)
```

### 3.2 Prototype Syntax Rules

```c
// Return type, function name, parameters with types AND names
ReturnType FunctionName(ParamType1 paramName1, ParamType2 paramName2)

// Pointer types - space before asterisk
GameUnit* GetUnit(int nId)

// Multiple pointers
char** GetStringArray(void)

// Const pointers
const char* GetName(void)

// Void return with no parameters
void Initialize(void)

// Void return with parameters
void SetValue(int nValue)
```

### 3.3 Parameter Naming Convention

Follow Hungarian notation for parameter names:

| Type | Prefix | Example |
|------|--------|---------|
| Pointer to struct | `p` | `pUnit`, `pContext` |
| Pointer to pointer | `pp` | `ppData` |
| Integer (32-bit) | `n` or `dw` | `nCount`, `dwFlags` |
| Integer (16-bit) | `w` | `wIndex` |
| Integer (8-bit) | `b` | `bValue` |
| Boolean | `b` or `f` | `bEnabled`, `fActive` |
| Character | `c` | `cChar` |
| String (char*) | `sz` | `szName` |
| Wide string | `wsz` | `wszName` |
| Handle | `h` | `hWnd`, `hFile` |
| Array pointer | `a` or `rg` | `aItems`, `rgPlayers` |
| Callback function | `pfn` | `pfnCallback` |

---

## Phase 4: Validation

### 4.1 Post-Fix Verification

After setting a prototype:

1. **Force Decompilation Refresh**
   ```python
   decompile_function(address=address, force=True)
   ```

2. **Check for Decompiler Warnings**
   - No "undefined" types remaining in locals
   - No type casts that suggest wrong parameter types
   - No pointer arithmetic on non-pointer parameters

3. **Verify Caller Consistency**
   - Callers should not show type mismatch warnings
   - Passed arguments should match parameter types

### 4.2 Common Mistakes to Avoid

| Mistake | Problem | Fix |
|---------|---------|-----|
| `void*` parameters | Too generic, hides structure | Use specific struct pointer |
| Missing `const` on string params | Allows modification of read-only | Add `const char*` |
| `int` for all integers | Loses size/sign information | Use `DWORD`, `WORD`, `BYTE` as appropriate |
| Generic names like `a1`, `a2` | No semantic meaning | Name by purpose: `nIndex`, `pBuffer` |
| Wrong calling convention | Corrupts stack | Verify with assembly |

---

## Phase 5: Batch Processing

### 5.1 Prioritization Strategy

Process functions in this order:
1. **Exported functions** - Public API, documentation essential
2. **High xref count** - Heavily used, fixing improves many callers
3. **Functions with known callers** - Can infer types from usage
4. **Leaf functions** - No callees, simpler analysis

### 5.2 Automation Script Pattern

```powershell
# Get functions sorted by xref count, filter incomplete
$functions = Get-Content prototype-audit.json | ConvertFrom-Json
$incomplete = $functions.functions | Where-Object {
    $_.Score -lt 80 -and 
    ($_.HasPrototype -eq $false -or $_.Name -like "FUN_*")
} | Sort-Object -Property { -as [int]$_.RecommendationsCount } -Descending

# Output prioritized list
$incomplete | Select-Object -First 50 | ForEach-Object {
    Write-Host "$($_.Name) @ $($_.Address) - Score: $($_.Score)"
}
```

---

## Quick Reference: Prototype Patterns

### Common D2 Game Patterns

```c
// Unit accessor
Unit* UNITS_GetUnit(UnitType eType, int nUnitId)

// Boolean check
BOOL UNITS_IsAlive(Unit* pUnit)

// Void setter
void UNITS_SetFlag(Unit* pUnit, DWORD dwFlag)

// Count/size return
int INVENTORY_GetItemCount(Unit* pPlayer)

// String return
const char* DATATABLES_GetStringFromIndex(int nTableId, int nIndex)

// Callback registration
void EVENTS_RegisterHandler(EventType eType, EventCallback pfnCallback, void* pUserData)
```

### Win32 API Patterns

```c
// Handle-based
HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwAccess, ...)
BOOL CloseHandle(HANDLE hObject)

// Success/failure
BOOL GetWindowRect(HWND hWnd, LPRECT lpRect)
DWORD GetLastError(void)

// Size return
DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
```

---

## Workflow Checklist

```
[ ] 1. Run bulk scan: .\functions-extract.ps1 -RefreshAll -RefreshOutput audit.json
[ ] 2. Filter for functions with incomplete prototypes (Score < 80, no custom name)
[ ] 3. For each function:
    [ ] a. Get disassembly and check return value patterns
    [ ] b. Identify calling convention from entry/exit
    [ ] c. Analyze parameter usage in decompiled code
    [ ] d. Check callers for type hints
    [ ] e. Set complete prototype with set_function_prototype()
    [ ] f. Force decompile refresh and verify
[ ] 4. Update completeness tracking database
```

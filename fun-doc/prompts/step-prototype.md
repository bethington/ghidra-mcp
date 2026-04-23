# Step 2: Rename Function + Set Prototype

## Allowed Tools
- `rename_function_by_address`
- `set_function_prototype`
- `get_function_callers`
- `decompile_function`

## Rename Policy

**Step 2a: Prefix decision (MUST do first)**

Before choosing any function name, determine the module prefix. Check these signals (need at least 2 to apply a prefix):

1. **Source/path hint** -- plate comment `Source:` line, string references pointing to a .cpp file
2. **Core behavior domain** -- function clearly belongs to one system (pathfinding, data tables, skills, etc.)
3. **Callee family** -- majority of called functions share a common prefix or module

If 2+ signals match a known prefix from the Known Module Prefixes table: the name **must** include that prefix.
If signals are mixed or weak: no prefix.

**Step 2b: Choose the full name (prefix + PascalCase verb)**

1. Combine the prefix decision with a descriptive PascalCase name: `DATATBLS_FreeResourceBuffer`, `PATH_FindNearestPosition`
2. If no rename is needed (current name already has correct prefix + accurate description): **SKIP** `rename_function_by_address`.
3. If the name needs changing: call `rename_function_by_address` with the complete prefixed name.

Call rename + prototype in parallel **only when rename is actually needed**. If later tool calls in the same pass need to re-query the function, use its address instead of assuming the new name is available immediately. If rename is skipped, call only `set_function_prototype`.

## Naming Rules

PascalCase, verb-first. Module prefixes (`UPPERCASE_`) are allowed and match original source conventions.

Valid patterns:
- `GetPlayerHealth`, `ProcessInputEvent`, `ValidateItemSlot` (plain PascalCase)
- `DATATBLS_CompileTxtDataTable`, `TREASURE_GenerateLoot`, `SKILLS_GetLevel` (with module prefix)

Invalid patterns:
- `processData` -> `ProcessData` (must be PascalCase)
- `doStuff` -> descriptive name based on actual behavior
- `DATATBLS_compileTable` -> `DATATBLS_CompileTable` (part after prefix must be PascalCase)

## Prototype Rules

- Use typed struct pointers (`UnitAny *` not `int *`) when the struct is known
- Use Hungarian camelCase for parameter names
- Verify calling convention from disassembly
- Mark implicit register parameters with IMPLICIT keyword in plate comment (Step 4)
- `__thiscall`: first param is `this` in ECX -- do NOT include a typed `this` in the prototype (see Step 3 known limitation)

**Note**: Prototype changes trigger re-decompilation and may create new SSA variables. Step 3 will refresh the variable list by address.

## Caller Verification (required for register params and enums)

Before committing semantic names to these parameter types, you MUST verify against callers:

1. **Register-passed parameters** (`in_EAX`, `in_EDX`, `in_ECX`): Call `get_function_callers` and `decompile_function` on 2-3 callers. Verify what value they pass in that register. Only assign a semantic name if callers confirm the role.
2. **Enum-like parameters** (compared against small integer sets, used in switch/case): Check callers to see what constants they pass. Do not assign names like `nCostMode` or `nVendorId` based solely on how the function uses the value internally.
3. **Flags/booleans**: If a parameter is compared to 0/1/true/false, check callers before naming it `bIsExclusive` vs `bCheckBoxType` -- the caller's context reveals intent.

If callers are unavailable or ambiguous, use conservative names (`nParam1`, `dwParam2`) and note in the plate comment:
```
Parameters:
  nParam3: int - Probable: cost mode (0/1/2 switch observed) -- not verified at call sites
```

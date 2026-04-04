# Step 2: Rename Function + Set Prototype

## Allowed Tools
- `rename_function_by_address`
- `set_function_prototype`

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

Call rename + prototype in parallel **only when rename is actually needed**. If rename is skipped, call only `set_function_prototype`.

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

**Note**: Prototype changes trigger re-decompilation and may create new SSA variables. Step 3 will refresh the variable list.

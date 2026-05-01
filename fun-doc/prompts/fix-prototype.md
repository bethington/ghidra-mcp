# Fix: Missing or Incorrect Prototype

**Category**: `missing_prototype`
**Trigger**: Function lacks a typed prototype, or return type is unresolved

## Allowed Tools
- `set_function_prototype`
- `get_function_variables` (to refresh after prototype change)
- `rename_variables` (to fix names after type changes)

## Recipe

1. **Analyze the decompiled source** to determine:
   - Return type: what does EAX hold at each RET? void, int, pointer, bool?
   - Parameter types: how are stack/register params used?
   - Calling convention: __stdcall, __cdecl, __fastcall, __thiscall
2. **Set prototype**: `set_function_prototype(address, prototype_string)`
   - Use typed struct pointers when the struct is known
   - Use Hungarian camelCase for parameter names
3. **Refresh variables**: `get_function_variables(address=...)` -- prototype changes may create new SSA variables; use the function address, not the name, in the same pass
4. **Fix names if needed**: single `rename_variables` call for any new variables
5. Scoring is handled externally -- do not call `analyze_function_completeness`.

## Important
- Prototype changes wipe plate comments. If plate comment exists, note its content before changing prototype and reapply it in the same pass.
- Prototype changes trigger re-decompilation. Variable list will be stale after this step.
- `set_function_prototype` does not rename the function. If the function name also needs to change, call `rename_function_by_address` separately.

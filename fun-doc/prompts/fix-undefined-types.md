# Fix: Undefined Variable Types

**Category**: `undefined_variables`
**Trigger**: Variables with `undefined1`, `undefined2`, `undefined4`, `undefined8` types

## Allowed Tools
- `get_function_variables`
- `set_local_variable_type`
- `set_parameter_type`
- `rename_variables`

## Recipe

1. **Review the inline variable list** for variables with `undefined*` types. Skip any variable with `is_phantom: true`; these stack-frame-only/decompiler artifact entries are not typeable through the API even when their type is `undefined4`.
2. **Determine correct type from usage context** in the decompiled source:
   - `undefined4` used as pointer -> `void *` or specific struct pointer
   - `undefined4` used in arithmetic -> `int` or `uint`
   - `undefined4` compared to 0/NULL -> `int` (flag) or pointer
   - `undefined2` -> `ushort` or `short`
   - `undefined1` -> `byte` or `bool`
   - `undefined8` -> `longlong` or `double`
3. **Apply types**: `set_local_variable_type` for each variable. Batch where possible.
4. **Rename**: After ALL types are set, single `rename_variables` call with Hungarian-prefixed names matching the resolved types
5. Scoring is handled externally -- do not call `analyze_function_completeness`.

## Skip Conditions
- Phantom variables (`is_phantom: true`, `extraout_*`, `in_*`, stack-frame-only `local_*`): do not attempt type-setting. Document in plate comment if relevant.
- Register-only variables: if `set_local_variable_type` fails, document via PRE_COMMENT instead.

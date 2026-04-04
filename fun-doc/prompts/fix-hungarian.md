# Fix: Hungarian Notation Violations

**Category**: `hungarian_notation_violations`
**Trigger**: Variable prefix doesn't match its type (e.g., `dwFlags` typed as `int`, `pData` typed as `uint`)

## Allowed Tools
- `get_function_variables`
- `set_local_variable_type`
- `set_parameter_type`
- `rename_variables`
- `set_function_prototype`

## Recipe

1. **Review violations** from the completeness evidence -- each lists the variable, its prefix, and its actual type
2. **Decide which to fix -- the type or the name**:
   - If the prefix is correct for the usage (e.g., `pData` is actually used as a pointer but typed `int`): fix the TYPE -> `set_local_variable_type` or `set_parameter_type`
   - If the type is correct but the prefix is wrong (e.g., `dwCount` but type is `int`): fix the NAME via `rename_variables`
3. **Apply all type fixes first**, then a single `rename_variables` call for all name fixes
4. Scoring is handled externally -- do not call `analyze_function_completeness`.

## Key Mappings
- `p` prefix requires pointer type (`void *`, struct pointer, etc.)
- `dw` prefix requires `uint` or `dword`
- `n` prefix requires `int` or `short`
- `b` prefix requires `byte`
- `f` prefix requires `bool`
- `w` prefix requires `ushort`
- `sz`/`lpsz` prefix requires `char *`

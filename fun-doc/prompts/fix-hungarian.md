# Fix: Hungarian Notation Violations

**Category**: `hungarian_notation_violations`
**Trigger**: Variable prefix doesn't match its type (e.g., `dwFlags` typed as `int`, `pData` typed as `uint`)

## Allowed Tools
- `get_function_variables`
- `set_variables` (atomic type + rename — **strongly preferred** for any change touching ≥2 variables)
- `set_variable_type` (single local/parameter fallback only)
- `rename_variables`
- `set_function_prototype`

## Recipe

1. **Review violations** from the completeness evidence -- each lists the variable, its prefix, and its actual type
2. **Decide which to fix -- the type or the name**:
   - If the prefix is correct for the usage (e.g., `pData` is actually used as a pointer but typed `int`): fix the TYPE -> `set_variable_type`
   - If the type is correct but the prefix is wrong (e.g., `dwCount` but type is `int`): fix the NAME via `rename_variables`
3. **Apply all type and name fixes in one atomic `set_variables` call** when touching ≥2 variables. Each individual `set_variable_type` call triggers re-decompilation that renumbers SSA variables (`iVar3` → `iVar4`, `psVar5` → `psVar4`), invalidating names you planned from the earlier decompile snapshot — subsequent calls fail with `Variable '<name>' not found`. `set_variables` does the entire batch in one transaction.
4. Scoring is handled externally -- do not call `analyze_function_completeness`.

## Key Mappings

The full prefix → type table lives in **`hungarian-table.md`** — that's
the single source of truth for all scopes (locals, parameters, struct
fields, globals). Don't restate it here. Refer to that file for the
complete list (`p`, `pp`, `pfn`, `dw`, `n`, `i`, `b`, `by`, `f`, `w`,
`sz`, `lpsz`, `lpcsz`, `wsz`, `ll`, `qw`, `fl`, `d`, `c`, `ch`, `l`,
`h`, `ab`, `aw`, `ad`) and the rules the validator enforces.

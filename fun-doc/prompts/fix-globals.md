# Fix: Unrenamed Globals

**Category**: `unrenamed_globals`
**Trigger**: DAT_* or s_* references in decompiled code that lack descriptive names

## Allowed Tools
- `rename_or_label`
- `apply_data_type`

## Recipe

1. **Review the evidence list** -- each entry identifies the global address and current name
2. **Determine purpose from usage context** in the decompiled source:
   - How is the global read/written?
   - What type is implied by the operations?
   - Is it a string, counter, pointer, flag?
3. **Set type first**: `apply_data_type(address, type)` if the global's type is unknown
4. **Rename**: `rename_or_label(address, new_name)` with `g_` prefix + Hungarian notation
   - Examples: `g_dwPlayerCount`, `g_pMainUnit`, `g_szConfigPath`, `g_pfnCallback`
5. Scoring is handled externally -- do not call `analyze_function_completeness`.

## Skip Conditions
- Globals used only as opaque pointers passed to other functions: `g_pUnk_ADDR` is acceptable

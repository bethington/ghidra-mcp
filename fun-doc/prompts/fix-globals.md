# Fix: Unrenamed Globals

**Category**: `unrenamed_globals`
**Trigger**: DAT_* or s_* references in decompiled code that lack descriptive names

## Allowed Tools
- `audit_globals_in_function` (one call lists every global the function references with per-global issues)
- `audit_global` (per-address inspector, useful mid-fix to recheck a single global)
- `set_global` (atomic type + name + plate-comment writer — **required** for any global change)

## Recipe

1. **List the function's globals**: `audit_globals_in_function(address=<function_addr>, program=...)` —
   one call returns every reachable global plus per-global issues and a summary histogram.
2. **For each global with issues**, fix everything in one `set_global` call:
   ```
   set_global(
     address="0x6fdf64d8",
     name="g_pDifficultyLevelsBIN",
     type_name="DifficultyLevels *",
     plate_comment="Pointer to the DifficultyLevels.bin table loaded at startup. Stride 0x58.",
     program="..."
   )
   ```
   - Name MUST follow `g_` + Hungarian-prefix + ≥2-char descriptor (the validator hard-rejects names that don't).
   - Examples: `g_dwPlayerCount`, `g_pMainUnit`, `g_szConfigPath`, `g_pfnCallback`.
   - Pass a real type — `undefined4`/`undefined1`/etc. are rejected.
   - Plate-comment first line must be a meaningful ≥4-word summary.
   - Use `array_length=N` for fixed-size arrays.
3. **Don't fall back to the broken-up chain** (`apply_data_type` → `rename_or_label` → `batch_set_comments`).
   `set_global` is atomic in a single transaction; the chain has known partial-application failure modes
   and the validator on `rename_or_label` hard-rejects most names you'd send through it.
4. Scoring is handled externally — do not call `analyze_function_completeness`.

See `step-globals.md` for the full naming convention table, plate-comment format, and the rules each
rejection code maps to.

## Skip Conditions

- Globals used only as opaque pointers passed to other functions: `g_pUnk_ADDR` is acceptable.
- OS-canonical globals (TIB/PEB/KUSER members) — the validator already exempts these; don't try to rename.

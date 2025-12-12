# Function Naming Validation

Run `python scripts/validate_function_names.py` to identify non-compliant functions. For each function in the output, use `get_decompiled_code` to understand its purpose, then apply `rename_function_by_address` with a compliant PascalCase verb-first name (e.g., ProcessPlayerSlots, ValidateEntityState, InitializeGameResources).

## Validation Criteria

- [ ] All names are PascalCase
- [ ] All names start with action verb
- [ ] Names reflect actual function purpose
- [ ] No generic names (Handler, Process, DoStuff)

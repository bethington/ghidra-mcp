# 6.0.0 Tool Consolidation — Migration Contract

Clean break (no aliases): old tools/routes are **deleted**; every internal caller
(fun-doc, bridge, scripts, skills, docs/prompts, tests) is migrated to the survivor.
Net advertised surface: **272 → ~250**. Survivors are chosen to be clear one-or-many
tools; removed tools' capabilities are fully preserved by the survivor.

Legend: **SURVIVOR** = kept (possibly extended). **REMOVE** = deleted. Transform = how a
call site is rewritten.

## Group 1 — Comments (CommentService.java)
| REMOVE | SURVIVOR | Transform |
| --- | --- | --- |
| `set_plate_comment(address, comment)` | `set_comment` | `set_comment(address, comment, type="plate")` |
| `set_decompiler_comment(address, comment)` | `set_comment` | `set_comment(address, comment, type="pre")` |
| `set_disassembly_comment(address, comment)` | `set_comment` | `set_comment(address, comment, type="eol")` |
| `get_plate_comment(address)` | `get_comment` | `get_comment(address)` → read `.plate` |

`batch_set_comments` is **kept** (distinct per-function multi-kind shape; not in baseline).

## Group 2 — single/batch → one variadic survivor
| REMOVE | SURVIVOR (extended to accept one-or-many) | Transform |
| --- | --- | --- |
| `batch_add_function_tags(assignments)` | `add_function_tag` (+ optional `assignments[]`) | `add_function_tag(assignments=[...])` |
| `batch_remove_function_tags(assignments)` | `remove_function_tag` (+ `assignments[]`) | `remove_function_tag(assignments=[...])` |
| `batch_create_labels(labels)` | `create_label` (+ `labels[]`) | `create_label(labels=[...])` |
| `batch_delete_labels(labels)` | `delete_label` (+ `labels[]`) | `delete_label(labels=[...])` |
| `batch_decompile(functions)` | `decompile_function` (+ `functions=`) | `decompile_function(functions="a,b,c")` |
| `batch_analyze_completeness(addresses)` | `analyze_function_completeness` (+ `addresses[]`) | `analyze_function_completeness(addresses=[...])` |
| `rename_variable(...)` | `rename_variables` (already many; also accepts one) | `rename_variables(function_address, variable_renames=[{old,new}])` |
| `batch_set_variable_types(function_address, variable_types)` | `set_variables` | `set_variables(function_address, variables=[{name,type}])` |

## Group 3 — true duplicates
| REMOVE | SURVIVOR | Transform / notes |
| --- | --- | --- |
| `get_data_type_size(type_name)` | `get_type_size(type_name)` | superset; drop-in |
| `mcp_health` | `check_connection` | **verify** dashboard/audit usage; if ops stats needed, fold into check_connection response |
| `validate_data_type_exists(type_name)` | `validate_data_type(address?, type_name)` | make `address` optional; when absent → existence-only. **Fixes BUG-1** (bare-name resolver) |
| `rename_function_by_address(function_address, new_name)` | `rename_function(old_name, new_name)` | `old_name` now accepts a **name OR address**; transform: `rename_function(old_name=<addr>, new_name)` |

## Tier-3 — semantic unifications
### set_variable_type (FunctionService.java)
Unifies `set_local_variable_type`, `set_parameter_type`, `set_decompiler_variable_type`.
- SURVIVOR: **`set_variable_type(function_address, variable_name, new_type)`** (new name).
- Transform: all three → `set_variable_type(...)` (`parameter_name`→`variable_name`).
- **Verify** local(DB) vs decompiler(high) equivalence during impl; survivor must apply at
  the level that satisfies both prior tools (decompiler high-var path covers params+locals).

### rename_symbol (SymbolLabelService.java)
Unifies `rename_data`, `rename_global_variable`, `rename_label`, `rename_or_label`, `rename_external_location`.
- SURVIVOR: **`rename_symbol(target, new_name, kind="auto")`** (new name). `target` = address or name.
  `kind ∈ {auto,data,global,label,external}`; `auto` detects the symbol kind at the address.
  Preserves `rename_or_label`'s create-if-missing behavior when `kind=label`/auto and none exists.
- Transforms:
  - `rename_data(address,new_name)` → `rename_symbol(address, new_name)` (auto→data)
  - `rename_global_variable(old_name,new_name)` → `rename_symbol(old_name, new_name)` (auto→global)
  - `rename_label(address,old_name,new_name)` → `rename_symbol(address, new_name, kind="label")`
  - `rename_or_label(address,name)` → `rename_symbol(address, name)` (auto, create-if-missing)
  - `rename_external_location(address,new_name)` → `rename_symbol(address, new_name, kind="external")`

## Bug fixes (independent, applied with the merges)
- **BUG-1** — folded into `validate_data_type` (resolver fix, above).
- **BUG-2** — `create_struct`/`remove_struct_field`/`modify_struct_field`: resolve a field by its
  **original (pre-Hungarian) stem** as a fallback, and have `create_struct` return the final field
  names in its response.
- **NIT** — `get_function_labels`: accept an **address** as well as a name; clearer missing-param error.

## Manual routes to delete (GhidraMCPPlugin.java)
`batch_set_variable_types`, `get_data_type_size`, `mcp_health` (pending verify) are manual routes,
not `@McpTool` — delete their route registration too.

## Migration mechanics
1. Java: extend survivors, delete removed methods + manual routes.
2. `codemod.py`: deterministic rewrite of call sites across fun-doc/, python/, scripts/, .claude/,
   docs/, tests/ using this table; then grep for any residual old names (must be zero outside
   this doc + CHANGELOG).
3. Regenerate `tests/endpoints.json` (`mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`)
   and README (`python -m tools.gen_readme_api_reference --write`).
4. Build → deploy → verify live schema count → run offline + integration + fun-doc benchmark.

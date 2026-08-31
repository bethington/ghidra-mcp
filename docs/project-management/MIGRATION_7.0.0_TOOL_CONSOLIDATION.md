# 7.0.0 Tool Consolidation — Migration Contract

Clean break (no aliases): old tools/routes are **deleted**; every internal caller
(fun-doc, bridge, scripts, skills, docs/prompts, tests) is migrated to the survivor.
Net advertised surface: **272 → 251**. Survivors are chosen to be clear one-or-many
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
| ~~`mcp_health`~~ | — | **KEPT — verified not a duplicate.** `/check_connection` is a trivial liveness probe; `/mcp/health` returns pool stats, uptime, memory, and active request count, and is consumed by `tests/performance/test_health_endpoint.py`, the fun-doc dashboard, and the recovery RFC's accessibility probe. Both are hardcoded auth-exempt paths in `SecurityConfig` / `UdsHttpServer`. Folding the diagnostics into the liveness probe would bloat the hot path for no surface win. |
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

## Manual routes deleted

`batch_set_variable_types` and `get_data_type_size` were manual routes, not `@McpTool`.
Their registrations are gone from `GhidraMCPHeadlessServer`'s manual-route list and their
descriptors from `ManualToolDescriptors.buildAll()` — `ManualToolDescriptorsParityTest`
fails on a descriptor with no registered route, which is what caught the leftovers.
`mcp_health` is **kept** (see the Group 3 row).

## Migration mechanics — DONE

1. **Java:** survivors extended, removed methods demoted to plain (non-`@McpTool`) helpers
   or deleted, manual routes + descriptors pruned. Also migrated: the user-facing guidance
   strings in `AnalysisService`'s `recommendations` / `actions` output, whose
   `params_template`s still carried the removed tools' parameter names.
2. **Call sites:** deterministic rewrite across `fun-doc/` (workers, prompts, provider tool
   allowlists, benchmark harness), `python/bridge_mcp_ghidra/`, `tools/setup/`,
   `ghidra_scripts/`, `tests/`, and the operator docs. Residual old names now appear only
   in history (CHANGELOG, `docs/archive/`, `docs/releases/`) and in survivor descriptions
   that state what they replaced.
3. **Catalog:** `tests/endpoints.json` regenerated
   (`mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true`), README API reference
   regenerated (`python -m tools.gen_readme_api_reference --write`) → 251 tools.
4. **Verification:** offline Java (390 tests), `tests/unit/`, and the offline
   `tests/performance/` set are green. **Open:** deploy → confirm live `/mcp/schema` = 251
   → integration tiers + the four live-Ghidra performance files → fun-doc benchmark.

## Call-shape changes worth knowing

- **`analyze_function_completeness` bulk mode is a GET** with `addresses` as a
  comma-separated string (the removed `batch_analyze_completeness` was a POST with a JSON
  array). This also moves bulk scoring onto the concurrent read path. Callers must join
  their address list; fun-doc's `_batch_score` sends `BATCH_SIZE=6` per request, far
  inside any request-line limit.
- **`set_comment` / `get_comment` work at any address**, so the old "use
  `batch_set_comments` for plate comments on data globals" workaround is obsolete —
  `worker-globals.md` was updated accordingly.
- **`rename_symbol(kind=auto)` routes an address to rename-or-create-label**, which
  validates names with warnings rather than the hard rejection `rename_data` applied. Pass
  `kind="data"` when you want that stricter gate (the global-endpoint tests do).

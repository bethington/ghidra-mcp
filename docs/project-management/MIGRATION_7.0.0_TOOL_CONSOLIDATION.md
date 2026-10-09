# 7.0.0 Tool Consolidation — Migration Contract

Clean break (no aliases): old tools/routes are **deleted**; every internal caller
(bridge, scripts, skills, docs/prompts, tests) is migrated to the survivor.
Net advertised surface for this pass: **272 → 251**. Survivors are chosen to be
clear one-or-many tools; removed tools' capabilities are fully preserved by the
survivor.

> **Where it landed.** This table describes the consolidation pass only. Two
> endpoints were added later in the 7.0.0 cycle — `/list_shadowed_globals` and
> `/batch_get_comments` — and three later passes removed more (see
> [Readers, listings and the server model](#readers-listings-and-the-server-model)),
> so the shipped catalog is **209** (with `/set_memory_block` added after rc.1, and
> `/apply_documentation` replacing both documentation writers), not 251. The
> authoritative count is always [`tests/endpoints.json`](../../tests/endpoints.json);
> `tests/unit/test_published_counts.py` fails if any published figure disagrees
> with it.

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
| `batch_decompile(functions)` | `get_functions` (+ `functions=`, `fields=decompiled_code`) | `get_functions(functions="a,b,c", fields="decompiled_code")` |
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
   `tests/performance/` set are green. **Open:** deploy → confirm live `/mcp/schema` = 215
   → integration tiers + the four live-Ghidra performance files → fun-doc benchmark.

## One tool for applying documentation

| REMOVE | SURVIVOR | Transform |
| --- | --- | --- |
| `apply_function_documentation(json_body)` | `apply_documentation` | Pass the export's fields as parameters instead of one JSON string: `apply_documentation(target_address=..., name=..., parameters=[...], comments=[...], labels=[...])`. |
| `batch_apply_documentation(address, ..., decompiler_comments, disassembly_comments)` | `apply_documentation` | Same fields, except the two comment lists become one: `comments=[{address, pre_comment, eol_comment}]`. |

`apply_documentation` also takes `entries=[...]` for many functions at once, plus the
prototype, variable-type and variable-rename fields that used to need separate calls.

## Folds after the consolidation

Fifteen more tools folded into a sibling, still within one permission tier. Each survivor
keeps its own single-item call unchanged and gains the removed tool's job.

| REMOVE | SURVIVOR | Transform |
| --- | --- | --- |
| `modify_struct_field_type(struct_name, field_name, new_type)` | `modify_struct_field` | `modify_struct_field(struct_name, field_name, new_type=...)` |
| `embed_struct_field(parent_struct, field_name, embedded_struct)` | `modify_struct_field` | `modify_struct_field(struct_name=parent_struct, field_name, new_type=embedded_struct)` |
| `create_typedef(name, base_type)` | `create_derived_type` | `create_derived_type(kind="typedef", name, base_type)` |
| `create_array_type(base_type, length, name)` | `create_derived_type` | `create_derived_type(kind="array", base_type, length, name)` |
| `create_pointer_type(base_type, name)` | `create_derived_type` | `create_derived_type(kind="pointer", base_type, name)` |
| `list_data_types(category)` | `find_data_types` | `find_data_types(category=...)`; entries are now records (`name`, `kind`, `category`, `size`, `path`) under `data_types`, not `name \| category \| size \| path` strings |
| `search_data_types(pattern)` | `find_data_types` | `find_data_types(pattern=...)`; same record shape, sorted by path |
| `list_data_type_categories()` | `find_data_types` | `find_data_types(categories=true)` |
| `batch_get_comments(addresses, only_with_comments)` | `get_comment` | `get_comment(addresses="a,b,c", only_with_comments=...)` |
| `get_bulk_function_hashes(offset, limit, filter)` | `get_function_hash` | `get_function_hash(offset, limit, filter)`, omitting `function` |
| `list_option_groups()` | `get_program_options` | `get_program_options()`, omitting `group` |
| `list_property_maps()` | `list_properties` | `list_properties()`, omitting `map` |
| `debugger_step_into()` | `debugger_step` | `debugger_step(kind="into")` |
| `debugger_step_over()` | `debugger_step` | `debugger_step(kind="over")` |
| `debugger_step_out()` | `debugger_step` | `debugger_step(kind="out")` |
| `get_function_tags(function)` | `get_functions` | `get_functions(function, fields="tags")`; `tags` is a list of names, and is part of the default bundle |
| `search_functions_by_tag(tag)` | `find_functions` | `find_functions(tag=...)`, or several names for any-of; every result also carries its `tags` |
| `create_function_tag(name, comment)` | `add_function_tag` | `add_function_tag(function, tags=name, tag_comments={name: comment})`, or `apply_documentation(tags=..., tag_comments=...)`; attaching creates the definition |

The bridge's own `debugger_step_into` / `debugger_step_over` proxies, which forward to the
external debugger server, are unaffected: only the GUI plugin's `/debugger/step_*` routes
folded.

## For consumers outside this repository (fun-doc, d2-game-exe)

This repository no longer contains fun-doc, so nothing here catches a break on that side.
Search the consumer for each item.

- **Retired and never coming back:** `/decompile_function` (use `get_functions`),
  `/health`, `/project/info`, `/load_program*`, `/tool/launch_codebrowser`,
  `/server/version_control/checkin` (use `/checkin_program`).
- **`/check_connection` is JSON now** (`status`, `server_kind`, `version`, `program`), not
  plain text; a client comparing it to a literal breaks.
- **`/server/*` is snake_case only** and answers the same way on both servers:
  `keep_checked_out`, `checkout_id`, `access_level`. `/server/repository/files` is the
  server's repository, not the project tree.
- **A name shared by several functions is an error** that lists their addresses, and a name
  typed in the wrong case resolves everywhere instead of in some tools.
- **Every tool listed under "Folds after the consolidation"** and `apply_function_documentation`
  (use `apply_documentation`; it takes the same export) are gone. `find_data_types` returns
  records under `data_types`, not preformatted strings.
- **Function tags:** `get_function_tags`, `search_functions_by_tag` and
  `create_function_tag` are gone (`doc_lint`, `conformance_dashboard`, `fun_doc`,
  `battletest_promoter`, `adversarial_reproof` and `golden_bench` call them). Reads are
  `get_functions(fields="tags")` and `find_functions(tag=...)`; `list_function_tags` stays.

## Readers, listings and the server model

Passes after rc.1 removed 51 tools. 13 are in the fold table above; this section covers
the other 38. Function reads became one call, listings
became one call per question, and the GUI and headless servers now share one program
model and one name per operation. Every removed tool's data is still available.

### Function reads: `get_functions`

`get_functions(function=...)` returns everything about one function, and
`get_functions(functions="a,b,c")` returns up to 20. `fields=` picks what comes back;
omit it for all fields. A selection that needs no decompiled text does not decompile.

Every function-scoped tool now takes `function=` (a name or an address). The old
spellings `address`, `name`, `function_name` and `function_address` still work as
aliases. A name two functions share is an error that lists both.

| REMOVE | SURVIVOR | Transform |
| --- | --- | --- |
| `decompile_function(address)` | `get_functions` | `get_functions(function=..., fields="decompiled_code")` |
| `get_function_by_address(address)` | `get_functions` | `get_functions(function=..., fields="signature,entry_point,body_start,body_end")` |
| `get_function_signature(address)` | `get_functions` | `get_functions(function=..., fields="signature,return_type,parameters")` |
| `get_function_variables(function_name)` | `get_functions` | `get_functions(function=..., fields="parameters,locals")` |
| `get_function_callers(name)` | `get_functions` | `get_functions(function=..., fields="callers")` |
| `get_function_callees(name)` | `get_functions` | `get_functions(function=..., fields="callees")` |
| `get_function_xrefs(name)` | `get_functions` | `get_functions(function=..., fields="xrefs")` |
| `get_function_labels(name)` | `get_functions` | `get_functions(function=..., fields="labels")` |
| `get_function_jump_targets(name)` | `get_functions` | `get_functions(function=..., fields="jump_targets")` |
| `get_function_tags(function)` | `get_functions` | `get_functions(function=..., fields="tags")` |

The full field list is `signature`, `classification`, `return_type`, `entry_point`,
`body_start`, `body_end`, `decompiled_code`, `plate_comment`, `comments`, `labels`,
`tags`, `parameters`, `locals`, `callers`, `call_context`, `callees`, `xrefs`,
`disassembly`, `jump_targets` and `refs`.

### Finding functions: `find_functions`

Every filter is optional, so with none it lists the whole program a page at a time.
Every result lists its tags.

| REMOVE | SURVIVOR | Transform |
| --- | --- | --- |
| `list_functions()` | `find_functions` | `find_functions(offset, limit)` |
| `list_functions_enhanced(offset, limit)` | `find_functions` | `find_functions(offset, limit)` |
| `search_functions(name_pattern)` | `find_functions` | `find_functions(name_pattern=...)` |
| `search_functions_enhanced(...)` | `find_functions` | same filters: `name_pattern`, `regex`, `min_xrefs`, `max_xrefs`, `calling_convention`, `has_custom_name`, `is_thunk`, `is_external`, `sort_by` |
| `search_functions_by_tag(tag)` | `find_functions` | `find_functions(tag=...)` |

### Program inventories: `list_program_items`

| REMOVE | SURVIVOR | Transform |
| --- | --- | --- |
| `list_classes()` | `list_program_items` | `list_program_items(kind="classes")` |
| `list_methods()` | `list_program_items` | `list_program_items(kind="methods")` |
| `list_namespaces()` | `list_program_items` | `list_program_items(kind="namespaces")` |
| `list_imports()` | `list_program_items` | `list_program_items(kind="imports")` |
| `list_exports()` | `list_program_items` | `list_program_items(kind="exports")` |
| `list_segments()` | `list_program_items` | `list_program_items(kind="segments")` |
| `list_data_items()` | `list_program_items` | `list_program_items(kind="data_items")` |
| `list_external_locations()` | `list_program_items` | `list_program_items(kind="external_locations")` |

### Cross-references and tags

| REMOVE | SURVIVOR | Transform |
| --- | --- | --- |
| `get_bulk_xrefs(addresses)` | `get_xrefs_to` | `get_xrefs_to(addresses="a,b,c")` |
| `create_function_tag(name, comment)` | `add_function_tag` | attaching a tag creates it; set its description with `set_function_tag_comment(name, comment)` |

### What the analyst is looking at: `get_ui_cursor`

GUI only, as before.

| REMOVE | SURVIVOR | Transform |
| --- | --- | --- |
| `get_current_address()` | `get_ui_cursor` | `get_ui_cursor(type="address")` |
| `get_current_function()` | `get_ui_cursor` | `get_ui_cursor(type="function")` |
| `get_current_selection()` | `get_ui_cursor` | `get_ui_cursor(type="selection")` |
| `get_current_program_info()` | `get_ui_cursor` | `get_ui_cursor(type="program")` |

### One program model, one name per operation

Both servers now open any program in the project the first time an endpoint names it, so
headless no longer needs a separate load step.

| REMOVE | SURVIVOR | Transform |
| --- | --- | --- |
| `load_program(file, language, compiler_spec)` (headless) | `import_file` | `import_file(file_path=..., language, compiler_spec)` |
| `load_program_from_project(path)` (headless) | `open_program` | `open_program(path=...)`, or just pass `program=<path>` to any endpoint |
| `project/info` (GUI) | `get_project_info` | `get_project_info()` on both servers |
| `server/version_control/checkin` | `checkin_program` | `checkin_program(path, comment, keep_checked_out)` |
| `tool/launch_codebrowser` | `open_program` | `open_program(path=...)` opens the program; CodeBrowser follows the project's open options |
| `health` (headless) | `check_connection` | returns `{status, server_kind, version}`; pool and memory stats are on `mcp/health` |
| `get_version()` | `check_connection` | `check_connection()`, then read `.version` |

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

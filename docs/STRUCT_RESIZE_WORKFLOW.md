# Structure resize workflow (MCP)

Generic guidance for growing, shrinking, or rebuilding C/C++ structures in Ghidra via MCP. Examples use typical Win32/MSVC PE layouts (`MyStruct`, `Widget`); substitute your program's recovered type names.

## When to use which tool

| Goal | Tool |
|------|------|
| Create a new struct | `create_struct` |
| 1-byte demangler/placeholder blocks same name | `create_struct` with `replace_placeholder=true`, or `resolve_duplicate_type` then `create_struct` |
| Grow/shrink total size, keep fields that still fit | `resize_struct` |
| Replace entire layout (export → edit → re-import) | `recreate_struct` |
| Change one field's type | `modify_struct_field_type` or `embed_struct_field` (by-value nested struct) |
| Remove unused `/Demangler` stub | `resolve_duplicate_type` |
| Fix `void * this` after member-function prototype | `set_function_this_type` |

## Example: grow `Widget` (0x40 → 0x60)

After field recovery, you may need padding for a vtable tail or trailing members:

```http
POST /resize_struct
{"name":"Widget","new_size":96,"preserve_fields":true,"force":false}
```

(`96` = `0x60` decimal.) Defined fields whose end offset fits within `new_size` are kept; growth pads with undefined filler.

## `resize_struct`

```http
POST /resize_struct
{"name":"MyStruct","new_size":64,"preserve_fields":true,"force":false}
```

- **`preserve_fields`** (default `true`): defined fields whose end offset fits within `new_size` are kept; growth pads with undefined filler.
- **`force`**: allow shrink past defined fields (clips trailing layout). Prefer `recreate_struct` when you need a new field map.

Shrinking from `0x40` (64) to `0x30` (48) without `force` fails if a field extends past byte 48 — the error suggests `force=true` or `recreate_struct`.

## `recreate_struct`

Atomic delete (when allowed) + create from a `fields` JSON array (same shape as `create_struct`):

```http
POST /recreate_struct
{"name":"MyStruct","replace_placeholder":true,"force":false,"fields":[{"name":"magic","type":"uint","offset":0},{"name":"length","type":"uint","offset":4}]}
```

Use when `resize_struct` cannot apply or you are rebuilding from `get_struct_layout` output.

## `create_struct` vs duplicates

If creation fails with "already exists":

1. Check size via `get_type_size` / `get_struct_layout`.
2. 1-byte stub → `replace_placeholder=true` or `resolve_duplicate_type`.
3. Full struct already present → `resize_struct` or `recreate_struct` instead of a second `create_struct`.

## Member functions (`__thiscall`)

Ghidra's implicit `this` is an **auto-parameter**: with auto-storage it cannot be retyped directly (the API rejects it as immutable). Instead, the auto-`this` type is derived from the function's **parent class namespace**, matched by name to a same-named structure. So `set_function_this_type` does not retype `this` — it associates the function with class `Widget` (creating the `GhidraClass` if needed and moving the function into it). No custom storage is used.

Prerequisite: a structure named `Widget` must exist (`create_struct`). Then:

```http
POST /set_function_prototype
{"function_address":"0x401000","prototype":"int __thiscall Widget_OnClick(uint msg)","calling_convention":"__thiscall"}

POST /set_function_this_type
{"function_address":"0x401000","this_type":"Widget *"}

GET /force_decompile?function_address=0x401000
```

After this the function appears as `Widget::Widget_OnClick` and the decompiler shows `this->member`, not `void *`.

**Pass:** decompilation shows `this->member`; the function is listed under class `Widget` in the Symbol Tree.

## Related

- Manual checks: [TESTING.md](TESTING.md)
- Contributing policy: [CONTRIBUTING.md](../CONTRIBUTING.md)

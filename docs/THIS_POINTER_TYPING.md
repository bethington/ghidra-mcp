# Typing the implicit `this` pointer (`__thiscall` / `__fastcall`)

## What goes wrong

On 32-bit Windows PE binaries, member functions often use `__thiscall`: the receiver lives in **ECX**.

Ghidra models that as an **auto-parameter** named `this` with storage like `ECX:4 (auto)`. Auto-parameters are **immutable** through the program API — the Ghidra docs state plainly: *"Within the Program API, auto-parameters may not be directly manipulated and are immutable."* Calls such as `HighFunctionDBUtil.updateDBVariable`, `Parameter.setDataType`, or `set_local_variable_type` on `this` fail with errors like `Cannot modify auto-parameter: this`.

That is a **Ghidra platform rule**, not a bug in the MCP bridge.

## How `this` actually gets its type

With **auto-storage** (the default), the `this` auto-parameter obtains its type from the function's **parent Class namespace**. If the function is not inside a `Class` namespace, `this` is `void *`. Ghidra keeps a loose association — **by name** — between a `Class` namespace and a structure of the same name (per [Ghidra issue #114](https://github.com/NationalSecurityAgency/ghidra/issues/114)).

So to make the decompiler show `this` as `Widget *`, the function must live in a `Class` namespace named `Widget`, and a structure named `Widget` must exist. This is the same thing the decompiler GUI does via **"Auto Fill in Class Structure"** or re-parenting a function under a class in the Symbol Tree.

## MCP tool: `set_function_this_type`

`set_function_this_type` automates exactly the auto-storage class association — **no custom storage, no signature rewriting, no retyping of the auto-parameter**:

1. Resolve `this_type` (`Widget *` or `Widget`) and require its base to be an existing **structure**.
2. Verify the function has an implicit `this` (i.e. a `hasThis` convention such as `__thiscall`/`__fastcall`). If not, it stops without modifying anything and tells you to set the convention first.
3. Find or create a `GhidraClass` named after the structure (`createClass` / `convertNamespaceToClass`).
4. Re-parent the function into that class (`Symbol.setNamespace`).
5. Read back the auto-`this` type and report it.

```http
POST /set_function_this_type
{"function_address":"0x00401000","this_type":"Widget *"}
```

The function becomes `Widget::<name>`, and `this` types as `Widget *` under auto-storage. Call `force_decompile` / `get_decompiled_code` to refresh output.

### Prerequisites

- The structure named by `this_type` must already exist — create it first with `create_struct` (or `recreate_struct`).
- The function must be `__thiscall` / `__fastcall` so Ghidra creates the implicit `this`. Set it with `set_function_prototype` if needed. The prototype does **not** need to mention `this` — it is implicit:

```http
POST /set_function_prototype
{"function_address":"0x00401000","prototype":"void Widget_OnClick(uint msg)","calling_convention":"__thiscall"}
```

## When it still fails

- **Missing struct** in the data type manager — `this_type` can't resolve (`create_struct` first).
- **Not a member / wrong convention** — no implicit `this`; set `__thiscall` via `set_function_prototype`.
- **Heavily optimized code** where Ghidra never recovered the call as `__thiscall`.

## Related

- [STRUCT_RESIZE_WORKFLOW.md](STRUCT_RESIZE_WORKFLOW.md) — struct create/resize/recreate tools used to build the `this` type.

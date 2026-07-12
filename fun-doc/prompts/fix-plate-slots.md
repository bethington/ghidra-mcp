# Fix: Unfilled Plate Scaffold Slots

**Category**: `plate_slot_unfilled`
**Trigger**: The harness-owned plate comment still has `<TODO: ...>` slots, or a parameter
description that just echoes the name/type instead of describing it.

The plate is a **scaffold**: the harness has already filled the empirical fields (the summary
frame, parameter names/types/storage, return type, Source, and any Provenance/Structure-Layout
grid). **Do not touch those.** Your job is only to replace each `<TODO: ...>` with a real
description, in place.

## Allowed Tools
- `get_comment` (read the current plate)
- `set_comment` with `type=plate` (write the plate back — keep the empirical fields byte-for-byte)

## Recipe

1. **Read the plate** (`get_comment`). Note every `<TODO: ...>` slot and the deduction's `items`.
2. **Fill each slot from the decompilation** — replace `<TODO: describe>` with a concise, accurate
   description of that specific param / return / behavior:
   - Summary slot → one line: what the function does.
   - Each parameter → what it is and how it's used (e.g. `item class ID, used to index into
     g_pItemRecords`), not a restatement of its type.
   - Return slot → what the value means and its range/failure value.
   - Algorithm slot → the numbered steps, grounded in the decompiled control flow.
3. **Preserve the empirical fields exactly** — do NOT change param names/types, the return type,
   the Source line, or any `[E]` grid. If a type looks wrong, that is a *separate* fix
   (`non_canonical_type`), not this one. The harness regenerates the empirical block; if you edit
   it, your edit is discarded on the next refresh.
4. **Write it back** with `set_comment type=plate`. Every `<TODO>` must be gone.
5. Scoring is handled externally — do not call `analyze_function_completeness`.

## Skip Conditions
- A description that is genuinely "none"/"unused" is acceptable prose (it exists) — but prefer a
  short reason (e.g. `unused — passed through to <callee>`).
- Do not invent Special Cases / Magic Numbers content that isn't in the code; leave optional
  sections out rather than filling them with filler.

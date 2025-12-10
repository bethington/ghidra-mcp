# DATA_SECTION_WORKFLOW

Targeted pass for .data/.rdata: enumerate, type, rename, and document globals and data structures.

## Scope
- Applies to .data, .rdata, and other writable/rodata segments
- Focus on globals, tables, strings, struct instances, function pointers, and import/ordinal tables

## Steps

### 1) Enumerate and Prioritize
- list_data_items_by_xrefs to rank by reference count
- analyze_data_region to get size/type hints
- list_strings for embedded strings
- Group findings: pointers/tables, vtables, scalars/flags, structs/arrays, strings/resources

### 2) Type First, Then Name
- Apply data types before renaming: apply_data_type (or create_struct when needed)
- For pointers/tables: follow pointer chains; type both the pointer and the target; set correct stride for arrays
- For function pointers/import tables: resolve ordinals using docs/KNOWN_ORDINALS.md; set function pointer types where possible

### 3) Structs and Ownership
- When globals point to structured data: infer layout from usage (xrefs, offsets, stride) or create_struct
- Apply the struct type on the target and pointer-to-struct type on the global symbol
- Rename with clarity: g_pStructName (pointer), g_StructName (by value), g_apStructName (array of pointers)
- Document ownership/lifetime in notes: who allocates/frees, validity window, mutability

### 4) Hungarian Naming Rules (Globals)
- Prefix g_ for globals; use type-driven prefixes (p/pp for pointers, pfn for function pointers, p+StructName for struct pointers)
- Strings: sz for ANSI, wsz for wide, szFmt for format strings, szPath for paths
- Arrays: a* pattern (ab/aw/ad/an) or g_ap* for pointer arrays
- Ensure prefix matches applied type; fix types first if mismatch

### 5) Inline Context and Comments
- Add concise inline comments where globals are heavily used to explain key fields, invariants, or role
- For function-pointer tables or ordinals, add brief purpose comments (e.g., /* D2Common.GetUnitStat */)

### 6) Validation Pass
- get_xrefs_to each renamed symbol to confirm usage matches type (stride, deref width, const-ness)
- Revisit any mismatches: adjust type, struct layout, or name
- Ensure no DAT_* or s_* remain unnamed; no unknown arrays without stride typing

### 7) Output / Tracking
- Record counts: renamed globals, typed globals, structs created/updated, remaining unknowns
- Note any unresolved items and why (insufficient xrefs, obfuscated data, needs dynamic analysis)

## Quick Checklist
- [ ] Enumerated .data/.rdata and prioritized by xrefs
- [ ] Types applied before renaming; pointer chains typed
- [ ] Structs created/applied for structured globals; ownership/lifetime documented
- [ ] Hungarian prefixes aligned with types; no DAT_* or s_* left
- [ ] Function pointers/ordinals resolved and commented
- [ ] Validation pass against xrefs and usage patterns
- [ ] Outstanding unknowns documented for follow-up

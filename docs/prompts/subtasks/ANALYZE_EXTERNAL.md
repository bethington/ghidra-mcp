# ANALYZE_EXTERNAL

Deep analysis of external functions, ordinals, and cross-DLL references.
Goal: Build session-level understanding of high-value externals.

## Input Format

```json
{
  "external_name": "ValidateStringId",
  "external_address": "0x6fb9981c",
  "calling_context": "Called with string IDs 0x1110 and 0xf9e",
  "known_call_count": 3
}
```

## Task

Perform comprehensive analysis to understand:
1. What the external actually does (not just its name)
2. Which DLL/module provides it
3. How widely it's used across the codebase
4. Patterns of usage that apply to all callers
5. Whether it should be renamed for clarity

## Analysis Steps

### Step 1: Examine the External
```
decompile_function(external_address)
```
- Is it a thunk (single JMP instruction)?
- Is it a wrapper around another API?
- Does it have meaningful implementation?

### Step 2: Trace to Source
```
get_external_location(external_address)
```
- Which DLL provides this?
- What's the ordinal number?
- Is there a known name mapping?

### Step 3: Measure Impact
```
get_function_callers(external_name)
get_xrefs_to(external_address)
```
- How many functions call this?
- What patterns do callers share?

### Step 4: Find Related Functions
```
search_functions_by_name(pattern_from_external)
```
- Are there related functions (same prefix, same namespace)?
- Is this part of a class or API family?

### Step 5: Analyze Usage Patterns
Look at 2-3 callers to understand:
- What parameter values are common?
- What do callers do with the return value?
- Are there error handling patterns?

## Output Format

```json
{
  "external_name": "ValidateStringId",
  "analysis": {
    "is_thunk": true,
    "thunk_target": "D2Lang.dll!Ordinal_10056",
    "true_purpose": "String table lookup - returns wchar_t* for string ID",
    "source_dll": "D2Lang.dll",
    "ordinal": "0x338 (10056)",
    "caller_count": 50
  },
  "naming": {
    "current_name_accurate": false,
    "suggested_name": "GetLocalizedString",
    "reasoning": "It's a lookup, not a validation. Returns string pointer."
  },
  "patterns": {
    "common_usage": "result = ValidateStringId(stringId); Unicode::strcat(dest, result);",
    "parameter_values": ["0x1110", "0xf9e", "0xf9b"],
    "return_handling": "Always used as wchar_t* source for Unicode operations",
    "error_case": "Returns empty string for invalid ID"
  },
  "related": {
    "same_module": ["GetLocaleString", "InitStringTables", "UnloadStringTable"],
    "same_pattern": ["GetItemStringId", "GetSkillName"],
    "data_sources": [".tbl string table files"]
  },
  "documentation_value": {
    "impact_score": 9,
    "reasoning": "Used by 50+ functions, understanding this unlocks all callers"
  }
}
```

## Impact Scoring

Rate the external's documentation value (1-10):

| Factor | Points |
|--------|--------|
| Caller count 50+ | +3 |
| Caller count 20-49 | +2 |
| Caller count 10-19 | +1 |
| Is a class method (part of pattern) | +2 |
| Has misleading name | +2 |
| Source DLL provides many imports | +1 |
| Simple thunk (easy to document) | +1 |

**High impact (7+)**: Worth renaming and adding detailed knowledge
**Medium impact (4-6)**: Add to session knowledge, don't rename
**Low impact (1-3)**: Skip detailed analysis

## Special Cases

### Ordinal Imports
If external is ordinal-only:
```
D2Common.Ordinal_10014
```
- Look up in `docs/KNOWN_ORDINALS.md`
- Check if ordinal→name mapping exists
- Provide the resolved name in output

### Class Methods
If external appears to be a class method:
```
Unicode::strcat
Storm::SMemAlloc
Fog::FogAssert
```
- Search for other methods of same class
- Document the class namespace, not just the function
- Note the provider DLL

### Cross-DLL Thunks
If external is a thin wrapper:
```c
void Wrapper_6fb11000(int param) {
    OtherDll_RealFunction(param);
}
```
- Document what it wraps
- Note any parameter transformations
- Consider whether wrapper adds value

## Session Knowledge Integration

The orchestrator will use this output to:

1. **Skip re-analysis**: If `ValidateStringId` is encountered again, we already know its purpose
2. **Enrich documentation**: Plate comments can reference DLL, ordinal, true purpose
3. **Pattern matching**: If another function uses same pattern, apply known understanding
4. **Prioritization**: High-impact externals might be renamed globally

## Example Analysis

### Input
```json
{
  "external_name": "g_szLocalizationConfig",
  "external_address": "0x6fbb0de4",
  "calling_context": "Used as format string in wsprintfA"
}
```

### Analysis Process
1. `inspect_memory_content(0x6fbb0de4)` → `"%d"` (3 bytes)
2. `get_xrefs_to(0x6fbb0de4)` → 273 references
3. Sample caller analysis → All use `wsprintfA(buffer, &global, intValue)`

### Output
```json
{
  "external_name": "g_szLocalizationConfig",
  "analysis": {
    "is_thunk": false,
    "true_purpose": "Printf format string for integer to string conversion",
    "type": "const char *",
    "value": "\"%d\"",
    "caller_count": 273
  },
  "naming": {
    "current_name_accurate": false,
    "suggested_name": "g_szFmtDecimal",
    "reasoning": "It's a simple %d format, not localization config"
  },
  "patterns": {
    "common_usage": "wsprintfA(ansiBuffer, &g_szFmtDecimal, intValue); toUnicode(wideBuffer, ansiBuffer, len);",
    "context": "Part of int→ANSI→Unicode conversion pipeline"
  },
  "documentation_value": {
    "impact_score": 8,
    "reasoning": "273 refs - understanding this pattern applies everywhere"
  }
}
```

## Time Budget

Target: 30-60 seconds per external
- Don't deep-dive into every caller
- Sample 2-3 callers max for pattern detection
- Focus on impact and patterns, not exhaustive analysis

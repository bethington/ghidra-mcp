# FUNCTION_DOC_WORKFLOW_V5

Orchestrator workflow with **opportunistic documentation** - document the neighborhood, not just the target.

## Philosophy

When analyzing function F, we inevitably read its callers, callees, and globals. V5 captures that understanding immediately rather than discarding it. This creates a "documentation wave" that spreads outward from each target.

**Key Principle**: Every function we touch gets *some* documentation, scaled by relevance:
- Target function → Full documentation (Opus)
- Direct neighbors → Stub documentation (Haiku)  
- Referenced data → Name + type only (Haiku)
- **External functions → Parallel deep analysis (Haiku)** ← V5.1

**V5.1 Insight**: Don't skip externals - they're HIGH VALUE targets for parallel analysis.
External functions like library calls, ordinals, and cross-DLL references are often called
from dozens or hundreds of functions. Understanding them once provides context for all callers.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    OPUS (Orchestrator)                      │
│  • Target function: Full V2-quality documentation           │
│  • Decision: Which neighbors warrant stub documentation?    │
│  • Quality: All MCP tool execution and verification         │
│  • Session Knowledge: Accumulate learned patterns           │
└─────────────────────────────────────────────────────────────┘
         │              │              │              │              │
         ▼              ▼              ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ HAIKU        │ │ HAIKU        │ │ HAIKU        │ │ HAIKU        │ │ HAIKU        │
│ Stub Callee  │ │ Stub Caller  │ │ Name Globals │ │ Format Docs  │ │ Analyze      │
│ (depth 1)    │ │ (depth 1)    │ │ & Ordinals   │ │ for Target   │ │ Externals    │
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
```

### V5.1 Session Knowledge Accumulation

Each function documented adds to a session-level knowledge base:

```
┌─────────────────────────────────────────────────────────────┐
│                 SESSION KNOWLEDGE BASE                      │
├─────────────────────────────────────────────────────────────┤
│ External Patterns:                                          │
│   ValidateStringId → D2Lang.dll string lookup (50+ callers) │
│   Unicode::strcat → Wide string concatenation               │
│   g_szLocalizationConfig → "%d" format string (273 refs)    │
│                                                             │
│ Class/Namespace Insights:                                   │
│   Unicode class: 28 functions in D2Client.dll               │
│   Provider DLLs: D2WIN.DLL (rendering), D2LANG.DLL (i18n)   │
│                                                             │
│ Reusable Patterns:                                          │
│   Buffer init: loop of Unicode::_default_constructor_closure│
│   Localization: wsprintfA → toUnicode → ValidateStringId    │
└─────────────────────────────────────────────────────────────┘
```

The second function using `ValidateStringId` already knows it's a string lookup,
saving analysis time and improving documentation quality.

---

## Documentation Tiers

### Tier 1: FULL (Target Function)
Complete V2-quality documentation:
- Function classification and caller analysis
- Control flow mapping with decompiler verification
- All variables typed and renamed (Hungarian)
- All globals renamed
- Comprehensive plate comment with algorithm
- Inline comments for complex logic
- Ordinal annotations

**Model**: Opus
**Token budget**: Unlimited (this is the goal)

### Tier 2: STUB (Direct Neighbors)
Minimal useful documentation:
- Function name (PascalCase, descriptive)
- Prototype with typed parameters
- One-line plate comment: `[STUB] Brief purpose description`
- NO variable renaming (leave for full pass)
- NO inline comments

**Model**: Haiku subagent
**Token budget**: ~500 tokens per function
**Depth limit**: 1 (direct callers/callees only)

### Tier 3: REFERENCE (Data Items)
Name and type only:
- Globals: `DAT_xxx` → `g_dwFlags` or `g_pConfig`
- Strings: `s_xxx` → `szErrorMessage` or `szPath`
- Ordinals: Comment with API name

**Model**: Haiku subagent
**Token budget**: ~100 tokens per item
**Scope**: Only items directly used by target

### Tier 4: PARALLEL (High-Value Externals) ← V5.1 NEW

Deep parallel analysis for frequently-used externals:
- External library functions with 10+ xrefs
- Ordinal imports that appear repeatedly
- Cross-DLL thunks that wrap APIs
- Class/namespace patterns (Unicode::*, Storm::*, etc.)

**Model**: Haiku subagent (parallel)
**Token budget**: ~1000 tokens per external
**Trigger**: First encounter of external with high xref count

**Why this matters**: Externals like `ValidateStringId` (50+ callers) or 
`g_szLocalizationConfig` (273 refs) provide understanding that applies
across the entire codebase. Analyze once, benefit everywhere.

### Tier 5: SKIP (Low Value)

Mark for future only:
- Add to work queue if not already documented
- No documentation action now

---

## Phase 1: Initialize & Assess Scope

### 1.1 Get Target Function (Opus)
```
get_current_selection() → address, function_name
analyze_function_complete(address) → full context
```

### 1.2 Identify Documentation Neighborhood

From `analyze_function_complete` results, extract:

```json
{
  "target": {
    "name": "FUN_6fb12340",
    "address": "0x6fb12340"
  },
  "callees": [
    {"name": "FUN_6fb11000", "address": "0x6fb11000", "call_count": 3},
    {"name": "Ordinal_10342", "address": null, "call_count": 1}
  ],
  "callers": [
    {"name": "FUN_6fb15000", "address": "0x6fb15000"}
  ],
  "globals": [
    {"name": "DAT_6fbf42a0", "address": "0x6fbf42a0", "access": "read"},
    {"name": "s_Error_6fbe1234", "address": "0x6fbe1234", "access": "read"}
  ]
}
```

### 1.3 Filter for Stub Candidates (Opus Decision)

**Include in stub documentation if**:
- Function has default name (FUN_xxx) - not already documented
- Called/calls target ≥2 times (indicates importance)
- Is a leaf function (quick to stub)
- Is a thunk (trivial to document)

**Exclude from stub documentation if**:
- Already has custom name (assume documented)
- Has >20 callees (too complex for stub)

**Promote to PARALLEL tier if**:
- Is an external/ordinal with 10+ xrefs across codebase
- Is a library class method (Unicode::, Storm::, Fog::)
- Is a cross-DLL thunk frequently used
- Has not been analyzed this session (check knowledge base)

Produce filtered list:
```json
{
  "stub_callees": ["FUN_6fb11000"],
  "stub_callers": [],
  "parallel_externals": ["ValidateStringId", "Unicode::strcat", "g_szLocalizationConfig"],
  "reference_globals": ["DAT_6fbf42a0", "s_Error_6fbe1234"],
  "reference_ordinals": ["Ordinal_10342"],
  "skip": ["FUN_6fb99999"]
}
```

---

## Phase 2: Parallel Haiku Delegation

Launch multiple Haiku subagents **simultaneously** for maximum efficiency:

### 2.0 Parallel External Analysis (Haiku) ← V5.1 NEW

For each external in `parallel_externals`, spawn a subagent:

**Prompt**: `subtasks/ANALYZE_EXTERNAL.md`
**Input**:
```json
{
  "external_name": "ValidateStringId",
  "external_address": "0x6fb9981c",
  "context": "Called to look up string IDs 0x1110 and 0xf9e"
}
```
**Parallel queries to execute**:
1. `search_functions_by_name` - Find related functions
2. `get_function_callers` - How widely used?
3. `decompile_function` - What does it do?
4. `get_xrefs_to` for related globals

**Output** (stored in session knowledge base):
```json
{
  "external_name": "ValidateStringId",
  "true_purpose": "D2Lang.dll string table lookup (ordinal 10056)",
  "better_name": "GetLocalizedString",
  "caller_count": 50,
  "pattern": "Returns wchar_t* for string ID from .tbl files",
  "related_externals": ["GetLocaleString", "InitStringTables"],
  "usage_example": "ValidateStringId(0x1110) → localized string"
}
```

This runs IN PARALLEL with stub documentation, not sequentially.

### 2.1 Stub Callees (Haiku)
**Prompt**: `subtasks/STUB_FUNCTION.md`
**Input**:
```json
{
  "address": "0x6fb11000",
  "context": "Called by ProcessPlayerSlots to get slot data"
}
```
**Output**:
```json
{
  "name": "GetInventorySlot",
  "prototype": "UnitAny * __fastcall GetInventorySlot(UnitAny * pUnit, int nSlotIndex)",
  "summary": "Returns item pointer at specified inventory slot index"
}
```

### 2.2 Stub Callers (Haiku)
Same as 2.1 but with caller context.

### 2.3 Reference Globals (Haiku)
**Prompt**: `subtasks/NAME_GLOBALS.md`
**Input**:
```json
{
  "globals": [
    {"name": "DAT_6fbf42a0", "address": "0x6fbf42a0", "usage": "compared against 0"}
  ]
}
```
**Output**:
```json
{
  "renames": [
    {"old": "DAT_6fbf42a0", "new": "g_dwGameFlags", "type": "uint"}
  ]
}
```

### 2.4 Reference Ordinals (Haiku)
**Prompt**: `subtasks/LOOKUP_ORDINALS.md`
**Input**: List of ordinal calls
**Output**: API name mappings

---

## Phase 3: Apply Stub Documentation (Opus)

### 3.0 Store External Knowledge (V5.1)

Before applying stubs, integrate external analysis results into session knowledge:

```python
# Pseudocode for session knowledge update
for external_result in parallel_external_results:
    session_knowledge.externals[external_result.name] = {
        "purpose": external_result.true_purpose,
        "better_name": external_result.better_name,
        "caller_count": external_result.caller_count,
        "pattern": external_result.pattern
    }
    
    # If external is a thunk to known API, optionally rename it
    if external_result.better_name and external_result.caller_count > 20:
        consider_rename_thunk(external_result)
```

### 3.1 Apply Stubs

For each stub result from Haiku:

```
# Apply callee/caller stubs
rename_function_by_address(address, haiku_name)
set_function_prototype(name, haiku_prototype)
set_plate_comment(address, "[STUB] " + haiku_summary)

# Apply global renames
rename_data(address, haiku_global_name)
apply_data_type(address, haiku_type)
```

**Verification**: Check each rename succeeded. Log failures but continue.

---

## Phase 4: Full Target Documentation (Opus)

Now document the target function with full V2 rigor:

### 4.1 Delegate Extraction (Haiku)
**Prompt**: `subtasks/EXTRACT_VARIABLES.md`
Extract all variables, remaining globals, and ordinals.

### 4.2 Semantic Analysis (Opus)

With stub context AND external knowledge now available:
1. **Classify function**: Leaf | Worker | Thunk | Init | Cleanup | Callback | API
2. **Analyze callers**: Now with named functions, easier to understand patterns
3. **Map control flow**: Branches, loops, returns
4. **Resolve types**: Leverage callee prototypes for parameter inference
5. **Apply external knowledge**: Use session knowledge for richer documentation
   - If function calls `ValidateStringId`, we KNOW it's doing string lookup
   - If function uses `g_szLocalizationConfig`, we KNOW it's format string "%d"

### 4.3 Delegate Naming (Haiku)
**Prompt**: `subtasks/GENERATE_HUNGARIAN_NAMES.md`
Generate Hungarian names for all variables.

### 4.4 Apply Full Documentation (Opus)

```
rename_function_by_address(address, semantic_name)
set_function_prototype(name, full_prototype)

# Type all variables first
for var in variables:
    set_local_variable_type(address, var.old, var.type)

# Then rename
rename_variables(address, {old: new for var in variables})

# Rename remaining globals
for global in globals:
    rename_data(global.address, global.new_name)
```

### 4.5 Delegate Documentation (Haiku)
**Prompt**: `subtasks/FORMAT_PLATE_COMMENT.md`
Generate comprehensive plate comment.

### 4.6 Finalize (Opus)
```
set_plate_comment(address, formatted_comment)
batch_set_comments(inline_comments)
```

---

## Phase 5: Update Work Queue & Knowledge Base

After completing target:

1. **Mark target complete** in tracking system
2. **Upgrade stubs to TODO**: Functions that got stub documentation should be added to work queue for eventual full documentation
3. **Record relationships**: Note which functions were stubbed from this target (helps prioritize related functions)
4. **Persist session knowledge**: External patterns learned persist for entire session

```json
{
  "completed": "ProcessPlayerSlots",
  "stubs_created": ["GetInventorySlot", "ValidateSlotIndex"],
  "globals_renamed": ["g_dwGameFlags", "g_nMaxSlots"],
  "externals_analyzed": ["ValidateStringId", "Unicode::strcat"],
  "knowledge_gained": {
    "ValidateStringId": "D2Lang string lookup, 50+ callers",
    "g_szLocalizationConfig": "\"%d\" format, 273 refs"
  },
  "suggested_next": ["GetInventorySlot"]
}
```

### Session Knowledge Carryover

The NEXT function documented benefits from this session's learning:

| External | First Encounter | Second Encounter |
|----------|-----------------|------------------|
| ValidateStringId | Spawn subagent, analyze | Already know it's string lookup |
| Unicode::strcat | Spawn subagent, find 28 funcs | Already know it's D2WIN.DLL |
| g_szLocalizationConfig | Spawn subagent, find 273 refs | Already know it's "%d" |

**Amortized cost**: Heavy analysis on first function, fast documentation on subsequent.

---

## Stub Quality Guidelines

A good stub captures enough to be useful without full analysis:

### Good Stub Plate Comment
```
[STUB] Returns item at inventory slot index.
Called by: ProcessPlayerSlots
Needs: Full variable analysis, inline comments
```

### Stub Prototype Rules
- Use obvious types from context (pUnit, nIndex, dwFlags)
- Prefer generic types if uncertain (void *, int, uint)
- Include calling convention if detectable
- Mark uncertain parameters with `/* uncertain */` suffix

### When to Skip Stubbing
- Function is already documented (has custom name)
- Function is in different module
- Function is too complex (>50 lines, >5 callees)
- Function is deeply nested utility (called by many)

---

## Efficiency Analysis

### Token Usage Comparison

| Approach | Target | Neighbors | Externals | Total | Quality |
|----------|--------|-----------|-----------|-------|---------|
| V2 (single) | 5000 | 0 | 0 | 5000 | Full target only |
| V4 (delegated) | 3000 | 0 | 0 | 3000 | Full target, efficient |
| V5 (opportunistic) | 3000 | 1500 | 0 | 4500 | Full target + 3 stubs |
| V5.1 (parallel ext) | 3000 | 1500 | 2000 | 6500 | Full + stubs + deep external knowledge |

**V5.1 first function**: ~6500 tokens (higher upfront investment)
**V5.1 subsequent functions**: ~3500 tokens (external knowledge reused)

### Parallel Execution Timing

```
Traditional (Sequential):                V5.1 (Parallel):
┌──────────────────────────┐             ┌──────────────────────────┐
│ Analyze target (30s)     │             │ Analyze target           │──┐
├──────────────────────────┤             │ (30s)                    │  │
│ Analyze external 1 (20s) │             └──────────────────────────┘  │
├──────────────────────────┤             ┌──────────────────────────┐  │
│ Analyze external 2 (20s) │             │ ║ Haiku: External 1      │  ├── All parallel
├──────────────────────────┤             │ ║ Haiku: External 2      │  │
│ Analyze external 3 (20s) │             │ ║ Haiku: External 3      │  │
├──────────────────────────┤             │ (20s total)              │──┘
│ Document (30s)           │             └──────────────────────────┘
├──────────────────────────┤             ┌──────────────────────────┐
│ Total: 120s              │             │ Document with context    │
└──────────────────────────┘             │ (30s)                    │
                                         ├──────────────────────────┤
                                         │ Total: 50s (58% faster)  │
                                         └──────────────────────────┘
```

### When V5.1 Wins
- Dense call graphs (many interconnected functions)
- Iterative documentation (stubs AND external knowledge accelerate future passes)
- Team workflows (stubs help others understand context)
- **High-fanout externals** (analyzing once benefits 50+ callers)
- **Long sessions** (amortized learning cost across many functions)

### When V5.1 Loses
- Sparse call graphs (isolated functions)
- One-off analysis (not returning to this area)
- Token-constrained scenarios
- **First function only** (upfront cost not amortized)

---

## Subtask Reference

| Subtask | Model | Purpose | New in V5? |
|---------|-------|---------|------------|
| `subtasks/EXTRACT_VARIABLES.md` | Haiku | Pattern extraction | No |
| `subtasks/GENERATE_HUNGARIAN_NAMES.md` | Haiku | Apply naming rules | No |
| `subtasks/LOOKUP_ORDINALS.md` | Haiku | Reference table lookup | No |
| `subtasks/FORMAT_PLATE_COMMENT.md` | Haiku | Template formatting | No |
| `subtasks/STUB_FUNCTION.md` | Haiku | Quick function stub | **Yes** |
| `subtasks/NAME_GLOBALS.md` | Haiku | Global naming | **Yes** |
| `subtasks/ANALYZE_EXTERNAL.md` | Haiku | Deep external analysis | **Yes (V5.1)** |

---

## Output Format

```
DONE: FunctionName
Completed: Yes
Stubs Created: 3 (GetInventorySlot, ValidateSlotIndex, CheckSlotFlags)
Globals Renamed: 5
Externals Analyzed: 2 (ValidateStringId, Unicode::strcat)
Session Knowledge: +2 patterns learned
Haiku Delegations: 8 (2 stub, 1 global, 1 extract, 1 name, 1 format, 2 external)
Changes: Full documentation + neighborhood stubs + external understanding
```

---

## Configuration Options

```json
{
  "stub_depth": 1,
  "max_stubs_per_target": 5,
  "stub_callee_threshold": 2,
  "stub_caller_threshold": 1,
  "skip_complex_threshold": 20,
  "include_already_named": false,
  "parallel_external_threshold": 10,
  "max_parallel_externals": 5,
  "enable_session_knowledge": true
}
```

Adjust based on:
- **stub_depth**: How far to stub (1 = direct only, 2 = neighbors of neighbors)
- **max_stubs_per_target**: Cap to prevent runaway stubbing
- **stub_callee_threshold**: Min call count to warrant stub
- **skip_complex_threshold**: Callee count that's "too complex"
- **parallel_external_threshold**: Min xref count to trigger parallel external analysis
- **max_parallel_externals**: Cap on parallel subagent spawns per function
- **enable_session_knowledge**: Whether to accumulate and reuse external patterns

---

## V5.1 Implementation Notes

### Decompiler Cache Management

After ALL changes are applied (stubs, renames, types, comments), force a single cache refresh:

```python
# Apply all changes first
rename_function_by_address(...)
set_function_prototype(...)
rename_variables(...)
batch_set_comments(...)

# THEN refresh cache once
decompile_function(address, force=True)  # Single refresh at end

# THEN verify
analyze_function_completeness(address)  # Now sees all changes
```

This prevents cache coherency issues where changes appear to not persist.

### Parallel Subagent Spawn Pattern

```python
# Spawn all external analysis subagents at once
async with parallel_execution():
    results = await asyncio.gather(
        analyze_external("ValidateStringId", ...),
        analyze_external("Unicode::strcat", ...),
        analyze_external("g_szLocalizationConfig", ...),
        stub_function("FUN_6fb11000", ...),
        stub_function("FUN_6fb22000", ...)
    )

# All complete in ~20s instead of ~100s sequential
```

### Session Knowledge Persistence

For multi-function sessions, maintain knowledge across targets:

```python
class SessionKnowledge:
    externals: Dict[str, ExternalInfo] = {}
    patterns: List[Pattern] = []
    
    def is_known(self, external_name: str) -> bool:
        return external_name in self.externals
    
    def add_external(self, name: str, info: ExternalInfo):
        self.externals[name] = info
        
    def get_external_context(self, name: str) -> Optional[str]:
        if name in self.externals:
            return self.externals[name].pattern
        return None
```

This allows the second function using `ValidateStringId` to skip analysis
and immediately apply the known pattern to its documentation.

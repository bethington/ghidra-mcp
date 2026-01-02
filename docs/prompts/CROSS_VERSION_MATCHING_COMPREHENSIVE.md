# Cross-Version Function Matching Comprehensive Workflow

Systematically propagate function documentation across all Diablo II / Lord of Destruction versions by leveraging version clustering, DLL migration awareness, and multi-tier matching strategies.

## Version Landscape

### Version Clusters

Versions naturally group into clusters based on code similarity:

| Cluster | Versions | Codename | Matching Strategy |
|---------|----------|----------|-------------------|
| **Classic** | 1.00-1.06b | Pre-LoD | Hash matching within cluster; string/callgraph to LoD |
| **Early LoD** | 1.07-1.10 | "Stable LoD" | High hash match rate (~40-60%) within cluster |
| **Refactor** | 1.10→1.11 | "The Great Refactor" | Complex matching required - string, callgraph, structure |
| **Modern LoD** | 1.11-1.14d | "Post-Refactor" | High hash match rate (~50-70%) within cluster |
| **PD2/Mods** | PD2 S1-current | "Modded" | Based on 1.13c/1.14d; high match to Modern LoD |

### Key Refactoring Events

1. **1.07 Release** (LoD Launch): Major restructuring from Classic
2. **1.09→1.10**: Synergy system, skill rebalance - moderate code changes
3. **1.10→1.11**: **MAJOR REFACTOR** - Function migration, DLL reorganization, calling convention changes
4. **1.13c→1.14**: Minor patches, some security fixes

### DLL Migration Patterns (1.10→1.11)

Functions were moved between DLLs during the 1.11 refactor:

| Original DLL | Destination DLL | Function Categories |
|--------------|-----------------|---------------------|
| D2Client.dll | D2Common.dll | Unit utilities, stat queries, inventory helpers |
| D2Client.dll | D2Game.dll | Server-authoritative game logic |
| D2Game.dll | D2Common.dll | Shared calculation functions |
| Inline code | D2Common.dll | Frequently duplicated utility code |

**Implication**: When a function is missing from D2Client 1.11, search D2Common.dll and D2Game.dll before concluding it was removed.

## Strategic DLL Processing Order

Follow BINARY_DOCUMENTATION_ORDER.md tiers, but optimize for cross-version propagation:

### Phase 1: Foundation DLLs (Best Cross-Version Stability)
```
1. Storm.dll      - Very stable across versions, high hash match
2. Fog.dll        - Memory patterns consistent, good hash match
3. D2Lang.dll     - Localization stable, string-heavy (good anchors)
4. D2CMP.dll      - Graphics formats stable
```

### Phase 2: Core Game Logic (Version-Sensitive)
```
5. D2Common.dll   - CRITICAL: Document in canonical version first
                    Then propagate to all versions
                    Functions ADDED in 1.11 migrated from D2Client
```

### Phase 3: Subsystems (Moderate Stability)
```
6-10. D2Sound, D2Win, D2Gfx, D2Gdi, D2Net - Relatively stable
```

### Phase 4: High-Level Logic (Most Version Variation)
```
11. D2Multi.dll   - Multiplayer code varies significantly
12. D2Game.dll    - Server logic - many version-specific changes
13. D2Client.dll  - Client logic - most affected by 1.11 refactor
```

### Phase 5: Entry Points
```
14-15. D2Launch, Game.exe - Stable loaders
```

## Canonical Version Selection

Choose a "canonical" version as documentation source:

| For Cluster | Canonical Version | Reason |
|-------------|-------------------|--------|
| Classic | 1.06b | Final pre-LoD, most symbols |
| Early LoD | 1.09d or 1.10 | Mature pre-refactor |
| Modern LoD | 1.13c or 1.13d | Best community documentation |
| PD2 | 1.13c base | Same as Modern LoD |

**Recommended Start**: 1.13d as canonical (most existing documentation), propagate backward to 1.10, then bridge to 1.07.

## Phase 0: Documentation Status Pre-Check

**CRITICAL**: Before starting cross-version matching, check what's already documented to avoid wasted effort.

### Step 1: Compare Documentation Levels
```
# Check undocumented function count in each version
search_functions_enhanced(has_custom_name=false, limit=1, program="1.07/D2Client.dll")
# Note the "total" field - this is undocumented count

search_functions_enhanced(has_custom_name=false, limit=1, program="1.11/D2Client.dll")
# Compare totals to understand documentation gap
```

### Step 2: Check Specific Function Categories
```
# See if Quest functions already match (example)
search_functions_by_name(query="Quest", program="1.07/D2Client.dll")
search_functions_by_name(query="Quest", program="1.11/D2Client.dll")
# If counts and names match → already propagated, skip this category
```

### Step 3: Identify String Anchor Coverage
Before matching, build a map of source file strings to undocumented functions:
```
# Find source file path strings
list_strings(filter=".cpp", limit=100)

# For each source file, check xrefs for FUN_* functions
get_xrefs_to(address="string_addr")
# If all xrefs are to named functions → category already documented
```

## Multi-Tier Matching Strategy

### Tier 1: Hash Matching (Automated, 100% Confidence)

**Within Cluster** - Expect 40-70% match rate:
```
# Build hash index from canonical version
build_function_hash_index(programs=["/1.13d/D2Client.dll"], filter="documented")

# Propagate to same-cluster version
open_program("/1.12a/D2Client.dll")
lookup_function_by_hash(address="0x...")  # For each FUN_*
propagate_documentation(source_hash="...", target_programs=["1.12a"])
```

**Across Cluster Boundary** - Expect 1-5% match rate:
```
# Still worth running - catches truly unchanged functions
# Small utility functions often survive refactors unchanged
```

### Tier 2: String Anchor Matching (Semi-Automated, High Confidence)

Strings are the most reliable cross-version anchors because:
- Error messages rarely change
- Registry keys persist
- Data file names are stable
- Debug/source paths remain

**String Categories by Reliability**:

| Reliability | String Type | Example | Why |
|-------------|-------------|---------|-----|
| **Highest** | Source file paths | `"..\Source\D2Client\UI\panel.cpp"` | Directly identifies code module; xrefs point to functions in that file |
| **Highest** | Registry keys | `"SOFTWARE\\Blizzard Entertainment\\Diablo II"` | Never change across versions |
| **High** | Data file paths | `"data\\global\\excel\\skills.txt"` | Stable file structure |
| **High** | Error messages | `"Failed to load character"` | Rarely modified |
| **Medium** | UI strings | `"Mini Panel"`, `"Character"` | May be localized differently |
| **Medium** | Assert messages | `"idx < NUM_QUESTS"` | Usually stable but may change |
| **Lower** | Generic strings | Numbers, common words | Too common, many false matches |

**Source File Path Strings Are Gold**: These strings (like `automap.cpp`, `panel.cpp`, `Quests.cpp`) directly identify which source file a function belongs to. Create a `string_anchors.json` mapping file to track these across versions:
```json
{
  "source_files": [
    {"name": "panel.cpp", "addr_1_07": "6fbb7784", "addr_1_11": "6fb86c18"},
    {"name": "automap.cpp", "addr_1_07": "6fbb1d70", "addr_1_11": "6fb85e3c"},
    {"name": "Quests.cpp", "addr_1_07": "6fbb10b4", "addr_1_11": "6fbb10b4"}
  ]
}
```

**Workflow**:
```
# 1. Export unique strings from canonical version
list_strings(program="1.13d/D2Client.dll", limit=10000)
# Filter for high-reliability strings (registry, paths, errors)

# 2. For each anchor string, find referencing function
get_xrefs_to(address="string_addr")
# Note: function name and purpose

# 3. Find same string in target version
list_strings(filter="Mini Panel", program="1.10/D2Client.dll")
get_xrefs_to(address="target_string_addr")

# 4. Compare decompiled code structure
decompile_function(address="source_func")
decompile_function(address="target_func")

# 5. If structure matches, propagate name
apply_function_documentation(target_address="...", function_name="...", ...)
```

### Tier 3: Call Graph Propagation (Manual, Medium-High Confidence)

Once anchor functions are matched, propagate through call relationships:

**Propagation Rules**:
1. **Direct Callees**: If MatchedFunc calls SubFuncA, and target MatchedFunc also has one callee → likely SubFuncA
2. **Direct Callers**: If ParentFunc calls MatchedFunc, find ParentFunc in target
3. **Sibling Functions**: Functions called by same parent often match

**Workflow**:
```
# Start from confirmed match
get_function_callees(name="SaveMiniPanelState", program="1.13d")
# Returns: [UpdateRegistryValue, GetPanelFlags, ...]

get_function_callees(name="FUN_6fb382c0", program="1.10")
# Returns: [FUN_xxx, FUN_yyy, ...]

# If callee count matches and ordinal patterns align → match
# Work outward from confirmed functions
```

**Call Graph Confidence Scoring**:
```
Score = (matched_callees * 2) + (matched_callers * 1.5) + (ordinal_matches * 1)
- Score > 5: High confidence
- Score 3-5: Medium confidence (verify manually)
- Score < 3: Low confidence (additional evidence needed)
```

### Tier 4: Ordinal Signature Matching (Targeted, Medium Confidence)

Functions calling specific D2Common/D2Game ordinals have a "fingerprint":

```
# Build ordinal signature for source function
get_function_callees(name="ProcessUnitStats")
# Signature: [Ordinal_10021, Ordinal_10047, Ordinal_10332, Ordinal_10854]

# Search target for functions with same ordinal combination
# Note: Ordinal NUMBERS change between versions!
# Map ordinals by FUNCTION NAME not number
```

**Ordinal Mapping Strategy**:
1. Document ordinal→name mapping for each version
2. Match by function name, not ordinal number
3. Create version-specific ordinal translation tables

### Tier 5: Structure-Based Matching (Complex, Medium Confidence)

For the 1.10→1.11 refactor boundary:

```
# Identify structure access patterns
analyze_struct_field_usage(address="0x...", struct_name="UnitAny")

# Match functions by:
# - Same fields accessed
# - Same access order
# - Same offset patterns
```

### Tier 6: Behavioral Matching (Manual, Low-Medium Confidence)

For functions with no clear anchors:

1. **Instruction Pattern**: Same prologue/epilogue, similar basic blocks
2. **Constant Values**: Same magic numbers, enum values
3. **Size/Complexity**: Similar instruction count, cyclomatic complexity
4. **Position Heuristic**: Functions at similar relative offsets within DLL

## Cross-DLL Migration Detection

When a function disappears between versions:

### Detection Workflow
```
# Function exists in D2Client 1.10 but not 1.11
decompile_function(name="ProcessUnitHelper", program="1.10/D2Client.dll")
# Note: unique strings, ordinal calls, structure accesses

# Search D2Common.dll (common migration target)
list_strings(filter="unique_string", program="1.11/D2Common.dll")
search_functions_by_name(query="Process", program="1.11/D2Common.dll")

# Search D2Game.dll (if server-related)
search_functions_by_name(query="Process", program="1.11/D2Game.dll")
```

### Migration Documentation
Record migrations in the function mapping database:
```json
{
  "ProcessUnitHelper": {
    "migration_history": {
      "1.07-1.10": {"dll": "D2Client.dll", "address": "0x6fb12340"},
      "1.11+": {"dll": "D2Common.dll", "address": "0x6fd45670", "ordinal": 10892}
    },
    "migration_notes": "Moved to D2Common during 1.11 refactor; now exported as ordinal"
  }
}
```

## Execution Workflow

### Phase 1: Index Building
```
1. Open canonical version (1.13d recommended)
2. Build hash index for all DLLs with documented functions
   build_function_hash_index(programs=["/1.13d/*"], filter="documented")
3. Export string anchor database
4. Export ordinal mapping table
```

### Phase 2: Same-Cluster Propagation
```
For each version in Modern LoD cluster (1.11b, 1.12, 1.13b, 1.14d):
  1. Open target DLL
  2. Run hash matching (expect 50-70% match)
  3. Apply string anchors for remaining
  4. Call graph propagation from matches
  5. Record unmatchable functions
```

### Phase 3: Cross-Cluster Propagation (1.13→1.10)
```
For Early LoD cluster (1.10, 1.09d, 1.09b):
  1. Hash matching (expect 1-10% match across boundary)
  2. String anchor matching (primary method)
  3. Call graph propagation
  4. DLL migration detection (check D2Common for missing D2Client funcs)
  5. Ordinal signature matching
  6. Manual behavioral matching for critical functions
```

### Phase 4: Early LoD Internal Propagation
```
For versions 1.07, 1.08, 1.09:
  1. Use 1.10 as intermediate canonical
  2. Hash matching (expect 40-60% within cluster)
  3. String/callgraph for remainder
```

### Phase 5: Classic Cluster (Optional)
```
1.00-1.06b requires separate effort:
  - Different DLL structure
  - Different function organization
  - String anchors still work
```

## Confidence Tracking

Maintain confidence levels for all propagated names:

| Level | Criteria | Marker |
|-------|----------|--------|
| **Verified** | Hash match OR manual code review | No marker |
| **High** | String anchor + structure match | `// [High confidence]` |
| **Medium** | Call graph + ordinal signature | `// [Medium confidence]` |
| **Low** | Behavioral/heuristic match | `// [Low confidence - verify]` |
| **Tentative** | Position/size heuristic only | `// [Tentative - needs review]` |

Add confidence marker to plate comment:
```
Match Confidence: High
Match Method: String anchor ("Mini Panel" registry key)
Source Version: 1.13d @ 0x6faf8c20
```

## Unmatchable Function Handling

Some functions genuinely don't exist across versions:

1. **Version-Specific Features**: Ladder-only, patch-specific
2. **Removed Code**: Dead code elimination
3. **Completely Rewritten**: Same purpose, different implementation
4. **Merged/Split**: Combined into other functions or split apart

Document unmatchable functions:
```
FUN_6fb99999 (1.10)
  Status: No match in 1.11+
  Reason: Feature removed (pre-ladder code)
  Related: Functionality moved to D2Game.dll server-side
```

## Output and Verification

### Per-Version Summary
```
D2Client.dll 1.10 → 1.13d Propagation Results:
  Hash Matches:      245 functions (12%)
  String Anchors:    412 functions (20%)
  Call Graph:        687 functions (33%)
  Ordinal Signature: 234 functions (11%)
  Manual Match:      156 functions (8%)
  Unmatched:         332 functions (16%)
  Total Documented:  1734 / 2066 (84%)
```

### Verification Checklist
- [ ] Hash matches applied without review needed
- [ ] String anchor matches verified structurally similar
- [ ] Call graph matches have 3+ common callees
- [ ] No accidental cross-DLL name collisions
- [ ] Migration functions documented in both DLLs
- [ ] Confidence markers added to plate comments
- [ ] Unmatched functions logged with reason

## Quick Reference Commands

```
# Build canonical index
build_function_hash_index(programs=["/1.13d/D2Client.dll", "/1.13d/D2Common.dll"], filter="documented")

# Check specific function hash
get_function_hash(address="0x...")
lookup_function_by_hash(address="0x...")

# String search across versions
list_strings(filter="search_term", program="version/dll")

# Call graph exploration
get_function_callers(name="FuncName", program="version/dll")
get_function_callees(name="FuncName", program="version/dll")

# Propagate single function
get_function_documentation(address="source_addr")
apply_function_documentation(target_address="target_addr", ...)

# Bulk propagation
propagate_documentation(source_address="0x...", target_programs=["1.10", "1.09d"])
```

## Practical Example: Source File String Anchor Workflow

This example shows the most effective cross-boundary matching technique.

### Step 1: Find Source File Strings
```
list_strings(filter=".cpp", limit=100)
# Output:
#   6fb86c18: "..\Source\D2Client\UI\panel.cpp"
#   6fb85e3c: "..\Source\D2Client\UI\automap.cpp"
#   6fbb10b4: "C:\Projects\Diablo2\Source\D2Client\QUEST\Quests.cpp"
```

### Step 2: Get XRefs to Find Undocumented Functions
```
get_xrefs_to(address="0x6fb86c18")  # panel.cpp
# Output:
#   From 6fadef83 in RenderGamePanels [DATA]      <- Already named
#   From 6fadecfe in FUN_6fadecd0 [DATA]          <- UNDOCUMENTED
#   From 6faded08 in FUN_6fadecd0 [DATA]
```

### Step 3: Examine and Name Undocumented Function
```
decompile_function(name="FUN_6fadecd0")
# Analyze: Gets player/merc units, calls skill panel renderer
# Conclusion: This renders skill panels for player and mercenary

rename_function(old_name="FUN_6fadecd0", new_name="RenderPlayerAndMercSkillPanels")
```

### Step 4: Follow Callees to Document Helper Functions
```
# FUN_6fadecd0 calls FUN_6fadebb0 - examine it
decompile_function(name="FUN_6fadebb0")
# Analyze: Renders skill panel at specific coordinates for a unit

rename_function(old_name="FUN_6fadebb0", new_name="RenderSkillPanelForUnit")
```

### Common Function Naming Patterns
| Pattern | Typical Purpose | Example |
|---------|----------------|---------|
| `LoadXxxResources` | Resource initialization | `LoadCharacterPanelResources` |
| `RenderXxx` | Drawing/display | `RenderPlayerAndMercSkillPanels` |
| `ProcessXxx` | Logic/iteration | `ProcessAutomapWaypoints` |
| `GetXxxForYyy` | Lookup/query | `GetAutomapIconForUnit` |
| `ClearXxx` / `ResetXxx` | Cleanup | `ClearAutomapMarkers` |
| `InitializeXxx` | Setup/init | `InitializeDialogStructure` |
| `HandleXxx` | Event handling | `HandlePanelMouseClick` |

## Tooling Improvement Opportunities

These tools would significantly accelerate cross-version matching:

| Tool | Purpose | Benefit |
|------|---------|---------|
| `compare_programs_documentation` | Compare FUN_* counts between programs | Quickly identify documentation gaps |
| `find_undocumented_by_string` | Return only FUN_* functions referencing a string | Filter out already-named functions |
| `batch_string_anchor_report` | For all .cpp strings, list FUN_* functions | Generate prioritized work queue |
| `function_similarity_score` | Compare two decompiled functions | Automate structural matching |

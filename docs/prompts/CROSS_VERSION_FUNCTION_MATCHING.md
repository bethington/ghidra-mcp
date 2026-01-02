# Cross-Version Function Matching Workflow

Match and synchronize function names across different versions of the same binary (e.g., D2Client.dll 1.07 vs 1.11).

## Strategy Overview

| Method | Best For | Match Rate | Confidence |
|--------|----------|------------|------------|
| Hash Matching | Identical functions | ~1-5% | 100% |
| String References | Functions using unique strings | ~10-20% | High |
| Call Graph | Functions with similar callers/callees | ~30-50% | Medium-High |
| Ordinal Signatures | Functions calling same DLL ordinals | ~20-40% | Medium |

## Method 1: Hash-Based Exact Matching

Use for functions that haven't changed between versions.

```
# Get hashes for documented functions in both versions
get_bulk_function_hashes(filter="documented", program="1.07/D2Client.dll")
get_bulk_function_hashes(filter="documented", program="1.11/D2Client.dll")

# Find exact matches
# Functions with identical hashes are structurally identical
# Propagate names directly
propagate_documentation(source_address="0x...", target_programs=["1.11"])
```

**Limitations**: Most functions change between versions (different instruction count, optimization changes). Expect only 1-5% exact matches.

## Method 2: String-Based Discovery

Find functions by unique string references they contain.

### Step 1: Identify Unique Strings
```
# Find strings that uniquely identify a function
list_strings(filter="Mini Panel")   # Registry keys
list_strings(filter=".txt")         # Data files
list_strings(filter="Error")        # Error messages
list_strings(filter="\\Source\\")   # Source file paths
```

### Step 2: Get Functions Referencing Strings
```
# Get xrefs to string in both versions
get_xrefs_to(address="string_addr_107", program="1.07")
get_xrefs_to(address="string_addr_111", program="1.11")
```

### Step 3: Verify Match
- Compare decompiled code structure
- Check if both read/write the string similarly
- Verify overall function purpose matches

**Best Strings for Matching**:
- Registry keys: "Diablo II", "Resolution", "Gamma"
- Data files: "sounds.txt", "skills.txt"
- Error messages: Unique error strings
- Source paths: "..\\Source\\D2Client\\..."

## Method 3: Call Graph Matching

Match functions by their caller/callee relationships.

### Step 1: Get Call Context
```
# For source function (already named)
get_function_callers(name="SourceFunc", program="1.07")
get_function_callees(name="SourceFunc", program="1.07")

# For candidate function
get_function_callers(name="FUN_xxx", program="1.11")
get_function_callees(name="FUN_xxx", program="1.11")
```

### Step 2: Match Criteria
Functions likely match if they share:
- **Same callee names** (especially ordinals like SetRegistryDword)
- **Similar caller structure** (parent functions with same purpose)
- **Same call depth position** (leaf vs worker vs orchestrator)

### Step 3: Propagate Through Graph
Once one function matches, its callers/callees become candidates:
```
1.07: ReinitializeGameSessionAndUI -> CleanupUIElementsAndSlots
1.11: FUN_6fb524b0               -> SaveMiniPanelStateAndCleanup
      ^^ Also likely matches! ^^
```

## Method 4: Ordinal Signature Matching

Match functions that call the same D2Common/D2Game ordinals.

### Step 1: Build Ordinal Signature
```
# Get callees and extract ordinal calls
get_function_callees(name="SourceFunc")
# Filter for Ordinal_XXXX calls
# Create signature: [10021, 10047, 10332]
```

### Step 2: Find Functions with Same Signature
```
# Search for functions calling same ordinal sequence
search_functions_by_name(query="Ordinal_10021")
# Check if they call same combination
```

### Ordinal Categories (D2Common.dll)
- 10001-10100: Core unit functions
- 10100-10200: Stat functions
- 10300-10400: Room/level functions
- 10800-10900: Item functions

## Recommended Workflow

### Phase 1: Exact Matches (Automated)
1. Build hash index for canonical (well-documented) version
2. Compute hashes for target version
3. Apply documentation to exact matches automatically

### Phase 2: String Discovery (Semi-Automated)
1. Export unique strings from canonical version
2. Find same strings in target version
3. Compare referencing functions
4. Apply names with human verification

### Phase 3: Call Graph Propagation (Manual)
1. Start from confirmed matches
2. Follow caller/callee relationships
3. Compare decompiled code
4. Apply names with verification

### Phase 4: Ordinal Signature (Targeted)
1. For remaining undocumented functions
2. Build ordinal call signature
3. Search for matching signatures
4. Verify via decompilation

## Function Mapping Database

Maintain a JSON database linking addresses across versions:

```json
{
  "functions": {
    "SaveMiniPanelStateAndCleanup": {
      "description": "Saves mini panel state to registry and cleans up resources",
      "match_method": "string_reference",
      "match_string": "Mini Panel",
      "versions": {
        "1.07": {"address": "0x6fb382c0", "name": "CleanupUIElementsAndSlots"},
        "1.11": {"address": "0x6faf8c20", "name": "SaveMiniPanelStateAndCleanup"},
        "1.13d": {"address": "0x6faf8c20", "name": "SaveMiniPanelStateAndCleanup"}
      }
    },
    "ReinitializeGameSessionAndUI": {
      "description": "Reinitializes game session after critical events",
      "match_method": "call_graph",
      "match_caller_of": "SaveMiniPanelStateAndCleanup",
      "versions": {
        "1.07": {"address": "0x6fb5a220", "name": "ReinitializeGameSessionAndUI"},
        "1.11": {"address": "0x6fb524b0", "name": "FUN_6fb524b0"}
      }
    }
  }
}
```

## Confidence Levels

| Confidence | Criteria | Action |
|------------|----------|--------|
| **High** | Hash match OR same string + same structure | Auto-apply |
| **Medium** | Same callees + similar callers | Apply with review |
| **Low** | Ordinal signature only | Manual verification required |
| **Tentative** | Similar structure only | Mark for future review |

## Common Pitfalls

1. **Same string, different function**: Functions may reference same string for different purposes (read vs write)
2. **Refactored functions**: Code may be split or merged between versions
3. **Inlined functions**: Small functions may be inlined in newer versions
4. **Renamed ordinals**: Ordinal numbers may change between DLL versions

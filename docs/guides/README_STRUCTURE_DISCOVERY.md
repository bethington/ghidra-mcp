# Structure Discovery Documentation Suite

## Complete Guide to Discovering and Applying Structures

This comprehensive documentation suite provides everything needed to systematically discover, verify, and apply data structures to functions in binary analysis.

**Version**: 1.0
**Last Updated**: 2025-10-23
**Status**: Complete Reference Suite

---

## What You'll Find Here

### Core Documentation Files

1. **STRUCTURE_DISCOVERY_PROMPT.md** - THE PROMPT
   - The complete prompt to use with Claude/Ghidra MCP
   - Use when starting structure discovery on any binary
   - 3000+ lines, 7-phase comprehensive methodology

2. **STRUCTURE_APPLICATION_WORKFLOW.md** - PRACTICAL GUIDE
   - Step-by-step practical implementation
   - Use when actually discovering a specific structure
   - Real examples (PlayerData struct), complete code examples

3. **STRUCTURE_DISCOVERY_MASTER_GUIDE.md** - COMPLETE REFERENCE
   - Unified complete guide combining all aspects
   - Use as master reference and training material
   - 5 essential prompts, workflow, checklists, patterns

---

## Quick Start (5 Minutes)

### The Essential Process

```
1. EXTRACT STRUCT (30 min)
   - Find definition in source
   - Document all fields and offsets
   - Create fingerprint

2. DISCOVER FUNCTIONS (2-3 hours)
   - Search for functions using key offsets
   - Decompile candidates
   - Analyze access patterns

3. VALIDATE (1-2 hours)
   - Score confidence for each function
   - Eliminate false positives
   - Sort by likelihood

4. APPLY (30-60 min)
   - Create struct in Ghidra
   - Apply to high-confidence functions
   - Spot-check results

5. DOCUMENT (1 hour)
   - Create results report
   - Generate examples
   - Build reference guides
```

**Total Time**: 6-8 hours per structure
**Result**: 30+ functions properly typed with correct struct types

---

## Which Document Should I Read?

### "I want to understand the complete methodology"
→ Read **STRUCTURE_DISCOVERY_MASTER_GUIDE.md** first

### "I need the exact prompt to give to Claude"
→ Use **STRUCTURE_DISCOVERY_PROMPT.md** (Part 1: Primary Prompt)

### "I'm actually discovering a structure right now"
→ Follow **STRUCTURE_APPLICATION_WORKFLOW.md** step-by-step

### "I need reference material while working"
→ Keep **STRUCTURE_DISCOVERY_MASTER_GUIDE.md** open

---

## Key Concepts

### Structure Fingerprint

Unique combination of features identifying a structure:

```
Example: PlayerData
- Offset 0x00: char[16] (name)
- Offset 0x10: pointer (quest)    ← KEY
- Offset 0x1c: pointer (waypoint) ← KEY
- Size: 0x28 bytes                ← DISTINCTIVE
- 3x adjacent pointers            ← UNIQUE
```

### Confidence Scoring

```
>85%  = CONFIRMED     (Apply immediately)
70-85% = LIKELY       (Apply after review)
50-70% = POSSIBLE     (Investigate)
<50%  = UNLIKELY      (Skip)
```

### Multi-Axis Search

```
Axis 1: Offset pattern
  - Functions accessing 0x10
  - Functions accessing 0x1c

Axis 2: Name pattern
  - Functions with "Player"
  - Functions with "Quest"

Result: Intersect for high confidence
```

---

## The 5 Essential Prompts

### 1. Structure Identification
Extract struct definition, document fields, create fingerprint

### 2. Function Discovery
Find all functions using struct, analyze patterns

### 3. Validation & Scoring
Score confidence, eliminate false positives

### 4. Struct Creation & Application
Create in Ghidra, apply to functions, verify

### 5. Documentation
Create results report, generate examples

---

## Methodology Overview

### 7-Phase Process

**Phase 1: IDENTIFICATION** (1-2 hours)
Extract struct, document fields, create fingerprint

**Phase 2: DISCOVERY** (2-3 hours)
Search patterns, decompile candidates, analyze results

**Phase 3: VALIDATION** (1-2 hours)
Score confidence, verify patterns, eliminate false positives

**Phase 4: CREATION** (30 min)
Create struct in Ghidra, verify creation

**Phase 5: APPLICATION** (1 hour)
Apply to functions, spot-check results

**Phase 6: VERIFICATION** (30 min)
Check applications, verify decompiler output

**Phase 7: DOCUMENTATION** (1-2 hours)
Create results report, generate examples

**Total**: 8-12 hours per structure

---

## Success Criteria

You'll know it's working when:

- ✅ Struct definition is complete and accurate
- ✅ Found 25+ functions using the struct
- ✅ Confidence scores average > 75%
- ✅ Struct created successfully in Ghidra
- ✅ Functions typed with correct struct type
- ✅ Decompiler shows named fields (not offsets)
- ✅ All spot checks pass
- ✅ Complete documentation created

---

## Common Structures to Discover

### D2Common.dll Structures

1. **UnitAny** (0xF4 bytes)
   - Universal entity (players, monsters, items)
   - 40+ functions, HIGH priority

2. **PlayerData** (0x28 bytes)
   - Player-specific data
   - 8+ functions, MEDIUM priority

3. **ItemData** (0x84 bytes)
   - Item properties
   - 30+ functions, HIGH priority

4. **Inventory** (0x2C bytes)
   - Item container
   - 40+ functions, HIGH priority

5. **StatList** (0x3C bytes)
   - Statistics container
   - 25+ functions, MEDIUM priority

---

## Tools Used

- **Ghidra 11.4.2**: Binary analysis
- **Ghidra MCP**: REST API operations
- **Claude**: Structure analysis
- **Text Editor**: Documentation

### Key Ghidra MCP Commands

```
search_functions_enhanced()     - Find functions
decompile_function()            - Get decompilation
create_struct()                 - Create struct
set_function_prototype()        - Type parameters
batch_decompile_functions()     - Process multiple
```

---

## Tips & Tricks

### Accelerating Discovery

1. Use multiple search axes simultaneously
2. Start with obvious anchor functions
3. Batch decompile 50+ functions at once
4. Leverage cross-references

### Avoiding False Positives

1. Don't rely on single field access alone
2. Watch for generic memory operations
3. Check for contradictory patterns
4. Look for logical consistency

---

## Common Patterns

### Pattern: Simple Accessor
```c
void *GetPlayerQuests(void *p) {
    return *(void**)(p + 0x10);
}
→ HIGH confidence if named correctly
```

### Pattern: Initialization
```c
void CreatePlayer(void *p) {
    memset(p, 0, 0x28);
    *(void**)(p + 0x10) = NULL;
}
→ VERY HIGH confidence if size matches
```

### Pattern: Linked List
```c
for (p = list; p; p = *(void**)(p + 0xE8)) { }
→ HIGH confidence (self-referential)
```

---

## Next Steps

1. Read STRUCTURE_DISCOVERY_MASTER_GUIDE.md
   - Understand complete methodology
   - Learn from examples

2. Choose a struct to discover
   - From common list or your binary

3. Follow STRUCTURE_APPLICATION_WORKFLOW.md
   - Step-by-step practical guide
   - Real code examples

4. Use STRUCTURE_DISCOVERY_PROMPT.md
   - Exact prompt to use
   - Feed to Claude

5. Execute the workflow
   - Follow methodology
   - Document findings

---

## Document Map

```
README_STRUCTURE_DISCOVERY.md (you are here)
  └─ Overview and navigation

STRUCTURE_DISCOVERY_PROMPT.md
  └─ Complete prompt (7 phases)

STRUCTURE_APPLICATION_WORKFLOW.md
  └─ Practical step-by-step guide

STRUCTURE_DISCOVERY_MASTER_GUIDE.md
  └─ Complete unified reference
```

---

## Conclusion

This documentation suite provides:

- ✅ Comprehensive methodology for any binary
- ✅ Exact prompts ready to use
- ✅ Practical examples with real data
- ✅ Step-by-step implementation guides
- ✅ Reference materials for lookup
- ✅ Troubleshooting guides
- ✅ Success criteria for verification

**Total Documentation**: 6500+ lines
**Coverage**: Complete methodology
**Status**: Production-ready

**Get Started Now**: Pick a struct and follow the workflow!

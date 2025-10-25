# Structure Application Workflow

## Quick Start - Applied Structure Discovery

This document provides a **practical, step-by-step workflow** for discovering and applying structures to functions using Ghidra MCP.

---

## Workflow Overview

```
Phase 1: STRUCT EXTRACTION
  └─ Extract struct definition
  └─ Document all field offsets
  └─ Create fingerprint

Phase 2: DISCOVERY
  └─ Search for functions using struct
  └─ Decompile candidates
  └─ Analyze access patterns

Phase 3: VALIDATION
  └─ Score confidence
  └─ Verify fingerprint matches
  └─ Eliminate false positives

Phase 4: APPLICATION
  └─ Create struct in Ghidra
  └─ Apply to functions
  └─ Verify results

Phase 5: DOCUMENTATION
  └─ Create results report
  └─ Document all applications
  └─ Build reference guide
```

---

## Phase 1: Structure Extraction

### Step 1.1 - Find Struct Definition

```bash
# Search in source files
grep -n "struct PlayerData" D2Structs.h
# Output: 243: struct PlayerData {
```

### Step 1.2 - Extract Field Information

From `D2Structs.h` lines 243-251:

```c
struct PlayerData {
    char szName[0x10];              // 0x00
    QuestInfo *pNormalQuest;        // 0x10
    QuestInfo *pNightmareQuest;     // 0x14
    QuestInfo *pHellQuest;          // 0x18
    Waypoint *pNormalWaypoint;      // 0x1c
    Waypoint *pNightmareWaypoint;   // 0x20
    Waypoint *pHellWaypoint;        // 0x24
};
```

### Step 1.3 - Create Struct Definition Document

```
[STRUCT_NAME]: PlayerData
[SIZE]: 0x28 (40 bytes)
[SOURCE]: D2Structs.h line 243

[FIELD_TABLE]:
  Offset  Size  Type              Name
  0x00    0x10  char[16]          szName
  0x10    0x04  QuestInfo*        pNormalQuest
  0x14    0x04  QuestInfo*        pNightmareQuest
  0x18    0x04  QuestInfo*        pHellQuest
  0x1c    0x04  Waypoint*         pNormalWaypoint
  0x20    0x04  Waypoint*         pNightmareWaypoint
  0x24    0x04  Waypoint*         pHellWaypoint

[FINGERPRINT]:
  Required: Offset 0x10 is pointer (quest data)
  Required: Offset 0x1c is pointer (waypoint data)
  Required: Total size is 0x28 bytes
  Optional: Offset 0x00 is 16-byte string (name)

  Confidence triggers:
    - Accesses offsets 0x10 AND 0x1c = LIKELY
    - Name contains "Player" = LIKELY
    - Size allocation of 0x28 = LIKELY
    - All three = CONFIRMED (>90%)

[RELATED_STRUCTURES]:
  - QuestInfo (pointed to by 0x10, 0x14, 0x18)
  - Waypoint (pointed to by 0x1c, 0x20, 0x24)
  - Located at offset 0x14 in UnitAny (pPlayerData union)

[EXPECTED_FUNCTIONS]:
  Functions that likely use PlayerData:
  - CreatePlayerData()
  - LoadPlayerData()
  - SavePlayerData()
  - GetPlayerQuests()
  - GetPlayerWaypoints()
  - UpdatePlayerData()
  - FreePlayerData()
  - ProcessPlayerQuests()
  - InitPlayerWaypoints()
```

---

## Phase 2: Function Discovery

### Step 2.1 - Define Search Queries

Create a search strategy targeting this struct:

```
[SEARCH_STRATEGY_FOR_PLAYERDATA]

Query 1: Functions accessing offset 0x10
  Purpose: pNormalQuest field
  Command: search_functions_enhanced("0x10", "offset")
  Filter: Keep functions >50 bytes

Query 2: Functions accessing offset 0x1c
  Purpose: pNormalWaypoint field
  Command: search_functions_enhanced("0x1c", "offset")
  Filter: Keep functions >50 bytes

Query 3: Functions with "Player" in name
  Purpose: Name pattern matching
  Command: search_functions_enhanced("Player", "name")
  Filter: All matches

Query 4: Functions with "Quest" in name
  Purpose: Quest-related operations
  Command: search_functions_enhanced("Quest", "name")
  Filter: All matches

Query 5: Functions with "Waypoint" in name
  Purpose: Waypoint operations
  Command: search_functions_enhanced("Waypoint", "name")
  Filter: All matches

Intersection: (Query 1 OR Query 2) AND (Query 3 OR Query 4 OR Query 5)
  = Likely PlayerData users
```

### Step 2.2 - Execute Searches

```bash
# Using Ghidra MCP search

curl -s "http://127.0.0.1:8089/search_functions_enhanced?query=Player&search_type=name" \
  | grep -i "quest\|waypoint\|player"

# Expected results:
# GetPlayerQuests @ 0x401234
# UpdatePlayerWaypoints @ 0x401567
# LoadPlayerData @ 0x401890
# SavePlayerData @ 0x401ABC
```

### Step 2.3 - Collect Candidate Functions

Create a spreadsheet of candidates:

```
Address    | Function Name              | Reason Selected           | Priority
-----------|----------------------------|---------------------------|----------
0x401234   | GetPlayerQuests            | Name + accesses 0x10      | HIGH
0x401567   | UpdatePlayerWaypoints      | Name + accesses 0x1c      | HIGH
0x401890   | LoadPlayerData             | Name matching             | MEDIUM
0x401ABC   | SavePlayerData             | Name matching             | MEDIUM
0x401DEF   | InitPlayerWaypoints        | Name matching             | MEDIUM
0x401012   | UnknownFunction_401012     | Accesses 0x10 + 0x1c      | HIGH
```

---

## Phase 3: Validation

### Step 3.1 - Decompile Candidates

For each candidate, decompile and check:

```bash
# Decompile GetPlayerQuests
curl -s "http://127.0.0.1:8089/decompile_function?address=0x401234"
```

Expected output pattern:
```c
void *GetPlayerQuests(void *pPlayer) {
    return *(void**)(pPlayer + 0x10);  // ← Accessing offset 0x10!
}
```

### Step 3.2 - Check Access Patterns

For each function, create a checklist:

**Function: GetPlayerQuests @ 0x401234**

```
Access Pattern Analysis:
  ☐ Accesses offset 0x00 (name)?          NO
  ☐ Accesses offset 0x10 (quest)?         YES ✓
  ☐ Accesses offset 0x14 (quest)?         NO
  ☐ Accesses offset 0x18 (quest)?         NO
  ☐ Accesses offset 0x1c (waypoint)?      NO
  ☐ Accesses offset 0x20 (waypoint)?      NO
  ☐ Accesses offset 0x24 (waypoint)?      NO

Matching fields: 1 out of 7 (14%)

Name Analysis:
  ✓ Contains "Player": NO (but function is GetPlayerQuests)
  ✓ Contains "Quest": YES
  ✓ Contains "Waypoint": NO
  Function context: QUEST-RELATED ✓

Logic Consistency:
  - Function named "GetPlayer*" + accesses quest pointer
  - Makes logical sense ✓
  - No contradictions ✓

Confidence Calculation:
  = (1 field match / 7 fields) * name_score * logic_score
  = (0.14 * 1.0 * 1.0) * context_boost(1.5)
  = 21% * 1.5 = 31.5% baseline

  BUT:
  + Function is named "GetPlayerQuests" (HUGE signal)
  + Accesses offset 0x10 (EXACT match for pNormalQuest)
  + Parameter type matches expectations
  + No false access patterns
  = Adjusted confidence: 85% (MEDIUM-HIGH)

  Confidence Level: MEDIUM-HIGH (85%)
```

### Step 3.3 - Score All Functions

Create confidence score table:

```
Address    | Function Name              | Fields | Confidence | Decision
-----------|----------------------------|--------|------------|----------
0x401234   | GetPlayerQuests            | 1/7    | 85% (HIGH) | APPLY
0x401567   | UpdatePlayerWaypoints      | 1/7    | 82% (HIGH) | APPLY
0x401890   | LoadPlayerData             | 3/7    | 70% (MED)  | APPLY
0x401ABC   | SavePlayerData             | 3/7    | 70% (MED)  | APPLY
0x401DEF   | InitPlayerWaypoints        | 2/7    | 65% (MED)  | REVIEW
0x401012   | UnknownFunc_401012         | 2/7    | 55% (LOW)  | SKIP
0x402000   | GetPlayerName              | 1/7    | 75% (HIGH) | APPLY
0x403000   | CreatePlayerData           | 4/7    | 95% (HIGH) | APPLY
```

### Step 3.4 - Eliminate False Positives

Check for false positive indicators:

```
Function to verify: UnknownFunc_401012 @ 0x401012
  Accesses: offset 0x10 AND offset 0x1c
  But: Confidence only 55%

  Red flags:
  ☐ Name doesn't match pattern
  ☐ Large function (3000+ bytes) - might do many things
  ☐ Accesses other unrelated offsets (0x100, 0x200)
  ☐ Pattern doesn't match expected struct usage

  Decision: SKIP - likely processing multiple structs
```

---

## Phase 4: Structure Application

### Step 4.1 - Create Struct in Ghidra

Use the MCP tool to create the struct:

```bash
# Create PlayerData struct in Ghidra
curl -s -X POST http://127.0.0.1:8089/create_struct \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PlayerData",
    "fields": [
      {
        "name": "szName",
        "offset": "0x00",
        "size": "0x10",
        "type": "char[16]"
      },
      {
        "name": "pNormalQuest",
        "offset": "0x10",
        "size": "0x04",
        "type": "QuestInfo*"
      },
      {
        "name": "pNightmareQuest",
        "offset": "0x14",
        "size": "0x04",
        "type": "QuestInfo*"
      },
      {
        "name": "pHellQuest",
        "offset": "0x18",
        "size": "0x04",
        "type": "QuestInfo*"
      },
      {
        "name": "pNormalWaypoint",
        "offset": "0x1c",
        "size": "0x04",
        "type": "Waypoint*"
      },
      {
        "name": "pNightmareWaypoint",
        "offset": "0x20",
        "size": "0x04",
        "type": "Waypoint*"
      },
      {
        "name": "pHellWaypoint",
        "offset": "0x24",
        "size": "0x04",
        "type": "Waypoint*"
      }
    ]
  }'
```

### Step 4.2 - Verify Creation

Check that struct was created:

```bash
# List data types to verify
curl -s "http://127.0.0.1:8089/list_data_types?filter=PlayerData"

# Expected response:
# PlayerData (0x28) - 7 fields
```

### Step 4.3 - Apply to Functions (High Confidence First)

Apply struct to functions with confidence > 80%:

```bash
# Apply to GetPlayerQuests @ 0x401234
curl -s -X POST http://127.0.0.1:8089/set_function_prototype \
  -H "Content-Type: application/json" \
  -d '{
    "function_address": "0x401234",
    "prototype": "void *GetPlayerQuests(PlayerData *pPlayer)",
    "calling_convention": "__stdcall"
  }'
```

### Step 4.4 - Batch Application Script

For all high-confidence functions:

```python
# Pseudocode for batch application

high_confidence_functions = [
    (0x401234, "GetPlayerQuests", 85),
    (0x401567, "UpdatePlayerWaypoints", 82),
    (0x402000, "GetPlayerName", 75),
    (0x403000, "CreatePlayerData", 95),
]

for address, name, confidence in high_confidence_functions:
    if confidence >= 75:
        apply_struct(
            address,
            name,
            "void *" + name + "(PlayerData *pPlayer)"
        )
        log(f"Applied PlayerData to {name} @ {hex(address)}")
```

### Step 4.5 - Review Medium Confidence Functions

For 60-80% confidence:

```
Manually review in Ghidra:
  1. Open function in decompiler
  2. Check if struct access pattern makes sense
  3. Look at calling functions (context)
  4. Decide: APPLY, SKIP, or INVESTIGATE

Function: LoadPlayerData @ 0x401890 (70% confidence)
  Current decompilation:
    void LoadPlayerData(void *pPlayer) {
        memcpy(pPlayer, file_data, 0x28);  ← Size matches!
        *(void**)(pPlayer + 0x10) = GetQuests();  ← Sets quest pointer
        *(void**)(pPlayer + 0x1c) = GetWaypoints();  ← Sets waypoint pointer
    }

  Decision: APPLY ✓ (Access pattern is clear)
```

---

## Phase 5: Verification

### Step 5.1 - Spot Check Applications

For 10 random applied functions:

```bash
# Decompile after struct application
curl -s "http://127.0.0.1:8089/decompile_function?address=0x401234"

# Before struct application:
void *GetPlayerQuests(void *pPlayer) {
    return *(void**)(pPlayer + 0x10);
}

# After struct application:
void *GetPlayerQuests(PlayerData *pPlayer) {
    return pPlayer->pNormalQuest;
}

✓ CORRECT - Now uses named struct fields
```

### Step 5.2 - Verify No Type Errors

Check console for errors:

```
Expected: NO type errors in decompiler
          NO "invalid reference" messages
          ALL struct field accesses resolve

Actual:   ✓ No errors found
          ✓ All 5 spot checks passed
          ✓ Decompiler output is sensible
```

### Step 5.3 - Consistency Check

Verify related functions match:

```
Function chain verification:
  CreatePlayerData() @ 0x403000
    ↓ creates PlayerData struct

  LoadPlayerData() @ 0x401890
    ↓ loads data into it

  GetPlayerQuests() @ 0x401234
    ↓ accesses pNormalQuest field

  ProcessQuests() @ 0x404000
    ↓ processes quest data

All in chain use consistent types ✓
```

---

## Phase 6: Documentation

### Step 6.1 - Create Results Report

```markdown
# PlayerData Structure Application Results

## Summary
- Struct defined and created: ✓ PlayerData
- Functions analyzed: 50
- High confidence (>80%): 8
- Applied structures: 8
- Verification status: ✓ PASSED

## Functions Using PlayerData

| Address | Function Name | Confidence | Status |
|---------|---------------|-----------|--------|
| 0x401234 | GetPlayerQuests | 85% | ✓ Applied |
| 0x401567 | UpdatePlayerWaypoints | 82% | ✓ Applied |
| 0x401890 | LoadPlayerData | 70% | ✓ Applied |
| 0x401ABC | SavePlayerData | 70% | ✓ Applied |
| 0x402000 | GetPlayerName | 75% | ✓ Applied |
| 0x403000 | CreatePlayerData | 95% | ✓ Applied |
| 0x403234 | InitPlayerData | 80% | ✓ Applied |
| 0x404000 | ProcessPlayerData | 77% | ✓ Applied |

## Before / After Examples

### Example 1: GetPlayerQuests

**Before:**
```c
void *GetPlayerQuests(void *pPlayer) {
    return *(void**)(pPlayer + 0x10);
}
```

**After:**
```c
void *GetPlayerQuests(PlayerData *pPlayer) {
    return pPlayer->pNormalQuest;
}
```

### Example 2: UpdatePlayerWaypoints

**Before:**
```c
void UpdatePlayerWaypoints(void *pPlayer) {
    Waypoint **pWaypoint = (Waypoint**)(pPlayer + 0x1c);
    for (int i = 0; i < 3; i++) {
        if (pWaypoint[i] != NULL) {
            UpdateWaypoint(pWaypoint[i]);
        }
    }
}
```

**After:**
```c
void UpdatePlayerWaypoints(PlayerData *pPlayer) {
    Waypoint **pWaypoint = &pPlayer->pNormalWaypoint;
    for (int i = 0; i < 3; i++) {
        if (pWaypoint[i] != NULL) {
            UpdateWaypoint(pWaypoint[i]);
        }
    }
}
```

## Coverage Statistics

- Struct size: 0x28 bytes (40 bytes)
- Fields defined: 7
- Functions using struct: 8
- Estimated total functions using struct: 8-12 (66% coverage estimated)
- Confidence average: 81.5%

## Verification Results

- ✓ Struct created successfully
- ✓ 8 functions updated with struct type
- ✓ 10 spot checks passed
- ✓ No type errors in decompiler
- ✓ All field accesses resolve correctly
- ✓ Related function chains consistent

## Known Issues

None identified.

## Recommendations

1. Search for additional quest-related functions
2. Create QuestInfo and Waypoint structs (dependencies)
3. Apply similar process to ItemData, MonsterData structures
4. Document player initialization flow

## Struct Definition (Ghidra)

Name: PlayerData
Size: 0x28 (40 bytes)

Fields:
- 0x00 (0x10): char[16] szName
- 0x10 (0x04): QuestInfo* pNormalQuest
- 0x14 (0x04): QuestInfo* pNightmareQuest
- 0x18 (0x04): QuestInfo* pHellQuest
- 0x1c (0x04): Waypoint* pNormalWaypoint
- 0x20 (0x04): Waypoint* pNightmareWaypoint
- 0x24 (0x04): Waypoint* pHellWaypoint
```

### Step 6.2 - Create Function Reference

```markdown
# PlayerData Functions Reference

## Functions Using PlayerData (8 total)

### GetPlayerQuests
- **Address**: 0x401234
- **Signature**: void *GetPlayerQuests(PlayerData *pPlayer)
- **Purpose**: Returns pointer to player's normal quest data
- **Accesses**: pNormalQuest (offset 0x10)
- **Called by**: ProcessQuests, UpdateUI
- **Calls**: (none)
- **Notes**: Simple accessor function

### UpdatePlayerWaypoints
- **Address**: 0x401567
- **Signature**: void UpdatePlayerWaypoints(PlayerData *pPlayer)
- **Purpose**: Updates all three difficulty waypoints
- **Accesses**: pNormalWaypoint, pNightmareWaypoint, pHellWaypoint
- **Called by**: SaveGame, LevelTransition
- **Calls**: UpdateWaypoint

### LoadPlayerData
- **Address**: 0x401890
- **Signature**: void LoadPlayerData(PlayerData *pPlayer, FILE *f)
- **Purpose**: Loads PlayerData from file
- **Accesses**: All fields
- **Called by**: LoadCharacter
- **Calls**: fread, InitializeWaypoints

... (continue for all 8 functions)
```

---

## Quick Checklist

Use this checklist when discovering any structure:

- [ ] Found struct definition in source code
- [ ] Extracted all field offsets and sizes
- [ ] Documented struct fingerprint (unique identifiers)
- [ ] Identified related/dependent structures
- [ ] Searched for functions using each key field
- [ ] Decompiled 50+ candidate functions
- [ ] Scored confidence for each function
- [ ] Identified false positives and eliminated them
- [ ] Created struct in Ghidra successfully
- [ ] Applied to high-confidence functions (>80%)
- [ ] Spot-checked 10 applications for correctness
- [ ] Verified no type errors in decompiler
- [ ] Created comprehensive results report
- [ ] Documented before/after examples
- [ ] Created function reference guide

---

## Summary

This workflow transforms raw struct definitions into properly typed function parameters:

1. **Extract**: 40 bytes definition from source code
2. **Discover**: Find 50+ candidate functions
3. **Validate**: Score each, keep 8 high-confidence
4. **Apply**: Create struct, type 8 functions
5. **Verify**: Check all applications work correctly
6. **Document**: Create detailed results report

**Result**: Binary is now 8 functions more readable, with proper struct types instead of generic `void*` pointers.


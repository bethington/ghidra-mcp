# Structure Discovery & Application Prompt

## Executive Summary

This document provides a systematic prompt and methodology for identifying, verifying, documenting, and applying data structures to functions in Ghidra using the MCP tools.

**Purpose**: Develop a repeatable, automatable process for discovering and applying struct types across a large binary codebase.

---

## Part 1: Structure Identification Prompt

### Primary Prompt (Use this in Claude/Ghidra MCP)

```
TASK: Comprehensive Structure Discovery and Application

OBJECTIVE:
Identify all instances of a specific struct pattern being used across the binary,
verify correctness, document findings, create/update in Ghidra, and apply to all
discovered functions.

METHODOLOGY:

PHASE 1: STRUCTURE PATTERN ANALYSIS
=====================================

Input: A struct name or pattern (e.g., "pUnit", "UnitAny", "PlayerData")

Step 1.1 - Source Identification
  - Search for struct definition in source files
  - Extract complete struct definition with all fields/offsets
  - Document struct size and field layout
  - Note any unions, arrays, or nested structures

Step 1.2 - Field Analysis
  - List all field names with their offsets
  - Document field types (pointers, DWORDs, WORDs, BYTEs, etc.)
  - Identify key distinguishing fields:
    * Signature/magic fields (e.g., dwSignature == 0x12345678)
    * Type fields (e.g., dwType == 1 means it's a unit)
    * Unique field names (e.g., "dwUnitId", "pFirstItem")
  - Create a field "fingerprint" (unique identifying fields)

Example Fingerprint for UnitAny:
  - Offset 0x00: dwType (values 0-5)
  - Offset 0x0C: dwUnitId (unique ID)
  - Offset 0x8C: wX coordinate (WORD)
  - Offset 0x8E: wY coordinate (WORD)
  - Offset 0xC4: dwFlags (flag bits)
  - Offset 0xE8: pListNext (self-referential for linked list)

Step 1.3 - Struct Documentation
  Create a reference document containing:

  [STRUCT_NAME]: <name>
  [SIZE]: <total_size_hex>
  [SIGNATURE_FIELD]: <offset_and_expected_value> (optional)
  [DISTINGUISHING_FIELDS]:
    - Field1: offset, type, description
    - Field2: offset, type, description
    - Field3: offset, type, description
  [UNIQUE_IDENTIFIER]: <most_reliable_way_to_identify>
  [SOURCE]: <where_struct_was_found>


PHASE 2: FUNCTION PARAMETER ANALYSIS
=====================================

Step 2.1 - Decompilation Analysis
  For a large sample of functions (~50+):

  a) Decompile function using Ghidra
  b) Look for these struct usage patterns:

     Pattern A - Direct Parameter:
       BOOL SomeFunction(void *pUnit)
       // Function body accesses: *(DWORD*)(pUnit + 0x0C) // dwUnitId

     Pattern B - Array Access:
       void ProcessUnit(...) {
           DWORD unitType = pUnit[0x00];  // dwType
           DWORD unitId = pUnit[0x0C];    // dwUnitId
       }

     Pattern C - Structure Member:
       void ProcessInventory(...) {
           Inventory *pInv = *(Inventory**)(pUnit + 0x60);  // offset matches!
       }

     Pattern D - Return Value:
       void *FindUnit(...) {
           // ... searching ...
           return pUnit;  // returning something that matches struct pattern
       }

     Pattern E - Comparison:
       if (*(DWORD*)(pUnit + 0x00) == 1) { // checking type field
           // This looks like UnitAny type checking!
       }

  c) Record:
     - Function address
     - Parameter name and position
     - How struct is accessed (array notation, pointer math)
     - Confidence level (HIGH/MEDIUM/LOW)

Step 2.2 - Access Pattern Matching
  Create a checklist of struct access patterns:

  For UnitAny specifically:
  ☐ Access at offset 0x00 (dwType)
  ☐ Access at offset 0x0C (dwUnitId)
  ☐ Access at offset 0x10 (dwMode)
  ☐ Access at offset 0x2C (pPath pointer)
  ☐ Access at offset 0x60 (pInventory)
  ☐ Access at offset 0x5C (pStats)
  ☐ Access at offset 0x8C-0x8E (wX, wY coordinates)
  ☐ Access at offset 0xC4 (dwFlags)
  ☐ Access at offset 0xE8 (pListNext chain)

  Count how many patterns match:
  - 5+ matches = CONFIRMED struct usage
  - 3-4 matches = LIKELY struct usage
  - 1-2 matches = POSSIBLE struct usage

Step 2.3 - Cross-Function Pattern Recognition

  a) Collect all suspicious functions that access the same offsets
  b) Group by access pattern similarity
  c) Look for function call chains:
     - Function A calls Function B
     - Both access same struct offsets
     - Likely same struct type

  d) Build a "struct usage graph"
  e) Note which functions are called together
  f) Identify high-confidence "anchor functions" that clearly use the struct


PHASE 3: STRUCT VALIDATION & VERIFICATION
===========================================

Step 3.1 - Confidence Scoring System

For each suspected function, calculate confidence score:

CONFIDENCE = (matching_fields / total_fields) * pattern_score

Where:
  - matching_fields = number of struct fields accessed
  - total_fields = total fields in struct definition
  - pattern_score = multiplier for access pattern type
    * Direct array access: 1.0x (most reliable)
    * Pointer math: 1.0x (reliable)
    * Single field access: 0.5x (could be coincidence)
    * Comparison only: 0.7x (type checking)

Example for UnitAny in FindClosestUnitInAreaByDistance:
  - Accesses: dwType (0x00), wX (0x8C), wY (0x8E), pListNext (0xE8)
  - Pattern: Array access throughout
  - Confidence = (4/40 fields) * 1.0 = 0.10 = 10% (LOW)

But combined with function name and context:
  - Context: "Find" + "Unit" + "Distance" = UNIT operation
  - Combined confidence: 85% (MEDIUM-HIGH)

Step 3.2 - Manual Verification Checklist

For HIGH confidence functions:
☐ Function name suggests struct type (contains "Unit", "Item", "Monster", etc.)
☐ Parameters match struct usage
☐ Return types match struct expectations
☐ Struct fields accessed are logically consistent
☐ No contradictions in field interpretation
☐ Cross-references to similar functions confirm pattern
☐ Documentation/comments mention struct name

Step 3.3 - False Positive Detection

Watch for patterns that look like struct but aren't:

  ❌ Single field access coincidence
     Example: Many functions access dword at 0x00, not necessarily a struct

  ❌ Generic memory access
     Example: memset(pData, 0, 0x100) - not struct-specific

  ❌ Different struct with same offset
     Example: offset 0x00 might be different things in different structs

  ❌ Hard-coded offsets
     Example: Some game code might hard-code values that happen to match

  Verification: Check if function only accesses one field - likely false positive
  Verification: If accesses seem random - not a struct, probably general data


PHASE 4: COMPREHENSIVE STRUCT SEARCH
=====================================

Step 4.1 - Systematic Function Search

Use this search strategy to find ALL functions using a struct:

Search 1: Direct string references (if available)
  - Search for struct field names in string constants
  - Search for variable names containing struct name
  - E.g., search for "pUnit" or "UnitAny"

Search 2: Offset-based pattern search
  - Search for functions accessing offset 0x00 (type field)
  - Search for functions accessing offset 0x0C (id field)
  - Search for functions accessing offset 0x8C (x coord)
  - Intersect results = likely users of this struct

Search 3: Cross-reference analysis
  - Find "anchor functions" that definitely use the struct
  - Get their callers (who calls them?)
  - Get their callees (what do they call?)
  - Functions in both sets likely process the struct

Search 4: Function name pattern search
  - Functions containing "Unit" keyword
  - Functions containing "Item" keyword
  - Functions containing "Monster" keyword
  - Functions containing "Player" keyword
  - Functions with names like "Get*", "Find*", "Create*", "Process*"

Search 5: Parameter type inference
  - Functions that take "void *pUnit" or similar
  - Functions that return "void *"
  - Functions that operate on data from known struct users

Step 4.2 - Build Complete Function List

For each function found:

  Function Address: 0x12345678
  Function Name: ProcessUnitData
  Parameter Position: First (pUnit)
  Confidence Level: HIGH (85%)
  Matching Fields: 5 out of 40
  Key Accesses:
    - [0x00]: Type checking (pUnit[0x00] == 1)
    - [0x8C]: X coordinate read
    - [0x8E]: Y coordinate read
    - [0xC4]: Flag checking
    - [0xE8]: List traversal
  Related Functions Called:
    - FindUnitInList()
    - UpdateUnitPosition()
  Related Functions That Call This:
    - MainGameLoop()
    - UpdateAllUnits()
  Notes: Clearly processes unit entities by coordinate


PHASE 5: STRUCT CREATION IN GHIDRA
===================================

Step 5.1 - Prepare Struct Definition

From source and analysis, create Ghidra struct definition:

Name: UnitAny
Size: 0xF4 (244 bytes)

Fields (in order):
  0x00  dwType         DWORD    "Unit type (0=Player, 1=Monster...)"
  0x04  dwTxtFileNo    DWORD    "TXT file record number"
  0x08  _1             DWORD    "Unknown"
  0x0C  dwUnitId       DWORD    "Unique unit ID"
  0x10  dwMode         DWORD    "Unit mode/state"
  0x14  pData          DWORD*   "Union: type-specific data pointer"
  0x18  dwAct          DWORD    "Act index"
  0x1C  pAct           DWORD*   "Act structure pointer"
  0x20  dwSeed[2]      DWORD[2] "Random seed"
  0x28  _2             DWORD    "Unknown"
  0x2C  pPath          DWORD*   "Path/movement data"
  ... (continue for all fields)

Step 5.2 - Create in Ghidra

Using Ghidra MCP:

  mcp_ghidra__create_struct(
      name="UnitAny",
      fields=[
          {"name": "dwType", "offset": 0x00, "size": 4, "type": "uint32_t"},
          {"name": "dwTxtFileNo", "offset": 0x04, "size": 4, "type": "uint32_t"},
          ... (all fields)
      ]
  )

Step 5.3 - Verification

  ☐ Struct created successfully
  ☐ All field offsets correct
  ☐ Struct size matches definition (0xF4)
  ☐ Struct appears in data type list
  ☐ Can apply to function parameters


PHASE 6: STRUCT APPLICATION TO FUNCTIONS
==========================================

Step 6.1 - High Confidence Application First

Sort functions by confidence score (highest first):

  1. Functions with confidence > 80%
  2. Functions with confidence 60-80%
  3. Functions with confidence 40-60%
  4. Functions with confidence < 40%

Apply structs to Category 1 first, verify, then proceed.

Step 6.2 - Application Process

For each function:

  a) Get function signature
  b) Identify which parameters are struct pointers
  c) Apply struct type:

     Using Ghidra MCP:
     mcp_ghidra__set_function_prototype(
         address="0x12345678",
         prototype="void ProcessUnit(UnitAny *pUnit, int flags)",
         ...
     )

  d) Verify in decompiler that types are now correct
  e) Check that all struct field accesses resolve properly
  f) Document the application

Step 6.3 - Batch Application Script

Pseudocode for automated application:

```python
for function in sorted_functions_by_confidence:
    if function.confidence > 80:  # AUTOMATIC
        apply_struct(function)
        mark_as_applied(function)
    elif function.confidence > 60:  # REVIEWED
        if manual_review_confirms():
            apply_struct(function)
            mark_as_applied(function)
    else:  # LOW CONFIDENCE
        flag_for_manual_review(function)
```


PHASE 7: VERIFICATION & DOCUMENTATION
======================================

Step 7.1 - Post-Application Verification

For each function where struct was applied:

  ☐ Function signature changed correctly
  ☐ Decompilation view shows typed access (e.g., pUnit->dwType)
  ☐ No type casting errors in decompiler
  ☐ All struct field accesses are valid
  ☐ Related functions still match pattern
  ☐ Cross-references still resolve correctly

Step 7.2 - Generate Verification Report

Create report showing:

  Total functions analyzed: 50
  High confidence (>80%): 25
  Medium confidence (60-80%): 15
  Low confidence (<60%): 10

  Structs created: 1 (UnitAny)
  Struct applications: 25
  Successful applications: 24
  Failed/reverted: 1

  Function coverage by category:
    - Unit Management: 5/5 applied
    - Search & Discovery: 8/8 applied
    - Position & Movement: 12/15 applied
    - ... etc

Step 7.3 - Documentation Output

Create comprehensive documentation file:

  STRUCTURE_APPLICATION_RESULTS.md

  Contains:
  - Struct definition with all fields
  - List of functions using struct
  - Confidence scores for each function
  - Before/after decompilation examples
  - Any challenges or exceptions
  - Verification checklist results
```

---

## Part 2: The Struct Discovery Algorithm

### High-Level Process

```
┌─────────────────────────────────────────┐
│ 1. IDENTIFY STRUCT FROM SOURCES          │
│    (D2Structs.h, comments, docs)        │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 2. EXTRACT STRUCT DEFINITION             │
│    (Fields, offsets, sizes, types)      │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 3. CREATE FINGERPRINT                    │
│    (Key identifying fields/offsets)     │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 4. SYSTEMATIC FUNCTION SEARCH            │
│    (Find all functions using struct)    │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 5. DECOMPILE & ANALYZE EACH FUNCTION     │
│    (Check for struct access patterns)   │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 6. CONFIDENCE SCORING                    │
│    (Rate likelihood of struct usage)    │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 7. CREATE STRUCT IN GHIDRA               │
│    (Define data type in database)       │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 8. APPLY TO HIGH CONFIDENCE FUNCTIONS    │
│    (Set function parameter types)       │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 9. VERIFY ALL APPLICATIONS               │
│    (Check decompiler output)            │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 10. DOCUMENT RESULTS                     │
│     (Complete report with all findings) │
└─────────────────────────────────────────┘
```

---

## Part 3: Implementation Steps for Specific Struct

### Example: PlayerData Structure

```
STRUCT IDENTIFICATION:
  Name: PlayerData
  Size: 0x28 (40 bytes)
  Location: Found in D2Structs.h line 243

  struct PlayerData {
      char szName[0x10];              // 0x00
      QuestInfo *pNormalQuest;        // 0x10
      QuestInfo *pNightmareQuest;     // 0x14
      QuestInfo *pHellQuest;          // 0x18
      Waypoint *pNormalWaypoint;      // 0x1C
      Waypoint *pNightmareWaypoint;   // 0x20
      Waypoint *pHellWaypoint;        // 0x24
  };

FINGERPRINT:
  ✓ Offset 0x00: char[16] (name)
  ✓ Offset 0x10: pointer (usually NULL initially)
  ✓ Offset 0x14: pointer (usually NULL initially)
  ✓ Offset 0x18: pointer (usually NULL initially)
  ✓ Offset 0x1C: pointer (waypoint)
  ✓ Size: 0x28 (40 bytes exactly)
  ✓ Unique: 3x adjacent pointers at 0x10, 0x14, 0x18

SEARCH STRATEGY:

  1) Search for functions accessing offset 0x00 (name field)
     AND offset 0x10 (quest pointer)
     AND size ~0x28 byte allocations

  2) Search for "PlayerData" string references

  3) Search for functions called "ProcessPlayerData",
     "GetPlayerData", "InitPlayerData", etc.

  4) Look at functions that take UnitAny parameter and
     then access pUnit[0x14] (pPlayerData union field)

  5) Find functions that allocate exactly 0x28 bytes
     for player-related operations

EXPECTED FUNCTIONS USING THIS:
  - CreatePlayerData()        // Allocates and initializes
  - LoadPlayerData()          // Loads from file
  - SavePlayerData()          // Writes to file
  - GetPlayerQuests()         // Accesses pNormalQuest
  - UpdatePlayerWaypoints()   // Accesses waypoint fields
  - FreePlayerData()          // Deallocates

VERIFICATION:
  ☐ All functions access name field (0x00)
  ☐ Access quest pointers (0x10-0x18)
  ☐ Access waypoint pointers (0x1C-0x24)
  ☐ No accesses beyond 0x28
  ☐ All functions use these fields logically
  ☐ Struct size match
```

---

## Part 4: Automated Workflow

### Use this prompt with Ghidra MCP in batch mode:

```
BATCH STRUCT DISCOVERY AND APPLICATION

BINARY: D2Common.dll
STRUCT_TARGET: [STRUCT_NAME]

AUTOMATED WORKFLOW:

1. SEARCH PHASE
   - Search for struct definition in binary metadata
   - Extract from source files (D2Structs.h)
   - Build field offset table

2. ANALYSIS PHASE
   - Get all functions in binary (~5000 functions)
   - Filter by size (sample ~100 functions)
   - For each function: decompile and scan for struct field accesses
   - Build confidence scores

3. FILTERING PHASE
   - Filter functions with confidence > 70%
   - Cross-reference filtered functions
   - Eliminate false positives
   - Build final candidate list

4. CREATION PHASE
   - Create struct definition in Ghidra
   - Verify struct created successfully

5. APPLICATION PHASE
   - Apply struct to all high-confidence functions
   - Check each application for correctness
   - Log all applications

6. VERIFICATION PHASE
   - Spot-check 10 functions for correctness
   - Verify decompiler output is sensible
   - Check for type errors

7. REPORTING PHASE
   - Generate results table
   - Create before/after examples
   - Document any failures
   - Calculate coverage statistics

OUTPUT:
  - List of 30+ functions using struct
  - Struct definition in Ghidra
  - All functions with correct typing
  - Comprehensive results report
```

---

## Part 5: Practical Example - Finding PlayerData Users

### Step-by-step example to follow:

```
STEP 1: Identify PlayerData from source
  Found in D2Structs.h line 243
  Size: 0x28 bytes
  Key fields: name[16], pointers to quest/waypoint data
  Unique identifier: 3x adjacent pointers + 16-byte char array

STEP 2: Find it in UnitAny union
  UnitAny at offset 0x14 has union containing:
    PlayerData *pPlayerData
    ItemData *pItemData
    MonsterData *pMonsterData
    ObjectData *pObjectData

  So: pUnit[0x14] contains PlayerData for player units

STEP 3: Systematic search
  Search for functions that:
    a) Take (void *pPlayer) or similar parameter
    b) Access pPlayer[0x10] (quest pointer)
    c) Access pPlayer[0x1C] (waypoint pointer)
    d) Function name contains "Player", "Quest", or "Waypoint"

STEP 4: Decompile candidates
  Example function: GetPlayerQuests
    void *GetPlayerQuests(void *pPlayer) {
        return *(void**)(pPlayer + 0x10);  // Accessing quest at 0x10!
    }
  → MATCH: Accesses offset 0x10 exactly like PlayerData.pNormalQuest

STEP 5: Score confidence
  - Accesses 0x10 (quest) ✓
  - Size check: if struct allocated, is 0x28? ✓
  - Function name contains "Quest" ✓
  - Only accesses valid offsets ✓
  → Confidence: 90% (HIGH)

STEP 6: Apply struct in Ghidra
  Function: GetPlayerQuests @ 0x401000
  New signature: void *GetPlayerQuests(PlayerData *pPlayer)

STEP 7: Verify
  Decompiler now shows:
    return pPlayer->pNormalQuest;
  Instead of:
    return *(void**)(pPlayer + 0x10);
  ✓ CORRECT - Now readable!
```

---

## Part 6: Success Criteria

### You'll know it's working when:

✅ **Structure Identification**
- Can point to exact location in source files
- Field offsets match binary analysis
- Size matches what's used in binary

✅ **Function Discovery**
- Find 30+ functions using each major struct
- Confidence scores > 70% average
- No obvious false positives

✅ **Struct Creation**
- Struct appears in Ghidra type list
- Can apply to function parameters
- Shows in decompiler output

✅ **Function Application**
- Decompiler shows `pUnit->dwType` instead of `*(DWORD*)(pUnit + 0x00)`
- All struct field accesses resolve correctly
- No type errors in decompiler
- Functions still match their purpose

✅ **Documentation**
- Clear list of all 30+ functions
- Confidence scores for each
- Before/after examples
- No errors or inconsistencies

---

## Part 7: Tools & Methodology

### Recommended approach:

1. **Use Ghidra MCP search_functions_enhanced()** with struct field offsets
2. **Batch decompile** suspected functions
3. **Parse decompilation output** for offset patterns
4. **Score automatically** based on pattern matches
5. **Create struct** programmatically
6. **Apply to high-confidence** functions
7. **Verify coverage** with spot checks

### Key Ghidra MCP tools to use:

- `search_functions_enhanced(query, search_type)` - Find functions
- `decompile_function(address)` - Get decompilation
- `get_function_variables(address)` - Get parameter info
- `set_function_prototype(address, prototype)` - Apply struct type
- `create_struct(name, fields)` - Create new struct
- `batch_decompile_functions(addresses)` - Process multiple functions

---

## Conclusion

This systematic approach ensures:

1. **Correctness** - Struct definitions match binary usage
2. **Completeness** - Find all functions using struct
3. **Confidence** - Score-based prioritization
4. **Auditability** - Every decision documented
5. **Scalability** - Works for any struct, any binary
6. **Verification** - Multiple checks at each step

Use this methodology for any struct discovery task in reverse engineering.

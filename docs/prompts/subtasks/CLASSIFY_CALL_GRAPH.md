# CLASSIFY_CALL_GRAPH

Analyze a function's call graph to prioritize documentation of neighbors.
Goal: Identify which callees/callers deserve stub documentation during this pass.

## Input Format

```json
{
  "target_function": {
    "name": "ProcessPlayerSlots",
    "address": "0x6fb11000"
  },
  "callees": [
    {"address": "0x6fb11100", "name": "FUN_6fb11100", "call_count": 5},
    {"address": "0x6fb11200", "name": "GetPlayerUnit", "call_count": 2},
    {"address": "0x6fb11300", "name": "FUN_6fb11300", "call_count": 1}
  ],
  "callers": [
    {"address": "0x6fb10000", "name": "FUN_6fb10000", "call_count": 1},
    {"address": "0x6fb10500", "name": "UpdateGameState", "call_count": 1}
  ]
}
```

## Task

Classify each neighbor into documentation tiers:

1. **SECONDARY**: Undocumented functions worth stub documentation
2. **SKIP**: Functions that should not be documented this pass

## Classification Rules

### SECONDARY Tier (Document as stub)
- Has default name (FUN_*, LAB_*, DAT_*)
- Called/calling the target multiple times (high affinity)
- Appears to be a helper/utility for the target function
- Located near target in address space (likely related)

### SKIP Tier (Do not document)
- Already has custom/documented name
- Is an external/imported function
- Is a library function (memcpy, strlen, etc.)
- Only called once and appears unrelated
- Would require >1 minute to analyze

## Priority Scoring

Score each undocumented neighbor (0-10):

| Factor | Points |
|--------|--------|
| Called 3+ times by target | +3 |
| Within 0x1000 of target address | +2 |
| Simple function (<30 lines) | +2 |
| Name contains target's context | +1 |
| Has multiple callers (utility) | +1 |
| Complex control flow | -2 |
| Calls many external functions | -1 |

**Threshold**: Score >= 4 → SECONDARY, else SKIP

## Output Format

```json
{
  "target": "ProcessPlayerSlots",
  "total_neighbors": 5,
  "documentation_plan": {
    "secondary": [
      {
        "address": "0x6fb11100",
        "current_name": "FUN_6fb11100",
        "score": 7,
        "reason": "Called 5x, simple helper, adjacent address",
        "estimated_time": "20s"
      }
    ],
    "skip": [
      {
        "address": "0x6fb11200",
        "current_name": "GetPlayerUnit",
        "reason": "Already documented"
      },
      {
        "address": "0x6fb11300",
        "current_name": "FUN_6fb11300",
        "score": 2,
        "reason": "Only called once, complex control flow"
      },
      {
        "address": "0x6fb10000",
        "current_name": "FUN_6fb10000",
        "reason": "Caller, not relevant to target analysis"
      }
    ]
  },
  "estimated_overhead": "20s",
  "recommendation": "Document 1 callee, skip 4 others"
}
```

## Budget Constraints

The orchestrator will specify a time budget. Respect it:

| Budget | Max Stubs |
|--------|-----------|
| minimal | 0 |
| light | 2 |
| standard | 5 |
| comprehensive | 10 |

Sort SECONDARY by score descending, take top N for budget.

## Special Cases

### Ordinal Functions
If a callee is an ordinal import (e.g., `Ordinal_10001`):
- Do NOT document (handled by ordinal lookup)
- Include in skip with reason "Ordinal import"

### Recursive Calls
If target calls itself:
- Document the recursion pattern in target's plate comment
- Do NOT add self to SECONDARY list

### Virtual Call Tables
If target uses vtable dispatch:
- Note the vtable access pattern
- Do NOT attempt to document all possible targets

## Example Analysis

### Input
```
Target: FUN_6fb385a0 (undocumented)
Callees:
  - FUN_6fb38600 (called 3x, +0x60 offset)
  - D2COMMON.Ordinal_10014 (imported)
  - memset (library)
  - FUN_6fb50000 (called 1x, far address)
```

### Output
```json
{
  "secondary": [
    {
      "address": "0x6fb38600",
      "score": 7,
      "reason": "Called 3x, adjacent (+0x60), likely helper"
    }
  ],
  "skip": [
    {"address": "D2COMMON.Ordinal_10014", "reason": "Ordinal import"},
    {"address": "memset", "reason": "Library function"},
    {"address": "0x6fb50000", "reason": "Single call, distant, low affinity"}
  ]
}
```

## Integration Notes

The orchestrator will:
1. Get call graph for target function
2. Run this classification
3. Fetch decompiled code for SECONDARY functions
4. Call STUB_FUNCTION for each
5. Apply stub documentation via batch API
6. Continue with primary function analysis

This adds minimal overhead while capturing contextual knowledge.

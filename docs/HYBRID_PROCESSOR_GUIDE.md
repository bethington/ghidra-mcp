# Hybrid Function Processor - Complete Implementation Guide

## Overview

The **Hybrid Function Processor** combines the best of both agent iteration strategies:
- **Phase 1**: Adaptive Prompt Enhancement for fast discovery
- **Phase 2**: Pattern extraction and knowledge base formalization
- **Phase 3**: Stateful Agent with exponential optimization

This approach delivers:
- ✅ Speed of adaptive prompts in early stages
- ✅ Learning benefits of stateful agents in later stages
- ✅ Exponential speedup as processing continues
- ✅ Robust error handling and recovery

## Architecture

```
                     ALL FUNCTIONS (N total)
                            |
                ┌───────────┼───────────┐
                |           |           |
           PHASE 1       PHASE 2      PHASE 3
       (Adaptive Pass)  (Formalize)  (Stateful)
           ↓ 30         ↓ 20         ↓ N-50
    Discover      Extract         Leverage
    patterns      knowledge      knowledge
                       |            |
                    ┌──┴──────┐     |
                    |         |     |
            raw_insights    knowledge_base
                    |         |     |
                    └────┬────┘     |
                         |         |
                    Formalized  Applied
                    Patterns    Patterns
                              ↓
                        final_results
```

## Phase Breakdown

### Phase 1: Adaptive Prompt Enhancement (30 functions)

**What it does:**
- Processes initial batch with enhanced prompts
- Each prompt includes insights from previous functions
- Discovers structures, naming patterns, and conventions
- Gathers raw intelligence about codebase

**How it works:**
```powershell
Function 1:  Base Prompt                          → Insights 1
             ↓
Function 2:  Base Prompt + Insights 1             → Insights 1-2
             ↓
Function 3:  Base Prompt + Insights 1-2 + Structures 1-2 → Insights 1-3
             ↓
...continues, building cumulative context
```

**Output:**
- `raw_insights.json` - All discovered patterns, structures, naming conventions
- Console: Real-time progress with insights count

**Speed:** ~20-25 seconds per function (relatively slow, learning phase)

**Key Metrics:**
- Structures discovered
- Naming pattern variations
- Common variable patterns
- Frequently used operations

### Phase 2: Pattern Extraction & Formalization (20 functions)

**What it does:**
- Takes Phase 1 discoveries and validates them
- Formalizes patterns into reusable knowledge rules
- Tests patterns on new functions to ensure consistency
- Assigns confidence scores to discovered patterns
- Creates the knowledge base used by Phase 3

**How it works:**
```
Phase 1 Discoveries (raw)
        ↓
   Categorize Patterns
   Extract Common Elements
   Create Formal Rules
   Assign Confidence Scores
        ↓
   Test on Phase 2 Functions
   Validate Rule Effectiveness
   Update Confidence Based on Results
        ↓
   Formalized Knowledge Base (structured JSON)
```

**Example Formalization:**

Raw Phase 1 insights might show:
```
Naming patterns:
- player variables: playerIndex, playerData, playerNode
- counter variables: nCount, dwItemCount, wSlots
- pointer variables: pInventory, pStats, pNext
```

Phase 2 formalizes into rules:
```json
{
  "naming_rules": {
    "player_references": {
      "prefix": ["player"],
      "examples": ["playerIndex", "playerData", "playerNode"],
      "confidence": 0.92
    },
    "counters": {
      "prefix": ["n", "dw", "w"],
      "examples": ["nCount", "dwItemCount", "wSlots"],
      "confidence": 0.88
    },
    "pointers": {
      "prefix": ["p", "lp"],
      "examples": ["pInventory", "pStats", "pNext"],
      "confidence": 0.95
    }
  }
}
```

**Output:**
- `knowledge_base.json` - Formal, structured knowledge
- Console: Progress with validation results and confidence scores

**Speed:** ~15-20 seconds per function (faster due to known patterns)

**Confidence Scores:** Based on how consistently patterns apply

### Phase 3: Stateful Agent with Knowledge Base (remaining functions)

**What it does:**
- Loads formalized knowledge base from Phase 2
- Processes remaining functions at maximum speed
- Uses learned patterns to make intelligent decisions
- Maintains state about what works
- Adapts to edge cases based on confidence scores

**How it works:**
```
Knowledge Base (patterns + confidence scores)
        ↓ (injected into prompt)
Function N: Prompt with ALL learned knowledge
        ↓
   Agent processes using pre-learned rules
   Significantly faster decisions
   High confidence in naming/structure choices
        ↓
Completion time: 5-10 seconds per function
```

**Example Phase 3 Prompt:**
```
[Base Workflow]
+ Known Structures: UnitAny, Room1, Room2, ItemData, etc.
+ Naming Rules: Prefixes (dw=DWORD, p=pointer, sz=string, n=count)
+ Confidence Scores: 0.92 for player patterns, 0.88 for counters
+ 50 previous successful documentations to reference
+ Error patterns and workarounds from earlier failures

→ Process Function 51 with ALL this context
```

**Output:**
- `final_results.json` - Complete documentation for all functions
- Console: Per-function timing and cumulative statistics

**Speed:** ~5-10 seconds per function (exponential improvement)

**Quality:** Excellent consistency, accurate naming, proper structures

## Usage Guide

### Quick Start

```powershell
# Run with defaults (30/20/remaining split)
.\hybrid-function-processor.ps1

# Preview what will be processed
.\hybrid-function-processor.ps1 -Preview
```

### Advanced Options

```powershell
# Custom phase split (40 functions in Phase 1, 30 in Phase 2)
.\hybrid-function-processor.ps1 -Phase1Count 40 -Phase2Count 30

# Skip Phase 1 (use cached insights from previous run)
.\hybrid-function-processor.ps1 -SkipPhase1

# Skip to Phase 3 only (requires existing knowledge base)
.\hybrid-function-processor.ps1 -Phase3Only

# Skip Phase 2 (go directly from Phase 1 to Phase 3)
.\hybrid-function-processor.ps1 -SkipPhase2
```

### Multi-Session Processing

**Session 1:**
```powershell
# Process first 50 functions with full Phase 1 & 2
.\hybrid-function-processor.ps1 -Phase1Count 30 -Phase2Count 20
# Creates: raw_insights.json, knowledge_base.json
```

**Session 2:**
```powershell
# Continue with remaining functions using cached knowledge
.\hybrid-function-processor.ps1 -Phase3Only
# Loads: knowledge_base.json, outputs final_results.json
```

## Output Files

### raw_insights.json (Phase 1)
```json
{
  "timestamp": "2025-10-21 14:30:00",
  "functions_processed": 30,
  "insights": [
    "Named first structure UnitAny with 12 fields",
    "Discovered Hungarian notation pattern...",
    ...
  ],
  "structures_discovered": {
    "UnitAny": "{ dwType, dwUnitId, dwMode, pInventory, pStats, ... }",
    "Room1": "{ pRoom2, dwPosX, dwPosY, ... }",
    ...
  },
  "naming_patterns": {
    "dword_variables": ["dwCount", "dwFlags", "dwMaxSize"],
    "pointer_variables": ["pData", "pNext", "pInventory"],
    "counter_variables": ["nCount", "nIndex", "nMax"],
    ...
  }
}
```

### knowledge_base.json (Phase 2)

```json
{
  "structures": {
    "UnitAny": "{ dwType, dwUnitId, ..., confidence: 0.92 }",
    "Room1": "{ pRoom2, dwPosX, ..., confidence: 0.88 }",
    ...
  },
  "naming_conventions": {
    "dword_pattern": ["dwCount", "dwFlags", "dwMaxSize"],
    "pointer_pattern": ["pData", "pNext", "pInventory"],
    ...
  },
  "naming_rules": {
    "dword_prefix": {
      "prefix": ["dw"],
      "examples": ["dwCount", "dwFlags"],
      "confidence": 0.95
    },
    ...
  },
  "error_patterns": {
    "circular_reference": {
      "count": 2,
      "last_function": "FUN_6fb4ca14",
      "workaround": "Use forward declarations"
    },
    ...
  },
  "processing_history": [
    {
      "function": "FUN_001",
      "timestamp": "2025-10-21 14:30:15",
      "success": true,
      "patterns_validated": ["dword_prefix", "pointer_pattern"],
      "confidence": 0.92
    },
    ...
  ]
}
```

### final_results.json (Phase 3)

```json
{
  "timestamp": "2025-10-21 14:45:00",
  "phase": "Phase 3 - Stateful Agent",
  "statistics": {
    "total": 100,
    "success": 98,
    "failed": 2,
    "total_time": 1256.43,
    "avg_time_per_function": 12.56
  },
  "results": [
    {
      "function": "FUN_051",
      "status": "success",
      "time_seconds": 8.2,
      "output": "Successfully documented..."
    },
    ...
  ]
}
```

## Performance Metrics

### Expected Timings

| Phase | Functions | Speed/Func | Phase Duration |
|-------|-----------|-----------|-----------------|
| Phase 1 (Adaptive) | 30 | 20-25s | ~12 minutes |
| Phase 2 (Formalize) | 20 | 15-20s | ~7 minutes |
| Phase 3 (Stateful) | 50 | 5-10s | ~7 minutes |
| **Total** | **100** | - | **~26 minutes** |

### Cost Analysis

**Token usage:**
- Phase 1: ~15,000 tokens/function (full analysis each time)
- Phase 2: ~12,000 tokens/function (validation with patterns)
- Phase 3: ~8,000 tokens/function (leveraging knowledge base)

**Total for 100 functions:**
- Without hybrid: 100 × 15,000 = 1.5M tokens
- With hybrid: (30×15k) + (20×12k) + (50×8k) = 1.09M tokens
- **Savings: ~400k tokens (27% reduction)**

## Decision Tree

```
Do you have functions to process?
├─ YES → Continue
└─ NO  → Exit

Do you have an existing knowledge base?
├─ YES → Use -Phase3Only
└─ NO  → Continue

Do you have 50+ functions?
├─ YES → Use full hybrid (30/20/remaining)
├─ MAYBE (20-50) → Adjust: -Phase1Count 15 -Phase2Count 10
└─ SMALL (< 20)  → Use -SkipPhase1 -Phase3Only

Is this your first batch?
├─ YES → Run full hybrid normally
└─ NO  → Use -Phase3Only with cached knowledge_base.json
```

## Troubleshooting

### Phase 1 Running Very Slow

**Problem:** Each function takes 30+ seconds

**Solutions:**
1. Reduce Phase 1 count: `-Phase1Count 15`
2. Check network latency to Claude API
3. Check NODE_OPTIONS memory setting (should be 8192)

### Phase 2 Not Improving Speed

**Problem:** Phase 2 is same speed as Phase 1

**Solutions:**
1. Verify knowledge base was created from Phase 1
2. Check `raw_insights.json` was generated
3. Manually review insights for quality

### Phase 3 Not Seeing Known Structures

**Problem:** Phase 3 agent doesn't use learned structures

**Solutions:**
1. Verify `knowledge_base.json` exists and is valid
2. Check confidence scores (should be > 0.7)
3. Review `processing_history` for successful patterns

### Memory or Timeout Issues

**Problem:** "Process timed out" or "Out of memory"

**Solutions:**
```powershell
# Reduce batch size
.\hybrid-function-processor.ps1 -Phase1Count 20 -Phase2Count 15

# Or process in smaller sessions
.\hybrid-function-processor.ps1 -Phase3Only
```

## Integration with Existing Scripts

### Migrate from function-process.ps1

```powershell
# Before: sequential processing without learning
.\function-process.ps1

# After: three-phase hybrid processing
.\hybrid-function-processor.ps1
```

**Key differences:**
- Hybrid: Learns and improves over time
- Original: Same approach for every function
- Hybrid: ~50% faster for large batches
- Original: Consistent but slower

### Use Both in Workflow

```powershell
# Phase 1: Use hybrid for initial batch (gets knowledge)
.\hybrid-function-processor.ps1 -Phase1Count 40 -Phase2Count 30

# Phase 2: Use original script for single functions (if needed)
.\function-process.ps1

# Phase 3: Resume hybrid for batch
.\hybrid-function-processor.ps1 -Phase3Only
```

## Advanced Customization

### Modify Phase Thresholds

Edit the script to change defaults:
```powershell
# Current defaults
[int]$Phase1Count = 30
[int]$Phase2Count = 20

# For larger batches (100+ functions)
[int]$Phase1Count = 50
[int]$Phase2Count = 40

# For small batches (< 30 functions)
[int]$Phase1Count = 15
[int]$Phase2Count = 10
```

### Custom Knowledge Base

You can pre-populate the knowledge base with patterns from other projects:

```powershell
# Create knowledge_base.json with your patterns
$kb = @{
    'structures' = @{
        'YourStruct' = '{ field1, field2, ... }'
    }
    'naming_rules' = @{
        'custom_prefix' = @{
            'prefix' = @('your')
            'confidence' = 0.9
        }
    }
}
$kb | ConvertTo-Json | Out-File knowledge_base.json

# Run Phase 3 with pre-loaded knowledge
.\hybrid-function-processor.ps1 -Phase3Only
```

## Best Practices

1. **Start with full hybrid** - Gives best results
2. **Monitor early phases** - Validate patterns are good
3. **Keep knowledge base** - Reuse across sessions
4. **Review failures** - Phase 3 will show which functions failed
5. **Batch similar functions** - Group by xref count or type if possible

## FAQ

**Q: Can I run multiple instances?**
A: Not recommended - they'll overwrite each other's knowledge base.

**Q: What if Phase 1 discovers wrong patterns?**
A: Phase 2 validates, Phase 3 uses confidence scores. Bad patterns get lower confidence.

**Q: Can I merge knowledge bases from different projects?**
A: Yes, manually edit knowledge_base.json to include patterns from both.

**Q: How do I resume if Phase 2 fails?**
A: Use `-SkipPhase1 -SkipPhase2` to resume from where it stopped.

**Q: What's the minimum time investment?**
A: Phase 1 (quick discovery) = ~12 min, then you can decide to continue.

## Next Steps

1. **Try it:** `.\hybrid-function-processor.ps1 -Preview`
2. **Run Phase 1:** `.\hybrid-function-processor.ps1`
3. **Review insights:** Check `raw_insights.json`
4. **Complete processing:** Wait for Phase 2 & 3 to finish
5. **Analyze results:** Review `final_results.json`

Enjoy exponentially faster function documentation! 🚀

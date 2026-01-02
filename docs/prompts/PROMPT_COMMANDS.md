# Prompt Commands Reference

Quick-reference commands for invoking analysis workflows. Copy and paste these prompts to execute the corresponding workflow.

## Function Documentation

### Full Function Documentation Workflow
```
Follow the instructions contained in docs\prompts\FUNCTION_DOC_WORKFLOW_V4.md
```

### Compact Function Documentation (Reduced Output)
```
Follow the instructions contained in docs\prompts\FUNCTION_DOC_WORKFLOW_V4_COMPACT.md
```

### Function Naming Validation
```
Follow the instructions contained in docs\prompts\FUNCTION_NAMING_VALIDATION.md
```

### Prototype Audit
```
Follow the instructions contained in docs\prompts\PROTOTYPE_AUDIT_WORKFLOW.md
```

## Data Section Analysis

### Data Section Workflow (Priority-based)
```
Follow the instructions contained in docs\prompts\DATA_SECTION_WORKFLOW.md
```

### Comprehensive Global Typing (No Gaps)
```
Follow the instructions contained in docs\prompts\DATA_GLOBALS_COMPREHENSIVE_TYPING.md
```

### Data Type Investigation
```
Follow the instructions contained in docs\prompts\DATA_TYPE_INVESTIGATION_WORKFLOW.md
```

### Quick Data Type Investigation
```
Follow the instructions contained in docs\prompts\DATA_TYPE_INVESTIGATION_QUICK.md
```

### Global Data Analysis
```
Follow the instructions contained in docs\prompts\GLOBAL_DATA_ANALYSIS_WORKFLOW.md
```

## Binary-Level Analysis

### Binary Documentation Order
```
Follow the instructions contained in docs\prompts\BINARY_DOCUMENTATION_ORDER.md
```

### Unified Analysis (Full Binary)
```
Follow the instructions contained in docs\prompts\UNIFIED_ANALYSIS_PROMPT.md
```

### Enhanced Analysis
```
Follow the instructions contained in docs\prompts\ENHANCED_ANALYSIS_PROMPT.md
```

## Cross-Version Analysis

### Cross-Version Function Matching (Basic)
```
Follow the instructions contained in docs\prompts\CROSS_VERSION_FUNCTION_MATCHING.md
```

### Cross-Version Matching Comprehensive (Multi-Version)
```
Follow the instructions contained in docs\prompts\CROSS_VERSION_MATCHING_COMPREHENSIVE.md
```

## Reference Documents

### Hungarian Notation Reference
```
Follow the instructions contained in docs\prompts\HUNGARIAN_NOTATION_REFERENCE.md
```

### String Labeling Convention
```
Follow the instructions contained in docs\prompts\STRING_LABELING_CONVENTION.md
```

### Plate Comment Format Guide
```
Follow the instructions contained in docs\prompts\PLATE_COMMENT_FORMAT_GUIDE.md
```

### Tool Usage Guide
```
Follow the instructions contained in docs\prompts\TOOL_USAGE_GUIDE.md
```

## Checklists

### Function Documentation Checklist
```
Follow the instructions contained in docs\prompts\FUNCTION_DOCUMENTATION_CHECKLIST.md
```

### Global Data Naming Checklist
```
Follow the instructions contained in docs\prompts\GLOBAL_DATA_NAMING_CHECKLIST.md
```

## Quick Start

### Quick Start Prompt
```
Follow the instructions contained in docs\prompts\QUICK_START_PROMPT.md
```

---

## Usage Tips

1. **Copy the entire code block** including the backticks-enclosed text
2. **Paste directly** into the chat to execute the workflow
3. **Workflows are cumulative** - run DATA_SECTION_WORKFLOW before FUNCTION_DOC_WORKFLOW for best results
4. **Check prerequisites** - some workflows assume prior analysis has been done

## Recommended Order for New Binaries

1. `BINARY_DOCUMENTATION_ORDER.md` - Determine analysis priority
2. `DATA_SECTION_WORKFLOW.md` - Type and name globals
3. `DATA_GLOBALS_COMPREHENSIVE_TYPING.md` - Eliminate orphan bytes
4. `FUNCTION_DOC_WORKFLOW_V4.md` - Document functions
5. `PROTOTYPE_AUDIT_WORKFLOW.md` - Validate prototypes

## Recommended Order for Cross-Version Propagation

1. **Document canonical version first** - Pick 1.13d (most community docs) or your best-documented version
2. `BINARY_DOCUMENTATION_ORDER.md` - Process DLLs in dependency order (Storm → Fog → D2Common → etc.)
3. `CROSS_VERSION_MATCHING_COMPREHENSIVE.md` - Propagate to same-cluster versions first (1.11-1.14)
4. **Bridge the 1.10→1.11 refactor** - Use string anchors and call graphs
5. **Propagate within Early LoD cluster** (1.07-1.10) - High hash match rate within cluster
6. **Document DLL migrations** - Track functions that moved between D2Client/D2Common/D2Game

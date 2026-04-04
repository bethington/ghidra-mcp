# Ghidra MCP AI Workflow Prompts

Battle-tested prompts for reverse engineering binary code in Ghidra using MCP tools. Refined across thousands of functions.

## Start Here

| Goal | Prompt | Description |
|------|--------|-------------|
| **Document a function** | [FUNCTION_DOC_WORKFLOW_V5.md](FUNCTION_DOC_WORKFLOW_V5.md) | Primary workflow. 7-step process with Hungarian notation, type auditing, and verification scoring. |
| **Find undiscovered code** | [ORPHANED_CODE_DISCOVERY_WORKFLOW.md](ORPHANED_CODE_DISCOVERY_WORKFLOW.md) | Automated scanner for functions hiding in gaps between known code. |
| **Investigate data types** | [DATA_TYPE_INVESTIGATION_WORKFLOW.md](DATA_TYPE_INVESTIGATION_WORKFLOW.md) | Systematic structure discovery and field analysis. |

## Function Documentation (V5 Workflow)

The V5 workflow is the current standard. It addresses every failure mode encountered in V1-V4.

**Key features:**
- Strict ordering (naming/typing BEFORE comments)
- Batch operations (`rename_variables` dict, `batch_set_comments`)
- Type audit checking actual storage types, not decompiler display types
- Built-in Hungarian notation reference
- Verification scoring via `analyze_function_completeness`

### Supporting References

| File | Purpose |
|------|---------|
| [STRING_LABELING_CONVENTION.md](STRING_LABELING_CONVENTION.md) | Hungarian notation for string labels |
| [TOOL_USAGE_GUIDE.md](TOOL_USAGE_GUIDE.md) | MCP tool reference and usage patterns |

## Data Analysis Workflows

| File | Purpose |
|------|---------|
| [DATA_TYPE_INVESTIGATION_WORKFLOW.md](DATA_TYPE_INVESTIGATION_WORKFLOW.md) | Full structure discovery workflow |
| [DATA_TYPE_INVESTIGATION_QUICK.md](DATA_TYPE_INVESTIGATION_QUICK.md) | Abbreviated version for simple types |
| [DATA_SECTION_WORKFLOW.md](DATA_SECTION_WORKFLOW.md) | Workflow for .data/.rdata section analysis |
| [GLOBAL_DATA_ANALYSIS_WORKFLOW.md](GLOBAL_DATA_ANALYSIS_WORKFLOW.md) | Global data naming and analysis |

## Cross-Binary Workflows

| File | Purpose |
|------|---------|
| [CROSS_VERSION_MATCHING_COMPREHENSIVE.md](CROSS_VERSION_MATCHING_COMPREHENSIVE.md) | Full hash-based function matching workflow |
| [CROSS_VERSION_FUNCTION_MATCHING.md](CROSS_VERSION_FUNCTION_MATCHING.md) | Quick cross-version matching guide |
| [BINARY_DOCUMENTATION_ORDER.md](BINARY_DOCUMENTATION_ORDER.md) | Optimal order for documenting binary families |

## Archive

Earlier workflow versions (V1-V4), compact/subagent variants, and superseded reference docs are in [archive/](archive/). Use V5 for all new work.

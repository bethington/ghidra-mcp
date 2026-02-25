# Ghidra MCP AI Workflow Prompts

This directory contains battle-tested prompts for reverse engineering binary code in Ghidra using MCP tools. These workflows have been refined across hundreds of functions and represent the most efficient approaches we've found for AI-assisted binary analysis.

## Start Here

| Goal | Prompt | Description |
|------|--------|-------------|
| **Document a function** | [FUNCTION_DOC_WORKFLOW_V5.md](FUNCTION_DOC_WORKFLOW_V5.md) | Primary workflow. 7-step process with Hungarian notation, type auditing, and verification scoring. |
| **Document many functions** | [FUNCTION_DOC_WORKFLOW_V5_BATCH.md](FUNCTION_DOC_WORKFLOW_V5_BATCH.md) | Orchestrates parallel subagents, each running V5 independently. |
| **Find undiscovered code** | [ORPHANED_CODE_DISCOVERY_WORKFLOW.md](ORPHANED_CODE_DISCOVERY_WORKFLOW.md) | Automated scanner for functions hiding in gaps between known code. |
| **Investigate data types** | [DATA_TYPE_INVESTIGATION_WORKFLOW.md](DATA_TYPE_INVESTIGATION_WORKFLOW.md) | Systematic structure discovery and field analysis. |
| **Quick start** | [QUICK_START_PROMPT.md](QUICK_START_PROMPT.md) | Simplified beginner workflow for getting started. |

## Function Documentation (V5 Workflow)

The V5 workflow is the current standard for function documentation. It was refined through extensive real-world use and addresses every failure mode we encountered in earlier versions (V1-V4).

**Key features:**
- Strict ordering (naming/typing BEFORE comments — `set_function_prototype` wipes plate comments)
- Batch operations (`rename_variables` dict, `batch_set_comments` for plate + PRE + EOL in one call)
- Type audit that checks actual storage types, not just decompiler display types
- Classification system (Thunk/Leaf/Worker/Init/Callback/API) to determine documentation depth
- Built-in Hungarian notation reference
- Verification scoring via `analyze_function_completeness`

### Supporting References

| File | Purpose |
|------|---------|
| [HUNGARIAN_NOTATION_REFERENCE.md](HUNGARIAN_NOTATION_REFERENCE.md) | Complete type-to-prefix mapping |
| [STRING_LABELING_CONVENTION.md](STRING_LABELING_CONVENTION.md) | Hungarian notation for string labels |
| [PLATE_COMMENT_FORMAT_GUIDE.md](PLATE_COMMENT_FORMAT_GUIDE.md) | Plate comment structure and formatting |
| [PLATE_COMMENT_EXAMPLES.md](PLATE_COMMENT_EXAMPLES.md) | Real-world plate comment examples |
| [FUNCTION_DOCUMENTATION_CHECKLIST.md](FUNCTION_DOCUMENTATION_CHECKLIST.md) | Quick checklist for documentation completeness |
| [FUNCTION_NAMING_VALIDATION.md](FUNCTION_NAMING_VALIDATION.md) | PascalCase naming rules and validation |

## Data Analysis Workflows

| File | Purpose |
|------|---------|
| [DATA_TYPE_INVESTIGATION_WORKFLOW.md](DATA_TYPE_INVESTIGATION_WORKFLOW.md) | Full structure discovery workflow |
| [DATA_TYPE_INVESTIGATION_QUICK.md](DATA_TYPE_INVESTIGATION_QUICK.md) | Abbreviated version for simple types |
| [DATA_DOCUMENTATION_TEMPLATE.md](DATA_DOCUMENTATION_TEMPLATE.md) | Template for documenting data structures |
| [DATA_SECTION_WORKFLOW.md](DATA_SECTION_WORKFLOW.md) | Workflow for .data/.rdata section analysis |
| [DATA_GLOBALS_COMPREHENSIVE_TYPING.md](DATA_GLOBALS_COMPREHENSIVE_TYPING.md) | Comprehensive global variable typing |
| [GLOBAL_DATA_ANALYSIS_WORKFLOW.md](GLOBAL_DATA_ANALYSIS_WORKFLOW.md) | Global data naming and analysis |
| [GLOBAL_DATA_NAMING_CHECKLIST.md](GLOBAL_DATA_NAMING_CHECKLIST.md) | Checklist for g_ prefix naming |

## Cross-Binary Workflows

| File | Purpose |
|------|---------|
| [CROSS_VERSION_MATCHING_COMPREHENSIVE.md](CROSS_VERSION_MATCHING_COMPREHENSIVE.md) | Full hash-based function matching workflow |
| [CROSS_VERSION_FUNCTION_MATCHING.md](CROSS_VERSION_FUNCTION_MATCHING.md) | Quick cross-version matching guide |
| [BINARY_DOCUMENTATION_ORDER.md](BINARY_DOCUMENTATION_ORDER.md) | Optimal order for documenting binary families |

## Additional Resources

| File | Purpose |
|------|---------|
| [TOOL_USAGE_GUIDE.md](TOOL_USAGE_GUIDE.md) | MCP tool reference and usage patterns |
| [DOCUMENTATION_WORKFLOW_INDEX.md](DOCUMENTATION_WORKFLOW_INDEX.md) | Decision tree for choosing the right workflow |
| [PROTOTYPE_AUDIT_WORKFLOW.md](PROTOTYPE_AUDIT_WORKFLOW.md) | Function prototype validation workflow |
| [PROMPT_COMMANDS.md](PROMPT_COMMANDS.md) | Slash command reference |

## Archived Workflows

These earlier workflow versions are preserved for reference. Use V5 for all new work.

| File | Status |
|------|--------|
| [FUNCTION_DOC_WORKFLOW_V4.md](FUNCTION_DOC_WORKFLOW_V4.md) | Superseded by V5 |
| [FUNCTION_DOC_WORKFLOW_V4_COMPACT.md](FUNCTION_DOC_WORKFLOW_V4_COMPACT.md) | Superseded by V5 |
| [FUNCTION_DOC_WORKFLOW_V4_SUBAGENT.md](FUNCTION_DOC_WORKFLOW_V4_SUBAGENT.md) | Superseded by V5 Batch |
| [FUNCTION_DOC_WORKFLOW_V3.md](FUNCTION_DOC_WORKFLOW_V3.md) | Superseded by V4 |
| [FUNCTION_DOC_WORKFLOW_V3_COMPACT.md](FUNCTION_DOC_WORKFLOW_V3_COMPACT.md) | Superseded by V4 |
| [FUNCTION_DOC_WORKFLOW_V2.md](FUNCTION_DOC_WORKFLOW_V2.md) | Superseded by V3 |
| [FUNCTION_DOC_WORKFLOW_V2_COMPACT.md](FUNCTION_DOC_WORKFLOW_V2_COMPACT.md) | Superseded by V3 |
| [FUNCTION_DOC_WORKFLOW_V1.md](FUNCTION_DOC_WORKFLOW_V1.md) | Original version |
| [UNIFIED_ANALYSIS_PROMPT.md](UNIFIED_ANALYSIS_PROMPT.md) | Early combined workflow |
| [ENHANCED_ANALYSIS_PROMPT.md](ENHANCED_ANALYSIS_PROMPT.md) | Early advanced workflow |
| [PLATE_DOCUMENTATION.md](PLATE_DOCUMENTATION.md) | Early plate comment guide |

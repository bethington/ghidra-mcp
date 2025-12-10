# Subtask Prompts for Function Documentation

This directory contains specialized prompts for Haiku (or other cheap models) to handle well-defined extraction and formatting tasks as part of the V4 workflow.

## Overview

The V4 workflow delegates mechanical tasks to cheaper models while reserving semantic reasoning for Opus:

| Subtask | Model | Purpose | I/O |
|---------|-------|---------|-----|
| `EXTRACT_VARIABLES.md` | Haiku | Pattern extraction | Code → JSON list |
| `GENERATE_HUNGARIAN_NAMES.md` | Haiku | Apply naming rules | Types → Names |
| `LOOKUP_ORDINALS.md` | Haiku | Reference lookup | Ordinals → APIs |
| `FORMAT_PLATE_COMMENT.md` | Haiku | Template formatting | Analysis → Text |

## Usage

These are called by the orchestrator (Opus) using the `runSubagent` tool:

```
runSubagent(
  prompt: "Follow subtasks/EXTRACT_VARIABLES.md. Input: [decompiled code]",
  description: "Extract variables"
)
```

## Design Principles

1. **No semantic analysis** - Haiku tasks are pattern matching only
2. **Structured I/O** - JSON in, JSON out (except FORMAT_PLATE_COMMENT)
3. **Complete coverage** - Tasks must handle ALL inputs, no filtering
4. **Deterministic** - Same input should produce same output

## Cost Savings

Estimated token distribution:
- Haiku: ~40% of total tokens (extraction, naming, formatting)
- Opus: ~60% of total tokens (analysis, reasoning, MCP calls)

With Haiku at ~10x cheaper than Opus, effective cost reduction: ~35-40%

# FUNCTION_DOC_WORKFLOW_V5_BATCH

Orchestrate parallel function documentation using subagents. Each subagent follows [FUNCTION_DOC_WORKFLOW_V5.md](FUNCTION_DOC_WORKFLOW_V5.md) independently. This document covers target selection, dispatch, and result collection only.

## Pre-flight Check

Before dispatching any subagents, verify Ghidra is running and the plugin is accessible:

1. Call `check_connection` MCP tool
2. If it returns successfully, proceed with dispatch
3. If connection refused: **stop immediately** and inform the user. Do not dispatch subagents - they will all fail with the same connection error. Suggest:
   - Start Ghidra and open a program in CodeBrowser
   - Run `ghidra-mcp-setup.ps1 -Deploy` to auto-activate the plugin
   - Verify the MCP server is started (Tools > GhidraMCP > Start MCP Server)

## Dispatch Pattern

```
Task(
  subagent_type: "general-purpose",
  model: "sonnet",  // or "opus" for Public API / complex Init functions
  description: "Document FunctionName",
  prompt: "Follow docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md to document the function
  at address 0xADDRESS (currently named 'FUN_XXXXXXXX').
  Skip get_current_selection() — the address is provided above.
  Apply all changes directly in Ghidra using MCP tools.
  Return the DONE output when complete."
)
```

**Concurrency**: Max 3 subagents at once. MCP tools serialize at the Ghidra HTTP layer — more than 3 risks timeouts without speed benefit.

**Model selection**: `sonnet` is the default for all functions. It produces A-grade documentation on 90%+ of CRT/game functions at ~5x lower cost than `opus`. Use `opus` only when:
- Function has 40+ decompiled lines with deep algorithm analysis needed
- First-pass Sonnet score is below 85% on a non-trivial function
- Function is a Public API entry point requiring cross-binary context

## Target Selection

### By completeness score
1. Run `analyze_function_completeness` on candidates
2. Filter to score < 70%, sort ascending (worst first)
3. Dispatch subagents for each

### By call graph (callees first)
1. `get_function_call_graph` on the target
2. Topological sort: leaves first, then callers
3. Dispatch leaves in parallel, then next tier

### By undocumented functions
1. `list_functions` filtered to `FUN_*` prefix, or `find_next_undefined_function` repeatedly
2. Dispatch in batches of 3

### By neighborhood (address-adjacent)
1. Pick a documented function as anchor
2. `list_functions` to find adjacent `FUN_*` entries
3. Useful after orphaned code discovery — process newly created functions in the same region

## Practical Notes

These issues come up repeatedly when running V5 at scale:

- **`get_function_variables` returns empty after prototype changes**: Register-only variables lose Ghidra symbols. Call `force_decompile` first to refresh, then retry. Even if still empty, `rename_variables` works by matching names from decompiled output.
- **`set_local_variable_type` "No HighVariable found"**: Common for stack arrays (e.g., `ushort[6]`) and decompiler-inferred composites. Skip on first failure — note in plate comment Special Cases. Do not retry.
- **Storage still `undefined4` despite resolved display type**: The decompiler shows `int`/`dword`/`FILE*` but storage remains `undefined4`. Explicitly calling `set_local_variable_type` with the same type resolves it. Critical for reaching 100%.
- **Unfixable deductions** (do not retry or flag for manual review):
  - `this` void* in `__thiscall` — convention keyword, can't rename or type further
  - HighVariable-unmappable arrays — decompiler limitation
  - API-mandated void* params (e.g., `DllMain pvReserved`)
  - Phantom variables (`extraout_*`, `in_*`)
  - Register-only SSA variables (e.g., `pDVar1`): no entry in `func.getLocalVariables()`, cannot be renamed or retyped. The checker now detects these and boosts `effective_score` accordingly.
  - `firstUseOffset` constraint: stack SSA variables at non-zero offsets that block `set_local_variable_type` and `rename_variables`. Detected at runtime (subagent gets error), not statically by the checker.
- **Trivial getters** (6 bytes, 2 instructions): 3 tool calls total — rename+prototype, plate comment, verify. Subagent overhead may not be worth it; consider documenting inline.

## Error Handling

- Subagent timeout/connection error: retry once, then skip and log
- Score < 50%: flag for manual review, do not re-dispatch
- Score 50-70% with only unfixable deductions (check `all_deductions_unfixable`): accept as complete

## Output

```
BATCH COMPLETE: N functions documented
Scores: FuncA=100%, FuncB=95%, FuncC=89% (unfixable: this void*)
Skipped: FuncD (timeout), FuncE (45% - manual review)
```

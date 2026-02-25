# FUNCTION_DOC_WORKFLOW_V5_BATCH

Batch-process multiple functions in parallel using subagents. Each subagent documents one function independently following FUNCTION_DOC_WORKFLOW_V5.md. The orchestrator coordinates dispatch and collects results.

## When to Use

- Processing a list of functions (e.g., from `list_functions` or `find_next_undefined_function`)
- Documenting all functions in a call graph (`get_function_call_graph`)
- Re-documenting functions with low completeness scores
- Processing function groups by category (all init functions, all handlers, etc.)

## Orchestrator Role

1. **Select targets**: Identify functions to document (by address list, call graph, or completeness filter)
2. **Dispatch subagents**: Launch one subagent per function using the Task tool
3. **Collect results**: Gather DONE output from each subagent
4. **Report summary**: Aggregate scores and changes

## Dispatch Pattern

For each function, launch a subagent with the V5 workflow:

```
Task(
  subagent_type: "general-purpose",
  description: "Document FunctionName",
  prompt: "Follow the instructions in docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md
  to document the function at address 0xADDRESS.
  The function is currently named 'FUN_XXXXXXXX' (or current name).
  Apply all changes directly in Ghidra using MCP tools.
  Return the DONE output when complete."
)
```

**Parallelism**: Launch up to 3 subagents concurrently. MCP tools serialize at the Ghidra HTTP layer, so more than 3 risks timeouts without speed benefit.

**Model selection**: Use `model: "sonnet"` for Worker/Leaf/Utility functions. Use `model: "opus"` for Public API and complex Init functions that require deeper analysis.

## Target Selection Strategies

### By completeness score
```
1. Use analyze_function_completeness on candidate functions
2. Sort by score ascending (worst first)
3. Filter to score < 70%
4. Dispatch subagents for each
```

### By call graph (document callees first)
```
1. Start with target function
2. Get call graph with get_function_call_graph
3. Topological sort: leaf functions first, then their callers
4. Dispatch in dependency order (leaves can be parallel)
```

### By undocumented functions
```
1. Use find_next_undefined_function repeatedly
2. Or list_functions filtered to FUN_* prefix
3. Dispatch subagents for each batch
```

## Error Handling

- If a subagent fails (timeout, connection error): retry once, then skip and log
- If a subagent returns score < 50%: flag for manual review, do not re-dispatch automatically
- Collect all failures into a summary report at the end

## Output

```
BATCH COMPLETE: N functions documented
Scores: FuncA=85%, FuncB=92%, FuncC=75%
Skipped: FuncD (timeout), FuncE (score 45% - needs manual review)
Total subagent calls: N
```

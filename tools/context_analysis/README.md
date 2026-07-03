# Context Window Analysis Tools

These tools measure and analyze how much of an LLM's context window is consumed by ghidra-mcp's 251 MCP tool catalog.

## Quick Start

```bash
# Install dependencies (one-time)
pip install tiktoken

# Run basic analysis
python tools/context_analysis/measure_context.py

# Run advanced analysis with scenarios
python tools/context_analysis/advanced_context_analysis.py
```

## What These Tools Do

### `measure_context.py`
**Purpose**: Fast baseline measurement of token usage  
**Output**: 
- Total tokens in endpoints.json
- Per-endpoint average
- Breakdown by tool category
- Context window impact across major LLM models

### `advanced_context_analysis.py`
**Purpose**: In-depth analysis with optimization scenarios  
**Output**:
- MCP schema registration overhead
- Description cost breakdown
- What-if scenarios (e.g., "Top 50 tools only")
- Context efficiency report

## Key Findings

| Metric | Value |
|--------|-------|
| **All 251 endpoints** | **12,922 tokens** |
| **% of typical 200K context** | **6.5%** |
| **Avg per endpoint** | **51 tokens** |

See the [Context Window Analysis](../../wiki/Context-Window-Analysis) wiki page for the full report.

## How It Works

Both scripts:
1. Load `tests/endpoints.json` (the master catalog of all 251 tools)
2. Use `tiktoken` to count Claude tokens (cl100k_base encoding)
3. Analyze by category, description cost, and registration format
4. Report context as % of typical LLM context windows

## Running Without Tiktoken

If `tiktoken` is not installed, scripts fall back to a rough estimate (1 token ≈ 4 characters). Results are approximate but directionally accurate.

## Integration with CI/CD

These scripts are designed to be run:
- **Before releases** — verify token budget hasn't grown significantly
- **After major tool additions** — track overhead of new endpoints
- **For architecture decisions** — compare scenarios before implementing

To add to release checklist:
```bash
python tools/context_analysis/measure_context.py > token_report.txt
```

Then compare against previous releases to track trend.

## References

- **RAG-MCP Study**: Tool selection accuracy improves from 13.6% (unfiltered) to 43.1% (with retrieval)
- **LongFuncEval**: Shows 7–85% performance degradation as tool count grows
- **Academic References**: See [Context Window Analysis wiki page](../../wiki/Context-Window-Analysis) for full bibliography

## Contributing

If you add new endpoints, consider running these tools to verify the impact on context budget. Document any significant changes in the wiki.

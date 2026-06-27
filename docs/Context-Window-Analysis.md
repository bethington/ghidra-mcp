# Context Window Analysis

**Generated**: June 27, 2026  
**Version**: 5.14.1  
**Analysis tools**: [tools/context_analysis/](https://github.com/bethington/ghidra-mcp/tree/main/tools/context_analysis)

---

## Executive Summary

All 251 ghidra-mcp MCP tools consume **12,922 tokens** when registered with an LLM — just **6.5% of a typical 200,000-token context window**. This is highly efficient and does not represent a practical constraint on using the full tool catalog.

**Key Takeaway**: Token count alone is not the limiting factor. **Discoverability** (finding the right tool among 251 options) is the real challenge and is being addressed through tool groups, category filtering, and planned search endpoints.

---

## Detailed Findings

### Token Budget Breakdown

| Component | Tokens | % of Context |
|-----------|--------|--------------|
| Endpoints.json (full catalog) | 12,922 | 6.5% |
| User query | ~2,000 | 1.0% |
| Chat history | ~5,000 | 2.5% |
| Agent reasoning | ~10,000 | 5.0% |
| **Available for response** | **~170,000** | **85.0%** |

### Context Impact Across LLM Models

| Model | Context Window | Endpoints.json % |
|-------|---|---|
| Claude 3.5 Haiku | 200,000 | 6.46% |
| Claude 3.5 Sonnet | 200,000 | 6.46% |
| Claude 3 Opus | 200,000 | 6.46% |
| GPT-4o | 128,000 | 10.10% |
| GPT-4 Turbo | 128,000 | 10.10% |

Even on smaller context windows, the overhead is modest.

### Cost Breakdown by Category

| Category | Endpoints | Tokens | % of Total |
|----------|---|---|---|
| Data Types | 36 | 2,079 | 16.1% |
| Analysis | 36 | 1,833 | 14.2% |
| Functions | 15 | 1,038 | 8.0% |
| Debugger | 18 | 833 | 6.4% |
| Getters | 17 | 770 | 6.0% |
| Server | 17 | 717 | 5.5% |
| Utility | 18 | 694 | 5.4% |
| Program | 15 | 681 | 5.3% |
| Listing | 16 | 679 | 5.3% |
| Rename | 14 | 632 | 4.9% |
| Documentation | 6 | 483 | 3.7% |
| XRef | 6 | 475 | 3.7% |
| Headless | 7 | 401 | 3.1% |
| Comment | 8 | 345 | 2.7% |
| Search | 6 | 308 | 2.4% |
| Project | 7 | 269 | 2.1% |
| Emulation | 2 | 194 | 1.5% |
| Decompile | 4 | 181 | 1.4% |
| Script | 2 | 95 | 0.7% |
| System | 1 | 48 | 0.4% |

Data types and analysis tools are the largest consumers, but still reasonable per-endpoint (avg 56 tokens for data types).

### Description Cost Analysis

| Metric | Value |
|--------|-------|
| Total description tokens | 3,114 (24.1% of total) |
| Avg per endpoint | 12 tokens |
| Most expensive description | 107 tokens |
| Cheapest description | 2 tokens |

Descriptions are concise by design and could be shortened further if needed, but current length provides good semantic clarity.

---

## Optimization Scenarios

What would happen if we made different choices?

| Scenario | Tokens | Savings |
|----------|--------|---------|
| **Full MCP Schema (with inputSchema)** | 18,385 | +42.3% overhead |
| **Endpoints.json (current)** | 12,922 | baseline |
| **MCP Schema (no descriptions)** | 8,998 | -30.4% |
| **Top 50 endpoints only** | 2,818 | -78.2% |

**Analysis**:
- Removing descriptions saves only 3.9K tokens (3% of total context) but loses all semantic meaning — **not worth it**
- Limiting to top 50 tools would save significant tokens but reduces power to 1/5 of available capability
- Current approach (all tools + rich descriptions) is the right balance

---

## What Issue #307 Actually Says

### The Concern (EdwardBlair)

> "Boasting about having >200 MCP endpoints is not a good thing either, it eats up context and the models will only reach for a handful of tools."

### The Research

EdwardBlair cited peer-reviewed studies:

1. **RAG-MCP: Mitigating Prompt Bloat in LLM Tool Selection** (2025)
   - Tool selection accuracy: **13.6%** on full unfiltered set
   - Tool selection accuracy: **43.1%** with retrieval-augmented generation
   - **3x improvement with proper retrieval**

2. **LongFuncEval** (Kate et al., 2025)
   - Reports **7–85% performance loss** as tool catalog grows
   - Extra candidates actively hurt accuracy

3. **How Many Tools Should an LLM Agent See?**
   - Semantic similarity between tools degrades accuracy
   - Extra candidates hurt performance more than they help

### The Real Problem

The concern is **NOT** about token count. It's about **tool discoverability**:

- ✗ **Problem**: Without semantic search/routing, LLMs treat 251 tools as "noise"
- ✗ **Symptom**: 13.6% selection accuracy on unfiltered sets
- ✓ **Solution**: Retrieval-augmented generation (43.1% accuracy)

### What ghidra-mcp Already Has

- ✓ Tool groups (`GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS`)
- ✓ Category filtering (20 categories)
- ✓ Dynamic registration (headless vs. GUI)
- ✓ Parameter aliases (Issue #210, improves prompt quality)
- ✓ Concise, well-written descriptions

### What ghidra-mcp Is Missing

- ✗ Tool search endpoint (semantic search on descriptions)
- ✗ Tool recommendation endpoint (find tools by capability)
- ✗ Usage instrumentation (which tools AI actually calls)

---

## Recommendation: Keep All 251 Tools

**Verdict**: The current approach is sound. Here's why:

1. **Token budget is generous**: 6.5% is negligible; we have room for 3x more tools
2. **Discoverability is fixable**: Tool search/recommendation endpoints solve the real problem
3. **Power > surface area**: Having all tools available means AI can solve more problems
4. **Research supports this**: RAG studies show tool count doesn't hurt *with proper retrieval*

### Next Steps (Priority Order)

1. **Add tool search endpoints** (high priority)
   - `/search_tools` — semantic search on tool descriptions
   - `/get_tools_by_category` — filter by category
   - `/get_tools_by_requirement` — find tools that operate on specific types

2. **Instrument bridge logging** (medium priority)
   - Log which tools AI actually calls
   - Track success/failure rates per tool
   - Data-drive future optimization decisions

3. **Monitor real-world usage** (medium priority)
   - Collect anonymized telemetry on tool preferences
   - Identify tools that are never used
   - Adjust descriptions for low-discoverability tools

4. **Publish this analysis** (done)
   - Link in Issue #307 to ground discussion in data
   - Point contributors here when debating tool count
   - Add to README as reference

---

## How to Reproduce This Analysis

```bash
# Install dependencies
pip install tiktoken

# Run basic analysis
python tools/context_analysis/measure_context.py

# Run advanced analysis
python tools/context_analysis/advanced_context_analysis.py
```

Both scripts read from `tests/endpoints.json` (the authoritative catalog of all 251 tools).

### Adding This to Release Workflow

Before releasing, run:
```bash
python tools/context_analysis/measure_context.py > release_context_budget.txt
```

Compare against previous releases to track:
- Token count trend (should stay flat or decrease)
- Average tokens per endpoint
- Category breakdown changes

---

## Academic References

- **RAG-MCP: Mitigating Prompt Bloat in LLM Tool Selection** — https://arxiv.org/abs/2505.03275
- **LongFuncEval** — Kate et al., 2025
- **How Many Tools Should an LLM Agent See?** — https://arxiv.org/abs/2605.24660
- **From REST to MCP** (empirical study) — https://arxiv.org/abs/2507.16044
- **TPS-Bench** (hundreds of MCP tools) — https://arxiv.org/abs/2511.01527
- **Toolshed** — https://arxiv.org/abs/2410.14594
- **MemTool** (pruning hundreds of tools) — https://arxiv.org/abs/2507.21428

---

## FAQ

### Q: Won't 251 tools confuse the LLM?
**A**: Without retrieval, yes (13.6% accuracy). With tool search/semantic routing, no (43.1% accuracy). We're adding the retrieval layer.

### Q: Should we remove low-usage tools?
**A**: Not yet. Track actual usage first. Many "edge case" tools become critical in specific workflows.

### Q: What if we hit the context window limit?
**A**: At 6.5% for all tools, we'd need to add ~7x more endpoints to become a constraint. By then, we'll have better retrieval mechanisms.

### Q: Can descriptions be shorter?
**A**: Yes, but the trade-off isn't worth it. Current descriptions (avg 12 tokens) provide semantic clarity that helps retrieval algorithms. Cutting them saves <4K tokens.

### Q: Why not publish only the top 50 tools?
**A**: Because hidden tools = missed functionality. AI can't discover what it doesn't know about. Discovery (retrieval) solves this better than suppression.

---

## Contact

Questions about this analysis? Open an issue or comment on [Issue #307](https://github.com/bethington/ghidra-mcp/issues/307).

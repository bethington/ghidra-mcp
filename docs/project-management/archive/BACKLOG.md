# Engineering Backlog

Items discovered from competitive fork analysis (April 2026).
Each item has a corresponding GitHub issue for tracking.

## Priority: Do Now

### Streamable HTTP Transport Documentation
**Status:** Already implemented — SDK supports it, argparse accepts it.
**Remaining:** Update docs, mcp-config.json examples, README client setup.
**Effort:** 15 minutes
**Branch:** `feature/streamable-http-transport`

## Priority: Do Next

### Composable Batch Query Endpoint
**Status:** Planning
**Effort:** Medium (2-3 days)
**Inspiration:** GhidraMCPd's `/api/collect.json` and starsong's `analyze_function_complete`
**GitHub Issue:** #109

A single endpoint that accepts a list of "fields" and returns everything in one
call instead of requiring 4+ sequential tool calls.

**Problem it solves:**
- fun_doc's `fetch_function_data()` makes 4 sequential HTTP calls per function
- MiniMax/Codex agent loops waste tokens on repeated round-trips
- Every AI consumer independently re-discovers the same multi-call pattern

**Proposed design:**
```
POST /analyze_function_bundle
{
  "address": "0x10042a30",
  "program": "/path/to/program",
  "fields": ["decompile", "variables", "completeness", "callers", "callees", "xrefs_to"]
}
```

Returns a single JSON object with all requested data keyed by field name.
Server-side, dispatches to existing service methods — no new business logic.

**Implementation notes:**
- New method in `AnalysisService.java` with `@McpTool`
- Fields map to existing service calls: decompile→FunctionService, variables→FunctionService, etc.
- `analyze_for_documentation` is a partial version of this but hardcoded
- Bridge doesn't need changes — annotation scanner auto-discovers it
- fun_doc's `fetch_function_data()` can switch to a single call

### Write Safety / Dry-Run Mode
**Status:** Implemented (v5.1.0)
**Effort:** Low (1 day)
**Inspiration:** GhidraMCPd's `ENABLE_WRITES` and `dry_run` flags
**GitHub Issue:** #110

Add a `dry_run` query parameter to all write endpoints that returns "would have
done X" without committing to the Ghidra database.

**Implementation:** AnnotationScanner intercepts `dry_run=true` on POST endpoints,
wraps the call in a nested transaction that always rolls back. Bridge auto-adds
`dry_run` parameter to all POST tool signatures.

## Priority: Plan For

### Data Flow Analysis Tool
**Status:** Research
**Effort:** High (3-5 days)
**Inspiration:** starsong's `analysis_get_dataflow`
**GitHub Issue:** #111

Track how data flows through a function — forward (where does this value go?)
and backward (where did this value come from?).

**Implementation notes:**
- Ghidra has Varnode/PcodeOp graph via `DecompInterface`
- New method in `AnalysisService.java`
- Parameters: address, direction (forward/backward), max_steps
- Returns chain of operations showing value provenance or propagation
- Self-contained — no existing code changes needed, ~200-300 lines Java

### Offline Test Fixtures
**Status:** Research
**Effort:** Medium (2-3 days)
**Inspiration:** GhidraMCPd's reference firmware + stub server
**GitHub Issue:** #112

CI tests that don't require a running Ghidra instance.

**Implementation notes:**
- Create a `FixtureProgramProvider` implementing `ProgramProvider`
- Returns canned data for a reference binary
- Services already accept `ProgramProvider` via constructor injection
- Tests AnnotationScanner, response format, endpoint routing
- Ships a small reference binary in `tests/fixtures/`

## Priority: Architect

### Native MCP Server (Eliminate Python Bridge)
**Status:** Researched, scoped
**Effort:** Medium-High (Phase 1: 2-3 days, Phase 2: 1 day, Phase 3: TBD)
**GitHub Issue:** #114

Replace the Python bridge with the official Java MCP SDK (`io.modelcontextprotocol.sdk:mcp` v1.1.1)
in headless mode. The bridge converts MCP↔HTTP — exactly the glue code MCP was designed to eliminate.

**Target architecture:**
```
AI Tool → MCP (stdio) → Ghidra Headless Server (Java, native MCP)
```

**Phase 1 — Headless stdio:**
- Add `mcp-core` + `mcp-json-jackson2` Maven deps
- `McpToolAdapter`: converts `AnnotationScanner` output → `SyncToolSpecification[]`
- New entry point using `StdioServerTransportProvider`
- Keep HTTP mode as fallback

**Phase 2 — Streamable HTTP:**
- Embedded servlet container (Jetty/Undertow) for `HttpServletStreamableServerTransportProvider`
- Replaces Python bridge for remote use cases

**Phase 3 — GUI plugin (future):**
- Plugin can't own stdio; needs embedded servlet or IPC

**Key decision:** Use Jackson 2 (`mcp-json-jackson2`) alongside existing Gson. No conflict —
Jackson only used internally by MCP SDK.

**SDK facts:** 3.4k stars, 100% server conformance (40/40), Java 17+ (we use 21),
supports stdio + streamable-http + SSE transports natively.

## Evaluated and Skipped

### HATEOAS / Self-Describing API (starsong)
**Why skipped:** Over-engineered for MCP use case. AI clients don't follow
hypermedia links — they call tools by name from the schema. Adds JSON bloat
that contradicts token-efficiency goals.

### Standalone CLI Tool (starsong)
**Why skipped:** Web dashboard + curl-able HTTP endpoints cover the use cases.
fun_doc handles batch automation. Low ROI given maintenance surface.

---

## Research Sources

- **starsong-consulting/GhydraMCP** (223 stars, v2.2.0): HATEOAS REST API,
  CLI tool, data flow analysis, port-based multi-instance, paginated endpoints
- **pinksawtooth/GhidraMCP** (77 stars): Streamable HTTP transport, Codex/Copilot
  setup docs, Doxygen API docs
- **mad-sol-dev/GhidraMCPd** (2 stars, 630 commits): Token-efficiency focus,
  batch collect endpoint, write safety guards, contract tests, offline fixtures

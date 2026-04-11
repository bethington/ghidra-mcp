# Creates GitHub issues for the engineering backlog items.
# Requires: gh auth login (GitHub CLI authenticated)
# Usage: .\create-backlog-issues.ps1

$repo = "bethington/ghidra-mcp"

# Issue 1: Streamable HTTP transport docs
gh issue create --repo $repo `
    --title "Document streamable-http transport as recommended option" `
    --label "enhancement","documentation" `
    --body @"
## Summary
Streamable HTTP transport is already supported (MCP SDK 1.21.1, argparse accepts it), but docs still reference SSE as the HTTP transport option.

## Tasks
- [ ] Update README client setup examples to show ``--transport streamable-http``
- [ ] Update mcp-config.json with streamable-http example
- [ ] Update help text for ``--mcp-host`` and ``--mcp-port`` to say "HTTP transport" not "SSE transport"
- [ ] Note SSE deprecation in MCP spec
- [ ] End-to-end test with Claude Desktop / VS Code Copilot

## Context
MCP spec has deprecated SSE in favor of streamable HTTP. Our SDK already supports it — this is docs-only.
"@

# Issue 2: Composable batch query endpoint
gh issue create --repo $repo `
    --title "Composable batch query endpoint (analyze_function_bundle)" `
    --label "enhancement" `
    --body @"
## Summary
Add a single endpoint that accepts a list of data fields and returns all requested data in one call, replacing the need for 4+ sequential tool calls.

## Problem
- ``fun_doc``'s ``fetch_function_data()`` makes 4 sequential HTTP calls per function
- AI agent loops waste tokens on repeated round-trips and JSON envelopes
- Every consumer independently re-discovers the same multi-call pattern

## Proposed API
``````
POST /analyze_function_bundle
{
  ""address"": ""0x10042a30"",
  ""program"": ""/path/to/program"",
  ""fields"": [""decompile"", ""variables"", ""completeness"", ""callers"", ""callees"", ""xrefs_to""]
}
``````

Returns a single JSON object with all requested data keyed by field name.

## Implementation Plan
- New ``@McpTool`` method in ``AnalysisService.java``
- Fields map to existing service methods (no new business logic)
- ``analyze_for_documentation`` is a partial version — this generalizes it
- Bridge auto-discovers via annotation scanner
- ``fun_doc`` switches ``fetch_function_data()`` to single call

## Inspiration
GhidraMCPd's ``/api/collect.json`` endpoint
"@

# Issue 3: Write safety / dry-run mode
gh issue create --repo $repo `
    --title "Write safety: dry_run mode for all write endpoints" `
    --label "enhancement","security" `
    --body @"
## Summary
Add a ``dry_run`` parameter to write endpoints that previews changes without committing to the Ghidra database.

## Motivation
- Cheaper models (MiniMax) sometimes make incorrect changes
- New users want to explore safely without corrupting their Ghidra project
- Enables preview-then-apply workflow: cheap model in dry-run, better model reviews and applies

## Design
- ``?dry_run=true`` query param on all write endpoints
- Returns same JSON shape with ``""dry_run"": true`` flag — no actual transaction
- Global default via ``GHIDRA_MCP_DRY_RUN=true`` env var
- Individual calls can override

## Implementation
- Add dry-run check in ``ServiceUtils`` before transaction open
- ~50 lines across service utilities
- No annotation scanner changes needed

## Inspiration
GhidraMCPd's ``ENABLE_WRITES`` and ``dry_run`` flags
"@

# Issue 4: Data flow analysis
gh issue create --repo $repo `
    --title "Data flow analysis tool (forward/backward value tracking)" `
    --label "enhancement" `
    --body @"
## Summary
Track how data flows through a function — forward (where does this value go?) and backward (where did this value come from?).

## Value
High-signal context for AI models: knowing ""this parameter flows into a memcpy size argument"" produces better function names and documentation than decompiled code alone.

## Proposed API
``````
GET /analyze_data_flow?address=0x10042a30&direction=forward&max_steps=10&program=...
``````

Returns a chain of operations showing value provenance or propagation through Varnode/PcodeOp graph.

## Implementation
- New ``@McpTool`` method in ``AnalysisService.java`` (~200-300 lines)
- Uses Ghidra's ``DecompInterface`` Varnode/PcodeOp graph
- Self-contained — no existing code changes needed

## Inspiration
starsong-consulting/GhydraMCP ``analysis_get_dataflow``
"@

# Issue 5: Offline test fixtures
gh issue create --repo $repo `
    --title "Offline test fixtures for CI without running Ghidra" `
    --label "enhancement","testing" `
    --body @"
## Summary
CI integration tests that don't require a running Ghidra instance, using fixture data and a mock ProgramProvider.

## Problem
- CI can only run unit tests (mocked)
- Integration tests require manual Ghidra setup
- Contributors can't validate service layer changes without Ghidra installed

## Design
- ``FixtureProgramProvider`` implementing ``ProgramProvider`` interface
- Returns canned data for a reference binary
- Tests AnnotationScanner, response format, endpoint routing
- Ships a small reference binary in ``tests/fixtures/``

## Implementation
- Services already take ``ProgramProvider`` via constructor injection
- Clean seam for dependency injection — architecture supports this by design

## Inspiration
GhidraMCPd's reference firmware fixture + stub MCP server
"@

Write-Host "`nAll backlog issues created successfully."

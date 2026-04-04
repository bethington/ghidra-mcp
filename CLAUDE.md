# Ghidra MCP - Claude Code Guide

## Overview

MCP server bridging Ghidra reverse engineering with AI tools. 193 MCP tools for binary analysis.

- **Package**: `com.xebyte` | **Version**: 5.0.0 | **Java**: 21 LTS | **Ghidra**: 12.0.3

## Architecture

```
AI Tools <-> MCP Bridge (bridge_mcp_ghidra.py) <-> Ghidra Plugin (GhidraMCPPlugin.jar)
```

- **Plugin**: `src/main/java/com/xebyte/GhidraMCPPlugin.java` -- HTTP server, delegates to services
- **Bridge**: `bridge_mcp_ghidra.py` (~1,100 lines) -- dynamic tool registration from `/mcp/schema` + 7 static tools
- **Service Layer**: `src/main/java/com/xebyte/core/` -- 12 service classes (~18K lines), `@McpTool`/`@Param` annotated
- **Headless**: `src/main/java/com/xebyte/headless/` -- standalone server without GUI
- **Annotation Scanner**: `AnnotationScanner.java` discovers `@McpTool` methods, generates `/mcp/schema`

Services use constructor injection: `ProgramProvider` + `ThreadingStrategy`.
- FrontEnd mode: `FrontEndProgramProvider` + `DirectThreadingStrategy`
- Headless mode: `HeadlessProgramProvider` + `DirectThreadingStrategy`

## Tool Inventory

Do not try to keep the full tool list in this file.

- **Authoritative repo snapshot**: `tests/endpoints.json` (193 endpoints, categories, descriptions)
- **Authoritative runtime schema**: `/mcp/schema` from the running server
- **Usage patterns / operator guide**: `docs/prompts/TOOL_USAGE_GUIDE.md`

Use this file for architecture, conventions, and implementation guidance; use the schema and endpoint catalog for the complete tool inventory.

## Build & Deploy

```powershell
.\ghidra-mcp-setup.ps1 -BuildOnly          # Build only (~7s)
.\ghidra-mcp-setup.ps1 -Deploy              # Build + deploy + restart Ghidra
.\ghidra-mcp-setup.ps1 -SetupDeps           # First-time: install Ghidra JARs to local Maven
```

- Maven: `C:\Users\benam\tools\apache-maven-3.9.6\bin\mvn.cmd`
- Ghidra install: `F:\ghidra_12.0.3_PUBLIC`
- Deploy handles: Maven build, extension install, FrontEndTool.xml patching, Ghidra restart

## Running the MCP Server

```bash
python bridge_mcp_ghidra.py                  # stdio (recommended for AI tools)
python bridge_mcp_ghidra.py --transport sse   # SSE (web/HTTP clients)
```

Ghidra HTTP endpoint: `http://127.0.0.1:8089`

## Adding New Endpoints

1. Add `@McpTool` + `@Param` method in the appropriate service class
2. AnnotationScanner auto-discovers it -- no bridge or registry changes needed
3. Add entry to `tests/endpoints.json` with path, method, category, description

For complex tools needing bridge-side logic (retries, multi-call orchestration), add a static `@mcp.tool()` in `bridge_mcp_ghidra.py` and add the name to `STATIC_TOOL_NAMES`.

## Code Conventions

- All endpoints return JSON
- Transactions must be committed for Ghidra database changes
- Prefer batch operations over individual calls
- `@Param(value = "program")` defaults to `ParamSource.QUERY` -- POST endpoints must send `program` as URL query param, not in JSON body

## Convention Enforcement (Opinionated Tooling)

The longer this project was used across many versions and hundreds of thousands of functions, the less reliable prompt-only discipline became. Models drift, improvise, and skip conventions in much the same way people do.

The tools actively enforce RE documentation standards. This is intentional. v5.0 moves conventions into the tool layer so documentation stays readable, reusable, and consistent across both solo large-scale RE workflows and teams.

- **`NamingConventions.java`**: Centralized validation. All naming tools route through this.
- **Struct fields**: Auto-prefixed with correct Hungarian notation on `create_struct`, `add_struct_field`, `modify_struct_field`. The model doesn't need to know the prefix rules -- the tool handles it.
- **Function names**: `rename_function_by_address` warns on non-PascalCase, missing verbs, short names. Module prefixes (`UPPERCASE_`) are accepted and validated separately.
- **Globals/Labels**: `rename_or_label` warns if globals lack `g_` prefix or labels aren't snake_case.
- **Plate comments**: `batch_set_comments` warns on missing Algorithm/Parameters/Returns sections.
- **Type changes**: `set_local_variable_type` rejects `undefined` -> `undefined` (no-op protection).
- **Completeness scoring**: `analyze_function_completeness` returns budgeted scores with log-scaled deductions. Structural deductions are fully forgiven in effective_score.

When building new tools or modifying existing ones, wire validation through `NamingConventions` to maintain consistency.

## Testing

- Java: `mvn test`
- Python: `pytest tests/`
- Integration tests require Ghidra running on port 8089

## Key Gotchas

- **Ghidra overwrites FrontEndTool.xml on exit** -- deploy must patch AFTER Ghidra exits
- **Shared server renames not persisted by save_program** -- must checkin to persist
- **Max ~5 shared server programs open at once** -- opening 20+ crashes Ghidra
- **`switch_program` matches by name** -- for multi-version work, use the `program` query parameter on individual endpoints instead
- **Plate comment `\n` creates literal text**, not newlines -- use actual multi-line text
- **GUI operations from HTTP threads** must use `SwingUtilities.invokeAndWait()`

## Documentation

- Workflow: `docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md`
- Data types: `docs/prompts/DATA_TYPE_INVESTIGATION_WORKFLOW.md`
- Tool guide: `docs/prompts/TOOL_USAGE_GUIDE.md`
- String labels: `docs/prompts/STRING_LABELING_CONVENTION.md`
- Version history: see `CHANGELOG.md`

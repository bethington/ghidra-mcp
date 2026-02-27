# Ghidra MCP - Claude Code Project Guide

## Project Overview

Ghidra MCP is a production-ready Model Context Protocol (MCP) server that bridges Ghidra's reverse engineering capabilities with AI tools. It provides **179 MCP tools** for binary analysis automation.

- **Package**: `com.xebyte`
- **Version**: 3.1.0 (see `pom.xml`)
- **License**: Apache 2.0
- **Java**: 21 LTS
- **Ghidra**: 12.0.3

## Architecture

```
AI/Automation Tools <-> MCP Bridge (bridge_mcp_ghidra.py) <-> Ghidra Plugin (GhidraMCP.jar)
```

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Ghidra Plugin | `src/main/java/com/xebyte/GhidraMCPPlugin.java` | HTTP server exposing 147 Ghidra API endpoints |
| MCP Bridge | `bridge_mcp_ghidra.py` | Translates MCP protocol to HTTP calls (179 tools) |
| Headless Server | `src/main/java/com/xebyte/headless/` | Standalone server without Ghidra GUI (172 endpoints) |
| Core Abstractions | `src/main/java/com/xebyte/core/` | Shared interfaces (ProgramProvider, ThreadingStrategy) |

## Build Commands

```powershell
# Build and deploy (recommended — handles Maven, deps, and Ghidra restart)
.\ghidra-mcp-setup.ps1 -Deploy -GhidraPath "C:\ghidra_12.0.3_PUBLIC"

# Build only (no deploy)
.\ghidra-mcp-setup.ps1 -BuildOnly

# First-time dependency setup (install Ghidra JARs into local Maven repo)
.\ghidra-mcp-setup.ps1 -SetupDeps -GhidraPath "C:\ghidra_12.0.3_PUBLIC"
```

> **Note (Windows):** Maven (`mvn`) must be in your PATH or invoked via the setup script.
> Maven is at `C:\Users\<user>\tools\apache-maven-3.9.6\bin\mvn.cmd` if installed by the setup script.

## Running the MCP Server

```bash
# Stdio transport (recommended for AI tools)
python bridge_mcp_ghidra.py

# SSE transport (web/HTTP clients)
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081

# Default Ghidra HTTP endpoint
http://127.0.0.1:8089
```

## Project Structure

```
ghidra-mcp/
├── src/main/java/com/xebyte/
│   ├── GhidraMCPPlugin.java      # Main plugin with all endpoints
│   ├── core/                      # Shared abstractions
│   └── headless/                  # Headless server implementation
├── bridge_mcp_ghidra.py           # MCP protocol bridge
├── ghidra_scripts/                # Ghidra scripts (Java)
├── docs/
│   ├── prompts/                   # Analysis workflow prompts
│   ├── releases/                  # Release documentation
│   └── project-management/        # Project-level docs
├── ghidra-mcp-setup.ps1            # Deployment script
└── functions-process.ps1          # Batch function processing
```

## Key Documentation

- **API Reference**: See README.md for complete tool listing (179 MCP tools)
- **Workflow Prompts**: `docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md` - Function documentation workflow (V5)
- **Batch Processing**: `docs/prompts/FUNCTION_DOC_WORKFLOW_V5_BATCH.md` - Multi-function parallel documentation
- **Data Analysis**: `docs/prompts/DATA_TYPE_INVESTIGATION_WORKFLOW.md`
- **Tool Guide**: `docs/prompts/TOOL_USAGE_GUIDE.md`
- **String Labeling**: `docs/prompts/STRING_LABELING_CONVENTION.md` - Hungarian notation for string labels

## Development Conventions

### Code Style
- Java package: `com.xebyte`
- All endpoints return JSON
- Use batch operations where possible (93% API call reduction)
- Transactions must be committed for Ghidra database changes

### Adding New Endpoints
1. Add handler method in `GhidraMCPPlugin.java` (GUI plugin) and/or `HeadlessEndpointHandler.java`
2. Register in `createContextsForServer()` (GUI) and/or `registerEndpoints()` (headless)
3. Add corresponding MCP tool in `bridge_mcp_ghidra.py`
4. Add entry to `tests/endpoints.json` with path, method, category, description
5. Update `total_endpoints` count in `tests/endpoints.json`

### Testing
- Tests: `src/test/java/com/xebyte/`
- Python tests: `tests/`
- Run with: `mvn test` or `pytest tests/`

## Ghidra Scripts

Located in `ghidra_scripts/`. Execute via:
- `mcp_ghidra_run_script` MCP tool
- Ghidra Script Manager UI
- `analyzeHeadless` command line

## Common Tasks

### Function Documentation Workflow
1. Use `list_functions` to enumerate functions
2. Use `decompile_function` to get pseudocode
3. Apply naming via `rename_function`, `rename_variable`
4. Add comments via `set_plate_comment`, `set_decompiler_comment`

### Data Type Analysis
1. Use `list_data_types` to see existing types
2. Create structures with `create_struct`
3. Apply with `apply_data_type`

## Troubleshooting

- **Plugin not loading**: Check `docs/troubleshooting/TROUBLESHOOTING_PLUGIN_LOAD.md`
- **Connection issues**: Verify Ghidra is running with plugin enabled on port 8089
- **Build failures**: Install Ghidra JARs to local Maven repo (run `ghidra-mcp-setup.ps1 -SetupDeps`)

## Version History

See `CHANGELOG.md` for complete history. Key releases:
- v3.0.0: Headless parity, 8 new tool categories, 179 MCP tools, 147 GUI endpoints, 172 headless endpoints
- v2.0.2: Ghidra 12.0.3 support, pagination for large functions
- v2.0.0: Label deletion endpoints, documentation updates
- v1.9.4: Function Hash Index for cross-binary documentation
- v1.7.x: Transaction fixes, variable storage control
- v1.6.x: Validation tools, enhanced analysis
- v1.5.x: Batch operations, workflow optimization

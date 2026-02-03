# Ghidra MCP - Claude Code Project Guide

## Project Overview

Ghidra MCP is a production-ready Model Context Protocol (MCP) server that bridges Ghidra's reverse engineering capabilities with AI tools. It provides **110 MCP tools** for binary analysis automation.

- **Package**: `com.xebyte`
- **Version**: 2.0.0 (see `pom.xml`)
- **License**: Apache 2.0
- **Java**: 21 LTS
- **Ghidra**: 11.4.2

## Architecture

```
AI/Automation Tools <-> MCP Bridge (bridge_mcp_ghidra.py) <-> Ghidra Plugin (GhidraMCP.jar)
```

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Ghidra Plugin | `src/main/java/com/xebyte/GhidraMCPPlugin.java` | HTTP server exposing Ghidra APIs |
| MCP Bridge | `bridge_mcp_ghidra.py` | Translates MCP protocol to HTTP calls |
| Headless Server | `src/main/java/com/xebyte/headless/` | Standalone server without Ghidra GUI |
| Core Abstractions | `src/main/java/com/xebyte/core/` | Shared interfaces (ProgramProvider, ThreadingStrategy) |

## Build Commands

```bash
# Build the plugin (creates target/GhidraMCP-{version}.zip)
mvn clean package assembly:single -DskipTests

# Quick compile check
mvn clean compile -q

# Deploy to Ghidra
.\deploy-to-ghidra.ps1

# Build headless server
mvn package -P headless -DskipTests
```

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
│   ├── API_REFERENCE.md           # Complete API documentation
│   ├── prompts/                   # Analysis workflow prompts
│   └── releases/                  # Release documentation
├── deploy-to-ghidra.ps1           # Deployment script
└── functions-process.ps1          # Batch function processing
```

## Key Documentation

- **API Reference**: See README.md for complete tool listing (110 MCP tools)
- **Workflow Prompts**: `docs/prompts/FUNCTION_DOC_WORKFLOW_V4.md` - Function documentation workflow
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
1. Add handler method in `GhidraMCPPlugin.java`
2. Register in `createContextsForServer()`
3. Add corresponding MCP tool in `bridge_mcp_ghidra.py`
4. Document in `docs/API_REFERENCE.md`

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
- **Build failures**: Ensure `lib/` contains Ghidra JARs (run `copy-ghidra-libs.bat`)

## Version History

See `CHANGELOG.md` for complete history. Key releases:
- v2.0.0: Label deletion endpoints, documentation updates
- v1.9.4: Function Hash Index for cross-binary documentation
- v1.7.x: Transaction fixes, variable storage control
- v1.6.x: Validation tools, enhanced analysis
- v1.5.x: Batch operations, workflow optimization

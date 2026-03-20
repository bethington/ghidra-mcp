# Ghidra MCP - Claude Code Project Guide

## Project Overview

Ghidra MCP is a production-ready Model Context Protocol (MCP) server that bridges Ghidra's reverse engineering capabilities with AI tools. It provides **193 MCP tools** for binary analysis automation.

- **Package**: `com.xebyte`
- **Version**: 4.3.0 (see `pom.xml`)
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
| Ghidra Plugin | `src/main/java/com/xebyte/GhidraMCPPlugin.java` | HTTP server + endpoint wiring, delegates to services |
| MCP Bridge | `bridge_mcp_ghidra.py` | Dynamic MCP tool registration from `/mcp/schema` + 22 static complex tools |
| Headless Server | `src/main/java/com/xebyte/headless/` | Standalone server without Ghidra GUI |
| Service Layer | `src/main/java/com/xebyte/core/` | 12 annotated service classes with `@McpTool`/`@Param` (~15K lines) |
| Annotation Scanner | `src/main/java/com/xebyte/core/AnnotationScanner.java` | Discovers `@McpTool` methods via reflection, generates `/mcp/schema` |
| Endpoint Registry | `src/main/java/com/xebyte/core/EndpointRegistry.java` | Declarative endpoint definitions (shared GUI/headless) |

### Service Layer (v4.0.0)

Business logic is in `com.xebyte.core/` service classes, shared between GUI and headless modes:

| Service | Lines | Responsibility |
|---------|-------|----------------|
| `ServiceUtils` | ~670 | Shared static utilities (escapeJson, paginateList, convertNumber) |
| `ListingService` | ~720 | Listing/enumeration endpoints |
| `FunctionService` | ~2,400 | Decompilation, rename, prototype, batch operations |
| `CommentService` | ~430 | Decompiler/disassembly/plate comments |
| `SymbolLabelService` | ~815 | Labels, data rename, globals, external locations |
| `XrefCallGraphService` | ~1,260 | Cross-references, call graphs |
| `DataTypeService` | ~2,580 | Struct/enum/union CRUD, validation |
| `AnalysisService` | ~2,510 | Completeness, control flow, similarity |
| `DocumentationHashService` | ~1,130 | Function hashing, cross-binary docs |
| `MalwareSecurityService` | ~940 | Anti-analysis detection, IOCs |
| `ProgramScriptService` | ~1,340 | Program management, scripts, memory |
| `BinaryComparisonService` | ~1,050 | Cross-binary comparison (static methods) |

Services use constructor injection: `ProgramProvider` + `ThreadingStrategy`. GUI uses `GuiProgramProvider` + `SwingThreadingStrategy`; headless uses `HeadlessProgramProvider` + `DirectThreadingStrategy`.

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
│   ├── core/                      # Shared service layer (12 services)
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

- **API Reference**: See README.md for complete tool listing (193 MCP tools)
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
1. Add a method annotated with `@McpTool` and `@Param` in the appropriate service class (e.g., `FunctionService.java`)
2. The `AnnotationScanner` automatically discovers it and registers the HTTP endpoint + `/mcp/schema` entry
3. The bridge dynamically registers the MCP tool at startup from `/mcp/schema` (no bridge code changes needed)
4. Add entry to `tests/endpoints.json` with path, method, category, description
5. Update `total_endpoints` count in `tests/endpoints.json`

For complex tools requiring bridge-side logic (retries, local I/O, multi-call), add a static `@mcp.tool()` function in `bridge_mcp_ghidra.py` and add the tool name to `STATIC_TOOL_NAMES`.

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
- v4.3.0: `@McpTool`/`@Param` annotations on all service methods, dynamic bridge registration from `/mcp/schema`, 72% bridge reduction (8,600 -> 2,400 lines), 193 MCP tools (22 static + ~170 dynamic)
- v4.2.0: Knowledge database integration, BSim cross-version matching, enum fix (#44), 193 MCP tools, 175 GUI endpoints, 183 headless endpoints
- v4.1.0: Parallel multi-binary support via universal `program` parameter, 188 MCP tools, 169 GUI endpoints, 173 headless endpoints
- v4.0.0: Service layer architecture refactor (12 shared services), 69% plugin reduction, 188 MCP tools, 169 GUI endpoints, 173 headless endpoints
- v3.2.0: Completeness checker overhaul, batch_analyze_completeness endpoint, multi-window fix (#35), 180 MCP tools, 149 GUI endpoints
- v3.1.0: Tools > GhidraMCP server control menu, deployment automation, completeness checker accuracy
- v3.0.0: Headless parity, 8 new tool categories, 179 MCP tools, 147 GUI endpoints, 172 headless endpoints
- v2.0.2: Ghidra 12.0.3 support, pagination for large functions
- v2.0.0: Label deletion endpoints, documentation updates
- v1.9.4: Function Hash Index for cross-binary documentation
- v1.7.x: Transaction fixes, variable storage control
- v1.6.x: Validation tools, enhanced analysis
- v1.5.x: Batch operations, workflow optimization

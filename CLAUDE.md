# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Ghidra MCP Server is a production-ready Model Context Protocol (MCP) server that bridges Ghidra's reverse engineering capabilities with AI tools. It exposes 108 MCP tools for binary analysis (98 implemented + 10 ROADMAP v2.0) through a dual-layer architecture: a Java plugin running in Ghidra that provides REST endpoints, and a Python bridge that implements the MCP protocol.

**Current Version**: 1.7.3
**Package**: com.xebyte
**Ghidra Version**: 11.4.2
**Java Version**: 21 LTS
**Python Version**: 3.8+

## Architecture

### Three-Layer System

1. **Ghidra Java Plugin** (`src/main/java/com/xebyte/GhidraMCPPlugin.java`)
   - Embedded HTTP server running on port 8089 (configurable)
   - Exposes Ghidra's reverse engineering API as REST endpoints
   - Single-file plugin (~9400 lines) with 108 endpoints (98 implemented + 10 ROADMAP v2.0)
   - Handles function analysis, decompilation, symbols, data types, cross-references

2. **Python MCP Bridge** (`bridge_mcp_ghidra.py`)
   - Translates REST API to MCP protocol using FastMCP framework
   - Implements connection pooling, retry logic, request caching
   - Input validation and security restrictions (localhost-only connections)
   - Two transport modes: stdio (default) and SSE

3. **Java Build System** (Maven-based)
   - System-scoped dependencies to Ghidra JARs in `lib/`
   - Custom assembly descriptor for Ghidra extension ZIP format
   - Fixed JAR name: `GhidraMCP.jar` (version-independent)

### Critical Architecture Details

- **Ghidra libraries must be copied first**: Before building, run `copy-ghidra-libs.bat` on Windows to copy JARs from your Ghidra installation to `lib/`
- **Plugin loads at Ghidra startup**: The Java plugin starts automatically when Ghidra launches if properly installed
- **REST API is stateful**: All operations work on the currently open program in Ghidra's CodeBrowser
- **MCP bridge is stateless**: Each MCP tool call translates to one or more HTTP requests

## Build and Development

### Initial Setup

```bash
# 1. Copy Ghidra libraries (required before first build)
copy-ghidra-libs.bat "C:\path\to\ghidra"

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Build the Java plugin
mvn clean package assembly:single
```

This produces:
- `target/GhidraMCP.jar` - The plugin JAR
- `target/GhidraMCP-1.7.3.zip` - Ghidra extension package

### Testing

```bash
# Unit tests only (no Ghidra required) - 66 tests
pytest tests/unit/

# Integration tests (requires running Ghidra with plugin and loaded binary)
pytest tests/integration/

# Functional end-to-end tests (requires Ghidra + binary)
pytest tests/functional/

# Run specific test file
pytest tests/unit/test_api_client.py

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

**Test Architecture**: Tests follow the Test Pyramid pattern:
- `tests/unit/` - Fast, isolated component tests (no dependencies)
- `tests/integration/` - REST API endpoint tests (requires Ghidra server)
- `tests/functional/` - Complete workflow tests (requires Ghidra + binary)

### Deployment to Ghidra

Automated installation (recommended):
```powershell
# Windows - automatically detects version and Ghidra installation
.\deploy-to-ghidra.ps1
```

Manual installation:
```bash
# Option 1: Copy JAR to Ghidra extensions
cp target/GhidraMCP.jar "<ghidra_install>/Extensions/Ghidra/"

# Option 2: Install ZIP via Ghidra GUI
# File → Install Extensions → Add Extension → Select GhidraMCP-1.7.3.zip
```

### Running the MCP Bridge

```bash
# Stdio transport (default, for AI tools like Claude)
python bridge_mcp_ghidra.py

# SSE transport (for web/HTTP clients)
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081

# Custom Ghidra server URL
python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8089/
```

## Key Files and Structure

### Core Implementation
- `bridge_mcp_ghidra.py` - Main MCP server (108 MCP tools: 98 implemented + 10 ROADMAP v2.0)
- `src/main/java/com/xebyte/GhidraMCPPlugin.java` - Ghidra plugin (all REST endpoints)
- `pom.xml` - Maven build configuration with system-scoped Ghidra dependencies
- `src/assembly/ghidra-extension.xml` - Assembly descriptor for ZIP packaging

### Configuration
- `.env.template` - Environment variables template (copy to `.env` for local config)
- `pytest.ini` - Test configuration with markers and coverage settings
- `requirements.txt` - Production dependencies (mcp, requests)
- `requirements-test.txt` - Test dependencies

### Documentation
- `README.md` - User-facing documentation
- `docs/API_REFERENCE.md` - Complete endpoint documentation
- `docs/DEVELOPMENT_GUIDE.md` - Contributing guidelines
- `tests/README.md` - Comprehensive test documentation

## Development Guidelines

### When Modifying the Java Plugin

1. **Port changes**: Server port configurable via Ghidra Tool Options (default: 8089)
2. **Thread safety**: All Ghidra API calls must use `SwingUtilities.invokeAndWait()` for thread-safe access
3. **Error handling**: Return HTTP 500 with error messages, never throw exceptions to HTTP layer
4. **Endpoint patterns**: GET for queries, POST for mutations
5. **Testing**: Requires full Ghidra restart to load plugin changes

### When Modifying the MCP Bridge

1. **Input validation**: Use `validate_hex_address()` and `validate_function_name()` for all user inputs
2. **Server URL restrictions**: Only local/private IPs allowed (security requirement)
3. **Request patterns**: Use `safe_get()` and `safe_post()` helpers, not direct requests
4. **Caching**: GET requests cached for 3 minutes (configurable), disabled for mutations
5. **Error propagation**: Return descriptive error messages, log with `logger.error()`

### Test Development Standards

- **Unit tests**: Must not depend on external services, use mocking
- **Integration tests**: Require running Ghidra server on port 8089
- **Functional tests**: Require Ghidra with loaded binary
- **Markers**: Use `@pytest.mark.integration`, `@pytest.mark.functional`, `@pytest.mark.slow`
- **All new features require 100% test pass rate**

## Common Patterns

### Adding a New MCP Tool

1. Add REST endpoint to Java plugin (`GhidraMCPPlugin.java`)
2. Add MCP tool function to `bridge_mcp_ghidra.py` with `@mcp.tool()` decorator
3. Implement input validation using validation functions
4. Use `safe_get()` or `safe_post()` for HTTP calls
5. Add integration test in `tests/integration/`

### Working with Data Types

Data type operations use JSON payloads for complex structures:
```python
# Creating structs - use safe_post_json()
fields = [{"name": "id", "type": "int"}, {"name": "name", "type": "char[32]"}]
result = safe_post_json("create_struct", {"name": "MyStruct", "fields": fields})
```

### Calling Conventions Support

The plugin supports setting function prototypes with calling conventions:
```python
set_function_prototype(
    function_address="0x401000",
    prototype="int main(int argc, char* argv[])",
    calling_convention="__cdecl"  # Optional: __cdecl, __stdcall, __fastcall, __thiscall
)
```

## Important Constraints

1. **Ghidra JARs are system-scoped**: Maven won't download them; they must exist in `lib/` before building
2. **Plugin requires Ghidra restart**: Changes to Java plugin only take effect after restarting Ghidra
3. **Python 3.8+ required**: MCP framework uses modern Python features
4. **No concurrent program access**: Ghidra API is single-threaded; all operations serialize through Swing EDT
5. **Security restrictions**: Bridge only accepts localhost/private IP connections for Ghidra server

## Troubleshooting

### Build fails with missing Ghidra JARs
Run `copy-ghidra-libs.bat` to copy JARs from Ghidra installation to `lib/`

### Plugin doesn't appear in Ghidra
Verify JAR is in `<ghidra>/Extensions/Ghidra/` and restart Ghidra completely

### MCP bridge can't connect
Ensure Ghidra is running with a program loaded and plugin started (check port 8089)

### Tests failing
- Unit tests: Should always pass (no dependencies)
- Integration tests: Requires Ghidra running with GhidraMCP plugin
- Functional tests: Requires Ghidra with a binary loaded in CodeBrowser

# Ghidra MCP Examples

This directory contains examples and demonstrations of how to use the Ghidra MCP Server with its 57 available tools.

## 🚀 Getting Started

The Ghidra MCP Server provides comprehensive binary analysis capabilities through 57 MCP tools. For complete documentation, see:

- **[API Reference](../docs/API_REFERENCE.md)** - Complete tool documentation
- **[Development Guide](../docs/DEVELOPMENT_GUIDE.md)** - Setup and development workflows

## 📋 Available Tools Categories

| Category | Tools | Description |
|----------|-------|-------------|
| **Core System** | 6 | Connection, metadata, utilities |
| **Function Analysis** | 19 | Discovery, analysis, modification |
| **Data Structures** | 16 | Types, structures, advanced tools |
| **Data Analysis** | 5 | Items, strings, cross-references |
| **Symbol Management** | 7 | Labels, globals, imports/exports |
| **Documentation** | 2 | Comments and annotations |
| **Advanced Features** | 2 | Call graphs, complex analysis |

## 🔧 Basic Usage Examples

### Starting the MCP Server

```bash
# Stdio transport (recommended for AI tools)
python bridge_mcp_ghidra.py

# SSE transport (for web clients)
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081
```

### Example Tool Usage

```python
# Get function information
functions = list_functions(limit=10)
current_func = get_current_function()

# Analyze a specific function
decompiled = decompile_function("main")
xrefs = get_function_xrefs("main")

# Data structure analysis
structs = list_data_types(category="struct")
analysis = analyze_data_types("0x401000", depth=2)
```

## 📚 Additional Resources

- **[Scripts Directory](../scripts/README.md)** - Utility scripts and tools
- **[Test Suite](../tests/README.md)** - Comprehensive testing examples
- **[Main Repository](../)** - Complete project documentation

---

**Note**: Examples require a running Ghidra instance with the GhidraMCP plugin loaded and a binary file analyzed.


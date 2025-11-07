# GhidraMCP Examples

This directory contains practical examples demonstrating how to use the Ghidra MCP Server for binary analysis tasks.

## Quick Start

All examples require the MCP server to be running:

```bash
# Terminal 1: Start Ghidra with open binary
ghidra

# Terminal 2: Start MCP server
python bridge_mcp_ghidra.py

# Terminal 3: Run an example
python examples/analyze-functions.py
```

## Examples

### 1. `analyze-functions.py`
**Purpose**: Get an overview of all functions in a binary

**What it does**:
- Lists all functions in the currently open program
- Decompiles each function to understand its purpose
- Gets cross-references (who calls this function)
- Generates a JSON report with complete analysis

**Use cases**:
- Understanding binary structure
- Finding important functions
- Identifying function relationships

**Run it**:
```bash
python examples/analyze-functions.py
```

---

### 2. `create-struct-workflow.py`
**Purpose**: Create custom data structures for better decompilation

**What it does**:
- Creates a new structure definition with typed fields
- Inspects memory layout at a specific address
- Applies the structure to memory locations
- Extends the structure with additional fields

**Use cases**:
- Improving decompilation quality
- Documenting data structures
- Enabling structure-aware analysis

**Run it**:
```bash
python examples/create-struct-workflow.py
```

---

### 3. `batch-rename.py`
**Purpose**: Automatically rename auto-generated function names to meaningful names

**What it does**:
- Finds auto-named functions (FUN_XXXXX) with multiple cross-references
- Analyzes decompiled code to suggest meaningful names
- Applies renames atomically
- Suggests variable names based on code patterns

**Use cases**:
- Improving readability of analysis
- Documenting important functions
- Preparing binary for team review

**Run it**:
```bash
python examples/batch-rename.py
```

---

### 4. `extract-strings.py`
**Purpose**: Extract and analyze all strings in a binary for IOCs and indicators

**What it does**:
- Lists all strings defined in the binary
- Extracts Indicators of Compromise (IOCs)
- Classifies strings by type
- Generates statistics and reports

**Use cases**:
- Finding hardcoded servers/endpoints
- Identifying external connections
- Detecting C2 infrastructure
- Malware analysis

**Run it**:
```bash
python examples/extract-strings.py
```

---

### 5. `document-binary.py`
**Purpose**: Generate comprehensive documentation for an entire binary

**What it does**:
- Analyzes program metadata
- Documents all important functions
- Generates both Markdown and JSON reports
- Creates statistics and call graphs

**Use cases**:
- Creating binary documentation
- Team knowledge sharing
- Audit trail documentation
- Report generation for clients

**Run it**:
```bash
python examples/document-binary.py
```

---

## Combining Examples

Chain examples together for comprehensive analysis:

```bash
# 1. Analyze all functions
python examples/analyze-functions.py

# 2. Extract strings and IOCs
python examples/extract-strings.py

# 3. Batch rename important functions
python examples/batch-rename.py

# 4. Create structures for better decompilation
python examples/create-struct-workflow.py

# 5. Generate final documentation
python examples/document-binary.py
```

---

## Troubleshooting

### "Connection refused"
- Ensure Ghidra is running
- Ensure MCP server is running: `python bridge_mcp_ghidra.py`
- Check if port 8089 is accessible

### "Function not found"
- Ensure a binary is open in Ghidra's CodeBrowser
- Wait for analysis to complete (see Ghidra window)
- Check function names match exactly (case-sensitive)

### Timeout errors
- Large binaries may need longer timeouts
- Modify `TIMEOUT = 30` to `TIMEOUT = 60` in examples
- Run on subset of functions first

---

## Additional Resources

- **Main Documentation**: See `README.md` for installation
- **API Reference**: See `DOCUMENTATION_INDEX.md` for all 109 MCP tools
- **Troubleshooting**: See `docs/ERROR_CODES.md` for common issues
- **Performance**: See `docs/PERFORMANCE_BASELINES.md` for timing expectations

## 📚 Additional Resources

- **[Scripts Directory](../scripts/README.md)** - Utility scripts and tools
- **[Test Suite](../tests/README.md)** - Comprehensive testing examples
- **[Main Repository](../)** - Complete project documentation

---

**Note**: Examples require a running Ghidra instance with the GhidraMCP plugin loaded and a binary file analyzed.


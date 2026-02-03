# Ghidra MCP Server

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Java Version](https://img.shields.io/badge/Java-21%20LTS-orange.svg)](https://openjdk.java.net/projects/jdk/21/)
[![Ghidra Version](https://img.shields.io/badge/Ghidra-12.0.2-green.svg)](https://ghidra-sre.org/)
[![Version](https://img.shields.io/badge/Version-2.0.0-brightgreen.svg)](CHANGELOG.md)

> If you find this useful, please ⭐ star the repo — it helps others discover it!

A production-ready Model Context Protocol (MCP) server that bridges Ghidra's powerful reverse engineering capabilities with modern AI tools and automation frameworks.

## 🌟 Features

### Core MCP Integration
- **Full MCP Compatibility** - Complete implementation of Model Context Protocol
- **110 MCP Tools Available** - Comprehensive API surface for binary analysis
- **Production-Ready Reliability** - Tested batch operations and atomic transactions
- **Real-time Analysis** - Live integration with Ghidra's analysis engine

### Binary Analysis Capabilities
- **Function Analysis** - Decompilation, call graphs, cross-references
- **Data Structure Discovery** - Automatic struct/union/enum creation
- **String Extraction** - Comprehensive string analysis and categorization  
- **Import/Export Analysis** - Symbol table and library dependency mapping
- **Memory Mapping** - Complete memory layout documentation
- **Cross-Binary Documentation** - Function hash matching across binary versions

### Development & Automation
- **Automated Development Cycle** - Complete build-test-deploy-verify pipeline
- **Ghidra Script Management** - Create, run, and manage Ghidra scripts via MCP
- **Multi-Program Support** - Switch between and compare multiple open programs
- **Batch Operations** - Efficient bulk renaming, commenting, and typing

## 🚀 Quick Start

### Prerequisites

- **Java 21 LTS** (OpenJDK recommended)
- **Apache Maven 3.9+**
- **Ghidra 12.0.2** (or compatible version)
- **Python 3.8+** with pip

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bethington/ghidra-mcp.git
   cd ghidra-mcp
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Copy Ghidra libraries** (see [Library Dependencies](#library-dependencies) for full list):
   ```bash
   # Windows - run the provided batch script
   copy-ghidra-libs.bat "C:\path\to\ghidra_12.0.2_PUBLIC"
   
   # Linux/Mac - copy manually from your Ghidra installation
   # See Library Dependencies section below for all 14 required JARs
   ```

4. **Build the plugin:**
   ```bash
   mvn clean package assembly:single -DskipTests
   ```

5. **Deploy to Ghidra:**
   ```powershell
   # Windows (automated)
   .\deploy-to-ghidra.ps1

   # Or manually copy to Ghidra Extensions
   Copy-Item target\GhidraMCP-2.0.0.zip "C:\ghidra\Extensions\Ghidra\"
   ```

### Basic Usage

#### Option 1: Stdio Transport (Recommended for AI tools)
```bash
python bridge_mcp_ghidra.py
```

#### Option 2: SSE Transport (Web/HTTP clients)
```bash
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081
```

#### In Ghidra
1. Start Ghidra and load a binary
2. Go to **Tools > GhidraMCP > Start MCP Server**
3. The server runs on `http://127.0.0.1:8080/` by default

## 📊 Production Performance

- **MCP Tools**: 110 tools fully implemented
- **Speed**: Sub-second response for most operations
- **Efficiency**: 93% reduction in API calls via batch operations
- **Reliability**: Atomic transactions with all-or-nothing semantics
- **Deployment**: Automated version-aware deployment script

## 🛠️ API Reference

### Core Operations
- `check_connection` - Verify MCP connectivity
- `get_metadata` - Program metadata and info
- `get_version` - Server version information
- `get_entry_points` - Binary entry points discovery

### Function Analysis
- `list_functions` - List all functions (paginated)
- `search_functions_by_name` - Search functions by name/pattern
- `search_functions_enhanced` - Advanced function search with filters
- `decompile_function` - Decompile function to C pseudocode
- `get_decompiled_code` - Get decompiled code by address
- `get_function_callers` - Get function callers
- `get_function_callees` - Get function callees
- `get_function_call_graph` - Function relationship graph
- `get_full_call_graph` - Complete call graph for program
- `analyze_function_complete` - Comprehensive function analysis
- `analyze_function_completeness` - Documentation completeness score

### Memory & Data
- `list_segments` - Memory segments and layout
- `get_function_by_address` - Function at address
- `disassemble_function` - Disassembly listing
- `disassemble_bytes` - Raw byte disassembly
- `get_xrefs_to` - Cross-references to address
- `get_xrefs_from` - Cross-references from address
- `get_bulk_xrefs` - Bulk cross-reference lookup
- `analyze_data_region` - Analyze memory region structure
- `inspect_memory_content` - View raw memory content
- `detect_array_bounds` - Detect array boundaries

### Cross-Binary Documentation (v1.9.4+)
- `get_function_hash` - SHA-256 hash of normalized function opcodes
- `get_bulk_function_hashes` - Paginated bulk hashing with filter
- `get_function_documentation` - Export complete function documentation
- `apply_function_documentation` - Import documentation to target function
- `build_function_hash_index` - Build persistent JSON index
- `lookup_function_by_hash` - Find matching functions in index
- `propagate_documentation` - Apply docs to all matching instances

### Data Types & Structures
- `list_data_types` - Available data types
- `search_data_types` - Search for data types
- `create_struct` - Create custom structure
- `add_struct_field` - Add field to structure
- `modify_struct_field` - Modify existing field
- `remove_struct_field` - Remove field from structure
- `create_enum` - Create enumeration
- `get_enum_values` - Get enumeration values
- `create_array_type` - Create array data type
- `apply_data_type` - Apply type to address
- `delete_data_type` - Delete a data type
- `consolidate_duplicate_types` - Merge duplicate types
- `get_valid_data_types` - Get list of valid Ghidra types

### Symbols & Labels
- `list_imports` - Imported symbols and libraries
- `list_exports` - Exported symbols and functions
- `list_external_locations` - External location references
- `list_strings` - Extracted strings with analysis
- `list_namespaces` - Available namespaces
- `list_globals` - Global variables
- `create_label` - Create label at address
- `batch_create_labels` - Bulk label creation
- `delete_label` - Delete label at address
- `batch_delete_labels` - Bulk label deletion
- `rename_label` - Rename existing label
- `rename_or_label` - Rename or create label

### Renaming & Documentation
- `rename_function` - Rename function by name
- `rename_function_by_address` - Rename function by address
- `rename_data` - Rename data item
- `rename_variables` - Rename function variables
- `rename_global_variable` - Rename global variable
- `rename_external_location` - Rename external reference
- `batch_rename_function_components` - Bulk renaming
- `set_decompiler_comment` - Set decompiler comment
- `set_disassembly_comment` - Set disassembly comment
- `set_plate_comment` - Set function plate comment
- `get_plate_comment` - Get function plate comment
- `batch_set_comments` - Bulk comment setting

### Type System
- `set_function_prototype` - Set function signature
- `set_local_variable_type` - Set variable type
- `set_parameter_type` - Set parameter type
- `batch_set_variable_types` - Bulk type setting
- `set_variable_storage` - Control variable storage location
- `set_function_no_return` - Mark function as non-returning
- `list_calling_conventions` - Available calling conventions
- `get_function_variables` - Get all function variables
- `get_function_labels` - Get labels in function

### Ghidra Script Management
- `list_scripts` - List available scripts
- `run_script` - Run a script
- `list_ghidra_scripts` - List custom Ghidra scripts
- `save_ghidra_script` - Save new script
- `get_ghidra_script` - Get script contents
- `run_ghidra_script` - Execute Ghidra script
- `update_ghidra_script` - Update existing script
- `delete_ghidra_script` - Delete script

### Multi-Program Support
- `list_open_programs` - List all open programs
- `get_current_program_info` - Current program details
- `switch_program` - Switch active program
- `list_project_files` - List project files
- `open_program` - Open program from project
- `compare_programs_documentation` - Compare documentation between programs

### Analysis Tools
- `find_next_undefined_function` - Find undefined functions
- `find_undocumented_by_string` - Find functions by string reference
- `batch_string_anchor_report` - String anchor analysis
- `search_byte_patterns` - Search for byte patterns
- `get_assembly_context` - Get assembly context
- `analyze_struct_field_usage` - Analyze structure field access
- `get_field_access_context` - Get field access patterns
- `create_function` - Create function at address
- `get_function_jump_target_addresses` - Get jump targets

See [docs/README.md](docs/README.md) for complete documentation.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI/Automation │◄──►│   MCP Bridge    │◄──►│  Ghidra Plugin  │
│     Tools       │    │ (bridge_mcp_    │    │ (GhidraMCP.jar) │
│  (Claude, etc.) │    │  ghidra.py)     │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
   MCP Protocol            HTTP REST              Ghidra API
   (stdio/SSE)          (localhost:8080)      (Program, Listing)
```

### Components

- **bridge_mcp_ghidra.py** - Python MCP server that translates MCP protocol to HTTP calls
- **GhidraMCP.jar** - Ghidra plugin that exposes analysis capabilities via HTTP
- **ghidra_scripts/** - Collection of 70+ automation scripts for common tasks

## 🔧 Development

### Building from Source
```bash
# Build the plugin (skip integration tests)
mvn clean package assembly:single -DskipTests

# Deploy to Ghidra
.\deploy-to-ghidra.ps1
```

### Project Structure
```
ghidra-mcp/
├── bridge_mcp_ghidra.py     # MCP server (Python)
├── src/main/java/           # Ghidra plugin (Java)
├── lib/                     # Ghidra library dependencies
├── ghidra_scripts/          # 70+ automation scripts
├── docs/                    # Documentation
│   ├── prompts/            # AI workflow prompts
│   ├── releases/           # Version release notes
│   └── project-management/ # Project docs
├── examples/                # Example usage
└── scripts/                 # Build/utility scripts
```

### Library Dependencies

The `lib/` folder must contain Ghidra JAR files for compilation. Run the provided script to copy them from your Ghidra installation:

```bash
# Windows
copy-ghidra-libs.bat "C:\path\to\ghidra_12.0.2_PUBLIC"

# Or manually copy from your Ghidra installation
```

**Required Libraries (14 JARs, ~37MB):**

| Library | Source Path | Purpose |
|---------|------------|---------|
| **Base.jar** | `Features/Base/lib/` | Core Ghidra functionality |
| **Decompiler.jar** | `Features/Decompiler/lib/` | Decompilation engine |
| **PDB.jar** | `Features/PDB/lib/` | Microsoft PDB symbol support |
| **FunctionID.jar** | `Features/FunctionID/lib/` | Function identification |
| **SoftwareModeling.jar** | `Framework/SoftwareModeling/lib/` | Program model API |
| **Project.jar** | `Framework/Project/lib/` | Project management |
| **Docking.jar** | `Framework/Docking/lib/` | UI docking framework |
| **Generic.jar** | `Framework/Generic/lib/` | Generic utilities |
| **Utility.jar** | `Framework/Utility/lib/` | Core utilities |
| **Gui.jar** | `Framework/Gui/lib/` | GUI components |
| **FileSystem.jar** | `Framework/FileSystem/lib/` | File system support |
| **Graph.jar** | `Framework/Graph/lib/` | Graph/call graph analysis |
| **DB.jar** | `Framework/DB/lib/` | Database operations |
| **Emulation.jar** | `Framework/Emulation/lib/` | P-code emulation |

> **Note**: Libraries are NOT included in the repository (see `.gitignore`). You must copy them from your Ghidra installation before building.

### Development Features
- **Automated Deployment**: Version-aware deployment script
- **Batch Operations**: Reduces API calls by 93%
- **Atomic Transactions**: All-or-nothing semantics
- **Comprehensive Logging**: Debug and trace capabilities

## 📚 Documentation

### Core Documentation
- [Documentation Index](docs/README.md) - Complete documentation navigation
- [Project Structure](docs/PROJECT_STRUCTURE.md) - Project organization guide
- [Naming Conventions](docs/NAMING_CONVENTIONS.md) - Code naming standards
- [Hungarian Notation](docs/HUNGARIAN_NOTATION.md) - Variable naming guide

### AI Workflow Prompts
- [Prompts Overview](docs/prompts/README.md) - AI prompting system guide
- [Function Documentation Workflow](docs/prompts/FUNCTION_DOC_WORKFLOW_V4.md) - Complete workflow
- [Quick Start Prompt](docs/prompts/QUICK_START_PROMPT.md) - Simplified beginner workflow
- [Cross-Version Matching](docs/prompts/CROSS_VERSION_MATCHING_COMPREHENSIVE.md) - Hash-based matching

### Release History
- [Complete Changelog](CHANGELOG.md) - All version release notes
- [Release Notes](docs/releases/) - Detailed release documentation

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

### Quick Start
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Build and test your changes (`mvn clean package assembly:single -DskipTests`)
4. Update documentation as needed
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🏆 Production Status

| Metric | Value |
|--------|-------|
| **Version** | 2.0.0 |
| **MCP Tools** | 110 fully implemented |
| **Compilation** | ✅ 100% success |
| **Batch Efficiency** | 93% API call reduction |
| **Ghidra Scripts** | 70+ automation scripts |
| **Documentation** | Comprehensive with AI prompts |

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.  

## 🙏 Acknowledgments

- **Ghidra Team** - For the incredible reverse engineering platform
- **Model Context Protocol** - For the standardized AI integration framework
- **Contributors** - For testing, feedback, and improvements

---

## 🔗 Related Projects

- [re-universe](https://github.com/bethington/re-universe) — Ghidra BSim PostgreSQL platform for large-scale binary similarity analysis. Pairs perfectly with GhidraMCP for AI-driven reverse engineering workflows.
- [cheat-engine-server-python](https://github.com/bethington/cheat-engine-server-python) — MCP server for dynamic memory analysis and debugging.

---

**Ready for production deployment with enterprise-grade reliability and comprehensive binary analysis capabilities.**

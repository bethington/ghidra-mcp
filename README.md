# Ghidra MCP Server

[![Tests](https://img.shields.io/github/actions/workflow/status/bethington/ghidra-mcp/tests.yml?branch=main&style=for-the-badge&label=Tests&logo=github-actions&logoColor=white)](https://github.com/bethington/ghidra-mcp/actions/workflows/tests.yml)
[![Release](https://img.shields.io/github/v/release/bethington/ghidra-mcp?style=for-the-badge&logo=github&logoColor=white&color=blue)](https://github.com/bethington/ghidra-mcp/releases/latest)
[![License](https://img.shields.io/github/license/bethington/ghidra-mcp?style=for-the-badge&color=green)](LICENSE)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/bethington?style=for-the-badge&logo=githubsponsors&logoColor=white&label=Sponsors&labelColor=ea4aaa&color=ea4aaa)](https://github.com/sponsors/bethington)

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Java](https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/projects/jdk/21/)
[![Ghidra](https://img.shields.io/badge/Ghidra-12.0.4-brightgreen?style=for-the-badge&logoColor=white)](https://ghidra-sre.org/)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-6C5CE7?style=for-the-badge&logoColor=white)](https://modelcontextprotocol.io/)

[![Stars](https://img.shields.io/github/stars/bethington/ghidra-mcp?style=for-the-badge&logo=github&logoColor=white&color=yellow)](https://github.com/bethington/ghidra-mcp/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/bethington/ghidra-mcp?style=for-the-badge&logo=git&logoColor=white)](https://github.com/bethington/ghidra-mcp/commits/main)
[![Discussions](https://img.shields.io/github/discussions/bethington/ghidra-mcp?style=for-the-badge&logo=github&logoColor=white)](https://github.com/bethington/ghidra-mcp/discussions)
[![Issues](https://img.shields.io/github/issues/bethington/ghidra-mcp?style=for-the-badge&logo=github&logoColor=white&color=orange)](https://github.com/bethington/ghidra-mcp/issues)

> If you find this useful, please ⭐ star the repo — it helps others discover it!
>
> If Ghidra MCP saves you time, consider [sponsoring the project](https://github.com/sponsors/bethington). One-time and recurring support both help fund compatibility updates, production hardening, docs, and new tooling.

A production-ready Model Context Protocol (MCP) server that bridges Ghidra's powerful reverse engineering capabilities with modern AI tools and automation frameworks. **225 MCP tools**, battle-tested AI workflows, and the most comprehensive Ghidra-MCP integration available — now including P-code emulation, live debugger integration, and PCode-graph data flow analysis.

## Why Ghidra MCP?

Most Ghidra MCP implementations give you a handful of read-only tools and call it a day. This project is different — it was built by a reverse engineer who uses it daily on real binaries, not as a demo.

- **225 MCP tools** — 3x more than any competing implementation. Not just read operations — full write access for renaming, typing, commenting, structure creation, script execution, P-code emulation, and live debugging.
- **Battle-tested AI workflows** — Proven documentation workflows (V5) refined across hundreds of functions. Includes step-by-step prompts, Hungarian notation reference, batch processing guides, and orphaned code discovery.
- **Production-grade reliability** — Atomic transactions, batch operations (93% API call reduction), configurable timeouts, and graceful error handling. No silent failures.
- **Cross-binary documentation transfer** — SHA-256 function hash matching propagates documentation across binary versions automatically. Document once, apply everywhere.
- **Full Ghidra Server integration** — Connect to shared Ghidra servers, manage repositories, version control, checkout/checkin workflows, and multi-user collaboration.
- **Headless and GUI modes** — Run with or without the Ghidra GUI. Docker-ready for CI/CD pipelines and automated analysis at scale.
- **Opinionated by design** — v5.0 moves naming conventions, type safety, and documentation standards into the tool layer. AI agents and human engineers produce consistent output without style guides in every prompt.

## Convention Enforcement

You've been there: six months into a project you find `ProcessItem`, `process_items`, `handleItem`, and `ItemProc` in the same codebase — four functions doing the same thing, named by four different sessions or engineers with no shared contract. Fixing it takes longer than it should, and the problem will happen again.

v5.0 moves conventions from "things to remember" into the tool layer, where they can actually be enforced.

| Tier | Behavior | Example |
|------|----------|---------|
| **Auto-fix** | Applied silently | `count` field on a `uint32` → auto-prefixed `dwCount` on save |
| **Warn** | Change goes through, warning returned | `processData` → "name should be PascalCase with a verb: `ProcessData`" |
| **Reject** | Change blocked with explanation | `undefined → undefined` type change → "no-op rejected, type unchanged" |

**For AI agents**, this means consistent output across every session, every model, every run — without pasting a style guide into every prompt. The tool knows the rules; the model just needs to make the call.

**For teams**, it eliminates the entire class of review comment that says "that's not our naming convention." Convention arbitration stays in the tool, not in code review.

**For solo work at scale**, `analyze_function_completeness` gives you a 0–100% score that measures honestly: structural deductions (unfixable compiler artifacts) are forgiven in your effective score, log-scaling prevents one bad category from burying everything else, and tiered plate comment quality means you know exactly what's missing and why.

## 🌟 Features

### Core MCP Integration
- **Full MCP Compatibility** — Complete implementation of Model Context Protocol
- **225 MCP Tools** — Comprehensive API surface covering every aspect of binary analysis
- **Production-Ready Reliability** — Atomic transactions, batch operations, configurable timeouts
- **Real-time Analysis** — Live integration with Ghidra's analysis engine

> **Compatibility note:** MCP tool names are normalized for GitHub Copilot CLI
> and CAPI validation. Exposed tool names use lowercase letters, digits,
> underscores, and hyphens only; nested HTTP paths such as `/debugger/status`
> are advertised as names like `debugger_status_2` when needed to avoid
> collisions with static bridge tools.

### Binary Analysis Capabilities
- **Function Analysis** — Decompilation, call graphs, cross-references, completeness scoring
- **Data Flow Analysis** — PCode-graph value propagation (forward / backward) from any variable or register
- **Data Structure Discovery** — Struct/union/enum creation with field analysis and naming suggestions
- **String Extraction** — Regex search, quality filtering, and string-anchored function discovery
- **Import/Export Analysis** — Symbol tables, external locations, ordinal import resolution
- **Memory & Data Inspection** — Raw memory reads, byte pattern search, array boundary detection
- **Cross-Binary Documentation** — Function hash matching and documentation propagation across versions

### Dynamic Analysis (v5.4.0)
- **P-code Emulation** — Run any function in isolation via Ghidra's `EmulatorHelper`; brute-force API hash resolution in milliseconds
- **Live Debugger Integration** — 17 Java endpoints + 22 Python bridge tools over Ghidra's TraceRmi framework (dbgeng on Windows PE, gdb/lldb otherwise): attach, step, breakpoints, registers, memory reads, non-breaking function tracing, ASLR-aware static↔dynamic address translation

### AI-Powered Reverse Engineering Workflows
- **Function Documentation Workflow V5** — 7-step process for complete function documentation with Hungarian notation, type auditing, and automated verification scoring
- **Batch Documentation** — Parallel subagent dispatch for documenting multiple functions simultaneously
- **Orphaned Code Discovery** — Automated scanner finds undiscovered functions in gaps between known code
- **Data Type Investigation** — Systematic workflows for structure discovery and field analysis
- **Cross-Version Matching** — Hash-based function matching across different binary versions

### Development & Automation
- **Ghidra Script Management** — Create, run, update, and delete Ghidra scripts entirely via MCP
- **Multi-Program Support** — Switch between and compare multiple open programs
- **Batch Operations** — Bulk renaming, commenting, typing, and label management (93% fewer API calls)
- **Headless Server** — Full analysis without Ghidra GUI — Docker and CI/CD ready
- **Project & Version Control** — Create projects, manage files, Ghidra Server integration
- **Analysis Control** — List, configure, and trigger Ghidra analyzers programmatically

## 🚀 Quick Start

### Prerequisites

- **Java 21 LTS** (OpenJDK recommended)
- **Apache Maven 3.9+**
- **Ghidra 12.0.4** (or compatible version)
- **Python 3.10+** with pip

### Installation

> Recommended for all platforms: use `python -m tools.setup` directly.
>
> `ensure-prereqs` installs runtime Python requirements plus the Ghidra JARs needed in the local Maven repository.
> `deploy` copies the build output, installs the user-profile extension, and patches Ghidra user config.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bethington/ghidra-mcp.git
   cd ghidra-mcp
   ```

2. **Recommended: run environment preflight first:**
   ```text
   python -m tools.setup preflight --ghidra-path "F:\ghidra_12.0.4_PUBLIC"
   ```

3. **Build and deploy to Ghidra:**
   ```text
   python -m tools.setup ensure-prereqs --ghidra-path "F:\ghidra_12.0.4_PUBLIC"
   python -m tools.setup build
   python -m tools.setup deploy --ghidra-path "F:\ghidra_12.0.4_PUBLIC"
   ```

   `deploy` saves/closes an already-running matching Ghidra instance when
   needed, installs the extension, starts Ghidra, waits for MCP health, and runs
   schema smoke checks.

4. **Optional strict/manual mode** (advanced):
   ```text
   # Skip automatic prerequisite setup
   python -m tools.setup build
   python -m tools.setup deploy --ghidra-path "F:\ghidra_12.0.4_PUBLIC"
   ```

5. **Show command help**:
   ```text
   python -m tools.setup --help
   ```

6. **Optional build-only mode** (advanced/troubleshooting):
   ```text
   python -m tools.setup build
   ```

   Supported build path: `python -m tools.setup build` uses Maven under the hood and is the canonical workflow used by the repo tasks and docs.

   ```bash
   # Manual Maven build (requires Ghidra deps already installed in local .m2)
   mvn clean package assembly:single -DskipTests
   ```

   ```bash
   # Secondary/manual Gradle build path only (not used by tools.setup or VS Code tasks)
   GHIDRA_INSTALL_DIR=/path/to/ghidra gradle buildExtension
   ```

### Installation (Linux — Ubuntu/Debian)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bethington/ghidra-mcp.git
   cd ghidra-mcp
   ```

2. **Install system prerequisites** (if not already installed):
   ```bash
   sudo apt update && sudo apt install -y openjdk-21-jdk maven python3 python3-pip curl jq unzip
   ```

3. **Run environment preflight:**
   ```bash
   python -m tools.setup preflight --ghidra-path ~/ghidra_12.0.4_PUBLIC
   ```

4. **Build and deploy to Ghidra (single command):**
   ```bash
   python -m tools.setup ensure-prereqs --ghidra-path ~/ghidra_12.0.4_PUBLIC
   python -m tools.setup build
   python -m tools.setup deploy --ghidra-path ~/ghidra_12.0.4_PUBLIC
   ```

   This will:
   - Install Ghidra JAR dependencies into your local `~/.m2/repository`
   - Build `GhidraMCP-<version>.zip` with Maven
   - Extract the extension to `~/.config/ghidra/ghidra_<version>_PUBLIC/Extensions/`
   - Update `preferences` with `LastExtensionImportDirectory`
   - Install Python requirements

5. **Optional: setup only Maven dependencies:**
   ```bash
   python -m tools.setup install-ghidra-deps --ghidra-path ~/ghidra_12.0.4_PUBLIC
   ```

6. **Show command help:**
   ```bash
   python -m tools.setup --help
   ```

> **Linux paths:** The extension is installed to `$HOME/.config/ghidra/ghidra_<version>_PUBLIC/Extensions/GhidraMCP/`.
> Ghidra config files are in `$HOME/.config/ghidra/ghidra_<version>_PUBLIC/`.

### Installation (macOS — Homebrew)

1. **Install prerequisites:**
   ```bash
   brew install openjdk@21 maven python ghidra
   ```

2. **Clone the repository:**
   ```bash
   git clone https://github.com/bethington/ghidra-mcp.git
   cd ghidra-mcp
   ```

3. **Install Ghidra JARs into local Maven:**
   ```bash
    python -m tools.setup install-ghidra-deps \
       --ghidra-path /opt/homebrew/opt/ghidra/libexec
   ```

4. **Build and deploy:**
   ```bash
    python -m tools.setup ensure-prereqs \
       --ghidra-path /opt/homebrew/opt/ghidra/libexec
    python -m tools.setup build
    python -m tools.setup deploy \
       --ghidra-path /opt/homebrew/opt/ghidra/libexec
   ```
   The extension is installed to `~/Library/ghidra/ghidra_12.0.4_PUBLIC/Extensions/GhidraMCP/`.

   > **Note:** `--ghidra-version` is required when using the Homebrew path because the path contains no version string.

5. **Start Ghidra and enable the plugin:**
   ```bash
   /opt/homebrew/opt/ghidra/libexec/ghidraRun
   ```
   In the main project window: **Tools > GhidraMCP > Start MCP Server**

6. **Configure Cursor/Claude MCP** (`~/.cursor/mcp.json`):
   ```json
   {
     "mcpServers": {
       "ghidra": {
         "command": "uv",
         "args": ["run", "--script", "/path/to/ghidra-mcp/bridge_mcp_ghidra.py"]
       }
     }
   }
   ```

### Basic Usage

#### Option 1: Stdio Transport (Recommended for AI tools)
```bash
python bridge_mcp_ghidra.py
```

#### Option 2: Streamable HTTP Transport (Recommended for web/HTTP clients)
```bash
python bridge_mcp_ghidra.py --transport streamable-http --mcp-host 127.0.0.1 --mcp-port 8081
```

MCP client config for the HTTP transport (add to your client's MCP config file):
```json
{
  "mcpServers": {
    "ghidra-mcp-http": {
      "url": "http://127.0.0.1:8081/mcp"
    }
  }
}
```

#### Option 3: SSE Transport (Deprecated — use streamable-http instead)
```bash
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081
```

#### Bridge advanced flags

| Flag | Default | Description |
|------|---------|-------------|
| `--transport` | `stdio` | `stdio` (AI tools), `streamable-http` (web clients), `sse` (deprecated) |
| `--mcp-host` | `127.0.0.1` | Bind host for HTTP transports |
| `--mcp-port` | — | Port for HTTP transports |
| `--lazy` | off | Load only the default tool groups on connect. Faster startup, but MCP clients that don't support `tools/list_changed` will see an incomplete tool list. Not recommended for Claude Code. |
| `--no-lazy` | (default) | Load all tool groups immediately on connect. Required for most AI clients. |
| `--default-groups` | `listing,function,program` | Comma-separated groups loaded on connect when `--lazy` is set. |

#### Optional: Start the standalone debugger server
```bash
python -m pip install -r requirements-debugger.txt
python -m debugger
```

The debugger server listens on `http://127.0.0.1:8099/` by default and is
required for the `debugger_*` proxy tools exposed by the MCP bridge.

Debugger server flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8099` | HTTP server port |
| `--host` | `127.0.0.1` | Bind address (`0.0.0.0` to expose on LAN) |
| `--exports-dir` | — | Path to a `dll_exports/` directory for ordinal-to-name resolution |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` |

Set `GHIDRA_DEBUGGER_URL` in `.env` if you change the default port or host so the bridge can find it.

#### In Ghidra
1. Start Ghidra and open a **CodeBrowser** window
2. In **CodeBrowser**, enable the plugin via **File > Configure > Configure All Plugins > GhidraMCP**
3. Optional: configure custom port via **CodeBrowser > Edit > Tool Options > GhidraMCP HTTP Server**
4. Start the server via **Tools > GhidraMCP > Start MCP Server**
5. The server runs on `http://127.0.0.1:8089/` by default

#### Verify It's Working
```bash
# Quick health check
curl http://127.0.0.1:8089/check_connection
# Expected: "Connected: GhidraMCP plugin running with program '<name>'"

# Get version info
curl http://127.0.0.1:8089/get_version
```

## Support This Project

If Ghidra MCP saves you engineering or reverse-engineering time, consider [sponsoring the project](https://github.com/sponsors/bethington).

- One-time sponsorship helps fund fixes, compatibility updates, and release work.
- Recurring sponsorship helps keep maintenance, docs, and production hardening moving.
- Company support helps prioritize long-term reliability for the bridge, headless server, debugger integration, and workflow tooling.

## 🔒 Security

GhidraMCP is designed for **localhost-only development**. The default configuration — HTTP server bound to `127.0.0.1`, no authentication — is safe on a trusted single-user workstation and matches pre-v5.4.1 behavior.

**If you expose the server beyond loopback, configure these three environment variables first.** The server refuses to start on a non-loopback bind without a token.

| Env var | Effect |
|---|---|
| `GHIDRA_MCP_AUTH_TOKEN` | When set, every HTTP request must carry `Authorization: Bearer <token>`. Timing-safe comparison. `/mcp/health`, `/health`, `/check_connection` are exempt. |
| `GHIDRA_MCP_ALLOW_SCRIPTS` | Set to `1`, `true`, or `yes` to enable `/run_script_inline` and `/run_ghidra_script`. **Off by default as of v5.4.1** — these endpoints execute arbitrary Java against the Ghidra process. |
| `GHIDRA_MCP_FILE_ROOT` | When set to a directory path, filesystem-path endpoints (`/import_file`, `/open_project`, `/delete_file`, etc.) canonicalize the input and require it to fall under this root. Prevents path-traversal. |

### Example: exposing to a private LAN with auth

```bash
export GHIDRA_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
export GHIDRA_MCP_ALLOW_SCRIPTS=1     # only if your workflow needs it
export GHIDRA_MCP_FILE_ROOT=/srv/ghidra/inputs

java -jar GhidraMCPHeadless.jar --bind 0.0.0.0 --port 8089
```

### Ghidra Server authentication

When connecting to a shared Ghidra Server, GhidraMCP can suppress the password dialog automatically. It resolves credentials in this order (first non-empty value wins):

1. `GHIDRA_SERVER_PASSWORD` environment variable (or `.env` file in the Ghidra install directory or `~`)
2. `~/.ghidra-cred` — single-line password file in your home directory
3. `<ghidra-install-dir>/.ghidra-cred`

Username resolves similarly: `GHIDRA_SERVER_USER` env var → `user.name` system property.

If no password is found, Ghidra shows its normal GUI prompt. Set these in `.env` (see `.env.template` for the full block) to enable silent auth.

### Migration from v5.4.0 → v5.4.1

- **Script endpoints now default-off.** If you relied on `/run_script_inline` or `/run_ghidra_script`, export `GHIDRA_MCP_ALLOW_SCRIPTS=1`. This is a deliberate breaking change; the prior default was unsafe.
- **Localhost-only deployments need no changes.** Auth, bind refusal, and path-root checks are all opt-in.

## ❓ Troubleshooting

### "GhidraMCP" menu not appearing in Tools

**Cause:** Plugin not enabled or installed incorrectly.

**Solution:**
1. Verify extension is installed: **File > Install Extensions** — GhidraMCP should be listed
2. Enable the plugin: **File > Configure > Configure All Plugins > GhidraMCP** (check the box)
3. **Restart Ghidra** after installation/enabling

### Server not responding / Connection refused

**Cause:** Server not started or wrong port.

**Solution:**
1. Ensure you started the server: **Tools > GhidraMCP > Start MCP Server**
2. Check configured port: **Edit > Tool Options > GhidraMCP HTTP Server**
3. Check if port is in use:
   ```bash
   # Linux/macOS
   lsof -i :8089
   # Windows
   netstat -ano | findstr :8089
   ```
4. Look for errors in Ghidra console: **Window > Console**

### `python -m debugger` fails with `ModuleNotFoundError` for `pybag` or `comtypes`

**Cause:** The standalone debugger server uses optional Windows-only Python
dependencies that are not installed by the base requirements file.

**Solution:**
```text
python -m pip install -r requirements-debugger.txt
python -m debugger
```

If you have both a global Python and a project venv, make sure you install
into and run from the same interpreter.

### 500 Internal Server Errors

**Cause:** Server-side exception, often due to missing program data.

**Solution:**
1. Ensure a binary is loaded in CodeBrowser
2. Run auto-analysis first: **Analysis > Auto Analyze**
3. Check Ghidra console (**Window > Console**) for Java exceptions
4. Some operations require fully analyzed binaries

### 404 Not Found Errors

**Cause:** Endpoint doesn't exist or wrong URL.

**Solution:**
1. Verify endpoint exists: `curl http://127.0.0.1:8089/get_version`
2. Check for typos in endpoint name
3. Ensure you're using correct HTTP method (GET vs POST)

### Extension not appearing in Install Extensions

**Cause:** JAR file in wrong location.

**Solution:**
1. Manual install location: `~/.ghidra/ghidra_12.0.4_PUBLIC/Extensions/GhidraMCP/lib/GhidraMCP.jar`
2. Or use: **File > Install Extensions > Add** and select the ZIP file
3. Ensure JAR/ZIP was built for your Ghidra version

### Build fails with "Ghidra dependencies not found"

**Cause:** Ghidra JARs not installed in local Maven repository.

**Solution:**
```text
# Windows (recommended)
python -m tools.setup install-ghidra-deps --ghidra-path "C:\ghidra_12.0.4_PUBLIC"
```

## 📊 Production Performance

- **MCP Tools**: 225 tools fully implemented
- **Speed**: Sub-second response for most operations
- **Efficiency**: 93% reduction in API calls via batch operations
- **Reliability**: Atomic transactions with all-or-nothing semantics
- **AI Workflows**: Proven documentation prompts refined across hundreds of real functions
- **Deployment**: Automated version-aware deployment script

## 🛠️ API Reference

### Core Operations
- `check_connection` - Verify MCP connectivity
- `get_metadata` - Program metadata and info
- `get_version` - Server version information
- `get_function_count` - Return total function count for a program
- `get_entry_points` - Binary entry points discovery
- `get_current_address` - Get cursor address (GUI only)
- `get_current_function` - Get function at cursor (GUI only)
- `get_current_selection` - Get current selection context (address + function)
- `read_memory` - Read raw bytes from memory
- `save_program` - Save the current program
- `exit_ghidra` - Save and exit Ghidra gracefully

### Function Analysis
- `list_functions` - List all functions (paginated)
- `list_functions_enhanced` - List with isThunk/isExternal flags
- `list_classes` - List namespace/class names (paginated)
- `search_functions_enhanced` - Advanced function search with filters
- `decompile_function` - Decompile function to C pseudocode
- `force_decompile` - Force fresh decompilation (bypass cache)
- `batch_decompile` - Batch decompile multiple functions
- `get_function_callers` - Get function callers
- `get_function_callees` - Get function callees
- `get_function_call_graph` - Function relationship graph
- `get_full_call_graph` - Complete call graph for program
- `get_function_signature` - Get function prototype string
- `get_function_hash` - SHA-256 hash of normalized function opcodes
- `get_bulk_function_hashes` - Paginated bulk hashing with filter
- `get_function_jump_targets` - Get jump target addresses from disassembly
- `get_function_metrics` - Get complexity metrics for a function
- `get_function_xrefs` - Get function cross-references
- `analyze_function_full` - Comprehensive function analysis
- `analyze_function_completeness` - Documentation completeness score
- `batch_analyze_completeness` - Batch completeness analysis for multiple functions
- `find_similar_functions_across_programs` - Cross-program similarity matching
- `bulk_fuzzy_match_functions` - Bulk fuzzy match across all functions
- `diff_functions` - Diff two functions side by side
- `validate_function_prototype` - Validate a function prototype string
- `can_rename_at_address` - Check if address can be renamed
- `delete_function` - Delete function at address

### Memory & Data
- `list_segments` - Memory segments and layout
- `list_data_items` - List defined data labels and values (paginated)
- `list_data_items_by_xrefs` - Data items sorted by xref count
- `get_function_by_address` - Function at address
- `disassemble_function` - Disassembly listing
- `disassemble_bytes` - Raw byte disassembly
- `get_xrefs_to` - Cross-references to address
- `get_xrefs_from` - Cross-references from address
- `get_bulk_xrefs` - Bulk cross-reference lookup
- `analyze_data_region` - Analyze memory region structure
- `inspect_memory_content` - View raw memory content
- `detect_array_bounds` - Detect array boundaries
- `search_byte_patterns` - Search for byte patterns
- `create_memory_block` - Create a new memory block

### Cross-Binary Documentation
- `get_function_documentation` - Export complete function documentation
- `apply_function_documentation` - Import documentation to target function
- `compare_programs_documentation` - Compare documentation between programs
- `build_function_hash_index` - Build persistent JSON index
- `lookup_function_by_hash` - Find matching functions in index
- `propagate_documentation` - Apply docs to all matching instances

### Data Types & Structures
- `list_data_types` - Available data types
- `search_data_types` - Search for data types
- `get_data_type_size` - Get byte size of a data type
- `get_valid_data_types` - Get list of valid Ghidra builtin types
- `get_struct_layout` - Get detailed field layout of a structure
- `validate_data_type` - Validate data type syntax
- `validate_data_type_exists` - Check if a data type exists
- `create_struct` - Create custom structure
- `add_struct_field` - Add field to structure
- `modify_struct_field` - Modify existing field
- `remove_struct_field` - Remove field from structure
- `create_enum` - Create enumeration
- `get_enum_values` - Get enumeration values
- `create_array_type` - Create array data type
- `create_typedef` - Create typedef alias
- `create_union` - Create union data type
- `create_pointer_type` - Create pointer data type
- `clone_data_type` - Clone a data type with a new name
- `apply_data_type` - Apply type to address
- `delete_data_type` - Delete a data type
- `consolidate_duplicate_types` - Merge duplicate types
- `suggest_field_names` - AI-assisted field name suggestions for a structure
- `create_data_type_category` - Create a category folder in the type manager
- `move_data_type_to_category` - Move a type to a different category
- `list_data_type_categories` - List all data type categories
- `import_data_types` - Import types from a GDT/header file

### Symbols & Labels
- `list_imports` - Imported symbols and libraries
- `list_exports` - Exported symbols and functions
- `list_external_locations` - External location references
- `get_external_location` - Specific external location detail
- `list_strings` - Extracted strings with analysis
- `search_memory_strings` - Search strings by regex/substring pattern
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
- `clear_function_comments` - Clear all comments for a function
- `list_bookmarks` - List all bookmarks
- `set_bookmark` - Create or update a bookmark
- `delete_bookmark` - Delete a bookmark

### Type System
- `set_function_prototype` - Set function signature
- `set_local_variable_type` - Set variable type
- `set_parameter_type` - Set parameter type
- `batch_set_variable_types` - Bulk type setting
- `set_variable_storage` - Control variable storage location
- `set_function_no_return` - Mark function as non-returning
- `clear_instruction_flow_override` - Clear flow override on instruction
- `list_calling_conventions` - Available calling conventions
- `get_function_variables` - Get all function variables
- `get_function_labels` - Get labels in function

### Ghidra Script Management
- `list_scripts` - List available scripts
- `list_ghidra_scripts` - List custom Ghidra scripts
- `save_ghidra_script` - Save new script
- `get_ghidra_script` - Get script contents
- `run_ghidra_script` - Execute Ghidra script by name
- `run_script_inline` - Execute inline script code
- `update_ghidra_script` - Update existing script
- `delete_ghidra_script` - Delete script

### Multi-Program Support
- `list_open_programs` - List all open programs
- `get_current_program_info` - Current program details
- `switch_program` - Switch active program
- `list_project_files` - List project files
- `open_program` - Open program from project

### Project Lifecycle
- `create_project` - Create a new Ghidra project
- `open_project` - Open an existing project
- `close_project` - Close the current project
- `delete_project` - Delete a project
- `list_projects` - List Ghidra projects in a directory

### Project Organization
- `create_folder` - Create a folder in the project tree
- `move_file` - Move a domain file to another folder
- `move_folder` - Move a folder to another location
- `delete_file` - Delete a domain file from the project

### Analysis Tools
- `find_next_undefined_function` - Find undefined functions
- `find_undocumented_by_string` - Find functions by string reference
- `find_undocumented_functions_by_strings` - Find undocumented functions by string references
- `get_assembly_context` - Get assembly context
- `analyze_struct_field_usage` - Analyze structure field access
- `get_field_access_context` - Get field access patterns
- `create_function` - Create function at address
- `analyze_control_flow` - Cyclomatic complexity and loop detection
- `analyze_call_graph` - Build function call graph
- `analyze_api_call_chains` - Detect API call threat patterns
- `detect_malware_behaviors` - Detect malware behavior categories
- `find_anti_analysis_techniques` - Find anti-analysis techniques
- `find_dead_code` - Detect unreachable code
- `extract_iocs_with_context` - Extract IOCs from strings
- `apply_data_classification` - Apply data classification to addresses

### Analysis Control
- `list_analyzers` - List all available Ghidra analyzers
- `configure_analyzer` - Enable/disable or configure an analyzer
- `run_analysis` - Trigger Ghidra auto-analysis programmatically

### Server Connection (Ghidra Server)
- `connect_server` - Connect to a Ghidra Server
- `disconnect_server` - Disconnect from Ghidra Server
- `server_status` - Check server connection status
- `list_repositories` - List repositories on the server
- `create_repository` - Create a new repository
- `list_repository_files` - List files in a server repository folder
- `get_repository_file` - Get metadata for a file in a server repository

### Version Control
- `checkout_file` - Check out a file from version control
- `checkin_file` - Check in a file with a comment
- `undo_checkout` - Undo a checkout without committing
- `add_to_version_control` - Add a file to version control

### Version History
- `get_version_history` - Get full version history for a file
- `get_checkouts` - Get active checkout status

### Admin
- `terminate_checkout` - Forcibly terminate a user's checkout
- `list_server_users` - List all users on the Ghidra Server
- `set_user_permissions` - Set a user's repository access level

See [CHANGELOG.md](CHANGELOG.md) for version history.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI/Automation │◄──►│   MCP Bridge    │◄──►│  Ghidra Plugin  │
│     Tools       │    │ (bridge_mcp_    │    │ (GhidraMCP.jar) │
│  (Claude, etc.) │    │  ghidra.py)     │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
   MCP Protocol            HTTP REST              Ghidra API
   (stdio/SSE)          (localhost:8089)      (Program, Listing)
```

### Components

- **bridge_mcp_ghidra.py** — Python MCP server that translates MCP protocol to HTTP calls (225 catalog entries)
- **GhidraMCP.jar** — Ghidra plugin that exposes analysis capabilities via HTTP (175 GUI endpoints)
- **GhidraMCPHeadlessServer** — Standalone headless server — 183 endpoints, no GUI required
- **ghidra_scripts/** — Collection of automation scripts for common tasks

## 🔧 Development

### Building from Source
```bash
# Recommended: direct Python-first workflow
python -m tools.setup ensure-prereqs --ghidra-path "C:\ghidra_12.0.4_PUBLIC"
python -m tools.setup build
python -m tools.setup deploy --ghidra-path "C:\ghidra_12.0.4_PUBLIC"

# Version bump (updates all maintained version references atomically)
python -m tools.setup bump-version --new X.Y.Z
```

The authoritative build system today is Maven. `tools.setup`, the VS Code tasks, and the documented deploy flow all build through `pom.xml` and write artifacts to `target/`. `build.gradle` remains in the repo as a manual fallback for direct Ghidra/Gradle users, but it is not the primary path.

### Command Reference

| Command | What it does |
|---------|-------------|
| `ensure-prereqs` | Install Python deps + Ghidra Maven JARs in one shot. Start here on a new machine. |
| `preflight` | Validate Python, build tool, Ghidra path, and JAR availability without making changes. Add `--strict` to also check network reachability. |
| `build` | Build the plugin JAR and extension ZIP via Maven (or Gradle when `TOOLS_SETUP_BACKEND=gradle`). |
| `deploy` | Copy the built extension into the Ghidra profile and patch `FrontEndTool.xml` for auto-activation. |
| `start-ghidra` | Launch the configured Ghidra installation. |
| `clean` | Remove Maven/Gradle build outputs (`target/`, `build/`). |
| `clean-all` | Remove build outputs plus local cache artifacts (`.m2` Ghidra JARs, etc.). |
| `install-ghidra-deps` | Install only the Ghidra JARs into `~/.m2`. Useful when the build environment changes. |
| `install-python-deps` | Install only the Python requirements files. |
| `run-tests` | Run the Java offline test suite (no live Ghidra needed). |
| `verify-version` | Check that version strings are consistent across `pom.xml`, `CHANGELOG.md`, and `README.md`. |
| `bump-version --new X.Y.Z` | Atomically update all version references. Pass `--tag` to create a git tag. |

Common flags accepted by most commands:

| Flag | Description |
|------|-------------|
| `--ghidra-path PATH` | Ghidra installation directory. Defaults to `GHIDRA_PATH` from `.env`. |
| `--dry-run` | Print actions without executing them. |
| `--force` | Reinstall Ghidra JARs even if already present (`install-ghidra-deps`, `ensure-prereqs`). |
| `--with-debugger` | Force-install debugger Python requirements (Windows only). |
| `--use-debugger-toggle` | Read `INSTALL_DEBUGGER_DEPS` from `.env` to decide whether to install debugger deps. |
| `--test TIER` | (`deploy` only) Opt into live deploy regression tiers such as `release` or `debugger-live`. |
| `--strict` | (`preflight` only) Also check network reachability for Maven Central and PyPI. |

Deploy test tiers are opt-in because benchmark tiers can import/reset
`Benchmark.dll` and `BenchmarkDebug.exe` in the active Ghidra project. Use
`--test release` before cutting releases, or set
`GHIDRA_MCP_DEPLOY_TESTS=release` in a local `.env` when you want every deploy
on your machine to run the live benchmark regression. See
[Testing and Release Regression](docs/TESTING.md).

```text
# Standard first-time setup and deploy
python -m tools.setup ensure-prereqs --ghidra-path "C:\ghidra_12.0.4_PUBLIC"
python -m tools.setup build
python -m tools.setup deploy --ghidra-path "C:\ghidra_12.0.4_PUBLIC"

# Preflight check before deploying
python -m tools.setup preflight --strict --ghidra-path "C:\ghidra_12.0.4_PUBLIC"

# Version bump and tag
python -m tools.setup bump-version --new X.Y.Z --tag

# Run offline Java tests
python -m tools.setup run-tests

# Show full help
python -m tools.setup --help
```

### Project Structure
```
ghidra-mcp/
├── bridge_mcp_ghidra.py     # MCP server (Python, 225 catalog entries)
├── src/main/java/           # Ghidra plugin + headless server (Java)
│   └── com/xebyte/
│       ├── GhidraMCPPlugin.java         # GUI plugin (177 endpoints)
│       ├── headless/                    # Headless server (183 endpoints)
│       └── core/                        # Shared service layer (12 services)
├── debugger/                # Optional standalone debugger server (port 8099)
├── ghidra_scripts/          # Automation scripts for batch workflows
├── tests/                   # Python unit tests + endpoint catalog
│   ├── unit/               # Catalog consistency, schema, tool function tests
│   └── endpoints.json      # Endpoint specification (225 entries)
├── docs/                    # Documentation
│   ├── prompts/            # AI workflow prompts (V5 documentation workflows)
│   ├── releases/           # Version release notes
│   └── project-management/ # Contributor planning docs (Gradle migration, etc.)
├── tools/setup/             # Build and deployment CLI (python -m tools.setup)
├── fun-doc/                 # Internal RE curation tool — not part of the MCP plugin
│                            #   Priority-queue worker, LLM scoring, web dashboard.
│                            #   See fun-doc/README.md for details.
└── .github/workflows/      # CI/CD pipelines
```

### Library Dependencies

Ghidra JARs must be installed into your local Maven repository (`~/.m2/repository`) before compilation.
This is a one-time setup per machine, and again when your Ghidra version changes.
`-Deploy` now installs these automatically by default.

The tool enforces version consistency between:
- `pom.xml` (`ghidra.version`)
- `--ghidra-path` version segment (e.g., `ghidra_12.0.4_PUBLIC`)

If these do not match, deployment fails fast with a clear error.

### Troubleshooting: Version Mismatch

If you see a version mismatch error, align both values:
1. `pom.xml` → `ghidra.version`
2. `--ghidra-path` version segment (`ghidra_X.Y.Z_PUBLIC`)

Then rerun:

```text
python -m tools.setup preflight --ghidra-path "C:\ghidra_12.0.4_PUBLIC"
```

```text
# Windows
python -m tools.setup install-ghidra-deps --ghidra-path "C:\path\to\ghidra_12.0.4_PUBLIC"
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

> **Note**: Libraries are NOT included in the repository (see `.gitignore`). You must install them from your Ghidra installation before building.

> **Automation entry point**:
> - `python -m tools.setup` is the supported setup/build/deploy/versioning interface
> - use `ensure-prereqs`, `build`, `deploy`, `preflight`, `clean-all`, and `bump-version` directly
> - these commands currently use Maven as the canonical Java build backend

### Development Features
- **Automated Deployment**: Version-aware deployment script
- **Batch Operations**: Reduces API calls by 93%
- **Atomic Transactions**: All-or-nothing semantics
- **Comprehensive Logging**: Debug and trace capabilities

## 📚 Documentation

### Core Documentation
- [Documentation Index](docs/README.md) - Complete documentation navigation
- [Project Structure](docs/PROJECT_STRUCTURE.md) - Project organization guide
- [Testing and Release Regression](docs/TESTING.md) - Local tests, CI, live Ghidra regression, and release gates
- [Naming Conventions](docs/NAMING_CONVENTIONS.md) - Code naming standards
- [Hungarian Notation](docs/HUNGARIAN_NOTATION.md) - Variable naming guide

### AI Workflow Prompts
- [Function Documentation V5](docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md) — Primary workflow: 7-step process with Hungarian notation, type auditing, and verification scoring
- [Batch Documentation V5](docs/prompts/FUNCTION_DOC_WORKFLOW_V5_BATCH.md) — Parallel subagent dispatch for multi-function processing
- [Orphaned Code Discovery](docs/prompts/ORPHANED_CODE_DISCOVERY_WORKFLOW.md) — Automated scanner for undiscovered functions
- [Data Type Investigation](docs/prompts/DATA_TYPE_INVESTIGATION_WORKFLOW.md) — Systematic structure discovery
- [Cross-Version Matching](docs/prompts/CROSS_VERSION_MATCHING_COMPREHENSIVE.md) — Hash-based function matching
- [Quick Start Prompt](docs/prompts/QUICK_START_PROMPT.md) — Simplified beginner workflow
- [All Prompts](docs/prompts/README.md) — Complete prompt index

### Release History
- [Complete Changelog](CHANGELOG.md) - All version release notes
- [Release Notes](docs/releases/) - Detailed release documentation

## 🐳 Headless Server (Docker)

GhidraMCP includes a headless server mode for automated analysis without the Ghidra GUI.

### Quick Start with Docker

```bash
# Build and run
docker-compose up -d ghidra-mcp

# Test connection
curl http://localhost:8089/check_connection
# Connection OK - GhidraMCP Headless Server v5.6.0
```

### Headless API Workflow

```bash
# 1. Load a binary
curl -X POST -d "file=/data/program.exe" http://localhost:8089/load_program

# 2. Run auto-analysis (identifies functions, strings, data types)
curl -X POST http://localhost:8089/run_analysis

# 3. List discovered functions
curl "http://localhost:8089/list_functions?limit=20"

# 4. Decompile a function
curl "http://localhost:8089/decompile_function?address=0x401000"

# 5. Get metadata
curl http://localhost:8089/get_metadata
```

### Key Headless Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/load_program` | POST | Load binary file for analysis |
| `/run_analysis` | POST | Run Ghidra auto-analysis |
| `/list_functions` | GET | List all discovered functions |
| `/list_exports` | GET | List exported symbols |
| `/list_imports` | GET | List imported symbols |
| `/decompile_function` | GET | Decompile function to C code |
| `/create_function` | POST | Create function at address |
| `/get_metadata` | GET | Get program metadata |
| `/create_project` | POST | Create a Ghidra project |
| `/list_analyzers` | GET | List available analyzers |
| `/server/status` | GET | Check Ghidra Server connection |

### Configuration

Environment variables for Docker:
- `GHIDRA_MCP_PORT` - Server port (default: 8089)
- `GHIDRA_MCP_BIND_ADDRESS` - Bind address (default: 0.0.0.0 in Docker)
- `JAVA_OPTS` - JVM options (default: -Xmx4g -XX:+UseG1GC)

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

### Quick Start
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Build and test your changes (`mvn clean package assembly:single -DskipTests` or `GHIDRA_INSTALL_DIR=/path/to/ghidra gradle buildExtension`)
4. Update documentation as needed
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🏆 Production Status

| Metric | Value |
|--------|-------|
| **Version** | 5.6.0 |
| **MCP Tools** | 225 fully implemented |
| **GUI Endpoints** | 177 (GhidraMCPPlugin) |
| **Headless Endpoints** | 195 (GhidraMCPHeadlessServer) |
| **Compilation** | ✅ 100% success |
| **Batch Efficiency** | 93% API call reduction |
| **AI Workflows** | 7 proven documentation workflows |
| **Ghidra Scripts** | Automation scripts included |
| **Documentation** | Comprehensive with AI prompts |

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.


## 🙏 Acknowledgments
## 👥 Contributors

This project has benefited from the work of dedicated contributors:

### Core Contributors

**[@heeen](https://github.com/heeen)** — Significant contributions including:
- Fuzzy function matching and structured diff for cross-binary comparison (#13)
- Script execution improvements and bug fixes (#12)
- New API endpoints: `save_program`, `exit_ghidra`, `delete_function`, `create_memory_block`, `run_script_inline` (#11)
- Architectural vision: annotation-driven design, UDS transport, Python bridge optimization proposals


- **Ghidra Team** - For the incredible reverse engineering platform
- **Model Context Protocol** - For the standardized AI integration framework
- **Contributors** - For testing, feedback, and improvements

---

## 🔗 Related Projects

- [re-universe](https://github.com/bethington/re-universe) — Ghidra BSim PostgreSQL platform for large-scale binary similarity analysis. Pairs perfectly with GhidraMCP for AI-driven reverse engineering workflows.
- [cheat-engine-server-python](https://github.com/bethington/cheat-engine-server-python) — MCP server for dynamic memory analysis and debugging.

---

**Ready for production deployment with enterprise-grade reliability and comprehensive binary analysis capabilities.**

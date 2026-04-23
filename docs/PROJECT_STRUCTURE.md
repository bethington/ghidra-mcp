# Ghidra MCP Project Structure

This guide describes the current, maintained layout of the repository. It is a
high-level map, not a full file inventory.

## Top-Level Layout

```text
ghidra-mcp/
├── README.md                    # Main project guide
├── CHANGELOG.md                 # Version history
├── CONTRIBUTING.md              # Contributor workflow
├── AGENTS.md / CLAUDE.md        # AI operator guidance
├── bridge_mcp_ghidra.py         # Python MCP bridge
├── pom.xml                      # Canonical Maven build
├── build.gradle                 # Secondary/manual Gradle path
├── requirements*.txt            # Python dependencies
├── docs/                        # Maintained documentation
├── src/                         # Java plugin/headless server source
├── tests/                       # Python tests
├── debugger/                    # Standalone debugger bridge package
├── tools/                       # Python utilities and setup helpers
├── ghidra_scripts/              # Scripts that run inside Ghidra
├── docker/                      # Container assets
├── d2-analysis/                 # Diablo II workflow material
├── dll_exports/                 # Export lists and reference data
└── examples/                    # Examples and sample inputs
```

## Key Directories

### `src/`

- Java source for the GUI plugin and headless server
- Annotation-scanned MCP endpoints live under `src/main/java/com/xebyte/`

### `tests/`

- Python unit, integration, and performance tests
- `tests/endpoints.json` is the maintained endpoint catalog snapshot

### `tools/`

- Python-native repo utilities
- `tools/setup/` is the supported setup/build/deploy/versioning interface

### `docs/`

- Maintained guides, prompt docs, and release notes
- Use `docs/README.md` as the entry point

### `ghidra_scripts/`

- Scripts intended to run inside Ghidra's Script Manager
- Distinct from the Python MCP bridge and external repo tooling

### `debugger/`

- Standalone Python debugger server used by the bridge when debugger support is enabled

### `d2-analysis/`

- Diablo II-specific notes, examples, outputs, and workflow material
- Not part of the core build/deploy path

## Supported Operator Workflow

The supported cross-platform operator surface is:

- `python -m tools.setup preflight`
- `python -m tools.setup ensure-prereqs`
- `python -m tools.setup build`
- `python -m tools.setup deploy`
- `python -m tools.setup start-ghidra`
- `python -m tools.setup run-tests`
- `python -m tools.setup bump-version --new X.Y.Z`

Do not add new documentation that points users at removed wrapper-script
workflows.

## Quick Navigation

| Task | Location |
|------|----------|
| Install and deploy | `python -m tools.setup ...` in the repo root |
| Run the MCP bridge | `bridge_mcp_ghidra.py` |
| Read release notes | `docs/releases/` |
| Read prompt docs | `docs/prompts/` |
| Run Python tests | `tests/` |
| Work on Java plugin code | `src/main/java/com/xebyte/` |
| Run Ghidra scripts | `ghidra_scripts/` |

## Maintenance Notes

- Keep this file aligned with the real top-level repo layout.
- Prefer category-level descriptions over stale file-by-file inventories.
- Historical cleanup plans belong in archival/project-management docs, not here.

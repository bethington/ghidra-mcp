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
├── ROADMAP.md / SECURITY.md     # Roadmap and security policy
├── LICENSE / NOTICE             # License and third-party notices
├── python/bridge_mcp_ghidra/    # Python MCP bridge package (ghidra-mcp-bridge wheel)
├── pyproject.toml               # uv project: wheel build + PEP 735 dependency groups
├── uv.lock                      # Pinned dependency lockfile (uv)
├── build.gradle                 # Gradle build: the default for local work
├── settings.gradle, gradlew*,   # Gradle wrapper
│   gradle/wrapper/
├── pom.xml                      # Maven build: what CI gates with (coverage, headless/docker profiles)
├── ghidra-mcp-setup.ps1         # Windows setup/deploy script
├── .github/                     # CI workflows, issue templates, dependabot
├── docs/                        # Maintained documentation
├── src/                         # Java plugin/headless server source and Java tests
├── tests/                       # Python tests, endpoint catalog, conformance snapshots
├── tools/                       # Python utilities and setup helpers
├── ghidra_scripts/              # Scripts that run inside Ghidra
└── docker/                      # Container assets
```

## Key Directories

### `src/`

- `src/main/java/com/xebyte/GhidraMCPPlugin.java`: the GUI plugin entry point
  (the Tools > GhidraMCP menu)
- `src/main/java/com/xebyte/core/`: everything both servers share
  - `*Service.java`: the 20 service classes whose `@McpTool` methods are the
    endpoints. `AnnotationScanner` discovers them and builds `/mcp/schema`;
    `ManualToolDescriptors` describes the few hand-registered routes.
  - `CoreServices`: the services both servers expose, built once from a
    `ProgramProvider` and a `ThreadingStrategy`. `DebuggerService`,
    `PromptPolicyService` and `GuiToolService` are added by the GUI plugin only.
  - `McpHttpServer`: the transport both servers serve through (UDS, plus TCP when
    asked), with the shared identity routes `/mcp/schema`, `/mcp/instance_info`,
    `/mcp/health` and `/check_connection`. `UdsHttpServer` is the socket side.
  - `ProjectProgramProvider`: opens any program in the project the first time an
    endpoint names it; `FrontEndProgramProvider` adds the GUI's open CodeBrowsers.
  - `FunctionFacts`: the single source for what `/get_functions` reports about a
    function.
  - `NamingConventions`: the naming, prefix and plate-comment rules every write
    tool validates against.
- `src/main/java/com/xebyte/headless/`: the standalone headless server,
  `HeadlessProgramProvider`, and `HeadlessManagementService` (headless-only project
  lifecycle tools)
- `src/test/java/com/xebyte/offline/` and `src/test/java/com/xebyte/core/`: the
  Java tests CI selects (see `docs/TESTING.md`)
- `src/assembly/`, `src/main/resources/`: extension packaging

### `tests/`

- `tests/unit/`: pure-Python tests, no Ghidra
- `tests/offline/`: a strict fake of the plugin's HTTP surface that runs the real
  bridge end to end with no Ghidra installed (read `tests/offline/README.md` first)
- `tests/integration/`: tests against a live Ghidra on port 8089
- `tests/conformance/`: the MCP conformance suite, which drives `tools/list` and
  `tools/call` through the bridge, and its golden snapshots (the offline tier
  checks calls against the recorded `/mcp/schema` in `snapshots/`)
- `tests/fixtures/`: the generated benchmark binaries the deploy regression uses
- `tests/pester/`: PowerShell tests for `ghidra-mcp-setup.ps1`
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

### `debugger/` — removed 2026-08-11

- The standalone Python debugger server is no longer part of this repo
- The bridge keeps 22 proxy tools that forward to an external debugger server
  at `GHIDRA_DEBUGGER_URL`. They are off by default and register only when
  `GHIDRA_DEBUGGER_URL` is set or `GHIDRA_DEBUGGER_TOOLS=1`

### Per-project analysis data — never tracked

- Notes, export maps, examples and outputs for a specific target binary belong
  in that target's own repository. Directories such as `dll_exports/`,
  `examples/` and `output/` are gitignored so local copies are never committed;
  nothing in the build/deploy path depends on them.

## Supported Operator Workflow

The supported cross-platform operator surface is:

- `python -m tools.setup preflight`
- `python -m tools.setup ensure-prereqs`
- `python -m tools.setup build`
- `python -m tools.setup deploy`
- `python -m tools.setup start-ghidra`
- `python -m tools.setup run-tests`
- `python -m tools.setup bump-version --new X.Y.Z`

`tools.setup` uses Maven unless `TOOLS_SETUP_BACKEND=gradle` is set. For local
builds Gradle is the default and needs no Maven install
(`./gradlew buildExtension -PGHIDRA_INSTALL_DIR=<ghidra>`); CI still builds and
gates with Maven. The root `CLAUDE.md` "Build & Deploy" section lists which
commands exist only under Maven.

Do not add new documentation that points users at removed wrapper-script
workflows.

## Quick Navigation

| Task | Location |
| ------ | ---------- |
| Install and deploy | `python -m tools.setup ...` in the repo root |
| Run the MCP bridge | `uv run bridge-mcp-ghidra` (or `python -m bridge_mcp_ghidra`) |
| Read release notes | `docs/releases/` |
| Read prompt docs | `docs/prompts/` |
| Run Python tests | `tests/` |
| Work on Java plugin code | `src/main/java/com/xebyte/` |
| Run Ghidra scripts | `ghidra_scripts/` |

## Maintenance Notes

- Keep this file aligned with the real top-level repo layout.
- Prefer category-level descriptions over stale file-by-file inventories.
- Historical cleanup plans belong in archival/project-management docs, not here.

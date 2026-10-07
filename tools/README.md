# Tools Directory

Utility scripts and tooling for the Ghidra MCP Server project.

## What's here

```text
tools/
├── setup/                         # Project setup, build, deploy, version-bump CLI
│                                  #   python -m tools.setup --help
├── audit_endpoint_categories.py   # tests/endpoints.json categories vs @McpTool annotations
├── audit_server_scope.py          # derive which server (GUI / headless) serves each endpoint
├── gen_readme_api_reference.py    # render README's API Reference from tests/endpoints.json
├── param_description_inventory.py # @Param annotations with no description
├── release_evidence.py            # recorded live-regression evidence for the release gate
├── ghidra_server_health_check.py  # bounded health probe with an opt-in layered doctor mode
├── upgrade_project_language.py    # upgrade a shared project's programs to a new SLEIGH version
├── build_reference_index.py       # build a BSim reference index from labelled binaries
├── context_analysis/              # measure MCP tool-schema context cost
└── launch-ghidra-scoped.ps1       # launch Ghidra with GHIDRA_MCP_PROJECT_FOLDER set
```

## Legacy function-documentation scripts

Three older scripts (`scan_undocumented_functions.py`,
`scan_functions_mcp.py`, `document_function.py`) were archived to
`docs/archive/legacy-tools/` in v5.10 and **removed in 7.0.0**: they called
endpoints the 7.0.0 tool consolidation removed, so they no longer ran. They
survive in git history (`git log --all -- docs/archive/legacy-tools`).
Automated function documentation is not part of this repository: drive the MCP
tools directly from your AI client (see
[`docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md`](../docs/prompts/FUNCTION_DOC_WORKFLOW_V5.md))
or from your own orchestration on top of the HTTP API.

## Setup CLI

The `setup/` package is the actively maintained tooling. Use it for
every build/deploy/release flow:

```bash
# show all subcommands
python -m tools.setup --help

# common ones
python -m tools.setup build
python -m tools.setup preflight      --ghidra-path F:\ghidra_12.1.4_PUBLIC
python -m tools.setup deploy         --ghidra-path F:\ghidra_12.1.4_PUBLIC
python -m tools.setup bump-version   --new 5.10.0
python -m tools.setup verify-version
```

See [`CLAUDE.md`](../CLAUDE.md) → **Build & Deploy** for the full
workflow including the Gradle alternative.

## Adding a tool

If you have a one-off script that genuinely doesn't fit inside
`tools/setup/` or `ghidra_scripts/`, drop a standalone file here with a
clear docstring and add a line to the tree above. Most of the time,
though, the right home for new utility code is one of those two
existing locations.

---

The scripts that talk to a running server (the health check, the language
upgrade's `--verify`) use its HTTP endpoint (default: `http://127.0.0.1:8089`).
The audit and render scripts read the repository only.

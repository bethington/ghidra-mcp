# Tools Directory

Utility scripts and tooling for the Ghidra MCP Server project.

## What's here

```
tools/
├── setup/         # Project setup, build, deploy, version-bump CLI
│                  #   python -m tools.setup --help
└── (CLI utilities live in fun-doc/ now — see below)
```

## Looking for the function-documentation CLI?

Three older scripts (`scan_undocumented_functions.py`,
`scan_functions_mcp.py`, `document_function.py`) used to live here.
They were archived to
[`docs/archive/legacy-tools/`](../docs/archive/legacy-tools/) in v5.10
because **`fun-doc/` does the same job, much better**:

| What you used to run | Now run |
| --- | --- |
| `tools/scan_undocumented_functions.py` | The fun-doc dashboard's "Worker" tab, or `python fun-doc/fun_doc.py --scan` for a one-shot inventory. |
| `tools/scan_functions_mcp.py` | Same — `fun-doc/` ranks candidates continuously with proper state. |
| `tools/document_function.py --function FUN_401000` | `python fun-doc/fun_doc.py --manual --address 0x401000` (single function), or just let the worker pick up the next candidate. |

`fun-doc/` adds state persistence (`state.db`), run-history tracking
(`runs.jsonl`), parallel workers with watchdog/heartbeat, the
completeness scoring rubric, provider routing/fallback, the web
dashboard, block-reason capture, and the library-code detector — all
the things the legacy scripts couldn't do.

## Setup CLI

The `setup/` package is the actively maintained tooling. Use it for
every build/deploy/release flow:

```bash
# show all subcommands
python -m tools.setup --help

# common ones
python -m tools.setup build
python -m tools.setup preflight      --ghidra-path F:\ghidra_12.1_PUBLIC
python -m tools.setup deploy         --ghidra-path F:\ghidra_12.1_PUBLIC
python -m tools.setup bump-version   --new 5.10.0
python -m tools.setup verify-version
```

See [`CLAUDE.md`](../CLAUDE.md) → **Build & Deploy** for the full
workflow including the Gradle alternative.

## Adding a tool

If you have a one-off script that genuinely doesn't fit inside
`fun-doc/`, `tools/setup/`, or `ghidra_scripts/`, drop a standalone
file here with a clear docstring and add a row to the table above.
Most of the time, though, the right home for new utility code is one
of those three existing locations.

---

All tools connect to Ghidra MCP Server via HTTP (default:
`http://127.0.0.1:8089`).

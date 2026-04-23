# fun-doc

Internal AI-driven function documentation system for large-scale reverse engineering projects. **Not part of the GhidraMCP plugin** — it is a personal productivity tool that runs alongside Ghidra and uses the MCP tools to document functions.

## What it does

- Maintains a priority queue of undocumented functions ranked by cross-reference count and completeness score
- Dispatches LLM workers (Claude, Codex, Minimax) to document each function using the Ghidra MCP tools
- Scores each function on a 0–100% completeness scale (naming, typing, plate comments, struct fields)
- Exposes a web dashboard for monitoring worker progress and queue state
- Writes atomic state to `state.json` with backup rotation

## How to run

```bash
# Start the dashboard + idle worker loop (primary entry point)
python fun_doc.py

# Dashboard only (no workers)
python fun_doc.py --no-worker

# Start with a specific provider
python fun_doc.py --provider claude

# Web dashboard only (requires fun_doc.py already running for the event bus)
python web.py
```

The dashboard is available at `http://127.0.0.1:5001/` by default.

## Prerequisites

- A running GhidraMCP server (`bridge_mcp_ghidra.py` or the Ghidra plugin on port 8089)
- Claude Code CLI, Codex CLI, or a Minimax API key depending on which provider you use
- Python packages from `requirements.txt`

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_MCP_URL` | `http://127.0.0.1:8089/` | Ghidra plugin HTTP server |
| `GHIDRA_INSTALL_DIR` | (auto-detected) | Ghidra installation path, used for auto-launch |
| `MINIMAX_API_KEY` | — | API key for `--provider minimax` |
| `FUNDOC_DASHBOARD` | `true` | Set to `false` to suppress the web dashboard on startup |

## State files

| File | Description |
|------|-------------|
| `state.json` | Per-function score cache and documentation state (auto-managed, can be large) |
| `state.json.bak` | One-generation backup, written before every save |
| `priority_queue.json` | Worker configuration and queue metadata |
| `logs/runs.jsonl` | JSONL audit trail of every worker run |

State files are gitignored. Delete `state.json` to start fresh (scores will be re-fetched from Ghidra on next run).

## Relationship to GhidraMCP

fun-doc is a consumer of the MCP tools, not a provider. It calls `analyze_function_completeness`, `decompile_function`, `rename_function_by_address`, `batch_set_comments`, etc. through Claude Code's MCP integration. No fun-doc code ships as part of the plugin JAR or the Python bridge.

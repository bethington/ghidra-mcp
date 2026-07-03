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

- A running GhidraMCP server (`uv run bridge-mcp-ghidra`, or the Ghidra plugin on port 8089)
- Claude Code CLI, Codex CLI, or a Minimax API key depending on which provider you use
- Python packages from the `fun-doc` dependency group: `uv sync --group fun-doc` (or `pip install -r fun-doc/requirements.txt`)

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_MCP_URL` | `http://127.0.0.1:8089/` | Ghidra plugin HTTP server |
| `GHIDRA_INSTALL_DIR` | (auto-detected) | Ghidra installation path, used for auto-launch |
| `MINIMAX_API_KEY` | — | API key for `--provider minimax` |
| `FUNDOC_DASHBOARD` | `true` | Set to `false` to suppress the web dashboard on startup |
| `FUN_DOC_DB_URL` | — | Storage backend URL. `postgresql://user:pw@host/db` for Postgres or `sqlite:///path/to/state.db` for SQLite. Wins over `priority_queue.json`'s `config.storage` block. |

## Storage backend

fun-doc persists per-function workflow state, run history, and binary inventories to a SQL store. Two backends are supported:

| Backend | Default? | Configuration |
|---------|----------|---------------|
| **SQLite** | yes | File at `fun-doc/state.db`. Stdlib only — no install. |
| **Postgres** | no | Set `FUN_DOC_DB_URL` or `priority_queue.json -> config.storage.url`. Requires `psycopg[binary]` (Python ≥ 3.10). |

Configuration in `priority_queue.json`:

```json
{
  "config": {
    "storage": {
      "backend": "postgres",
      "url": "postgresql://re_kb:***@10.0.10.30:5432/bsim",
      "schema": "fun_doc"
    }
  }
}
```

Omit the `storage` block to default to bundled SQLite. Slow queries (>100 ms) are logged via the `fun_doc.storage.slow_query` logger.

### Migrating from `state.json` (one-time)

If you have an existing `state.json` from a pre-migration install, run:

```bash
# Apply schema (idempotent)
python -m db.migrate --backend sqlite      # or --backend postgres

# Load state.json + runs.jsonl + inventory files into the SQL store
python -m scripts.migrate_state_to_sql --backend sqlite

# Verify zero diff before deleting / archiving state.json
python -m scripts.verify_migration --backend sqlite
```

The verifier exits 0 only when the SQL store is byte-identical to the source files (counts, scores, last_run timestamps, audit/escalation chains, run-history length). After it passes, rename `state.json` to `state.json.migrated-YYYY-MM-DD` and remove it from the runtime path. fun-doc no longer reads or writes the file.

## State files

| File | Description |
|------|-------------|
| `state.db` | SQLite database when `backend=sqlite`. Default location. |
| `state.json` | Legacy per-function cache. Read only as a fallback when the storage layer can't be loaded. |
| `state.json.bak` | One-generation backup of the legacy file. |
| `priority_queue.json` | Worker configuration and queue metadata |
| `logs/runs.jsonl` | JSONL audit trail of every worker run. Migrated into the `runs` table by `migrate_state_to_sql.py` and kept as an append-only operational log. |

State files are gitignored. Delete `state.db` (or both `state.db` and `state.json`) to start fresh; scores will be re-fetched from Ghidra on next run.

## Relationship to GhidraMCP

fun-doc is a consumer of the MCP tools, not a provider. It calls `analyze_function_completeness`, `decompile_function`, `rename_function_by_address`, `batch_set_comments`, etc. through Claude Code's MCP integration. No fun-doc code ships as part of the plugin JAR or the Python bridge.

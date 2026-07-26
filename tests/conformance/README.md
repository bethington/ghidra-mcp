# MCP Conformance Suite

Exercises the Ghidra MCP tool surface **through the MCP protocol**, not through
the plugin's raw HTTP routes.

That distinction is the whole point. A test that calls
`http://127.0.0.1:8089/decompile_function` verifies the Java HTTP layer and
proves nothing about an MCP implementation. This suite drives
`tools/list` + `tools/call` over a pluggable transport, so the same corpus runs
against:

- the **Python bridge** over stdio (today), and
- the **Java-native `/mcp` endpoint** over Streamable HTTP (planned).

Run it against both and diff: snapshot drift between the two *is* the list of
behavioral differences the port introduced. That is the acceptance gate for
retiring the bridge.

## Layout

| Path | Role |
| --- | --- |
| `mcp_client.py` | Transports (`StdioTransport`, `StreamableHttpTransport`) + `ToolResult` |
| `runner.py` | Assertion engine, snapshot normalization/diffing |
| `cases.py` | Case model, bootstrap generation, parameter synthesis |
| `run_conformance.py` | CLI |
| `corpus/*.yaml` | The cases |
| `snapshots/*.snap` | Golden normalized responses |

## Usage

```bash
# bootstrap a skeleton case for every tool in the live schema
python -m tests.conformance.run_conformance --generate

# read-only tier — safe to run while fun-doc workers are active
python -m tests.conformance.run_conformance --tier read --record

# full run: semantic assertions + snapshot diffing
python -m tests.conformance.run_conformance

# accept current behavior as the new baseline (review the diff first!)
python -m tests.conformance.run_conformance --update-snapshots
```

## Two assertion layers

1. **Semantic** (`assert:` per case) — encodes intent: this key exists, this
   write took effect, this bad input is refused. Catches "it returns something,
   but the wrong thing".
2. **Golden snapshots** — the normalized response, recorded. Catches
   field-level drift nobody thought to assert, which is exactly what a
   reimplementation breaks.

Neither is sufficient alone. A snapshot passes as long as output is unchanged,
so it cannot tell you a write tool silently stopped writing; a hand assertion
only covers what its author imagined.

## Normalization, and why it matters more than it looks

Responses embed values that legitimately vary run to run — elapsed times,
timestamps, pids, absolute paths. Those are masked before comparison.

**Network locations and session state are masked or excluded outright.** The
first recording pass captured a private Ghidra Server address into
`project_info.snap`, and the repo's own `test_no_default_data_egress` guard
failed the build over it. This is a public repo; snapshots must not carry
operator infrastructure. Tools whose output describes the *operator's session*
rather than the program under test (`project_info`, `list_open_programs`,
`list_project_files`, ...) are listed in `cases.ENVIRONMENT_COUPLED` and get
shape assertions instead of snapshots.

If you add a tool whose output includes hostnames, ports, usernames, or the set
of currently-open programs, add it to that set.

## Tiers

- `read` — no writes. Safe to run against a live session with workers active.
- `write` — mutates the benchmark binaries. Stop fun-doc workers first: several
  tools mutate whole-session state (`switch_program` retargets the active
  program, so a worker call that omits `program` would land on the wrong binary).
- `destructive` — opt-in via `--destructive`. Ends the session or executes
  arbitrary code (`exit_ghidra`, `run_ghidra_script`, `delete_file`). Runs last.

## Targets

The benchmark pair only — `Benchmark.dll` and `BenchmarkDebug.exe`, both built
from `fun-doc/benchmark/` specifically to be disposable. Never point the write
or destructive tiers at a real RE target.

State determinism comes from `tools.setup.ghidra.reset_benchmark_fixture`,
which deletes the project copies and re-imports both binaries from disk. Golden
snapshots are only meaningful from a known starting state.

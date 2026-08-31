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

### A refusal is not a golden

`assert: is_error` is the MCP **protocol** flag. A tool that returns
`{"error": "..."}` in its *body* did not raise a protocol error, so
`is_error: false` passes on it — and so does `nonempty: true`, because an error
string is not empty. Recording that body then makes the case assert that the
endpoint stays broken, and it passes forever.

This is measured, not hypothetical: **20 of 124 goldens in the first recording
pass were bare `{"error": ...}` bodies**, every one of them a case whose own
arguments the server refused. So:

- `--record` / `--update-snapshots` **refuse** to write a bare error payload and
  report it as a case failure. If the refusal is genuinely the point of the case
  (a bad-input negative test), set `expect_error_payload: true` on it.
- `tests/unit/test_conformance_snapshots.py` runs offline and enumerates the
  remaining known-bad goldens with a diagnosis each. That list can only shrink.

When a case's arguments are wrong, fix the **generator**, not just the YAML:
`--generate` overwrites `corpus/generated_baseline.yaml` wholesale, so a
hand-edit there is reverted by the next regeneration. `TOOL_ARG_OVERRIDES` in
`cases.py` is the durable half. It exists because the synthesizer maps a
parameter *name* to a value globally and that has two blind spots a schema
cannot close: cross-parameter constraints (`/search_instructions` declares
`mnemonic` and `operand_pattern` both optional but rejects the call when both
are empty), and one name meaning different things in different tools (`pattern`
is a type name for `/search_data_types`, a hex byte string for
`/search_byte_patterns`).

### `mcp_schema.snap` records a JAR, not a branch

That snapshot stores the whole tool surface — every category, description and
per-parameter description string. It is therefore only as current as the
**deployed** plugin, which is usually behind `dev`, and refreshing it from a
stale deploy re-blesses whatever that build got wrong.

Refresh it only from a server running a JAR built from the tree you intend the
snapshot to describe. In practice: merge the annotation-touching PRs, deploy,
then re-record. Re-recording before that produces a confidently wrong golden —
`get_version.endpoint_count` and the live `count` are the cheap check that the
deployed build is the one you think it is.

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

# Testing and Release Regression

This project has two different testing surfaces:

- Offline tests that run on normal GitHub-hosted runners and do not need a live
  Ghidra project.
- Live Ghidra regression tests that deploy the extension, start Ghidra, and
  exercise MCP endpoints against a benchmark binary inside an active project.

The live tests are intentionally opt-in because they can add or reset
`Benchmark.dll` and `BenchmarkDebug.exe` in the current Ghidra project.

## Quick Commands

Run the normal local checks:

```text
python -m tools.setup build
pytest tests/unit/ -v --no-cov
```

Deploy without importing the benchmark binary:

```text
python -m tools.setup deploy --ghidra-path "F:\ghidra_12.0.4_PUBLIC"
```

Deploy and run the release-grade live regression:

```text
python -m tools.setup deploy --ghidra-path "F:\ghidra_12.0.4_PUBLIC" --test release
```

Opt in locally so every deploy runs the release regression:

```text
GHIDRA_MCP_DEPLOY_TESTS=release
```

`GHIDRA_MCP_DEPLOY_TESTS` belongs in a local `.env`; it is not intended as the
repository default.

## What Runs by Default

A plain deploy:

1. Detects matching running Ghidra processes for the target install.
2. Requests `save_all_programs`.
3. Requests graceful `exit_ghidra`, which saves open programs and debugger
   traces before closing.
4. Force-kills remaining matching Ghidra processes if graceful exit did not
   finish.
5. Installs the extension and bridge files.
6. Starts Ghidra.
7. Waits for MCP health.
8. Waits for a project-backed endpoint to confirm the active project is ready.
9. Runs MCP schema smoke checks.

A plain deploy does **not** import `Benchmark.dll` or `BenchmarkDebug.exe`
unless the user opts in with `--test ...` or `GHIDRA_MCP_DEPLOY_TESTS`.

## Live Test Tiers

Pass one or more `--test` values to `python -m tools.setup deploy`.

| Tier | Project Mutation | Purpose |
|------|------------------|---------|
| `selected-contract` | No benchmark import | Checks selected release-critical tools against live schema and `tests/endpoints.json`. |
| `endpoint-catalog` | No benchmark import | Confirms all catalog endpoints are present in the live schema. |
| `benchmark-read` | Imports/resets benchmark | Runs broader read-only endpoint checks against `/testing/benchmark/Benchmark.dll`. |
| `benchmark-write` | Imports/resets benchmark, writes test metadata | Runs reversible write smoke checks against the benchmark. |
| `multi-program` | Imports/resets benchmark | Confirms project-path targeting works when multiple programs are open. |
| `negative-contract` | Imports/resets benchmark | Asserts important error cases return actionable messages. |
| `debugger-live` | Imports/resets benchmark, launches test process | Launches `BenchmarkDebug.exe` through MCP debugger endpoints and reads live trace state. |
| `release` | Imports/resets benchmark, writes test metadata, launches test process | Runs the release-grade suite. |

The `release` tier currently runs:

1. Benchmark reset/import.
2. Selected endpoint contract checks.
3. Extended benchmark read checks.
4. Multi-program targeting checks.
5. Negative/error-shape checks.
6. Debugger live launch/status/module/register/stack checks.

Default deploy also runs the schema smoke check before any selected tier.

When a benchmark tier runs, deploy temporarily enables the `/prompt_policy`
endpoint. This narrowly-scoped prompt policy only responds to known automation
dialogs for the benchmark flow, such as benchmark analysis prompts, modified
file saves, and tool-layout save prompts. Unknown dialogs are left alone.

## Benchmark Fixture

The benchmark binary is built from `fun-doc/benchmark` and imported into the
active Ghidra project at:

```text
/testing/benchmark/Benchmark.dll
/testing/benchmark/BenchmarkDebug.exe
```

The filesystem build artifacts stay at:

```text
fun-doc/benchmark/build/Benchmark.dll
fun-doc/benchmark/build/BenchmarkDebug.exe
```

Before benchmark tiers run, the deploy harness deletes any existing benchmark
project file at the legacy and current benchmark paths, recreates the
`/testing/benchmark` folder, imports the current binaries, and waits for
analysis to become idle. It also removes restored benchmark CodeBrowser or
Debugger tool state from the active project before startup so old benchmark
windows do not trigger first-open dialogs before MCP is ready.

This reset is why benchmark tiers are opt-in: users should not get a test binary
added to their project merely because they deployed the extension.

The debugger live tier is Windows-only today and uses Ghidra's Trace RMI
debugger launcher. If the default Python on `PATH` is not compatible with the
Ghidra debugger wheels, set `GHIDRA_DEBUGGER_PYTHON` in local `.env` to the
Python executable Ghidra should use for debugger launches.

## GitHub Actions

### Pull Requests and Merges

`.github/workflows/tests.yml` runs on pull requests and pushes to `main` and
`develop`. It runs the merge-gating checks that work on GitHub-hosted runners:

- Maven build and offline Java tests.
- Python unit tests across supported Python versions.
- Pester setup tests on Windows.
- Documentation linting.

These checks should be configured as required status checks in branch protection.

The live Ghidra release regression can also run on pull requests, but it is
opt-in. Add the PR label:

```text
live-ghidra-regression
```

When that label is present, `.github/workflows/release-regression.yml` runs on a
self-hosted Windows runner and executes the live deploy regression.

This avoids making every external PR wait forever for a private self-hosted
runner while still giving maintainers a real gate for risky MCP/Ghidra changes.

### Releases

`.github/workflows/release-regression.yml` is also available manually from the
Actions tab. It is called by the release and pre-release workflows when
`run_live_regression` is enabled.

For manual release workflows:

1. Open **Create Release** or **Create Pre-Release** in GitHub Actions.
2. Enable `run_live_regression`.
3. Set `ghidra_path` for the self-hosted runner.
4. Start the workflow.

The release job waits for the live regression job and only publishes if it
passes or if the live regression option was not selected.

## Runner Requirements

The normal CI suite runs on GitHub-hosted runners.

The live release regression requires a self-hosted Windows runner with:

- Ghidra 12.0.4 installed.
- Java 21.
- Python 3.13.
- Maven.
- Access to the Ghidra project that should receive `/testing/benchmark`.
- Any `.env` credentials needed to open the project or authenticate to Ghidra
  Server.

The workflow uses:

```yaml
runs-on: [self-hosted, Windows]
```

Set the runner or repository variable `GHIDRA_PATH` if you do not want to pass
`ghidra_path` manually.

## Can the Full Live Suite Run in a GitHub Container?

Not as currently implemented.

The release regression is a GUI/project lifecycle test. It starts Ghidra, waits
for the active project, imports a binary into that project, and exercises GUI MCP
plugin endpoints. A stock GitHub-hosted container has no existing Ghidra project,
no desktop session, and no private Ghidra Server/project credentials.

There are two practical options:

- Use a self-hosted Windows runner for the current full live suite.
- Add a separate headless disposable-project suite later. That suite could run
  on hosted Linux or in a container if it creates a temporary project, starts the
  headless server, imports `Benchmark.dll`, and runs the same read/write
  endpoint contracts against headless mode.

The second option would be valuable, but it should be treated as a different
test target: headless parity and disposable-project coverage, not the same thing
as proving the installed GUI plugin works in a real user project.

## What To Run Before a Release

For the full release runbook, including versioning, documentation, PR, tagging,
and post-release steps, see
[`docs/releases/RELEASE_CHECKLIST.md`](releases/RELEASE_CHECKLIST.md).

Minimum local verification:

```text
python -m tools.setup preflight --ghidra-path "F:\ghidra_12.0.4_PUBLIC"
python -m tools.setup build
pytest tests/unit/ -v --no-cov
python -m tools.setup deploy --ghidra-path "F:\ghidra_12.0.4_PUBLIC" --test release
```

For GitHub releases, enable `run_live_regression` in the release workflow when a
self-hosted runner is available.

# GitHub Workflows

This directory contains the maintained CI, release, and live-regression
workflows for GhidraMCP.

## Workflows

| Workflow | Trigger | Runner | Purpose |
|----------|---------|--------|---------|
| `tests.yml` | Push and pull request to `main`/`dev`/`develop` | GitHub-hosted Ubuntu/Windows | Merge-gating build, unit, offline Java, Pester, and docs checks. |
| `codeql.yml` | Push/PR to `main`/`dev`, weekly schedule | GitHub-hosted | CodeQL security analysis. |
| `scorecard.yml` | Push to `dev`, weekly schedule, manual | GitHub-hosted | OSSF Scorecard supply-chain score. |
| `release-regression.yml` | Manual, reusable workflow call, PR label | Self-hosted Windows | Live Ghidra deploy regression. |
| `release.yml` | Version tags or manual dispatch | GitHub-hosted, optional self-hosted regression | Stable release artifact creation. |
| `pre-release.yml` | Manual dispatch | GitHub-hosted, optional self-hosted regression | Pre-release artifact creation. |

## Pull Request Gates

`tests.yml` runs automatically on pull requests and is the default merge gate.
Configure branch protection to require its status checks.

The live Ghidra regression is opt-in on pull requests. Add this PR label:

```text
live-ghidra-regression
```

When the label is present, `release-regression.yml` runs on a self-hosted
Windows runner and executes:

```text
python -m tools.setup deploy --ghidra-path <path> --test <tier>
```

This is not enabled for every PR by default because public GitHub-hosted runners
do not have the required active Ghidra project, and external PRs should not hang
waiting for a private self-hosted runner.

> **The `release` tier cannot run from this repository.** `fun-doc/` moved to
> the `d2-game-exe` repository on 2026-08-10 and took the `Benchmark.dll`
> fixture with it. Every tier that resets that fixture — `release`,
> `benchmark-read`, `benchmark-write`, `multi-program`, `debugger-live` and
> `negative-contract` — now fails in `reset_benchmark_fixture()`. Only
> `endpoint-catalog` and `selected-contract` still run here. The workflow
> fails fast with this explanation rather than discovering it after a deploy.
> Choosing the replacement release gate is an open maintainer decision.

## Release Gates

`release.yml` and `pre-release.yml` expose a `run_live_regression` input. Enable
it when a self-hosted Windows runner is available and you want the release job to
wait for the live regression before publishing.

The release regression workflow expects:

- Ghidra installed on the self-hosted runner.
- Java 21, Python 3.13, and Maven.
- Access to the target Ghidra project.
- Any `.env` credentials needed by the project or Ghidra Server.

See [docs/TESTING.md](../../docs/TESTING.md) for the full testing model,
commands, side effects, and runner/container notes.

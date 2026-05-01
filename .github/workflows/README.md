# GitHub Workflows

This directory contains the maintained CI, release, and live-regression
workflows for GhidraMCP.

## Workflows

| Workflow | Trigger | Runner | Purpose |
|----------|---------|--------|---------|
| `tests.yml` | Push and pull request to `main`/`develop` | GitHub-hosted Ubuntu/Windows | Merge-gating build, unit, offline Java, Pester, and docs checks. |
| `build.yml` | Project build triggers | GitHub-hosted | Build-focused CI path. |
| `release-regression.yml` | Manual, reusable workflow call, PR label | Self-hosted Windows | Live Ghidra deploy and benchmark regression. |
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
python -m tools.setup deploy --ghidra-path <path> --test release
```

This is not enabled for every PR by default because public GitHub-hosted runners
do not have the required active Ghidra project, and external PRs should not hang
waiting for a private self-hosted runner.

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

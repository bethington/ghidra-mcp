# Release Checklist

Use this checklist when preparing a stable release or pre-release. It is written
for humans working with Claude Code, Codex, or another coding agent: keep the
agent focused on one phase at a time, make it show command results, and do not
let it tag or publish until the verification gates are complete.

## Release Owner Rules

- Keep this file as the canonical release checklist.
- Keep `CLAUDE.md` and `AGENTS.md` as short pointers to this file, not full
  copies of the runbook.
- Use `python -m tools.setup bump-version --new X.Y.Z` for version changes.
- Do not create a release tag until the release branch is merged to `main` or
  the release workflow is intentionally creating the tag from the selected
  branch.
- Do not run deploy/live regression from an agent session without confirming
  the current Ghidra UI state when modal dialogs may be present.

## 1. Decide Version Scope

- [ ] Identify the release type:
  - Patch: bug fixes only, no new behavior.
  - Minor: backward-compatible features, new endpoints, new tests, workflow
    improvements.
  - Major: breaking endpoint behavior, removed tools, or incompatible config.
- [ ] Confirm the target version does not already exist as a tag:

```text
git tag --list "v*" --sort=-v:refname
```

- [ ] Update the version:

```text
python -m tools.setup bump-version --new X.Y.Z
```

- [ ] Verify version consistency:

```text
python -m tools.setup verify-version
```

## 2. Documentation and Metadata

- [ ] Update `CHANGELOG.md` with a new top entry for the release.
- [ ] Update `docs/releases/README.md` so the latest release summary is current.
- [ ] Update user-facing docs for any changed commands, defaults, side effects,
  endpoints, or environment variables.
- [ ] Confirm `README.md` examples and version references are current.
- [ ] If endpoint annotations changed, update `tests/endpoints.json`.

For agent-assisted releases, ask the agent to search for stale version and tool
count references before committing:

```text
rg -n "OLD_VERSION|NEW_VERSION|MCP Tools|GUI Endpoints|Headless Endpoints|total_endpoints" README.md CHANGELOG.md docs tests src pom.xml
```

## 3. Local Verification

Run the cheap gates before any live Ghidra work:

```text
python -m tools.setup preflight --ghidra-path "F:\ghidra_12.1.2_PUBLIC"
python -m tools.setup build
uv build                                  # build the ghidra-mcp-bridge wheel (-> dist/)
uv run pytest tests/unit/ -v --no-cov
git diff --check
git diff --cached --check
```

`bump-version` keeps `pyproject.toml` (the wheel version) and the
`python/bridge_mcp_ghidra/__init__.py` `__version__` fallback in lockstep with
`pom.xml`; `test_project_consistency.py::test_pyproject_version_matches_pom`
guards the wheel version, and CI builds + attaches
`ghidra_mcp_bridge-X.Y.Z-py3-none-any.whl` as the release asset (the raw
bridge script is no longer shipped).

For setup/version/catalog changes, also run:

```text
pytest tests/unit/test_version_bump.py tests/unit/test_endpoint_catalog.py tests/unit/test_setup_cli.py tests/unit/test_setup_ghidra.py -v --no-cov
```

For Java endpoint/catalog changes, run the offline Java scanner/parity tests.
On a clean machine the Ghidra JARs must be in the local Maven repository first,
or dependency resolution fails before any test runs:

```text
python -m tools.setup install-ghidra-deps --ghidra-path "F:\ghidra_12.1.2_PUBLIC"
mvn test -Dtest='com.xebyte.offline.*Test'
```

If `EndpointsJsonParityTest` fails, `tests/endpoints.json` is stale. Regenerate
it, then refresh the generated README API section it feeds:

```text
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
python -m tools.gen_readme_api_reference --write
```

## 4. Live Ghidra Regression

Live regression is required before merging risky deploy, GUI plugin, debugger,
benchmark, or endpoint behavior changes.

> **BLOCKED — the `release` tier cannot run from this repository.**
> `fun-doc/` moved to the `d2-game-exe` repository on 2026-08-10 (commit
> `10960f76`) and took the `Benchmark.dll` fixture with it. Every tier that
> resets that fixture — `release`, `benchmark-read`, `benchmark-write`,
> `multi-program`, `debugger-live`, `negative-contract` — now raises in
> `reset_benchmark_fixture()` (`tools/setup/ghidra.py`) before a single
> assertion runs. The two tiers that still work here are `endpoint-catalog`
> and `selected-contract`.
>
> Until a maintainer decides what the release gate should be, do not treat
> this section as satisfiable. The options are: run the benchmark tiers from
> `d2-game-exe`, re-home a fixture here, or downgrade the gate to the tiers
> that still run. Recording "passed" for a tier that cannot execute is worse
> than recording that it is blocked.

- [ ] Confirm the current Ghidra UI has no blocking modal dialogs.
- [ ] Run the deploy regression at a tier that can execute:

```text
python -m tools.setup deploy --ghidra-path "F:\ghidra_12.1.2_PUBLIC" --test selected-contract
python -m tools.setup deploy --ghidra-path "F:\ghidra_12.1.2_PUBLIC" --test endpoint-catalog
```

- [ ] Record which tiers were run and whether they passed. Note explicitly that
  the benchmark-backed tiers were skipped as unrunnable, not as passing.
- [ ] If the run required manual dialog intervention, document the popup and
  decide whether the deploy/prompt-policy automation needs another fix before
  release.

## 5. Commit and Pull Request

- [ ] Review staged files:

```text
git status --short --branch
git diff --cached --stat
git diff --cached --check
```

- [ ] Commit with a release-appropriate message.
- [ ] Push the branch.
- [ ] Open or update the PR with:
  - Version number.
  - Summary of user-facing changes.
  - Tests run and live regression result.
  - Known risks or intentionally deferred items.
- [ ] Confirm GitHub `tests.yml` checks pass.
- [ ] For high-risk Ghidra changes, add the `live-ghidra-regression` PR label
  if a self-hosted runner is available.

## 6. Merge and Publish

- [ ] Merge the PR to `main`.
- [ ] Confirm `main` contains the intended version:

```text
git fetch origin
git checkout main
git pull --ff-only
python -m tools.setup verify-version
```

- [ ] Publish using the GitHub **Create Release** workflow, or create/push an
  annotated tag and let `release.yml` run:

```text
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

- [ ] Leave `run_live_regression` **off** in the release workflow until the
  benchmark-tier question above is resolved. It calls `release-regression.yml`
  with `test_tier: release`, which now fails fast by design (see section 4).
  Enabling it today guarantees a red release run.
- [ ] Verify release assets include `GhidraMCP-X.Y.Z.zip`.
- [ ] Download the release ZIP and sanity-check that it installs or at least
  contains the expected extension payload.

## 7. Post-Release

- [ ] Confirm GitHub release notes are accurate.
- [ ] Confirm the latest release badge points at the new release.
- [ ] Close or update issues/PRs covered by the release.
- [ ] If the release exposed follow-up work, create issues before moving on.

## Agent Usage Notes

- Ask the agent to execute one checklist phase at a time.
- Require exact command results in the final PR/release summary.
- Keep secrets, local `.env`, and generated runtime reports out of commits.
- Prefer deterministic repo tools over hand editing version metadata.
- For UI-touching Ghidra actions, pause for a screenshot/checkpoint if the
  agent cannot inspect the Ghidra window directly.

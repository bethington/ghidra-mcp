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
python -m tools.setup preflight --ghidra-path "F:\ghidra_12.0.4_PUBLIC"
python -m tools.setup build
pytest tests/unit/ -v --no-cov
git diff --check
git diff --cached --check
```

For setup/version/catalog changes, also run:

```text
pytest tests/unit/test_version_bump.py tests/unit/test_endpoint_catalog.py tests/unit/test_setup_cli.py tests/unit/test_setup_ghidra.py -v --no-cov
```

For Java endpoint/catalog changes, run the offline Java scanner/parity tests:

```text
mvn test -Dtest='com.xebyte.offline.*Test'
```

## 4. Live Ghidra Regression

Live regression is required before merging risky deploy, GUI plugin, debugger,
benchmark, or endpoint behavior changes.

- [ ] Confirm the current Ghidra UI has no blocking modal dialogs.
- [ ] Run the release-grade deploy regression:

```text
python -m tools.setup deploy --ghidra-path "F:\ghidra_12.0.4_PUBLIC" --test release
```

- [ ] Record whether the release regression passed.
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

- [ ] Enable `run_live_regression` in the release workflow when the
  self-hosted Windows runner is available.
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

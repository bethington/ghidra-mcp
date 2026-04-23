# Gradle Migration Checklist

**Status**: Proposed
**Goal**: Make Gradle the canonical Java/plugin build and deploy backend for this repo without regressing the Python runtime workflows.
**Scope**: Migrate the current `python -m tools.setup` Java/plugin command surface away from Maven and onto Gradle tasks.

## Migration Objective

Replace the Maven-backed Java/plugin workflow with a Gradle-backed workflow while preserving the current operator UX where practical.

The desired end state is:

- Gradle owns Java compile, test, packaging, validation, deploy, and launch tasks.
- `tools.setup` remains as a stable Python CLI facade, but mostly shells out to Gradle for Java/plugin operations.
- Python remains the source of truth for runtime systems such as `bridge_mcp_ghidra.py`, `debugger/`, and `fun-doc/`.
- Maven is removed as an active build dependency after cutover.

## Non-Goals

- Do not migrate `bridge_mcp_ghidra.py` runtime logic into Gradle.
- Do not migrate the standalone debugger server into Gradle.
- Do not migrate `fun-doc` orchestration into Gradle.
- Do not keep Maven and Gradle as equal first-class build backends after cutover.

## Command Mapping

Current `tools.setup` command to proposed Gradle task mapping:

| Current command | Current backend | Target Gradle task(s) | Notes |
|---|---|---|---|
| `install-python-deps` | Python + pip | `installPythonDeps` wrapper or stay Python-native | Keep the real dependency logic in Python; Gradle may wrap it but should not own the Python environment model. |
| `verify-version` | Python + `pom.xml` | `verifyVersion` | Read Gradle project version and compare against the selected Ghidra install version. |
| `preflight` | Python + Maven + filesystem checks | `preflight` | Split internally into version, Java, Ghidra layout, write-access, and optional network checks. |
| `build` | Maven | `buildPlugin` or canonical `buildExtension` | Becomes the authoritative jar + extension zip build. |
| `clean` | Maven | `clean` | Native Gradle `clean`. |
| `run-tests` | Maven | `test` | Native Gradle Java test task. |
| `install-ghidra-deps` | Maven local repo install | `prepareGhidraClasspath` | Redesign this instead of porting the Maven local-repo install literally. |
| `deploy` | Python file copy/extract/patch | `deployExtension`, `installUserExtension`, `patchGhidraUserConfig`, aggregate `deploy` | Good Gradle fit. |
| `start-ghidra` | Python subprocess | `startGhidra` | Straightforward `Exec` task. |
| `clean-all` | Python filesystem cleanup | `cleanAll` | Remove Gradle outputs plus repo caches. |
| `ensure-prereqs` | Python aggregate | `ensurePrereqs` | Aggregate orchestration task that may still delegate Python dependency installs to Python. |
| `bump-version` | Python text rewrite | Keep Python-native | This is release/repo tooling, not core build logic. |

## Proposed Gradle Task Set

Canonical tasks to introduce or formalize:

- `verifyVersion`
- `preflight`
- `prepareGhidraClasspath`
- `buildPlugin`
- `buildExtension`
- `test`
- `deployExtension`
- `installUserExtension`
- `patchGhidraUserConfig`
- `deploy`
- `startGhidra`
- `cleanAll`
- Optional wrapper tasks: `installPythonDeps`, `installDebuggerPythonDeps`, `ensurePrereqs`

## Phase 0: Baseline And Design Freeze

Goal: establish what must remain behaviorally identical after the backend switch.

Checklist:

- [ ] Freeze the supported CLI surface in `tools.setup` for the migration window.
- [ ] Record the current artifact outputs from Maven: jar name, zip name, destination paths, and contents.
- [ ] Record the current deploy behavior: install-root copy, user-profile extraction, stale-jar cleanup, and config patching.
- [ ] Record the current VS Code task behavior and labels.
- [ ] Decide whether `tools.setup` remains the public operator entry point after migration.

Acceptance criteria:

- There is a written inventory of current Maven outputs and deploy side effects.
- The team has decided whether the user-facing command surface remains `python -m tools.setup` or shifts to direct Gradle use.

## Phase 1: Make Gradle Capable Of Full Build Parity

Goal: Gradle must produce the same plugin jar and extension zip that Maven produces today.

Checklist:

- [ ] Extend `build.gradle` so `buildExtension` is the canonical extension archive task, not a secondary/manual path.
- [ ] Ensure `processResources` performs all required version/property substitutions.
- [ ] Ensure manifest attributes match the current Maven build output.
- [ ] Ensure the Gradle build produces a stable artifact path under `build/` or `build/distributions/`.
- [ ] Decide whether Gradle should keep reading `pom.xml` for version data during transition or own version metadata directly.

Acceptance criteria:

- Gradle builds a jar and extension zip successfully against a valid Ghidra install.
- The zip contains the same required payload as the current Maven-produced extension zip.
- Output paths are stable enough for deploy automation to consume.

## Phase 2: Replace Maven Build/Test/Clean Commands In `tools.setup`

Goal: switch the low-risk commands first while preserving the current CLI.

Checklist:

- [ ] Replace `tools.setup build` backend from Maven to Gradle.
- [ ] Replace `tools.setup clean` backend from Maven to Gradle.
- [ ] Replace `tools.setup run-tests` backend from Maven to Gradle.
- [ ] Keep the Python CLI flags and command names unchanged during this phase.
- [ ] Update `.vscode/tasks.json` only if task arguments or task IDs need to change.

Acceptance criteria:

- `python -m tools.setup build` succeeds without invoking Maven.
- `python -m tools.setup clean` succeeds without invoking Maven.
- `python -m tools.setup run-tests` succeeds without invoking Maven.
- Existing VS Code tasks still work with no user-facing task renames.

## Phase 3: Replace Ghidra Dependency Handling

Goal: remove the Maven-local-repository dependency model.

Checklist:

- [ ] Remove the need for `mvn install:install-file` for Ghidra jars.
- [ ] Decide whether Gradle consumes Ghidra jars directly from the selected Ghidra installation or via a staged local directory.
- [ ] Implement `prepareGhidraClasspath` or equivalent validation/configuration task.
- [ ] Update `tools.setup install-ghidra-deps` to either call the new Gradle preparation task or deprecate the command entirely.
- [ ] Remove `.m2`-specific assumptions from setup docs if the new model no longer uses Maven local repo installation.

Acceptance criteria:

- A fresh machine with Java, Python, and Ghidra can build without manually installing Ghidra jars into `~/.m2`.
- `tools.setup` no longer requires Maven for dependency preparation.

## Phase 4: Replace Version And Preflight Validation

Goal: move Java/plugin validation logic to Gradle while keeping Python only where it still adds value.

Checklist:

- [ ] Implement `verifyVersion` in Gradle.
- [ ] Implement `preflight` in Gradle.
- [ ] Validate Java availability, Ghidra executable presence, Ghidra jar presence, version compatibility, and filesystem write access.
- [ ] Decide whether pip validation stays in Python or is wrapped by Gradle.
- [ ] Update `tools.setup verify-version` and `tools.setup preflight` to call Gradle.

Acceptance criteria:

- `python -m tools.setup verify-version --ghidra-path ...` succeeds via Gradle.
- `python -m tools.setup preflight --ghidra-path ...` succeeds via Gradle for Java/Ghidra/plugin checks.
- Any remaining Python-owned preflight checks are explicitly documented as such.

## Phase 5: Replace Deploy And Launch Workflow

Goal: make Gradle the canonical deploy/install/start backend.

Checklist:

- [ ] Implement `deployExtension` to copy the extension archive into the Ghidra install.
- [ ] Implement `installUserExtension` to extract into the user-profile extensions directory.
- [ ] Implement stale plugin jar cleanup before extraction.
- [ ] Implement `patchGhidraUserConfig` for `FrontEndTool.xml` and `_code_browser.tcd` patching.
- [ ] Implement `startGhidra`.
- [ ] Implement aggregate `deploy` task.
- [ ] Update `tools.setup deploy` and `tools.setup start-ghidra` to call Gradle.

Acceptance criteria:

- `python -m tools.setup deploy --ghidra-path ...` succeeds via Gradle.
- Deploy side effects match the current Python deploy behavior.
- `python -m tools.setup start-ghidra --ghidra-path ...` launches the configured Ghidra install successfully.

## Phase 6: Decide What To Do With Python Dependency Installation

Goal: avoid confusing ownership for Python environment setup.

Checklist:

- [ ] Decide whether `install-python-deps` remains fully Python-native.
- [ ] If desired, add Gradle wrapper tasks that call the Python installer rather than reimplementing pip behavior in Gradle.
- [ ] Preserve debugger dependency toggle semantics if they remain supported.
- [ ] Keep the actual Python dependency resolution logic in Python unless there is a strong reason to duplicate it.

Acceptance criteria:

- There is one clearly documented owner for Python environment setup.
- The migration does not create two competing ways to define Python requirements behavior.

## Phase 7: Cut Over Docs, Tasks, And CI

Goal: remove ambiguity after the backend switch is complete.

Checklist:

- [ ] Update `README.md` to describe Gradle as the canonical Java/plugin build backend.
- [ ] Update `CLAUDE.md`, `AGENTS.md`, `CONTRIBUTING.md`, and relevant docs pages.
- [ ] Update CI to run Gradle instead of Maven.
- [ ] Update VS Code tasks if direct Gradle usage is desired or if task output paths changed.
- [ ] Remove or archive Maven-specific docs such as Maven-only operator guidance.

Acceptance criteria:

- No current operator docs describe Maven as the canonical backend.
- CI builds and tests through Gradle.
- VS Code tasks and documentation agree on the same backend.

## Phase 8: Remove Maven As An Active Backend

Goal: finish the migration instead of keeping both forever.

Checklist:

- [ ] Remove Maven invocation code from `tools.setup`.
- [ ] Remove `tools/setup/maven.py` if no longer needed.
- [ ] Remove Maven-only task wiring and docs references.
- [ ] Decide whether to delete `pom.xml` entirely or keep it temporarily only for metadata/version transition.
- [ ] If `pom.xml` is deleted, move version authority fully into Gradle and adjust version-reading utilities accordingly.

Acceptance criteria:

- The repo has one active Java/plugin build backend.
- No routine build, test, deploy, or setup flow requires Maven.

## Rollback Strategy

If any migration phase fails to reach parity, stop at that phase and keep `tools.setup` pointing at the previous working backend.

Rollback rules:

- Do not remove Maven invocation code until the Gradle replacement for that command is validated.
- Do not switch CI until local and task-based parity is proven.
- Do not delete `pom.xml` while any versioning, packaging, or documentation logic still depends on it.

## Validation Matrix

Run these checks at each cutover point:

- [ ] Build succeeds on Windows.
- [ ] Build succeeds on Linux.
- [ ] Build succeeds on macOS if Homebrew Ghidra remains a supported path.
- [ ] Java tests pass.
- [ ] Extension zip contents are correct.
- [ ] Deploy installs into both the Ghidra install tree and the user extension tree as expected.
- [ ] FrontEnd and CodeBrowser config patching still works.
- [ ] VS Code tasks still succeed.
- [ ] CI succeeds.

## Recommended Ownership After Migration

Keep this split:

- Gradle owns Java/plugin build, package, validate, deploy, and launch tasks.
- Python owns runtime systems and repo utilities.
- `tools.setup bump-version` stays Python-native unless you intentionally want Gradle to become the release tooling owner too.

## Cutover Decision Gate

Only declare the migration complete when all of the following are true:

- [ ] `tools.setup build`, `clean`, `run-tests`, `verify-version`, `preflight`, `deploy`, and `start-ghidra` all run without Maven.
- [ ] CI runs without Maven.
- [ ] Current docs describe Gradle as canonical.
- [ ] Maven is no longer required for any day-to-day developer workflow.
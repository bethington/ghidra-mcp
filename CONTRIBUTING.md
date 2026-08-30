# Contributing to Ghidra MCP

This guide is written so that a first-time contributor can get from `git clone`
to a green PR without guessing. Every command in it was run against this
repository before it was written down.

If something here does not work, that is a bug in this file. Open an issue
saying so.

## Quick links

- **Issues**: [GitHub Issues](https://github.com/bethington/ghidra-mcp/issues)
- **Discussions**: [GitHub Discussions](https://github.com/bethington/ghidra-mcp/discussions)
- **Direction and priorities**: [ROADMAP.md](ROADMAP.md)
- **Documentation index**: [docs/README.md](docs/README.md)
- **Tool inventory** (253 endpoints, generated): [tests/endpoints.json](tests/endpoints.json)
- **Testing tiers in depth**: [docs/TESTING.md](docs/TESTING.md)
- **Security reports**: [SECURITY.md](SECURITY.md) — do not file these as public issues

If your team depends on Ghidra MCP in production or client work, please consider
[sponsoring the project](https://github.com/sponsors/bethington) to help fund
maintenance and compatibility updates.

## How this project uses AI

To be upfront: AI tooling assists with code, reviews, and drafting on this
project. To keep that from getting in the way of the humans here, the maintainer
commits to:

- **A human reviews and posts every maintainer action.** Closing, merging,
  commenting on, or editing an issue or PR is done by a person, not by
  automation. Your issue text is never edited by a bot.
- **Draft / WIP PRs are left alone.** If you mark a PR draft, its work won't be
  merged or cherry-picked until you mark it ready. To have your work land, it
  goes through your PR — with your authorship — not by lifting the commit around
  you.
- **Claims about your work get checked before they're posted.** If a summary of
  your PR is wrong, that's a bug — please call it out and it'll be fixed.

If you ever see any of this violated, flag it. It's a standard, not a nicety.

## The one thing to understand first

**Most of this project's tests do not need Ghidra.** This is the single most
confusing thing about the repo for a newcomer, because the product is a Ghidra
plugin and it is reasonable to assume nothing can be run without it.

| Tier | Needs Ghidra installed? | Needs Ghidra *running* on port 8089? | Runs in CI? |
| --- | --- | --- | --- |
| Python unit (`tests/unit/`) | No | No | Yes — gating |
| Offline Java (`com.xebyte.offline.*`, `com.xebyte.core.*`) | Yes, for the jars to compile against | No | Yes — gating |
| Pester (`tests/pester/`) | No | No | Yes — gating |
| Java integration (`GhidraMCPPluginTest`, `EndpointRegistrationTest`, `AppTest`) | Yes | Yes | No |
| Python integration (`tests/integration/`) | Yes | Yes, with a program loaded | No |
| Conformance (`tests/conformance/`) | Yes | Yes | No |

Everything CI gates on is in the top three rows. **You can contribute a
reviewable, mergeable change without ever launching Ghidra**, as long as you
stay out of the live tiers. If a change genuinely needs the live tiers, say so
in the PR and the maintainer will run them — you are not expected to own a
Ghidra project full of binaries.

Two separate contributors have reported the test suite as broken when what they
had actually hit was a live tier failing without a server. If `pytest tests/`
(no path) fails for you, run `pytest tests/unit/` first — that is the tier CI
gates on.

## Prerequisites

| Requirement | Version | Needed for |
| --- | --- | --- |
| Java | 21 LTS | Any Java build or test |
| Python | 3.10–3.13 | Bridge, `tools.setup`, Python tests |
| [uv](https://docs.astral.sh/uv/) | current | Dependency resolution from `uv.lock` |
| Maven | 3.9+ | Default Java backend |
| Gradle | bundled wrapper (`./gradlew`) | Alternative Java backend |
| Ghidra | 12.1.2 | Compiling against Ghidra's jars; all live tiers |

Python-only changes need Java and Ghidra for nothing at all.

Check what you have:

```text
python -m tools.setup preflight
```

It runs without `--ghidra-path` and simply reports that the Ghidra-specific
checks were skipped, which is the correct state for a Python-only contributor:

```text
Python: .../.venv/Scripts/python.exe
Maven: .../mvn.cmd
uv: available
Java: available on PATH
Project version: 7.0.0
Ghidra version from pom.xml: 12.1.2
No Ghidra path configured; skipped Ghidra-specific preflight checks.
```

Add `--ghidra-path <dir>` to also validate the install and that its version
matches `pom.xml`.

## Build

Two Java backends are supported and both are maintained. Maven is the default;
Gradle exists as the migration path
([checklist](docs/project-management/GRADLE_MIGRATION_CHECKLIST.md)). Pick
either — CI builds with Maven.

### Maven (default)

```text
python -m tools.setup build
```

This wraps `mvn clean package assembly:single` and produces
`target/GhidraMCP-<version>.jar` and `target/GhidraMCP-<version>.zip` (the
Ghidra extension archive). Verified: `BUILD SUCCESS`, about 10 seconds on a warm
local repository.

The first Maven build needs Ghidra's jars installed into your local repository:

```text
python -m tools.setup ensure-prereqs --ghidra-path <your-ghidra-install>
```

### Gradle

Gradle reads the jars straight out of the Ghidra installation, so there is no
`install-file` step:

```text
./gradlew buildExtension -PGHIDRA_INSTALL_DIR=<your-ghidra-install>
```

To route the `tools.setup` commands through Gradle instead of Maven, set
`TOOLS_SETUP_BACKEND=gradle`.

**Git Bash users: use forward slashes in the Ghidra path.** A Windows-style
backslash path is mangled before Gradle sees it, `GHIDRA_INSTALL_DIR` resolves
to nothing, and you get a hundred `package ghidra.program.model.address does not
exist` errors that look like a broken repository rather than a broken argument.
Verified both ways:

```text
# Git Bash — works
./gradlew test --tests 'com.xebyte.offline.*' "-PGHIDRA_INSTALL_DIR=F:/ghidra_12.1.2_PUBLIC"

# Git Bash — fails with 100 "package does not exist" errors
./gradlew test --tests 'com.xebyte.offline.*' -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC

# PowerShell — the backslash form is fine
.\gradlew.bat test --tests 'com.xebyte.offline.*' -PGHIDRA_INSTALL_DIR=F:\ghidra_12.1.2_PUBLIC
```

## Test

### Python unit tests — no Ghidra, ~17 seconds

```text
uv run pytest tests/unit/ --no-cov
```

Verified: 568 tests, 560 passed, 8 skipped, 0 failures, about 17 seconds. The
skips are platform forks (`AF_UNIX` is absent on Windows CPython, and the
debugger/oracle proxy gating differs), not failures.

Add `--frozen` (`uv run --frozen pytest ...`) if you want `uv.lock` left alone —
see the gotcha below, it currently gets rewritten by any plain `uv run`.

Drop `--no-cov` to run the same coverage gate CI runs:

```text
uv run pytest tests/unit/
```

Verified: `Required test coverage of 55% reached. Total coverage: 57.33%`. The
`--cov-fail-under` floor lives in `.github/workflows/tests.yml` and is a
ratchet — it is raised as coverage improves and is never lowered to make a build
pass.

### Offline Java tests — needs the Ghidra jars, no running Ghidra

```text
# Maven
mvn test -Dtest='com.xebyte.offline.*Test'

# Gradle
./gradlew test --tests 'com.xebyte.offline.*' "-PGHIDRA_INSTALL_DIR=<path>"
```

Verified: 444 tests via Maven (44 suites) and 445 via Gradle (45 suites), 0
failures either way. The one-test difference is a suite that self-skips under
Maven when `GHIDRA_INSTALL_DIR` is unset.

CI additionally runs `com.xebyte.core.*Test` in the same command — those are
Mockito/ProgramBuilder tests that need no server either. To match CI exactly:

```text
mvn -q test -Pcoverage-gate -Dtest='com.xebyte.offline.*Test,com.xebyte.core.*Test'
```

### Pester — PowerShell installer tests, no Ghidra

```text
powershell -ExecutionPolicy Bypass -File tests\pester\Run-Tests.ps1
```

Verified: 10 passed, 0 failed, 6.3 seconds. Add `-CI` to make a failure set the
exit code. The runner installs Pester 5 to `CurrentUser` scope if it is missing.

### Live tiers — Ghidra running on port 8089 with a program open

Only run these if your change needs them.

```text
pytest tests/ -m readonly      # reads only
pytest tests/ -m safe_write    # identity writes (writes the same value back)
pytest tests/                  # everything, including mutating tests
mvn test                       # includes the Java integration tests
```

The bridge and tests target `http://127.0.0.1:8089` by default; override with
`GHIDRA_MCP_URL`. The deploy-driven release regression, its tiers, and what each
one mutates in your Ghidra project are documented in
[docs/TESTING.md](docs/TESTING.md). Note that some tiers import and reset a
benchmark binary in the active project — that is why they are opt-in.

## What CI runs on your PR

`.github/workflows/tests.yml` runs on every PR into `dev`.

| Job | Gates the build? | What it does |
| --- | --- | --- |
| Java Build (Maven) | **Yes** | Downloads Ghidra 12.1.2, installs its jars, `mvn package`, runs the offline + core Java tests under the JaCoCo coverage gate |
| Python Tests (pytest) | **Yes** | `tests/unit/` on Python 3.10, 3.11, 3.12, 3.13 with the coverage floor |
| Python Tests (pytest, Windows) | **Yes** | `tests/unit/` on Windows, no coverage floor — it exists so both sides of every `os.name == "nt"` branch execute |
| Pester | **Yes** | `tests/pester/Run-Tests.ps1 -CI` |
| Build Status | **Yes** | Aggregate of the four above — this is the check to watch |
| Code Quality | No | flake8 and black, advisory: every step ends in `\|\| true` |
| Documentation Quality | No | markdownlint, advisory: `continue-on-error: true` |
| CodeQL | No | Separate workflow; static analysis for Java and Python, findings land in the Security tab |

`scorecard.yml` runs only on pushes to the default branch and on a schedule, so
it will not appear on your PR. `release.yml`, `pre-release.yml`, and
`release-regression.yml` are maintainer-triggered and will not either.

### If your PR shows no checks at all, that is on us, not you

GitHub requires a maintainer to approve workflow runs for a first-time
contributor. Until that click happens, **nothing runs** — you see an empty
checks list, not a red one, and there is no notification telling you what you
are waiting for.

This has genuinely gone wrong here: five outside pull requests sat for three
weeks with zero CI results for exactly this reason and nobody noticed. If your
PR has no checks after a day or so, say so in the thread. That is the fastest
way to unstick it and it is a legitimate thing to chase.

A related failure mode: a PR can be red for a reason that has nothing to do with
its content. In August 2026 the Python coverage floor sat one point above the
measured coverage, so it failed pull requests that touched no Python at all —
including one that changed two Markdown files. If your PR is red and the failure
does not mention any file you touched, check whether `dev` is red too before
assuming you broke something.

## Which tests to run for your change

`CLAUDE.md` carries a long change-to-test table used by maintainers, with the
reasoning behind each row. The practical summary:

| You changed | Run |
| --- | --- |
| `python/bridge_mcp_ghidra/**` | `uv run pytest tests/unit/` |
| `tools/**`, `pom.xml`, `build.gradle` | `uv run pytest tests/unit/` (covers the setup CLI, Gradle tasks, version bump, project consistency) |
| `ghidra-mcp-setup.ps1` | Pester suite |
| Any `src/main/java/com/xebyte/core/*Service.java` | Offline Java, then the live Java + `tests/integration/test_readonly_endpoints.py` if you can |
| Added or edited an `@McpTool` / `@Param` annotation | Offline Java **and** the catalog regeneration below |
| `src/main/java/com/xebyte/GhidraMCPPlugin.java` (HTTP routes) | Offline Java + `EndpointRegistrationTest` (live) |
| `src/main/java/com/xebyte/headless/**` | Offline Java + `tests/unit/test_setup_ghidra.py` |
| Docs only | `uv run pytest tests/unit/` — see the README-drift gotcha below |

The bridge has a per-module size cap of 800 lines, enforced by
`test_bridge_modules_stay_focused`. Mock-patch targets are module-qualified
(`bridge_mcp_ghidra.transport.do_request`, not a re-export), and mutable runtime
state lives in `bridge_mcp_ghidra/state.py`, so each function has exactly one
canonical patch target.

## Gotchas that have actually bitten people

Each of these cost someone real time.

### Annotation changes have two generated artifacts, not one

Adding or editing an `@McpTool` or `@Param` makes `tests/endpoints.json` stale,
which `EndpointsJsonParityTest` catches. Regenerating it then makes the README's
API Reference section stale, which `tests/unit/test_project_consistency.py`
catches — in a *different* test tier, so fixing the first failure hands you a
second one in the other language. Run both:

```text
mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
python -m tools.gen_readme_api_reference --write
```

Both are idempotent. Verified against a clean tree: the Maven step exits 0 and
leaves `tests/endpoints.json` unchanged, and the Python step prints `README API
Reference is up to date.` Without `--write` the Python command is a check that
exits 1 on drift, which is what you want in a pre-push hook.

The regeneration preserves hand-authored descriptions and hand-registered
routes, so do not hand-edit the generated block in `README.md`.

### A plain `uv run` rewrites `uv.lock` — do not commit that

The committed `uv.lock` is currently ahead of `pyproject.toml` by 23 packages
(`flask`, `bidict`, `blinker`, `claude-agent-sdk` and friends) left behind when
a subsystem moved out of this repository. No dependency group declares them any
more, so the first `uv run` you type re-resolves and prunes them, and `git
status` shows `uv.lock` modified with a 653-line deletion you did not ask for.

Use `--frozen` for anything that should not touch the lock:

```text
uv run --frozen pytest tests/unit/ --no-cov
```

Verified: 560 passed, 8 skipped, `uv.lock` unchanged. If you already dirtied it,
`git checkout -- uv.lock` puts it back. Only commit a lockfile change when
changing dependencies is the actual point of your PR.

### `program` is a query parameter, not a body field

`@Param(value = "program")` defaults to `ParamSource.QUERY`. A POST endpoint
that receives `program` in the JSON body silently ignores it and operates on
whichever program is focused in the UI. This has caused writes to land on the
wrong binary.

### Plate comments need real newlines

A literal `\n` in a plate comment becomes the two characters, not a line break.
Pass actual multi-line text.

### GUI work from an HTTP thread must hop to Swing

Anything touching Ghidra's UI from a request handler needs
`SwingUtilities.invokeAndWait()`.

### Ghidra transactions must be committed

Database changes are lost otherwise, and a failed create can leave a transaction
open. Save after a batch of creates.

### Two tests read source files relative to the working directory

*(Placeholder — a fix is in flight. This section will name the tests and the
correct invocation once that lands. If you hit a test that fails only when you
run pytest from outside the repository root, that is this, and it is known.)*

## Adding an MCP tool

Tools are discovered from annotations. **There is no registry to edit and no
bridge-side function to write** for a normal tool — `AnnotationScanner` finds
`@McpTool` methods at startup, publishes them on `/mcp/schema`, and the Python
bridge registers whatever the schema advertises.

1. Add an `@McpTool` + `@Param` annotated method to the appropriate service
   class in `src/main/java/com/xebyte/core/`.
2. Regenerate the catalog and the README section (see the gotcha above).
3. Route any naming or convention validation through `NamingConventions.java`
   rather than reimplementing it. This project deliberately enforces RE
   documentation conventions in the tool layer instead of in prompts; see
   [docs/NAMING_CONVENTIONS.md](docs/NAMING_CONVENTIONS.md) and
   [docs/HUNGARIAN_NOTATION.md](docs/HUNGARIAN_NOTATION.md).
4. Return JSON. Every endpoint returns JSON as of 7.0.0 — list-shaped tools
   return a named plural key plus `count`/`total`, and errors are
   `{"error": ...}`.

Only add a static `@mcp.tool()` in `python/bridge_mcp_ghidra/static_tools.py`
when the tool needs bridge-side logic that has no server-side equivalent —
retries, multi-call orchestration, instance discovery. Those names must also be
listed in `STATIC_TOOL_NAMES` in `config.py`.

## Code style

- **Python**: PEP 8, type hints, line length 120 (`[tool.black]` in
  `pyproject.toml`). flake8 and black run advisory in CI; matching them is
  appreciated and not enforced.
- **Java**: explicit error handling, clear names, comments on non-obvious logic.
- **Markdown**: `.markdownlintrc` holds the rule set. The lint job is advisory.

### Resource ownership checklist

Use this whenever you touch Ghidra services, headless code, or bundled scripts.
Most of the hard-won bugs in this repo are leaks of exactly these kinds.

- `DecompInterface`, emulators, and other disposable Ghidra helpers must be
  owned by the smallest possible scope and released in `finally`.
- Transactions started with `startTransaction(...)` must always end in `finally`
  with the correct success flag.
- Opened `Program`, `DomainObject`, or project resources must be released on
  every exit path. A stray `DomainObject` consumer makes a shared-server
  DomainFile permanently "in use" and no amount of closing fixes it short of a
  Ghidra restart.
- `ProcessBuilder` or `subprocess` launches need an explicit lifecycle decision:
  detached fire-and-forget with a comment explaining why, or a waited child with
  exit-code handling.
- Child-process stdout/stderr must be drained and closed.
- Long waits need a timeout or a written justification for blocking forever.
- Prefer bounded network timeouts over unbounded waits.

## Commit messages

```text
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `perf`, `ci`,
`build`, `chore`. Reference the issue in the footer (`Fixes #123`).

## Pull requests

**Branch from `dev` and target `dev`.** `dev` is the default branch and every
open PR targets it. `main` is release-only.

Before you open it:

- Run the tiers your change touches, from the table above.
- If you changed an annotation, regenerate both artifacts.
- If you changed anything user-visible, add a `CHANGELOG.md` entry.
- Say in the PR description which tiers you ran and which you could not.

Saying "I could not run the live tier, I have no Ghidra project set up" is a
completely acceptable PR description. Silently skipping it and implying you ran
it is not.

### How review and merge actually work

- One maintainer reviews. CODEOWNERS assigns everything to `@bethington`.
- **Small gaps are usually fixed in a follow-up maintainer commit rather than
  bounced back to you.** If your change is right in substance but misses a
  regenerated file or a changelog line, expect it to be merged and topped up,
  not returned with a checklist. This keeps the queue moving.
- Because of that, **a merge is not a claim your work was flawless**, and a
  follow-up commit on top of your merge is not a criticism. Look at the
  follow-up if you want to know what was missing; it is not hidden.
- Draft PRs are not touched. Mark a PR draft and its work stays yours until you
  mark it ready.
- Your commits keep your authorship. Work is never lifted out of a PR and
  applied around the author.
- Dependency bumps from Dependabot are handled by automation and merged once CI
  is green. That carve-out applies only to `dependabot[bot]`, never to a human
  contributor proposing a similar bump.

## Reporting bugs and requesting features

Use the issue templates in `.github/ISSUE_TEMPLATE/`. They exist because the
same four questions get asked on nearly every report: **Ghidra version, bridge
version, MCP client and transport, and the exact command with its exact
output.** A report with those four things can usually be acted on immediately; a
report without them costs a round trip before anything can start.

Security vulnerabilities do not go in issues — see [SECURITY.md](SECURITY.md)
for the private reporting route.

## Code of conduct

- Be respectful and constructive.
- Assume good intent.
- Focus on code, not people.
- Report harassment to the maintainer.

## License

By contributing, you agree that your contributions are licensed under the
project's Apache 2.0 license.

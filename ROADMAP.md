# Ghidra MCP — Roadmap

This document exists to make the project's direction legible, so that anyone
reading an issue can tell whether it is being worked on, queued, or will not
happen. It is built from what is actually in the repository — open issues, open
pull requests, `CHANGELOG.md` — not from intentions.

It carries **no dates**. A theme with no date is more honest than a date that
slips, and this project has one maintainer. What it does carry is a status per
theme, and a section for work that is explicitly **not planned**, which is the
part that lets someone stop waiting.

_Last updated: 2026-09-18, against `dev` during the 7.0.0 release
preparation. For the tool inventory see
[`tests/endpoints.json`](tests/endpoints.json); for architecture see
[`CLAUDE.md`](CLAUDE.md); for how to build and test see
[`CONTRIBUTING.md`](CONTRIBUTING.md)._

## Guiding principles

- **Thin bridge, fat plugin.** Tool logic lives in the Java service layer and is
  auto-discovered from `@McpTool` annotations. The Python bridge is a generic
  HTTP multiplexer that registers tools dynamically from `/mcp/schema`. There is
  no hand-maintained tool list to keep in sync.
- **Conventions enforced in the tool layer, not in prompts.** Naming, typing and
  plate-comment rules are validated by the server, because prompt-only
  discipline measurably decays over long runs.
- **Bug reports from real users are first-class.** Issues get a reproduction or
  a clear "cannot reproduce / need info" — not a silent close.

## Themes

### 1. Tool-surface size

**The problem.** The server advertises 253 tools. Several MCP clients cannot
accept a `tools/list` that large. Gemini rejects it outright with HTTP 400
`INVALID_ARGUMENT` — "too many states for serving" — before a single tool is
called (#440). Even where it works, the schema consumes context that the model
should be spending on the binary.

**Done.** Tool groups with `load_tool_group` / `unload_tool_group`; a
`search_tools` catalog-search meta-tool so an agent running lazily can discover
tools it has not loaded; `check_tools`; a `--lazy` / `--no-lazy` startup flag and
`--default-groups`; and the 7.0.0 consolidation pass, which folded 272 tools
down to 251 by merging redundant ones into "one-or-many" survivors, without
removing any capability. The catalog stands at 253 today. See `CHANGELOG.md` and
`docs/project-management/MIGRATION_7.0.0_TOOL_CONSOLIDATION.md` for the
old-to-new call-site mapping.

**Also done, in 7.0.0.** Lazy loading is now the **default** (#440, PR #452), so
a client that cannot take the full set works out of the box rather than after
reading the docs. The core groups loaded on connect are `listing`, `function`
and `program` — 84 endpoints plus the 8 static bridge tools. `--no-lazy`
restores eager registration for clients that ignore `tools/list_changed`.

Issue #440 is still open: the fix is on `dev` and has not shipped in a tagged
release yet.

**Next.** Auditing for tools that overlap enough to merge now that
`search_tools` makes discovery cheap. This is a judgement pass, not a mechanical
one, and it moves in the 8.0.0 breaking window rather than piecemeal.

### 2. Transport correctness for non-Anthropic clients

**The problem.** Most development happens against one client. Everything else —
Open WebUI, Cline, the MCP Inspector, LibreChat — finds the edges. The reported
symptoms have been connection failures with no useful error rather than wrong
answers.

**Done.** `streamable-http` transport, recommended for HTTP clients. `sse`
retained for backward compatibility only.

**Also done, in 7.0.0.** The `OPTIONS` preflight returning 405 and breaking Open
WebUI (#399, PR #455). The root cause was that **two** gates read the `Origin`
header — `CORSMiddleware` answers the preflight, the SDK's
`TransportSecurityMiddleware` re-checks Host and Origin on the actual request —
and their allowlists were maintained side by side in different syntaxes and had
drifted. Both now derive from one `_policy_hosts()` set, so they cannot
disagree.

Also done: service-launched MCP clients could not spawn a bare `uv`, because the
client's `PATH` does not include `~/.local/bin` and the failure surfaced only as
`spawn ENOENT` (#441, PR #456). `preflight` now resolves and prints the absolute
launcher path to put in a client config.

Issues #399 and #441 are still open; both fixes are on `dev` and unreleased.

**In flight.** Community PR #438 on unauthenticated non-loopback binding
overlaps this area and has to be reconciled with the above. It matters more now
that the bridge ships as a container: a published port cannot reach a loopback
bind, so the containerised bridge binds `0.0.0.0` while holding a credential for
Ghidra, and an unauthenticated bridge in that position is a confused deputy.

**Not started.** A written support matrix stating which clients are tested
against and which are best-effort. Right now that distinction exists only in the
maintainer's head, which is why client-specific issues read as surprises.

### 3. Parameter and schema quality

**The problem.** The tool schema is generated from annotations, so a missing
`@Param` description is a missing description in every client's tool picker.

**Done.** 7.0.0's JSON response contract: every endpoint returns JSON, list
tools return a named plural key plus `count`/`total`, and errors are
`{"error": ...}` rather than an English sentence you had to pattern-match. Also
done: parameter-name consistency across endpoints — `address` versus
`function_address`, `new_name` versus `newName` (#210, closed 2026-06-27).

**Also done, in 7.0.0.** Every advertised parameter now has a description
(PR #454, 294 undocumented to 0). Nine advertised-but-unread parameters were
wired up or removed — a switch the schema offers and the handler never reads is
worse than no switch. `@Param` aliases are published in `/mcp/schema`, so a
valid spelling is no longer one the schema declines to mention.

**In flight.** Community PR #425, propagating `@Param` descriptions into the MCP
`inputSchema`.

**Next.** Nothing queued beyond that PR. Report a parameter whose description is
wrong or missing and it gets fixed; there is no larger schema project waiting
behind it.

### 4. Test infrastructure that does not need a live Ghidra

**The problem.** The tests that prove the most require a running Ghidra with a
program loaded. That makes them unrunnable in CI and unrunnable for a
contributor who does not keep a Ghidra project full of binaries. The visible
cost: two separate contributors reported the test suite as broken when it was
not — they had run a live tier without a server.

**Done.** The Python unit tier (1,048 tests, no Ghidra), the offline Java tier
(549 tests across 56 classes, needs a Ghidra install but no server), the Pester
tier, a Windows CI leg so both sides of every platform branch execute, and an
MCP-protocol conformance suite that drives a real MCP client instead of raw
HTTP.

**Done in 7.0.0 — the long-pole closed.** Offline test fixtures for CI (#112).
`tests/offline/` is a strict fake of the plugin's HTTP surface: it routes from
`tests/endpoints.json`, validates parameters against the recorded `/mcp/schema`,
and replays conformance snapshots, so the real bridge runs end to end over a
real socket with **no Ghidra installed**. The read-only integration file runs
against it (61 pass, 11 documented gaps). Its limits are written down in
`tests/offline/README.md` and matter: it proves the bridge speaks the protocol
and that shapes match the recordings, and it proves nothing about what Ghidra
does today. The issue is still open pending a tagged release.

That tier immediately earned itself. An AST check of every integration HTTP
call against the catalog and schema found **ten** wrong parameter names in the
read-only suite that were invisible at runtime — `AnnotationScanner` does not
find an unknown name, uses the default, and returns 200, so those assertions had
been passing while asserting nothing.

Two other tiers stopped silently not running. The **real-Ghidra tier** had never
executed anywhere: with `GHIDRA_INSTALL_DIR` set it died in `@Before` on a
missing log4j class, and with it unset every test self-skipped — and
`assumeTrue` reports a skipped tier as SUCCESS. And **14 offline security tests**
sat in a package CI's Surefire glob could not select, so they were compiled,
committed and never run. Both routes are now asserted rather than commented.

**In flight.** Nothing structural. Recent work has been paying off coverage debt
(PR #453) rather than extending the offline surface.

### 5. Docker and headless deployment

**The problem.** The headless path is real and used, but the container story has
sharp edges that only show up on someone else's machine.

**Done.** `HeadlessManagementService` for program and project lifecycle; a
headless server that runs without the GUI; Docker files under `docker/`.

**Done in 7.0.0.** The MCP bridge is part of the Compose stack.
`docker/Dockerfile.bridge` existed and worked, but nothing referenced it, so
`docker compose up` brought up a Ghidra REST server and no MCP endpoint at all.
`docker compose up -d --build` now starts both. `docker-compose.multi.yml`
deliberately gets no bridge, and now says why: `network_mode: "service:X"` names
one container and cannot target a scaled service, so a bridge in front of the
load balancer would hand consecutive tool calls to different Ghidra instances
holding different projects. **Not yet verified against a live engine** — the
invariants are pinned by tests that need no daemon, but a first
`docker compose up` is still owed.

**In flight.** The image fails to build when GID 1000 is already taken (#416,
community PR #449 addresses the fixed container UIDs). `ensure-prereqs`
uninstalling a pip that protobuf requires (#434).

**Next.** No further container work is planned beyond fixing what is reported.

### 6. Maintainer process

**The problem.** This is the theme this file was written for. Concretely
measured: five outside pull requests sat three weeks with **zero** CI results
because a first-time contributor's workflow runs need maintainer approval and
nobody was watching for it. Eight more were red for a coverage-floor reason
unrelated to their content, including one that changed only Markdown.

**Done.** The coverage floor no longer red-lines unrelated PRs. `CONTRIBUTING.md`
now states what CI runs, what gates, and that an empty check list means the
maintainer has not clicked approve. Issue and PR templates ask for the four
things that otherwise cost a round trip every time.

**Done in 7.0.0 — gates that can actually fail.** Several could not, which is a
worse state than not having them. The publish gate accepted
`release-regression.result == 'skipped'`, and on a tag push that job is _always_
skipped, so it had never once blocked a release; it now verifies recorded local
evidence carrying a **source fingerprint**, not a timestamp. The Markdown lint
job had been aborting before it read a file because of a filename
`markdownlint-cli2` rejects — 2,598 violations were hidden behind it. Scorecard's
push trigger named a branch the action refuses to run on, so every push started
a run that could only fail. A `.env` typo made `--test release` exit 0 having run
only the smoke test. Each of those is now asserted by a unit test rather than
left to a comment.

Gradle is also now the documented default for local work, because the
Maven-first runbooks could not run on a machine without Maven. CI still builds
and gates with Maven, so it remains a maintained peer.

**Not done.** There is no automated check that an open PR is sitting with zero
checks. Until there is, the reliable signal is a contributor saying so in the
thread, and that is an explicitly welcome thing to do.

**Not planned.** Adding maintainers or a formal review SLA. The project has one
maintainer and pretending otherwise would be a promise it cannot keep.

## Long-poles with their own issues

Two items are large enough that they are tracked as their own issues rather than
folded into a theme. Neither is scheduled, and both are the kind of change that
happens in one deliberate push or not at all.

- **Native Java MCP server, replacing the Python bridge (#114).** Serve MCP over
  streamable-HTTP directly from the Ghidra extension using the Java MCP SDK, so
  the Python bridge becomes optional. This would remove an entire process, an
  entire language runtime, and the `spawn ENOENT` class of problem from the
  install path. It is an architectural change, not a quick fix, and it is not
  started.
- **Offline test fixtures for CI (#112).** Landed in 7.0.0 — see theme 4. Kept
  here until the issue is closed, so this list and the issue tracker do not
  disagree.

## Not planned

Saying no is the point of this section. If your issue is here, it is not being
ignored — it has been decided.

- **Paid API-key metering or a payments integration (#439).** Out of scope for a
  Ghidra plugin. The project takes sponsorship, not per-call billing.
- **A hosted or default-on outbound data exchange.** The cross-version
  documentation archive and BSim integration exist, but outbound exchange is
  **disabled by default** and requires an explicitly configured endpoint. There
  is no default destination and no plan to add one; a regression test
  (`tests/unit/test_no_default_data_egress.py`) fails the build if a baked-in
  destination reappears. #391 tracks the remaining cleanup, not a reversal of
  the decision.
- **Backward-compatibility aliases for the 7.0.0 tool consolidation.** 7.0.0 is
  the breaking boundary and is a clean break by design. The old-to-new mapping
  is in `CHANGELOG.md` and in
  `docs/project-management/MIGRATION_7.0.0_TOOL_CONSOLIDATION.md`, and
  `tests/unit/test_migration_guide_successors.py` fails if any of the 23
  removals loses its successor. The aliases are not coming back.
- **Prose responses from any endpoint.** Everything returns JSON as of 7.0.0.
  Tooling that parsed stdout as English needs to read the envelope.
- **Supporting multiple Ghidra versions at once.** The project targets one
  Ghidra release at a time (currently **12.1.3**, tracked in `pom.xml` and
  pinned in the three CI workflows). A new Ghidra release is a retarget, not a
  compatibility matrix.
- **A GUI, web dashboard, or IDE plugin shipped from this repository.** The
  product is an MCP server. Clients are other people's software.
- **Game-specific or corpus-specific tooling.** Anything that only makes sense
  for one binary or one game belongs in the repository that owns that work, not
  here. Tools shipped from this repo work on any binary.

## How to influence this

Open an issue that describes the **problem**, not only the proposed solution,
with a concrete reproduction or use case. Include the four things
`CONTRIBUTING.md` asks for — Ghidra version, bridge version, MCP client and
transport, and the exact command with its exact output.

Feature requests arriving with a pull request attached move fastest. Feature
requests for anything in the **Not planned** section will be closed with a link
to this file, not with silence.

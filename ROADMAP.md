# Ghidra MCP — Roadmap

This document exists to make the project's direction legible, so that anyone
reading an issue can tell whether it is being worked on, queued, or will not
happen. It is built from what is actually in the repository — open issues, open
pull requests, `CHANGELOG.md` — not from intentions.

It carries **no dates**. A theme with no date is more honest than a date that
slips, and this project has one maintainer. What it does carry is a status per
theme, and a section for work that is explicitly **not planned**, which is the
part that lets someone stop waiting.

_Last updated: 2026-08-30. For the tool inventory see
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

**In flight.** Making lazy loading the default (#440, PR #452), so a client that
cannot take the full set works out of the box rather than after reading the
docs. The core groups loaded on connect are `listing`, `function`, `program`.

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

**In flight.** `OPTIONS` preflight returning 405 and breaking Open WebUI (#399,
PR #455) — the fix makes CORS and the DNS-rebinding host policy agree on one
host policy instead of two. A community PR (#438) on unauthenticated non-loopback
binding overlaps this area and has to be reconciled with it.

**Also in flight.** Service-launched MCP clients cannot spawn a bare `uv`,
because the client's `PATH` does not include `~/.local/bin` and the failure
surfaces only as `spawn ENOENT` (#441, PR #456). This is a documentation and
preflight problem more than a code one, and it has been reported by more than
one person.

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

**In flight.** Propagating `@Param` descriptions into the MCP `inputSchema`
(community PR #425), and filling in every advertised parameter that had no
description (PR #454, 294 undocumented parameters to 0). #425 lands first; #454
builds on it.

**Next.** Nothing queued beyond finishing the two in-flight PRs. Report a
parameter whose description is wrong or missing and it gets fixed; there is no
larger schema project waiting behind them.

### 4. Test infrastructure that does not need a live Ghidra

**The problem.** The tests that prove the most require a running Ghidra with a
program loaded. That makes them unrunnable in CI and unrunnable for a
contributor who does not keep a Ghidra project full of binaries. The visible
cost: two separate contributors reported the test suite as broken when it was
not — they had run a live tier without a server.

**Done.** The Python unit tier (568 tests, no Ghidra), the offline Java tier
(444 tests, needs the jars but no server), the Pester tier, a Windows CI leg so
both sides of every platform branch execute, and an MCP-protocol conformance
suite that drives a real MCP client instead of raw HTTP.

**In flight.** Nothing structural. The recent work here has been paying off
coverage debt (PR #453) rather than extending the offline surface.

**Open long-pole.** Offline test fixtures for CI (#112) — recorded or
synthesized program state so that endpoint behaviour, not just registration, can
be asserted without Ghidra. This is the single change that would most improve
outside contribution, and it is not scheduled.

### 5. Docker and headless deployment

**The problem.** The headless path is real and used, but the container story has
sharp edges that only show up on someone else's machine.

**Done.** `HeadlessManagementService` for program and project lifecycle; a
headless server that runs without the GUI; Docker files under `docker/`.

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
- **Offline test fixtures for CI (#112).** See theme 4.

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
  `docs/project-management/MIGRATION_7.0.0_TOOL_CONSOLIDATION.md`; the aliases
  are not coming back.
- **Prose responses from any endpoint.** Everything returns JSON as of 7.0.0.
  Tooling that parsed stdout as English needs to read the envelope.
- **Supporting multiple Ghidra versions at once.** The project targets one
  Ghidra release at a time (currently 12.1.2, tracked in `pom.xml` and pinned in
  CI). A new Ghidra release is a retarget, not a compatibility matrix.
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

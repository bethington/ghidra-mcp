# RFC: Native MCP Runtime

**Status**: Draft for community review  
**Audience**: Ghidra MCP users, headless automation users, GUI plugin users, MCP client authors, and sponsors  
**Scope**: Native Java MCP support for headless and GUI modes, with bridge fallback during migration

## Summary

Ghidra MCP currently uses a Python bridge to speak MCP to AI clients and forward calls over HTTP to the Java Ghidra extension or headless server. This works and should remain supported during migration, but it adds another process, another protocol hop, and another deployment surface.

This RFC proposes **Native MCP Runtime**: Ghidra MCP should speak MCP directly from Java in both headless and GUI modes. Headless mode should support MCP over stdio first, then streamable HTTP. GUI mode should support embedded streamable HTTP first, with named pipe or Unix-domain-socket transports considered later if needed.

The Python bridge should remain a supported fallback during migration and may later become a compatibility/proxy layer for legacy clients and special workflows.

## Problem

Current architecture:

```text
AI Tool -> MCP -> bridge_mcp_ghidra.py -> HTTP/UDS/TCP -> Ghidra Java server
```

This architecture has served the project well, but it creates friction:

- headless users need Python even when the runtime is otherwise Java/Ghidra
- every tool call crosses an MCP-to-HTTP translation boundary
- deployment has two runtime surfaces
- bridge-specific static tools need separate lifecycle decisions
- transport and discovery behavior differs across clients
- native MCP conformance depends on the bridge rather than the Java runtime

The long-term target should be:

```text
Headless:
  AI Tool -> MCP stdio/streamable HTTP -> Ghidra Java headless server

GUI:
  AI Tool -> MCP streamable HTTP -> Ghidra GUI plugin
```

## Goals

- Implement native Java MCP support using the official Java MCP SDK directly.
- Include both headless and GUI native MCP in the RFC from the start.
- Support headless stdio first.
- Support headless streamable HTTP second.
- Support GUI embedded streamable HTTP first.
- Keep legacy HTTP and the Python bridge as supported fallback during migration.
- Reuse the existing `@McpTool` annotation system as the runtime source of truth.
- Adapt `AnnotationScanner` / `EndpointDef` into MCP tool specifications.
- Expose all annotation-scanned tools from day one.
- Classify Python bridge helper tools as port, replace, or retire.
- Support one MCP server per Ghidra instance first, with future coordinator/discovery protocol.
- Validate native MCP with conformance tests and endpoint/schema parity tests.

## Non-goals

- Do not remove `bridge_mcp_ghidra.py` abruptly.
- Do not hand-write 225+ MCP tools.
- Do not make `tests/endpoints.json` the runtime source of truth.
- Do not require GUI mode to own stdio.
- Do not solve all multi-instance coordination in the first milestone.

## Proposed Runtime Model

```text
@McpTool annotations
  Runtime source of tool metadata and handlers.

AnnotationScanner
  Discovers services and produces descriptors/endpoint handlers.

MCP adapter
  Converts descriptors and handlers into Java MCP SDK tool specifications.

Native transports
  Headless stdio, headless streamable HTTP, GUI streamable HTTP.

Legacy HTTP
  Kept as fallback during migration.

Python bridge
  Supported fallback first; possible compatibility/proxy layer later.
```

The endpoint catalog remains important, but as a validation artifact:

```text
annotations are runtime truth
tests/endpoints.json validates parity and drift
```

## Transports

### Headless

Phase order:

```text
1. stdio
2. streamable HTTP
3. keep legacy HTTP fallback throughout
```

Headless stdio is the cleanest way to eliminate the Python bridge for local MCP clients.

### GUI

GUI mode should not try to own stdio as the first native path. The GUI plugin lives inside Ghidra's JVM and has different lifecycle constraints.

Phase order:

```text
1. embedded streamable HTTP MCP server
2. named pipe or Unix-domain-socket MCP transport later if useful
3. keep Python bridge fallback during migration
```

## Java MCP SDK

Use the official Java MCP SDK directly.

Initial dependency approach:

```text
Jackson 2 via the SDK's Jackson 2 module
```

Mitigation:

```text
shade/relocate SDK JSON dependencies if GUI plugin classloading conflicts appear
```

This avoids building a custom MCP implementation while preserving a fallback plan for Ghidra classloader constraints.

## Tool Adapter

The MCP adapter should convert existing annotation-scanned tools into SDK tool specs:

```text
Tool name
  Derived from endpoint path using the same MCP-safe normalization rules.

Description
  From @McpTool description and category/group metadata.

Input schema
  Derived from @Param annotations and existing ToolDescriptor metadata.

Handler
  Calls the existing EndpointDef handler directly, bypassing HTTP serialization.

Response
  Returns the same JSON-compatible response shapes users expect today.
```

The adapter should preserve current behavior for:

- query/body parameter binding
- default values
- semantic address parameters
- write/dry-run behavior
- errors
- tool categories/groups
- all annotation-scanned services

Lazy tool groups may be preserved as an optional optimization later, but the first native implementation should expose all annotation-scanned tools to prove broad parity.

## Bridge Helper Tool Classification

The Python bridge currently provides helper behavior beyond simple endpoint forwarding. Native MCP should classify each helper as:

```text
port
  Native mode still needs this capability as a Java MCP tool.

replace
  Native runtime provides an equivalent through different lifecycle semantics.

retire
  Helper only existed because of the bridge architecture.
```

Examples to classify:

- instance discovery
- connect/switch instance
- lazy tool-group loading
- debugger proxy helpers
- bridge health/status helpers
- address normalization helpers
- transport fallback helpers

Helpers needed in native mode should be ported to Java MCP tools.

## Multi-instance Model

First implementation:

```text
one MCP server per Ghidra instance/project
```

This gives simple lifecycle and clear state. It also matches what many MCP clients expect: one configured server entry equals one tool context.

Future:

```text
coordinator/discovery protocol
```

A later coordinator could discover multiple GUI/headless instances, expose instance metadata, and help clients switch or connect intentionally.

## Migration Strategy

Native MCP should be additive:

```text
existing Python bridge: supported fallback
legacy HTTP: supported fallback
native headless stdio: new path
native headless streamable HTTP: new path
native GUI streamable HTTP: new path
```

Over time, docs can steer new headless users toward native MCP while keeping bridge configs working.

Long-term bridge role:

```text
compatibility/proxy layer for legacy clients and special workflows if needed
```

## Testing Plan

First acceptance gate:

```text
MCP conformance tests
endpoint/schema parity tests
```

Full phased testing:

```text
MCP conformance tests
  Verify protocol correctness through the official SDK path.

Endpoint/schema parity tests
  Ensure native MCP exposes the same annotation-scanned tool surface.

Golden JSON-RPC transcript tests
  Catch accidental protocol/response regressions.

Existing unit/integration tests
  Continue validating service behavior and endpoint catalog drift.
```

Specific cases:

- all annotation-scanned tools are exposed natively
- MCP-safe tool naming matches bridge naming where possible
- parameter schemas match existing `/mcp/schema`
- write endpoints preserve safety behavior
- errors are structured consistently
- headless stdio starts and handles tool calls
- headless streamable HTTP starts and handles tool calls
- GUI streamable HTTP starts/stops with plugin lifecycle
- bridge fallback remains functional

## Implementation Phases

### Phase 1: Headless Native MCP over Stdio

- Add official Java MCP SDK dependencies.
- Add `McpToolAdapter`.
- Create native headless MCP entry point or mode.
- Expose all annotation-scanned tools.
- Keep legacy HTTP mode.
- Add MCP conformance and parity tests.

Acceptance criteria:

- A local MCP client can run the headless server without `bridge_mcp_ghidra.py`.
- All annotation-scanned tools are available.
- Existing HTTP fallback still works.

### Phase 2: Headless Streamable HTTP

- Add streamable HTTP transport for native headless MCP.
- Document local and remote client configuration.
- Validate auth/bind safety expectations.

Acceptance criteria:

- Headless native MCP supports both stdio and streamable HTTP.
- Remote/server deployments no longer require the Python bridge for MCP transport.

### Phase 3: GUI Native MCP over Embedded Streamable HTTP

- Add GUI plugin native MCP streamable HTTP server.
- Integrate with plugin lifecycle and server status UI.
- Validate classloader behavior with SDK/Jackson dependencies.
- Apply shading/relocation if needed.

Acceptance criteria:

- A client can connect directly to the GUI plugin over MCP streamable HTTP.
- GUI native MCP exposes annotation-scanned tools.
- Legacy bridge + HTTP remains available.

### Phase 4: Bridge Helper Migration

- Classify bridge helper tools.
- Port required helpers to Java MCP tools.
- Replace or retire bridge-specific helpers.
- Document behavior differences.

Acceptance criteria:

- Native mode covers the helper workflows users need.
- Bridge-only helpers are documented as legacy or unnecessary.

### Phase 5: Coordinator and Discovery

- Design instance discovery/coordinator protocol.
- Support multiple Ghidra instances intentionally.
- Consider named pipe/UDS MCP transports for GUI if streamable HTTP is insufficient.

Acceptance criteria:

- Multi-instance users have a native path that does not depend on bridge-specific discovery.

## Funding and Prioritization

This should be framed as a sponsored milestone: **Native MCP Runtime**.

The work is significant because it spans protocol integration, Java SDK dependencies, transport support, GUI/headless lifecycle differences, adapter design, bridge migration, conformance testing, classloader mitigation, docs, and compatibility guarantees.

Sponsors may support the overall milestone or mention a subpart:

- headless native MCP over stdio
- headless streamable HTTP
- GUI streamable HTTP
- MCP SDK adapter
- bridge helper migration
- conformance testing
- classloader/shading hardening
- multi-instance coordinator

Funding helps prioritize maintainer time while keeping the migration public, reviewable, and compatible with existing users.

## Open Questions for Review

1. Which clients would use native headless stdio immediately?
2. Which clients need native streamable HTTP first?
3. Should GUI native MCP require authentication by default?
4. Which bridge helper tools are still needed in native mode?
5. How closely must native MCP tool names match bridge-generated tool names?
6. Should lazy tool groups be preserved in native mode or replaced by full tool exposure?
7. What classloader/dependency constraints should GUI plugin users test early?
8. Should the coordinator/discovery protocol be part of the first release or a later milestone?
9. How long should the Python bridge remain first-class after native MCP ships?
10. Which parts of this milestone are worth sponsoring first?

## Suggested Review Prompt

Use this text when opening a GitHub Discussion or issue:

```markdown
We are considering a sponsored milestone called **Native MCP Runtime**.

The proposed design would let Ghidra MCP speak MCP directly from Java. Headless mode would support stdio first and streamable HTTP second. GUI mode would support embedded streamable HTTP first. The existing Python bridge and legacy HTTP transport would remain supported fallbacks during migration.

The implementation would use the official Java MCP SDK, adapt the existing `@McpTool` / `AnnotationScanner` system into MCP tools, expose all annotation-scanned tools from day one, and validate compatibility with MCP conformance plus endpoint/schema parity tests.

Please review the RFC and comment especially on:

- Whether you would use native headless stdio, streamable HTTP, or GUI streamable HTTP.
- Which bridge helper tools still matter in native mode.
- How important exact tool-name compatibility is.
- What classloader/dependency risks you see in GUI mode.
- Which parts of this milestone you would be willing to sponsor or help test.
```


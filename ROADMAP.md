# Ghidra MCP — Roadmap & Project Direction

This document exists to make the project's direction legible. It is intentionally
short and is updated as priorities shift. For the full tool inventory see
[`tests/endpoints.json`](tests/endpoints.json); for architecture see
[`CLAUDE.md`](CLAUDE.md).

_Last updated: 2026-06-14._

## Guiding principles

- **Thin bridge, fat plugin.** Tool logic lives in the Java service layer and is
  auto-discovered from `@McpTool` annotations. The Python bridge is a generic
  HTTP multiplexer that registers tools dynamically from `/mcp/schema` — there
  is no hand-maintained tool list to keep in sync.
- **Conventions enforced in the tool layer**, not in prompts, so documentation
  output stays consistent across large-scale runs.
- **Bug reports from real users are first-class.** Issues are triaged with a
  reproduction or a clear "can't reproduce / need info" — not closed silently.

## Now (in progress)

- **Tool-context overhead (#267, #153).** The catalog is large. The levers
  already exist — tool groups (`load_tool_group` / `unload_tool_group`),
  `--lazy` startup, and as of v5.x a `search_tools` catalog-search meta-tool so
  agents can run lazy and discover unloaded tools by keyword. Next step:
  evaluate making `--lazy + search_tools` the recommended default once the
  `tools/list_changed` story is solid across common clients.
- **Transport modernization.** `streamable-http` is supported and recommended;
  `sse` is deprecated and retained only for backward compatibility. Tracking a
  reported MCP Inspector preflight/`OPTIONS` issue on the HTTP transport.
- **API parameter-name consistency (#210).** Normalize `address` vs
  `function_address`, `new_name` vs `newName` across endpoints.

## Next

- **Reference write tools (#298).** `add_memory_reference` / `remove_reference`
  to complement the read-side xref tools (community PR #299 under review).
- **Reduce surface area further.** Audit for redundant/overlapping tools that
  can be merged now that `search_tools` exists.
- **Single-process option.** Investigate serving MCP-over-streamable-HTTP
  directly from the Ghidra Java extension to make the Python bridge optional.
  Larger architectural change — scoped as a future direction, not a quick fix.

## Process commitments

- A pinned issue tracks current direction; this file is the canonical source.
- Issues are not auto-closed by templated messages without a human decision.
- Dependency bumps flow through Dependabot and are batched after CI is green.

## How to influence the roadmap

Open an issue describing the problem (not just the solution) with a concrete
repro or use case. Feature requests with a PR attached move fastest.

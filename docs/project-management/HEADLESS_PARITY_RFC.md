# RFC: Headless Parity for Automation and AI Workflows

**Status**: Draft for community review  
**Audience**: Ghidra MCP users, contributors, automation operators, and sponsors  
**Scope**: Endpoint, workflow, and operational parity between GUI and headless modes

## Summary

Ghidra MCP supports both GUI and headless operation, but the two modes do not yet have a crisp public parity contract. This makes it harder for users to know which workflows can run unattended, harder for contributors to add endpoints safely, and harder for maintainers to prevent regressions.

This RFC proposes strict headless parity unless technically impossible, starting with the function documentation workflow. The first concrete deliverable should be a GUI-vs-headless parity matrix in `tests/endpoints.json`, enforced by tests and exposed through docs.

## Problem

Headless mode is essential for long-running automation, CI, batch documentation, and server-side reverse-engineering workflows. Today, users still need to discover gaps through trial and error:

- Some endpoints work in GUI mode but not headless mode.
- Some GUI-only behavior depends on CodeBrowser selection, active tools, or Swing context.
- Some workflows are technically possible headlessly, but the endpoint contract is not documented.
- The endpoint catalog tracks the API surface, but not headless compatibility.
- Contributors do not have one obvious place to mark whether a new endpoint supports headless mode.

The result is uncertainty for automation users and drift risk for the project.

## Goals

- Define strict parity as the engineering posture: every GUI endpoint should have a headless equivalent unless Ghidra APIs make it technically impossible.
- Put compatibility metadata in `tests/endpoints.json` so the matrix can be tested.
- Prioritize endpoints needed by automation and AI function documentation.
- Include safe write operations needed for documentation workflows.
- Reuse GUI validation and transaction rules in headless mode.
- Keep debugger parity out of this RFC and track it as a separate candidate feature.
- Return structured unsupported responses for endpoints that cannot work headlessly.
- Use the RFC as a fundable milestone with clear phases and acceptance criteria.

## Non-goals

- Do not make debugger parity part of the first headless parity milestone.
- Do not relax write safety to achieve superficial parity.
- Do not hide unsupported GUI-only endpoints from tool discovery without explanation.
- Do not require every impossible GUI-specific interaction to have fake headless semantics.

## Definition of Parity

This RFC treats headless parity as three related contracts:

```text
Endpoint parity
  Every GUI endpoint exists in headless mode where Ghidra APIs allow it.

Workflow parity
  Important AI and automation workflows can run headlessly end to end.

Operational parity
  Headless mode can be installed, launched, monitored, recovered, and tested
  with the same confidence as GUI mode.
```

The first milestone should use endpoint parity as the measurable foundation and the function documentation workflow as the acceptance scenario.

## First Target Workflow

The first target workflow is function documentation:

```text
1. Open or select a program.
2. Locate a function by name or address.
3. Decompile and inspect function metadata.
4. Inspect variables, parameters, xrefs, strings, and related data.
5. Rename functions and variables.
6. Apply comments.
7. Set variable types and function signatures.
8. Run completeness/verification analysis.
9. Repeat safely across many functions.
```

This workflow is the strongest fit for unattended AI assistance and batch documentation.

## Write Safety

Headless parity should include safe writes required for documentation:

- function rename
- variable rename
- comments
- variable types
- function signatures
- related documentation metadata

Write behavior should reuse the same validation and transaction rules as GUI mode. Headless-specific tests should prove the same safety expectations hold without GUI state.

## Unsupported Endpoints

When an endpoint cannot be supported headlessly, it should remain discoverable and return a structured response:

```json
{
  "error": "unsupported_in_headless",
  "reason": "Requires active CodeBrowser selection",
  "gui_endpoint": "/get_current_address",
  "headless_status": "unsupported"
}
```

This is preferred over hiding the endpoint from `/mcp/schema` because agents and users can understand that the capability exists but is not available in the current runtime mode.

## Endpoint Catalog Metadata

The parity matrix should live in `tests/endpoints.json`, extending each endpoint entry with compatibility metadata.

Example:

```json
{
  "path": "/decompile_function",
  "method": "GET",
  "category": "decompile",
  "params": ["address", "program"],
  "description": "Decompile function",
  "compatibility": {
    "gui": true,
    "headless": true,
    "headless_status": "full",
    "reason": "",
    "workflows": ["function_docs", "batch_docs"],
    "requirements": {
      "requires_project": true,
      "requires_program": true,
      "requires_selection": false,
      "requires_codebrowser": false,
      "requires_gui_tool": false,
      "writes_project": false
    }
  }
}
```

Suggested `headless_status` values:

```text
full
  Equivalent behavior is available in headless mode.

partial
  Headless behavior exists but has documented limitations.

unsupported
  Endpoint is intentionally unavailable in headless mode.

unknown
  Not yet classified.
```

Suggested workflow tags:

```text
function_docs
batch_docs
readonly_exploration
project_management
datatype_work
comments
renaming
analysis
emulation
server
debugger
```

Suggested technical requirement fields:

```text
requires_project
requires_program
requires_selection
requires_codebrowser
requires_gui_tool
requires_trace
writes_project
writes_program
opens_program
long_running
```

## Testing Plan

The first milestone should add tests that enforce the metadata contract before requiring full implementation for every endpoint.

Core tests:

- Every endpoint in `tests/endpoints.json` has compatibility metadata.
- `headless_status` is one of the allowed values.
- `unsupported` entries must include a non-empty reason.
- `function_docs` endpoints cannot remain `unknown`.
- Write endpoints tagged for `function_docs` must identify write requirements.
- Annotation-scanned Java endpoints and the endpoint catalog stay in sync.
- Headless schema exposes unsupported endpoints with structured unsupported behavior.

Later tests:

- Live headless smoke tests for the function documentation workflow.
- Release-regression tests comparing GUI and headless endpoint behavior.
- Generated docs from compatibility metadata.

## Implementation Phases

### Phase 1: Parity Matrix and Tests

- Add `compatibility` metadata to `tests/endpoints.json`.
- Add unit/offline tests for metadata completeness and validity.
- Classify function-documentation endpoints first.
- Add docs explaining compatibility statuses.

Acceptance criteria:

- CI fails when an endpoint lacks compatibility metadata.
- Function-documentation endpoints are classified.
- Unsupported endpoints have explicit reasons.

### Phase 2: Function Documentation Headless Parity

- Implement or repair headless endpoints needed by the function documentation workflow.
- Include safe writes: rename, comments, variable types, and function signatures.
- Reuse GUI validation and transaction rules.
- Add live headless smoke coverage for the workflow.

Acceptance criteria:

- A documented function can be read, modified, scored, and verified in headless mode.
- The workflow does not require CodeBrowser or Swing state.

### Phase 3: Broader Automation Parity

- Expand classification and support to readonly exploration, datatype work, project management, emulation, and batch analysis.
- Add generated compatibility docs from `tests/endpoints.json`.
- Add release-regression checks for high-value endpoint groups.

Acceptance criteria:

- Most non-GUI-specific endpoint categories are `full` or `partial`.
- Remaining unsupported endpoints have documented Ghidra API constraints.

### Phase 4: Operational Parity

- Improve headless launch, monitoring, setup, and recovery docs.
- Align health/status reporting with GUI mode.
- Ensure recovery RFC work can treat headless mode as a first-class target.

Acceptance criteria:

- Headless mode has clear setup, launch, health, and troubleshooting guidance.
- Health/status responses expose enough information for automation and recovery.

## Out of Scope: Debugger Parity

Debugger parity should be a separate RFC. It is valuable, but it has different risks:

- platform-specific backends
- dbgeng vs gdb/lldb behavior
- trace/session lifecycle
- runtime process safety
- live target state

This headless parity RFC should mention debugger endpoints in the matrix, but not require debugger parity as part of the first milestone.

## Funding and Prioritization

This is a significant cross-cutting effort: endpoint classification, Java headless implementation work, write-safety validation, catalog tests, live smoke tests, docs, and release-regression coverage.

The proposed funding shape is a sponsored milestone with clear phases and acceptance criteria. Community funding helps decide whether this moves ahead of other large roadmap work.

Sponsors may support the overall milestone or mention a specific area, such as:

- function documentation parity
- safe write parity
- datatype parity
- project-management parity
- headless CI/release testing
- operational docs and recovery alignment

Funding does not buy private control of the design. It helps prioritize maintainer time while keeping the implementation broadly useful and maintainable.

## Open Questions for Review

1. Are the proposed compatibility fields enough, or should the catalog include additional requirements?
2. Which function-documentation endpoints are most important to classify first?
3. Should unsupported GUI-only endpoints remain in `/mcp/schema` by default in headless mode?
4. What structured error shape would be most useful to MCP clients and AI agents?
5. Should headless write operations require an additional runtime guard, or is reusing GUI validation enough?
6. Which live headless smoke tests would best represent real community workflows?
7. What headless workflows outside function documentation should be prioritized next?
8. Should operational parity be part of this milestone or a follow-up RFC?

## Suggested Review Prompt

Use this text when opening a GitHub Discussion or issue:

```markdown
We are considering a sponsored milestone for headless parity in Ghidra MCP.

The proposed design treats strict parity as the default: every GUI endpoint should work headlessly unless Ghidra APIs make it technically impossible. The first deliverable would be a compatibility matrix in `tests/endpoints.json`, enforced by tests. The first workflow target would be AI function documentation, including safe writes for rename, comments, variable types, and function signatures.

Please review the RFC and comment especially on:

- Which endpoints or workflows you need headlessly.
- Whether unsupported GUI-only endpoints should remain visible in tool discovery.
- Whether the proposed compatibility metadata is enough.
- Whether headless writes should require additional runtime guards.
- Which parts of this milestone you would be willing to sponsor or help test.
```


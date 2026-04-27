# RFC: Dynamic Knowledge Validation

**Status**: Draft for community review  
**Audience**: Ghidra MCP users, reverse engineers, debugger workflow users, and sponsors  
**Scope**: Live debugger evidence capture for validating and expanding the Ghidra knowledge corpus

## Summary

Ghidra MCP has static analysis, documentation, emulation, and live debugger tooling. The next step is to connect those pieces into a higher-level workflow: use runtime evidence to verify, correct, and expand the knowledge already documented in Ghidra.

This RFC proposes **Dynamic Knowledge Validation**. The debugger is the instrument, but the product is structured evidence: runtime captures, normalized observations, validation findings, and reviewable reports that can feed back into function documentation, prototypes, structures, comments, and future corpus workflows.

Phase 1 should focus on **Runtime Prototype Validation** using non-invasive debugger capture: set temporary function entry/exit breakpoints, capture registers, stack arguments, return values, call stacks, and hit counts, then report whether the observed runtime behavior supports or challenges the current Ghidra prototype.

## Problem

Static documentation can be wrong or incomplete:

- prototypes may have the wrong calling convention
- argument count or argument types may be guessed
- return values may be undocumented
- plate comments may contain inferred behavior that was never observed
- global state and table values may only become meaningful at runtime
- structure fields may be hard to identify from static access patterns alone

The existing debugger tools expose useful primitives, but validating knowledge at scale requires repeatable evidence workflows, structured reports, and a way to connect findings back to the documented corpus.

## Goals

- Treat debugger workflows as dynamic knowledge acquisition, not just debugger convenience.
- Validate and expand the static Ghidra documentation corpus.
- Support runtime validation of documented functions first.
- Validate prototypes first: argument values, calling convention, return values, and call stacks.
- Design for runtime data structure discovery, behavior tracing, and dynamic call graph evidence later.
- Use a cross-platform evidence model, with Windows/dbgeng for PE targets as the first backend.
- Store concise evidence summaries in Ghidra and produce structured reports.
- Support configurable automation modes, starting with suggest-only.
- Support multiple target selection modes, starting with user-selected functions.
- Use non-invasive temporary capture first, with scripted scenarios later.
- Keep the first safety level observe-only/read-only.
- Expose high-level MCP workflow tools first, while preserving low-level debugger primitives.

## Non-goals

- Do not auto-fix prototypes in the first milestone.
- Do not require instruction-by-instruction tracing for initial validation.
- Do not mutate target process memory or registers in the first milestone.
- Do not make Windows/dbgeng assumptions part of the evidence schema.
- Do not replace static analysis, emulation, or function documentation workflows.

## Dynamic Knowledge Targets

The full RFC should support these targets in phases:

```text
runtime validation of documented functions
  Verify prototypes, behavior claims, argument use, return values, and call paths.

runtime data structure discovery
  Observe pointer fields, allocation patterns, field reads/writes, object lifetimes,
  tables, vtables, state machines, and flags.

runtime call graph and behavior tracing
  Capture real caller/callee paths, hot functions, branch behavior, event-driven flows,
  and scenario-specific execution.
```

First milestone:

```text
Runtime Prototype Validation
```

## Phase 1: Runtime Prototype Validation

The first milestone should collect evidence at function entry and exit:

```text
function entry
  registers
  stack slots
  decoded argument observations
  call stack
  thread id
  module/runtime address
  hit count

function exit
  return register/value
  output registers where relevant
  optional post-call stack/register snapshot
```

This evidence can validate or challenge:

```text
calling convention
argument count
argument locations
argument value shapes
pointer/null patterns
return value behavior
real callers
static-to-runtime address mapping
```

## Evidence Model

Use a debugger-agnostic evidence model:

```json
{
  "target": {
    "program": "/Mods/PD2-S12/D2Common.dll",
    "function": "GetSkillManaCost_9d00",
    "static_address": "0x6fcee520",
    "runtime_address": "0x1234e520"
  },
  "backend": {
    "platform": "windows",
    "engine": "dbgeng"
  },
  "capture": {
    "hit_count": 5,
    "entry": [
      {
        "timestamp": "2026-04-25T22:30:00Z",
        "thread_id": 1234,
        "registers": {"EAX": "0x0", "ECX": "0x6ff00000"},
        "stack": [{"offset": 4, "value": "0x00000001"}],
        "call_stack": ["CallerA", "CallerB"]
      }
    ],
    "exit": [
      {
        "return_register": "EAX",
        "return_value": "0x0000002a"
      }
    ]
  },
  "observations": {
    "argument_count_min": 2,
    "possible_calling_convention": "stdcall",
    "return_values": ["0x2a", "0x0"],
    "confidence": "medium"
  }
}
```

First milestone reports should include raw captures plus basic normalized observations.

## Storage and Reporting

The full design should support:

```text
Ghidra-attached evidence summary
  Concise function-level summary visible in Ghidra.

external evidence database
  JSON/SQLite or similar storage for large-scale querying and repeated runs.

Markdown/JSON validation reports
  Reviewable output for humans, agents, and team workflows.
```

First milestone:

```text
write concise evidence summaries into Ghidra
produce structured Markdown/JSON reports
```

## Automation Modes

The RFC should support:

```text
suggest-only
  Collect evidence and produce findings, but do not change prototypes.

review-required
  Stage proposed prototype/comment changes for human approval.

auto-apply-with-thresholds
  Apply high-confidence changes when configured.
```

First milestone:

```text
suggest-only
```

## Target Selection

The full design should support:

```text
selected functions
score-filtered functions
uncertainty-filtered functions
module-wide runs
scenario-linked functions
```

First milestone:

```text
user-selected functions
```

This keeps early validation focused and easier to debug.

## Execution Control

The full design should support:

```text
non-invasive temporary capture
  Set temporary breakpoints, resume, capture, restore debugger state.

interactive capture
  User drives execution; tools capture when relevant breakpoints hit.

scripted scenario capture
  Launch/attach, run setup steps, trigger behavior, capture evidence.
```

First milestone:

```text
non-invasive temporary capture
```

Scripted scenarios should come later because they are the path to repeatable corpus validation.

## Safety Levels

The RFC should define configurable safety levels:

```text
observe-only
  Breakpoints, registers, memory reads, call stacks. No memory/register writes.

controlled-intervention
  Limited, explicit memory/register writes for specific experiments.

experimental
  Advanced target manipulation with strong warnings and audit logs.
```

First milestone:

```text
observe-only/read-only debugger operations
```

## MCP Tool Surface

The full RFC should support both high-level workflow tools and low-level debugger primitives.

First milestone workflow tools:

```text
debugger_validate_function
  Start a runtime validation capture for a selected function.

debugger_validation_status
  Inspect active or completed validation jobs.

debugger_validation_report
  Return structured evidence, observations, and suggested follow-up.
```

Later workflow tools:

```text
debugger_validate_batch
debugger_collect_structure_evidence
debugger_trace_behavior_scenario
debugger_dynamic_call_graph
debugger_evidence_inventory
debugger_apply_validation_findings
```

Low-level primitives should remain available or continue evolving separately:

```text
attach/detach/status
modules
static-to-runtime and runtime-to-static mapping
breakpoints
continue/step
registers
memory reads
stack traces
argument reads
function tracing
watchpoints
```

## Platform Plan

Use a cross-platform abstraction with Windows/dbgeng first:

```text
Design contract
  debugger-agnostic evidence model and workflow semantics.

First backend
  Windows/dbgeng for PE targets.

Later backends
  Linux/gdb and macOS/lldb.
```

This matches current Windows PE-heavy workflows while keeping the community path open.

## Relationship to Other RFCs

This RFC complements:

- `FUNCTION_DOCUMENTATION_SCALE_RFC.md`: dynamic evidence can validate generated documentation.
- `BSIM_CORPUS_RFC.md`: runtime evidence can help interpret and propagate high-confidence matches.
- `HEADLESS_PARITY_RFC.md`: future dynamic validation may need headless or service-mode execution support.
- `GHIDRA_RECOVERY_RFC.md`: long debugger captures benefit from recovery and clear failure states.

## Testing Plan

Unit tests:

- evidence model serialization
- observation normalization
- prototype validation heuristics
- report generation
- target selection
- safety-level enforcement
- backend abstraction behavior

Integration tests:

- mocked debugger backend captures
- static-to-runtime mapping behavior
- temporary breakpoint lifecycle
- validation job status transitions
- report generation from captured evidence

Live tests:

- small Windows/dbgeng fixture when available
- attach, capture entry/exit evidence, detach/cleanup
- verify no memory/register writes in observe-only mode

## Implementation Phases

### Phase 1: Runtime Prototype Validation

- Define evidence schema.
- Add high-level validation tools.
- Implement Windows/dbgeng capture using temporary entry/exit breakpoints.
- Capture registers, stack slots, return values, call stacks, and hit counts.
- Add basic normalized observations.
- Write concise summaries into Ghidra.
- Produce Markdown/JSON reports.
- Keep mode suggest-only and observe-only.

Acceptance criteria:

- A user-selected function can be validated at runtime.
- The report includes raw evidence and basic prototype observations.
- No prototype changes are applied automatically.
- Debugger state is cleaned up after capture.

### Phase 2: Structured Findings and Review

- Add review-required mode.
- Add suggested prototype/comment updates.
- Add confidence scoring.
- Add dashboard/report integration where useful.

Acceptance criteria:

- Users can review validation findings before applying changes.
- Findings explain which captures support each suggestion.

### Phase 3: Runtime Data Structure Discovery

- Add watchpoint/memory-read workflows for pointer fields and structure offsets.
- Capture field read/write evidence.
- Produce structure refinement suggestions.

Acceptance criteria:

- Runtime field access evidence can be attached to structures/functions.
- Suggestions are reviewable and traceable to captures.

### Phase 4: Behavior and Scenario Tracing

- Add scripted scenario definitions.
- Add dynamic call graph and branch/path evidence.
- Support repeatable validation scenarios.

Acceptance criteria:

- Users can run repeatable dynamic scenarios and compare reports across runs.

### Phase 5: Cross-platform Backends

- Generalize backend provider interface.
- Add Linux/gdb support.
- Add macOS/lldb support where practical.

Acceptance criteria:

- The same evidence/report model works across supported debugger backends.

## Funding and Prioritization

This should be framed as a sponsored milestone: **Dynamic Knowledge Validation**.

Phase 1 is **Runtime Prototype Validation**.

This is significant work because it spans debugger lifecycle reliability, static-to-runtime mapping, evidence modeling, report generation, Ghidra annotation, safety controls, tests, and platform-specific backend behavior. Community funding helps signal that dynamic validation should move ahead of other major roadmap items.

Sponsors may support the overall milestone or mention a subpart:

- runtime prototype validation
- evidence report format
- Ghidra evidence summaries
- temporary breakpoint capture
- scripted scenarios
- runtime structure discovery
- dynamic call graph tracing
- Linux/gdb or macOS/lldb backend support

Funding helps prioritize maintainer time while keeping the design public, reviewable, and broadly useful.

## Open Questions for Review

1. Which runtime facts are most valuable to validate first: prototypes, behavior claims, globals, structures, or call paths?
2. Which targets/platforms should be prioritized after Windows/dbgeng?
3. What evidence summary should be written back into Ghidra without cluttering comments?
4. What report format would be most useful for review and future automation?
5. How many runtime samples are enough before a finding becomes high confidence?
6. Should runtime prototype validation ever auto-apply changes?
7. What safety levels are acceptable for live targets?
8. What scripted scenarios would make this valuable for repeatable corpus validation?
9. How should dynamic evidence interact with existing function documentation scores?
10. Which parts of this milestone are worth sponsoring first?

## Suggested Review Prompt

Use this text when opening a GitHub Discussion or issue:

```markdown
We are considering a sponsored milestone called **Dynamic Knowledge Validation**.

The proposed design uses the live debugger to validate and expand the knowledge already documented in Ghidra. Phase 1, **Runtime Prototype Validation**, would collect non-invasive runtime evidence for selected functions: entry/exit breakpoints, registers, stack arguments, return values, call stacks, hit counts, normalized observations, Ghidra-attached summaries, and Markdown/JSON reports.

The first backend would be Windows/dbgeng for PE targets, but the evidence model would be designed to support gdb/lldb later.

Please review the RFC and comment especially on:

- Which runtime facts you most want to validate.
- Whether suggest-only is the right first automation mode.
- What evidence should be written back into Ghidra.
- What scripted scenarios would help your workflows.
- Which parts of this milestone you would be willing to sponsor or help test.
```


# RFC: Function Documentation at Scale

**Status**: Draft for community review  
**Audience**: Ghidra MCP users, AI workflow operators, reverse-engineering teams, and sponsors  
**Scope**: Reliable batch documentation, review UX, quality gates, provider policy, and dashboard workflows

## Summary

Ghidra MCP already enables AI-assisted function documentation through its tool surface and the internal `fun-doc` workflow. The next step is to turn the lessons from that workflow into a community-reviewed, fundable roadmap for documenting large binaries reliably.

This RFC proposes **Function Documentation at Scale**: a batch documentation pipeline that can prioritize functions, run controlled parallel workers, survive Ghidra/model failures, score quality, produce reports, and support a dashboard review flow with queue, progress, diffs, accept/reject, and retry controls.

The first implementation should use function-level jobs as the basic unit while designing toward a hierarchy of workflow jobs, program jobs, and function jobs.

## Problem

Documenting a large binary is not just "call the model on every function." Real runs need to handle:

- thousands of functions
- incomplete or misleading decompiler output
- Ghidra offline events
- decompile timeouts
- model/provider errors
- duplicate work after restarts
- bad or low-confidence generated docs
- functions that depend on undocumented callees
- prioritization across many binaries or modules
- review and audit of changes made by AI workers

The internal `fun-doc` tool has proven the value of priority queues, scoring, workers, logs, and a dashboard. Community users need a clear spec for what a supported, scalable version of this should become.

## Goals

- Support reliable unattended batch documentation across many functions.
- Provide a dashboard review UX for queue, progress, generated diffs, accept/reject, and retries.
- Improve documentation quality through prompts, scoring, validation, and configurable thresholds.
- Use function-level jobs first, while designing for workflow/program/function hierarchy.
- Prioritize work using documentation completeness, call graph, xrefs, exports/imports, strings, name quality, and user pins.
- Treat bottom-up call graph ordering as a major weighted signal so leaf functions tend to be documented before callers.
- Persist state so runs resume safely after failures.
- Support failure policies by type.
- Use controlled parallel workers with rate limits and Ghidra serialization awareness.
- Use existing provider configuration first, while designing toward a full provider policy engine.
- Produce run logs, per-function state, Markdown reports, and JSON reports in the first milestone.

## Non-goals

- Do not require fully autonomous writes for every user.
- Do not make model self-critique the only quality gate.
- Do not ignore Ghidra's concurrency constraints.
- Do not make the internal `fun-doc` implementation a required long-term architecture without review.
- Do not make BSim propagation or Ghidra auto-recovery prerequisites for the first milestone, though both can improve later phases.

## Job Model

The full design should support a job hierarchy:

```text
workflow job
  Covers a complete documentation campaign across one or more programs.

program job
  Covers one binary/program within the workflow.

function job
  Covers one function: analyze, document, validate, write or stage, report.
```

First implementation unit:

```text
function job
```

Each function job should track:

```text
program
address
function name
mode
priority score
attempt count
status
failure type
retry policy
score before
score after
provider/model
tool call count
logs/report paths
review state
timestamps
```

## Prioritization

The default strategy should be priority scoring based on importance and current documentation quality.

First scoring signals:

```text
documentation completeness
xrefs and call graph centrality
exports/imports
string references
name quality
user pins/manual priority
bottom-up call graph position
```

Bottom-up call graph ordering should be a major weighted signal, not an absolute rule. Leaf functions should get a boost because documenting callees first often makes caller documentation easier and more accurate. Exports, central functions, user pins, and poor documentation can still raise priority.

Future queue strategies:

```text
priority
manual list
address order
changed-only
bottom-up
top-down
centrality-first
module/folder scoped
```

## Failure Policies

The RFC should classify failures and allow different policy by type:

```text
ghidra_offline
decompile_timeout
model_timeout
model_error
provider_rate_limited
validation_failed
low_confidence
write_failed
tool_contract_error
worker_crashed
```

Default behavior for transient failures:

```text
persist state
mark function retryable
apply backoff
continue where possible
resume later without losing progress
```

Non-transient failures should be visible in reports and dashboard filters.

## Review Modes

The pipeline should support configurable review modes:

```text
suggest-only
  Generate documentation and reports, but do not write to Ghidra.

review-required
  Stage changes for human review before writing.

auto-apply-with-thresholds
  Apply high-confidence changes automatically and send low-confidence results
  to review.
```

Recommended default for mature workflows:

```text
auto-apply high-confidence results
queue low-confidence results for review
```

The first milestone may keep conservative defaults while building the mechanics for these modes.

## Dashboard UX

The first UI target should be the existing `fun-doc` dashboard surface, evolved through review rather than replaced immediately.

Target dashboard capabilities:

```text
queue overview
worker status
progress by program/module
function detail page
score before/after
generated diff
tool call trace
failure reason and retry controls
accept/reject/stage/apply
provider/model status
filter by status, score, failure type, module, provider
Markdown/JSON report links
```

The dashboard should make the pipeline understandable during unattended runs and useful for human-in-the-loop review afterward.

## Provider Policy

First implementation:

```text
use existing provider configuration
add per-mode defaults where needed
```

Full RFC direction:

```text
provider policy engine
model routing by task difficulty
cost caps
provider fallback
provider retries
rate limits
quality gates
pause/resume by provider
```

The policy engine should be designed carefully because provider behavior directly affects cost, quality, and reliability.

## Quality Gates

The full design should include configurable thresholds for:

```text
completeness score
validation checks
confidence rubric
changed-code/documentation diff review
model self-critique
write safety checks
regression checks after apply
```

No single gate should be the whole safety story. Completeness score and validation checks are the strongest first foundation; diffs and review states make the results auditable.

Possible outcomes:

```text
accepted
auto-applied
queued-for-review
retry-with-fix-mode
retry-with-different-provider
failed
deferred
ignored
```

## Parallelism

The pipeline should support controlled parallel workers with rate limits and Ghidra serialization awareness.

Principles:

- Ghidra requests that must be serialized should remain serialized.
- Model calls can run concurrently within configured limits.
- Writes should be transaction-safe and coordinated.
- Worker state must be persisted often enough to survive crashes.
- Provider rate limits should slow the queue instead of corrupting state.

Future architecture may split read, model, and write worker pools, but the first implementation should keep the model understandable.

## Artifacts

First milestone:

```text
run logs
per-function state
Markdown batch reports
JSON batch reports
```

Later phases:

```text
review bundles
exportable documentation bundles
cross-version propagation bundles
team audit reports
dashboard-generated reports
```

Reports should make it clear what was proven, inferred, unresolved, changed, skipped, or failed.

## Relationship to Other RFCs

This RFC pairs naturally with:

- `GHIDRA_RECOVERY_RFC.md`: improves resilience when Ghidra goes offline.
- `HEADLESS_PARITY_RFC.md`: enables unattended documentation outside GUI sessions.
- `BSIM_CORPUS_RFC.md`: can provide similarity matches and later propagation suggestions.

None of these should block the first milestone, but each can improve later phases.

## Testing Plan

Unit tests:

- priority scorer
- bottom-up call graph weighting
- function job state transitions
- retry/backoff policy
- failure classification
- review mode behavior
- provider policy selection
- quality gate outcomes
- report generation

Integration/performance tests:

- worker lifecycle
- provider timeout handling
- Ghidra offline handling
- decompile timeout handling
- dashboard/event bus behavior
- state atomicity and resume
- controlled parallelism

Live smoke tests:

- document a small fixture set
- produce Markdown/JSON reports
- verify scoring before/after
- verify review queue states

## Implementation Phases

### Phase 1: Reliable Function Jobs

- Define function job schema.
- Implement priority scoring with completeness, xrefs/call graph, exports/imports, strings, name quality, pins, and bottom-up weighting.
- Persist resumable per-function state.
- Classify failures and apply retry/backoff policy.
- Produce Markdown/JSON batch reports.
- Use existing provider config with per-mode defaults.
- Support controlled parallel workers.

Acceptance criteria:

- A large run can resume after interruption.
- Failed functions remain visible and retryable.
- Reports explain completed, failed, skipped, and review-needed functions.

### Phase 2: Dashboard Review UX

- Evolve the existing `fun-doc` dashboard.
- Add queue/progress/review views.
- Add generated diffs.
- Add accept/reject/retry controls.
- Add filters by score, status, failure type, module, and provider.

Acceptance criteria:

- Users can monitor an active run and review staged results after the run.
- Low-confidence results can be triaged without digging through raw logs.

### Phase 3: Quality and Provider Policy

- Add configurable quality thresholds.
- Add confidence rubric.
- Add provider fallback and cost/rate limits.
- Add retry-with-different-provider policy.
- Add regression checks after apply.

Acceptance criteria:

- Users can tune quality/cost tradeoffs.
- The pipeline can recover from provider failures without losing run state.

### Phase 4: Workflow and Program Jobs

- Add workflow-level and program-level job orchestration.
- Add module/folder scoped runs.
- Add changed-only runs.
- Add dashboard rollups by workflow/program/module.

Acceptance criteria:

- Users can run a documentation campaign across multiple programs with coherent progress and reporting.

### Phase 5: Propagation and Bundles

- Add exportable documentation bundles.
- Add cross-version propagation bundles.
- Integrate BSim suggestions where available.
- Add reviewable apply plans.

Acceptance criteria:

- Documentation work can be reused across versions while preserving review and audit trails.

## Funding and Prioritization

This should be framed as a sponsored milestone: **Function Documentation at Scale**.

The work is significant because it spans queueing, scoring, model/provider policy, state persistence, dashboard UX, quality gates, failure recovery, reports, tests, and documentation. Community funding helps signal that this should move ahead of other major roadmap items.

Sponsors may support the overall milestone or mention a subpart:

- priority scorer and bottom-up ordering
- reliable resumable function jobs
- dashboard review UX
- provider policy and rate limits
- quality gates and diffs
- reports and export bundles
- headless/unattended operation

Funding helps prioritize maintainer time while keeping the design public, reviewable, and broadly useful.

## Open Questions for Review

1. Which users want fully unattended documentation versus review-required workflows?
2. Which priority signals matter most in real binaries?
3. How strongly should bottom-up call graph ordering influence the default queue?
4. What dashboard review controls are must-have for the first UI milestone?
5. What quality thresholds should decide auto-apply versus review?
6. Which provider/model policies matter most: cost caps, fallback, rate limits, or quality routing?
7. What reports would teams actually share or archive?
8. Should this remain a separate `fun-doc` tool, move closer to the MCP bridge, or become a supported companion package?
9. How much parallelism is safe for common Ghidra setups?
10. Which parts of the workflow are worth sponsoring first?

## Suggested Review Prompt

Use this text when opening a GitHub Discussion or issue:

```markdown
We are considering a sponsored milestone called **Function Documentation at Scale**.

The proposed design would turn the lessons from the internal `fun-doc` workflow into a supported roadmap for reliable batch documentation: prioritized function jobs, bottom-up call graph ordering, controlled parallel workers, failure recovery, provider policy, quality gates, Markdown/JSON reports, and dashboard review with diffs and accept/reject/retry controls.

Please review the RFC and comment especially on:

- Whether you need unattended, review-required, or hybrid documentation.
- Which priority signals should decide what gets documented first.
- What dashboard review features are must-have.
- What quality gates should control auto-apply.
- Which parts of this milestone you would be willing to sponsor or help test.
```


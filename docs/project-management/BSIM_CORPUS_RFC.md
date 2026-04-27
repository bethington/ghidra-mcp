# RFC: BSim Large Corpus Similarity Search

**Status**: Draft for community review  
**Audience**: Ghidra MCP users, reverse engineers with binary corpora, team operators, and sponsors  
**Scope**: BSim-backed corpus indexing, search, inventory, and workflow automation

## Summary

Ghidra MCP already supports cross-binary workflows through function hashes, structural similarity helpers, and documentation propagation prompts. Those workflows are useful, but they do not yet provide a first-class, corpus-scale BSim automation layer.

This RFC proposes a local-first, pluggable BSim corpus system. The first implementation should use Ghidra's existing BSim database tooling, expose simple MCP tools for indexing and search, track job and corpus state, and return transparent similarity scores with default confidence tiers.

Later phases can add higher-level workflow helpers, team/shared corpus backends, propagation suggestions, and provider support for third-party or community corpus services.

## Problem

Reverse engineers often need to answer questions across more than one binary:

- Have I seen this function before?
- Which binaries contain similar code?
- Which functions in this new version correspond to functions I already documented?
- How much of a corpus has been indexed and searched?
- Which matches are strong enough to guide naming or documentation work?

Current Ghidra MCP workflows can use exact hashes, strings, call graphs, and local structural similarity. BSim can provide stronger corpus-scale similarity search, but using it effectively requires setup, indexing, search orchestration, progress tracking, result normalization, and eventual integration with documentation workflows.

Without a first-class MCP workflow, BSim remains powerful but underused by AI agents and unattended automation.

## Goals

- Provide large corpus similarity search as the primary BSim automation goal.
- Use a local-first architecture that supports local, shared-team, and future public/community corpora.
- Design a pluggable backend abstraction.
- Use Ghidra's existing BSim database tooling as the first implementation target.
- Let users index the current program, explicit targets, or recursively scanned directories.
- Track corpus inventory, indexing status, BSim statistics, and later rich binary metadata.
- Expose simple MCP tools first, then higher-level workflow helpers later.
- Return raw BSim scores/ranks and default confidence tiers in the first milestone.
- Defer automatic propagation until search/reporting behavior is trusted.
- Run long operations through jobs with IDs, progress/status, cancellation, and logs.

## Non-goals

- Do not build an official public/community corpus in the first implementation.
- Do not replace existing hash-based cross-version workflows.
- Do not automatically apply names, comments, or signatures in the first milestone.
- Do not reimplement BSim feature extraction when upstream Ghidra tooling can provide it.
- Do not require shared infrastructure for local users.

## Architecture

The design should be local-first but not local-only:

```text
MCP tools
  Start jobs, check status, search functions, inspect corpus inventory.

BSim corpus manager
  Owns target selection, job tracking, inventory, confidence policy, and reports.

Backend provider
  Executes indexing/search against a specific BSim backend.

Initial backend
  Ghidra's existing BSim database tooling.

Future backends
  Shared team service, external worker pool, or third-party/community provider.
```

Recommended first backend:

```text
local_bsim
  Uses Ghidra's existing BSim database tooling and a project-local state store.
```

## Corpus Targets

Users should be able to index:

```text
current program
  Useful for interactive analysis and quick bootstrapping.

explicit targets
  Program paths, project paths, binary paths, or manifest files. This is the
  safest automation default.

recursive scans
  Configured directories with include/exclude filters, dedupe, and limits.
```

Explicit targets should be the safest default for unattended automation.

## Inventory State

The RFC should define rich inventory metadata, but the first milestone should implement only the pieces needed to manage jobs and validate BSim coverage.

First milestone:

```text
target
status
error
timestamps
job id
BSim database id/name
function count
indexed function count
match/search statistics
```

Later metadata:

```text
file hashes
architecture
compiler/language id
program version
symbol/import/export stats
string stats
project path
source provenance
tags
notes
```

State storage should be configurable:

```text
project-local
  First implementation default.

user-global
  Useful for personal corpora shared across projects.

external service
  Useful for teams and future hosted/provider-backed corpora.
```

## Proposed MCP Surface

First milestone tools:

```text
bsim_index_targets
  Start indexing current program, explicit targets, or recursive scans.

bsim_search_function
  Search the configured corpus for functions similar to a function by address,
  name, or program/path reference.

bsim_index_status
  Inspect job progress, indexed targets, failures, and BSim statistics.
```

Future tools:

```text
bsim_cancel_job
bsim_list_corpora
bsim_create_corpus
bsim_corpus_inventory
bsim_search_batch
bsim_compare_versions
bsim_match_report
bsim_propagation_suggestions
bsim_corpus_search_workflow
```

The full design should support both low-level tools and high-level workflow helpers. The first milestone should implement the simple low-level tools.

## Search Result Shape

Search results should be transparent enough for humans and agents:

```json
{
  "query": {
    "program": "/Mods/PD2-S12/D2Common.dll",
    "function": "GetSkillManaCost_9d00",
    "address": "0x6fcee520"
  },
  "corpus": "local",
  "results": [
    {
      "program": "/Versions/1.11/D2Common.dll",
      "function": "FUN_6fcd1234",
      "address": "0x6fcd1234",
      "bsim_score": 0.92,
      "rank": 1,
      "confidence": "high",
      "metadata": {
        "architecture": "x86:LE:32:default",
        "indexed_at": "2026-04-25T22:30:00Z"
      }
    }
  ]
}
```

Confidence policy in the RFC:

```text
raw scores/ranks
  Always returned.

default confidence tiers
  Returned by default for agent ergonomics.

configurable thresholds
  Added as a later phase.
```

First milestone: raw scores/ranks plus default tiers.

## Long-Running Jobs

Indexing and large searches should not run as fragile synchronous calls. Use a job model:

```text
job id
operation type
created/started/finished timestamps
status: queued|running|completed|failed|cancelled
progress counts
current target
warnings/errors
log path or recent log lines
cancel requested
```

First implementation: in-process job queue.

Future evolution: MCP starts jobs while external workers execute them for shared/team corpora.

## Public and Community Corpora

Official public corpus hosting should be deferred. It raises hard questions:

- binary licensing
- malware handling
- privacy and proprietary code
- moderation
- storage and hosting cost
- trust and abuse prevention

The architecture should still allow third-party or community providers later through a backend/provider model. Ghidra MCP should not need to own the first public corpus to make BSim automation useful.

## Propagation

Automatic propagation is out of scope for the first milestone.

Later phases may add:

```text
dry-run propagation suggestions
high-confidence name/comment/signature recommendations
batch review reports
auditable apply operations
undo or rollback plans
confidence-gated writes
```

Propagation should only happen after search results, confidence policy, and reporting are trusted.

## Testing Plan

Unit tests should cover:

- target selection modes
- recursive scan filtering and limits
- job lifecycle state transitions
- cancellation requests
- inventory persistence
- confidence tier assignment
- backend provider selection
- search result normalization

Integration tests should cover:

- local BSim database setup detection
- indexing a small fixture corpus
- searching by function address/name
- failed target handling
- index status and statistics

Release-regression tests should avoid requiring a large corpus. Use small fixtures or mocked BSim backend behavior where possible.

## Implementation Phases

### Phase 1: Local Corpus Index and Search

- Add backend abstraction.
- Implement local BSim backend using Ghidra's existing BSim database tooling.
- Add project-local state.
- Add job queue.
- Add `bsim_index_targets`.
- Add `bsim_search_function`.
- Add `bsim_index_status`.
- Return raw scores/ranks and default confidence tiers.

Acceptance criteria:

- Users can index explicit targets into a local BSim database.
- Users can search for functions similar to a function by address or name.
- Jobs expose status, progress, errors, and basic BSim statistics.
- No automatic propagation occurs.

### Phase 2: Inventory and Reports

- Add richer binary metadata.
- Add corpus inventory views.
- Add match reports.
- Add batch search.
- Add compare-two-versions report.

Acceptance criteria:

- Users can see what is indexed and why a target failed.
- Users can produce a reusable similarity report for a binary or version pair.

### Phase 3: Workflow Helpers

- Add `bsim_corpus_search_workflow`.
- Add agent-friendly guidance in responses.
- Add configurable confidence thresholds.
- Add dry-run propagation suggestions.

Acceptance criteria:

- Agents can run a guided corpus search workflow without manually composing every low-level call.
- Users can inspect suggestions before applying anything.

### Phase 4: Shared and External Backends

- Add shared/team backend configuration.
- Add external worker execution option.
- Add provider interface documentation.
- Add auth/config hooks where needed.

Acceptance criteria:

- Teams can point Ghidra MCP at a shared BSim corpus.
- External providers can integrate without changing core workflow semantics.

### Phase 5: Propagation

- Add auditable propagation of names/comments/signatures.
- Require confidence gates and dry-run review.
- Reuse existing write validation and transaction rules.

Acceptance criteria:

- High-confidence matches can be reviewed and applied safely.
- Applied changes are traceable and reversible where practical.

## Funding and Prioritization

This should be framed as a sponsored milestone: **Large Corpus Similarity Search**.

The work spans BSim setup, backend abstraction, job orchestration, corpus inventory, MCP tool design, confidence policy, result normalization, tests, docs, and later shared-provider architecture. Community funding is a practical signal that this should move ahead of other significant roadmap items.

Sponsors may support the overall milestone or mention a subpart:

- local BSim backend
- indexing workflow
- search workflow
- job queue and cancellation
- corpus inventory
- version comparison reports
- shared/team backend support
- propagation suggestions

Funding helps prioritize maintainer time while keeping the design public, reviewable, and broadly useful.

## Open Questions for Review

1. Which BSim database setup do users already have, if any?
2. Should the first backend assume a local database, PostgreSQL-backed BSim, or both?
3. What target selection mode matters most: current program, explicit targets, recursive scan, or manifest files?
4. What metadata is essential for corpus inventory in real workflows?
5. What default confidence tiers make sense for BSim scores?
6. Should search support one query function at a time first, or batch query from the start?
7. What should cancellation guarantee for long-running indexing jobs?
8. Which reports would be most useful before propagation is implemented?
9. What requirements would teams have for shared corpus backends?
10. Are there legal/privacy constraints that should shape provider support?

## Suggested Review Prompt

Use this text when opening a GitHub Discussion or issue:

```markdown
We are considering a sponsored milestone for BSim-backed large corpus similarity search in Ghidra MCP.

The proposed design is local-first with a pluggable backend architecture. The first implementation would use Ghidra's existing BSim database tooling, add job-based indexing/search, track corpus inventory and BSim statistics, and expose simple MCP tools such as `bsim_index_targets`, `bsim_search_function`, and `bsim_index_status`.

Automatic propagation of names/comments/signatures would be deferred until search results and confidence policy are well tested.

Please review the RFC and comment especially on:

- What kind of corpus you would use this with.
- Which BSim backend/deployment model you already use or want.
- What inventory metadata and reports matter most.
- Whether the first milestone should support batch search.
- Which parts of this milestone you would be willing to sponsor or help test.
```


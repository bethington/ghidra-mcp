# Fundable Roadmap

**Status**: Draft for community discussion  
**Purpose**: Collect large, community-reviewable Ghidra MCP efforts that need meaningful design, implementation, testing, and maintenance time.

## Why This Exists

Ghidra MCP has more good ideas than maintainer hours. Some features are quick fixes, but others are real engineering projects: they cut across the Python bridge, Java plugin, headless server, debugger integration, CI, docs, and release testing.

This roadmap is a way for the community to help prioritize that work.

Comments, test offers, design feedback, and sponsorship all matter. Funding is especially useful as a prioritization signal: it shows which features are important enough that users or organizations want maintainer time focused there.

Funding does not buy private control of the project. It helps move public, reviewable, broadly useful work up the queue.

## How To Signal Interest

- Comment on the RFC or linked GitHub Discussion with your workflow and constraints.
- Sponsor the project and mention the milestone name in your sponsor note.
- Offer test environments, sample projects, fixtures, or validation time.
- Help refine acceptance criteria before implementation starts.
- For organization-backed work, reach out about sponsored development or invoice-based support.

Sponsor link: https://github.com/sponsors/bethington

## Current RFC Milestones

| Milestone | RFC | Primary Value | First Phase | Status |
|---|---|---|---|---|
| Native MCP Runtime | `NATIVE_MCP_RUNTIME_RFC.md` | Java speaks MCP directly in headless and GUI modes, reducing bridge/process complexity | Headless native MCP over stdio | Draft RFC |
| Function Documentation at Scale | `FUNCTION_DOCUMENTATION_SCALE_RFC.md` | Reliable AI documentation across many functions with queueing, scoring, reports, and dashboard review | Reliable function-level jobs | Draft RFC |
| Dynamic Knowledge Validation | `DYNAMIC_KNOWLEDGE_VALIDATION_RFC.md` | Use live debugger evidence to validate and expand the Ghidra knowledge corpus | Runtime Prototype Validation | Draft RFC |
| BSim Large Corpus Similarity Search | `BSIM_CORPUS_RFC.md` | Index and search large binary corpora for similar functions using BSim | Local corpus index and search | Draft RFC |
| Headless Parity | `HEADLESS_PARITY_RFC.md` | Make GUI and headless modes predictable for automation and CI | Endpoint parity matrix and tests | Draft RFC |
| Opt-in Ghidra Recovery and Relaunch | `GHIDRA_RECOVERY_RFC.md` | Recover long-running workflows when Ghidra becomes unavailable | Python-side recovery skeleton | Draft RFC |

## Milestone Summaries

### Native MCP Runtime

Goal: let Ghidra MCP speak MCP directly from Java.

The first phase targets headless stdio using the official Java MCP SDK. Later phases add headless streamable HTTP and GUI embedded streamable HTTP. The Python bridge remains a supported fallback during migration and may become a compatibility/proxy layer later.

Best for sponsors who care about:

- simpler headless deployment
- fewer runtime processes
- direct MCP conformance
- GUI/headless native MCP support
- long-term architecture cleanup

### Function Documentation at Scale

Goal: make AI-assisted documentation reliable across large binaries.

The first phase focuses on resumable function-level jobs, priority scoring, failure policies, controlled parallelism, and Markdown/JSON reports. Later phases expand the existing `fun-doc` dashboard into review, diff, accept/reject, retry, provider policy, and cross-version documentation bundles.

Best for sponsors who care about:

- documenting thousands of functions
- human review of AI-generated docs
- provider cost/quality controls
- overnight or unattended documentation runs
- dashboard-based triage and reporting

### Dynamic Knowledge Validation

Goal: use live debugging to validate and expand the static documentation corpus.

The first phase, Runtime Prototype Validation, captures entry/exit evidence for selected functions: registers, stack arguments, return values, call stacks, hit counts, normalized observations, Ghidra-attached summaries, and structured reports.

Best for sponsors who care about:

- proving function prototypes at runtime
- validating inferred documentation
- discovering structure fields and runtime state
- dynamic call graph and behavior traces
- Windows/dbgeng PE workflows first, with gdb/lldb later

### BSim Large Corpus Similarity Search

Goal: make BSim usable through Ghidra MCP for corpus-scale similarity search.

The first phase uses Ghidra's existing BSim database tooling to index explicit targets into a local corpus and search similar functions by address/name. Later phases add richer inventory, reports, batch search, shared/team backends, provider plugins, and propagation suggestions.

Best for sponsors who care about:

- large binary corpora
- finding reused/similar code
- cross-version matching
- team/shared BSim databases
- future documentation propagation workflows

### Headless Parity

Goal: make headless behavior predictable and enforceable.

The first phase adds compatibility metadata to `tests/endpoints.json`, producing a GUI-vs-headless parity matrix enforced by tests. The first workflow target is function documentation, including safe writes needed for renames, comments, variable types, and function signatures.

Best for sponsors who care about:

- CI and automation
- headless deployments
- endpoint compatibility guarantees
- disposable project testing
- AI workflows without GUI sessions

### Opt-in Ghidra Recovery and Relaunch

Goal: recover gracefully when Ghidra becomes inaccessible during long-running workflows.

The first phase tracks failures, persists last-known project/program state, starts a watchdog, and reconnects/restarts only when explicitly enabled. Later phases add Java health detail, launch/reopen behavior, process ownership policies, and stronger recovery automation.

Best for sponsors who care about:

- unattended batch runs
- overnight documentation jobs
- fewer manual restarts
- reliable Ghidra health monitoring
- safe recovery without surprising GUI users

## Candidate Backlog Items Needing More Scoping

These may become RFCs later, but need more clarification or may be absorbed into the milestones above:

| Candidate | Source | Likely Direction |
|---|---|---|
| Offline/disposable CI test fixtures | GitHub issue `#112`, `docs/TESTING.md` | Could become a CI Reliability RFC or fold into Headless Parity |
| Cross-client discovery/connectivity hardening | GitHub issue `#170` | Could become a Client Compatibility RFC or fold into Recovery/Native MCP |
| Gradle migration completion | `GRADLE_MIGRATION_CHECKLIST.md` | Could become Build and Release Modernization milestone |

Older backlog items such as composable batch queries and P-code dataflow analysis appear to have been mostly addressed by existing endpoints like `analyze_function_complete`, `analyze_for_documentation`, and `analyze_dataflow`.

## Suggested Community Post

Use this text for a pinned GitHub Discussion:

```markdown
Ghidra MCP has several large roadmap ideas that are too significant to treat as quick issues. I have started writing RFCs so the community can review the designs before implementation.

The current fundable roadmap includes:

- Native MCP Runtime
- Function Documentation at Scale
- Dynamic Knowledge Validation
- BSim Large Corpus Similarity Search
- Headless Parity
- Opt-in Ghidra Recovery and Relaunch

If one of these would materially help your workflow, please comment with your use case. Sponsorship is also a strong prioritization signal: it helps me decide where to spend deep implementation time.

Funding does not buy private control of the project. It helps prioritize public, reviewable work that remains broadly useful to the Ghidra MCP community.

Sponsor link: https://github.com/sponsors/bethington
```

## Maintenance Notes

- Keep this roadmap limited to large, sponsor-worthy efforts.
- Keep small bugs and straightforward enhancements in normal issues.
- Add an RFC before implementation when a milestone affects architecture, user workflows, or long-term maintenance.
- Update statuses when an RFC moves from draft to accepted, in progress, shipped, or deferred.


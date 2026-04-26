# Documentation

This directory contains the maintained project guides, reference material, and
release notes for Ghidra MCP.

## What To Read First

- Start in the repo root `README.md` for installation, build, and day-to-day
  usage.
- Read `PROJECT_STRUCTURE.md` for the current layout of the codebase and where
  major subsystems live.
- Read `TESTING.md` for local, CI, and live Ghidra release-regression testing.
- Read `NAMING_CONVENTIONS.md` for naming and file-layout guidance.
- Read `releases/README.md` for version-specific release notes.
- Read `project-management/FUNDABLE_ROADMAP.md` for the draft community
  roadmap of large RFC-sized efforts and sponsorship-priority signals.
- Read `project-management/GHIDRA_RECOVERY_RFC.md` for the draft
  community-review proposal for opt-in Ghidra recovery and relaunch.
- Read `project-management/HEADLESS_PARITY_RFC.md` for the draft
  community-review proposal for GUI/headless parity.
- Read `project-management/BSIM_CORPUS_RFC.md` for the draft
  community-review proposal for BSim-backed large corpus similarity search.
- Read `project-management/FUNCTION_DOCUMENTATION_SCALE_RFC.md` for the draft
  community-review proposal for large-scale AI function documentation.
- Read `project-management/DYNAMIC_KNOWLEDGE_VALIDATION_RFC.md` for the draft
  community-review proposal for debugger-backed runtime evidence workflows.
- Read `project-management/NATIVE_MCP_RUNTIME_RFC.md` for the draft
  community-review proposal for native Java MCP support in headless and GUI modes.

## Directory Layout

```text
docs/
├── README.md
├── PROJECT_STRUCTURE.md
├── NAMING_CONVENTIONS.md
├── HUNGARIAN_NOTATION.md
├── PLATE_COMMENT_BEST_PRACTICES.md
├── GHIDRA_VARIABLE_APIS_EXPLAINED.md
├── JAVA_HANDLER_REFACTORING.md
├── MAVEN_VERSION_MANAGEMENT.md
├── MULTI_PROGRAM_SUPPORT_ANALYSIS.md
├── QUICK_REFERENCE_SCRIPTS.md
├── SESSION_SUMMARY_DOCUMENTATION_SYSTEM.md
├── WORKFLOW_DOCUMENTATION_PROPAGATION.md
├── ORGANIZATION_SUMMARY.md
├── project-management/
├── prompts/
└── releases/
```

## Categories

### Maintained Guides

- Architecture, structure, and naming guidance
- Local, CI, and release-regression testing guidance
- Reverse-engineering workflow notes
- Versioning and release-process documentation

### Prompting Workflows

- Operator prompt docs for function documentation, data typing, and MCP tool use

### Release Notes

- Historical release-specific notes and summaries under `releases/`

### Project History

- Older organization and project-management notes kept for context

## Current Command Surface

The supported operator workflow is Python-first:

- `python -m tools.setup preflight`
- `python -m tools.setup ensure-prereqs`
- `python -m tools.setup build`
- `python -m tools.setup deploy`
- `python -m tools.setup start-ghidra`
- `python -m tools.setup bump-version --new X.Y.Z`

Documentation in this directory should prefer that command surface and should
not point readers at removed wrapper-script workflows.

## Maintenance Rules

- Keep setup/build/deploy guidance aligned with the root `README.md`.
- Put release-specific material under `releases/vX.Y.Z/`.
- Keep historical notes clearly separated from current operator guidance.
- Do not reintroduce references to removed wrapper-script workflows.

# Project Organization Summary

This file is a brief historical note about the documentation reorganization
work. The current source of truth for repo layout is `PROJECT_STRUCTURE.md`.

## What Still Matters

- The repo is documented from a Python-first operator perspective.
- The supported setup/build/deploy/versioning workflow lives under
  `python -m tools.setup`.
- Detailed release notes live under `docs/releases/`.
- Prompt/operator workflow notes live under `docs/prompts/`.

## What Changed Since The Original Cleanup Pass

- Earlier organization notes described larger script inventories and legacy
  wrapper workflows that are no longer part of the supported path.
- The active repo tooling surface has been consolidated around Python helpers in
  `tools/setup/`.
- Structure documentation is now kept intentionally high-level so it does not
  drift every time utility files move.

## Use This Document For

- historical context on why the documentation was reorganized
- a pointer to the maintained docs entry points

## Use These Files For Current Guidance

- `README.md` for setup and usage
- `PROJECT_STRUCTURE.md` for layout
- `NAMING_CONVENTIONS.md` for naming guidance
- `releases/README.md` for release history

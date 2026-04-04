# Release Documentation Index

This directory contains version-specific release documentation for the Ghidra MCP project.

## Available Releases

### v5.0.0 (Latest)

- **Major Feature Release** - Completeness scoring redesign, naming convention enforcement, fun-doc automation engine
- Log-scaled budget scoring system with tiered plate comment quality
- NamingConventions.java: auto-fix Hungarian prefixes on struct fields, PascalCase validation, module prefix support
- New tools: `set_variables` (atomic type+rename), `check_tools`, `rename_variables`
- fun-doc automation: Codex SDK + Claude Code SDK integration, select mode with depth, multi-provider support
- CodeBrowser detection fix, `batch_set_comments` optional arrays, `add_struct_field` overlay fix
- 193 MCP tools, 175 GUI endpoints, 183 headless endpoints
- See [CHANGELOG.md](../../CHANGELOG.md) for full details

### v4.3.0

- **Feature Release** - Knowledge database integration, BSim cross-version matching, enum fix
- 5 new knowledge DB MCP tools (store/query function knowledge, ordinal mappings, export)
- BSim Ghidra scripts for cross-version function similarity matching
- Fixed enum value parsing (GitHub issue #44)
- Dead code cleanup (~243KB of deprecated workflow modules removed)
- 193 MCP tools, 176 GUI endpoints, 184 headless endpoints
- See [CHANGELOG.md](../../CHANGELOG.md) for full details

### v4.1.0

- **Feature Release** - Parallel multi-binary support via universal `program` parameter
- Every program-scoped MCP tool now accepts optional `program` parameter for parallel workflows
- 188 MCP tools, 169 GUI endpoints, 173 headless endpoints
- See [CHANGELOG.md](../../CHANGELOG.md) for full details

### v4.0.0

- **Major Release** - Service layer architecture refactor
- Extracted 12 shared service classes from monolith (`com.xebyte.core/`)
- Plugin reduced 69% (16,945 to 5,273 lines), headless reduced 67% (6,452 to 2,153 lines)
- Zero breaking changes to HTTP API or MCP tools
- 184 MCP tools, 169 GUI endpoints, 173 headless endpoints
- See [CHANGELOG.md](../../CHANGELOG.md) for full details

### v3.2.0

- **Bug Fixes + Version Management** - Cherry-picked fixes from PR #38
- Fixed trailing slash, fuzzy match JSON parsing, OSGi class naming for inline scripts
- Completeness checker overhaul, batch_analyze_completeness endpoint, multi-window fix
- See [CHANGELOG.md](../../CHANGELOG.md) for full details

### v3.1.0

- **Feature Release** - Server control menu + deployment automation
- Tools > GhidraMCP menu for server start/stop/restart
- Deployment automation (TCD auto-activation, AutoOpen, ServerPassword)
- Completeness checker accuracy improvements (ordinals, storage types, Hungarian notation)
- See [CHANGELOG.md](../../CHANGELOG.md) for full details

### v3.0.0

- **Major Release** - Headless server parity + 8 new tool categories
- New categories: Project Lifecycle, Project Organization, Server Connection, Version Control, Version History, Admin, Analysis Control, Script Execution improvements
- 179 MCP tools (up from 110), 147 GUI endpoints, 172 headless endpoints
- New `bump-version.ps1` for atomic version management across all project files
- New `tests/unit/` suite for endpoint catalog consistency
- See [CHANGELOG.md](../../CHANGELOG.md) for full details

### v2.0.2

- Ghidra 12.0.3 support, pagination for large functions

### v2.0.1

- CI fixes, documentation improvements, PowerShell setup improvements

### v2.0.0

- Label deletion endpoints, documentation updates

### v1.9.4

- **Function Hash Index Release** - Cross-binary documentation propagation
- New tools: `get_function_hash`, `get_bulk_function_hashes`, `get_function_documentation`, `apply_function_documentation`, `build_function_hash_index`, `lookup_function_by_hash`, `propagate_documentation`
- SHA-256 normalized opcode hashing for position-independent function matching
- See [CHANGELOG.md](../../CHANGELOG.md) for full details

### v1.9.3

- [Release Notes](v1.9.3/RELEASE_NOTES_v1.9.3.md) - Documentation organization and workflow enhancements
- [Release Checklist](v1.9.3/RELEASE_CHECKLIST_v1.9.3.md) - Pre-release verification tasks

### v1.9.2

- [Release Checklist](v1.9.2/RELEASE_CHECKLIST_v1.9.2.md) - Pre-release verification tasks
- [Release Notes](v1.9.2/RELEASE_NOTES_v1.9.2.md) - Features, fixes, and changes
- [Release Completion Report](v1.9.2/RELEASE_COMPLETE_v1.9.2.md) - Post-release summary

### v1.7.3

- [Release Notes](v1.7.3/RELEASE_NOTES.md) - Version 1.7.3 changes
- [Documentation Review](v1.7.3/DOCUMENTATION_REVIEW.md) - Documentation updates

### v1.7.2

- [Release Notes](v1.7.2/RELEASE_NOTES.md) - Version 1.7.2 changes

### v1.7.0

- [Release Notes](v1.7.0/RELEASE_NOTES.md) - Version 1.7.0 changes

### v1.6.0

- [Release Notes](v1.6.0/RELEASE_NOTES.md) - Version 1.6.0 changes
- [Feature Status](v1.6.0/FEATURE_STATUS.md) - Feature implementation status
- [Implementation Summary](v1.6.0/IMPLEMENTATION_SUMMARY.md) - Technical implementation details
- [Verification Report](v1.6.0/VERIFICATION_REPORT.md) - Testing and verification results

### v1.5.1

- [Final Improvements](v1.5.1/FINAL_IMPROVEMENTS_V1.5.1.md) - Final improvements implemented
- [Improvements Implemented](v1.5.1/IMPROVEMENTS_IMPLEMENTED.md) - Detailed improvement list

### v1.5.0

- [Release Notes](v1.5.0/RELEASE_NOTES_V1.5.0.md) - Version 1.5.0 changes
- [Implementation Details](v1.5.0/IMPLEMENTATION_V1.5.0.md) - Technical implementation
- [Hotfix v1.5.0.1](v1.5.0/HOTFIX_V1.5.0.1.md) - Emergency hotfix details

### v1.4.0

- [Code Review](v1.4.0/CODE_REVIEW_V1.4.0.md) - Code review findings
- [Data Structures Summary](v1.4.0/DATA_STRUCTURES_SUMMARY.md) - Data structure documentation
- [Field Analysis Implementation](v1.4.0/FIELD_ANALYSIS_IMPLEMENTATION.md) - Field analysis features
- [Fixes Applied](v1.4.0/FIXES_APPLIED_V1.4.0.md) - Bug fixes and corrections

## Documentation Standards

Each release directory should contain:

1. **Release Notes** (`RELEASE_NOTES.md` or `RELEASE_NOTES_vX.Y.Z.md`) - User-facing changes
2. **Implementation Details** - Technical implementation specifics
3. **Feature Status** - Feature completion and status reports
4. **Bug Fixes** - Detailed fix documentation
5. **Verification Reports** - Testing and validation results

## Navigation

- For the latest release: See [CHANGELOG.md](../../CHANGELOG.md) (v4.3.0)
- For specific versions: Browse the version directories above
- For overall project changes: See [CHANGELOG.md](../CHANGELOG.md) in the project root

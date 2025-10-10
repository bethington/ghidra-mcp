# Documentation Cleanup Plan - v1.5.1

## Analysis of Current Documentation (22 root-level MD files)

### KEEP in Root (Essential - 3 files)
1. **README.md** - Main project documentation
2. **CLAUDE.md** - Claude Code AI assistant instructions
3. **FINAL_IMPROVEMENTS_V1.5.1.md** - Latest comprehensive release report

### MOVE to docs/ (User Documentation - 2 files)
4. **UNIFIED_ANALYSIS_PROMPT.md** → `docs/prompts/`
5. **ENHANCED_ANALYSIS_PROMPT.md** → `docs/prompts/`

### MOVE to docs/releases/ (Release History - 7 files)
6. **RELEASE_NOTES_V1.5.0.md** → `docs/releases/`
7. **IMPLEMENTATION_V1.5.0.md** → `docs/releases/`
8. **HOTFIX_V1.5.0.1.md** → `docs/releases/`
9. **IMPROVEMENTS_IMPLEMENTED.md** (v1.5.1) → `docs/releases/v1.5.1/`
10. **FIXES_APPLIED_V1.4.0.md** → `docs/releases/v1.4.0/`
11. **CODE_REVIEW_V1.4.0.md** → `docs/releases/v1.4.0/`
12. **FIELD_ANALYSIS_IMPLEMENTATION.md** (v1.4.0) → `docs/releases/v1.4.0/`

### MOVE to docs/reports/ (Development Reports - 6 files)
13. **SESSION_EVALUATION_REPORT.md** → `docs/reports/`
14. **MCP_CODE_REVIEW_REPORT.md** → `docs/reports/`
15. **MCP_ENHANCEMENT_RECOMMENDATIONS.md** → `docs/reports/`
16. **BUILD_VERIFICATION.md** → `docs/reports/`
17. **DEPLOYMENT_VERIFICATION.md** → `docs/reports/`
18. **TROUBLESHOOTING_PLUGIN_LOAD.md** → `docs/troubleshooting/`

### ARCHIVE (Superseded - 4 files)
19. **GHIDRA_ANALYSIS_PROMPT.md** → `docs/archive/prompts/` (superseded by UNIFIED)
20. **GHIDRA_DATA_ANALYSIS_PROTOCOL.md** → `docs/archive/prompts/` (superseded by ENHANCED)
21. **OPTIMIZED_ANALYSIS_PROMPT.md** → `docs/archive/prompts/` (superseded by UNIFIED)
22. **PROMPT_OPTIMIZATION_ANALYSIS.md** → `docs/archive/` (historical analysis)

---

## New Directory Structure

```
ghidra-mcp/
├── README.md                              # Main documentation (KEEP)
├── CLAUDE.md                              # AI assistant instructions (KEEP)
├── FINAL_IMPROVEMENTS_V1.5.1.md          # Latest release summary (KEEP)
├── docs/
│   ├── README.md                          # Docs index (exists)
│   ├── API_REFERENCE.md                   # API documentation (exists)
│   ├── DEVELOPMENT_GUIDE.md               # Contributing guide (exists)
│   ├── DOCUMENTATION_INDEX.md             # (exists)
│   ├── DATA_TYPE_TOOLS.md                 # (exists)
│   ├── STRING_DETECTION_GUIDE.md          # (exists)
│   ├── STRING_DETECTION_QUICK_REFERENCE.md # (exists)
│   ├── COMPLETE_IMPLEMENTATION_SUMMARY.md  # (exists)
│   ├── REQUIREMENTS.md                    # (exists)
│   ├── prompts/                           # NEW: User prompts
│   │   ├── UNIFIED_ANALYSIS_PROMPT.md     # MOVE: Combined function+data analysis
│   │   └── ENHANCED_ANALYSIS_PROMPT.md    # MOVE: Data structure analysis
│   ├── releases/                          # NEW: Release documentation
│   │   ├── v1.5.1/
│   │   │   └── IMPROVEMENTS_IMPLEMENTED.md
│   │   ├── v1.5.0/
│   │   │   ├── RELEASE_NOTES_V1.5.0.md
│   │   │   ├── IMPLEMENTATION_V1.5.0.md
│   │   │   └── HOTFIX_V1.5.0.1.md
│   │   └── v1.4.0/
│   │       ├── FIXES_APPLIED_V1.4.0.md
│   │       ├── CODE_REVIEW_V1.4.0.md
│   │       └── FIELD_ANALYSIS_IMPLEMENTATION.md
│   ├── reports/                           # NEW: Development reports
│   │   ├── SESSION_EVALUATION_REPORT.md
│   │   ├── MCP_CODE_REVIEW_REPORT.md
│   │   ├── MCP_ENHANCEMENT_RECOMMENDATIONS.md
│   │   ├── BUILD_VERIFICATION.md
│   │   └── DEPLOYMENT_VERIFICATION.md
│   ├── troubleshooting/                   # NEW: Troubleshooting guides
│   │   └── TROUBLESHOOTING_PLUGIN_LOAD.md
│   ├── archive/                           # Archive (exists)
│   │   ├── prompts/                       # NEW: Superseded prompts
│   │   │   ├── GHIDRA_ANALYSIS_PROMPT.md
│   │   │   ├── GHIDRA_DATA_ANALYSIS_PROTOCOL.md
│   │   │   └── OPTIMIZED_ANALYSIS_PROMPT.md
│   │   ├── PROMPT_OPTIMIZATION_ANALYSIS.md
│   │   ├── COMPLETE_SUCCESS_REPORT.md     # (exists)
│   │   └── ... (other existing archive files)
│   └── code-reviews/                      # (exists)
│       └── ... (existing code review files)
```

---

## Rationale

### Root Directory (Minimal)
- Only essential files that users need immediately
- README.md - first file users see
- CLAUDE.md - AI assistant configuration
- FINAL_IMPROVEMENTS_V1.5.1.md - latest comprehensive report

### docs/prompts/ (NEW)
- **Purpose**: User-facing analysis prompts for AI-assisted reverse engineering
- **Contents**: UNIFIED_ANALYSIS_PROMPT.md (primary), ENHANCED_ANALYSIS_PROMPT.md (data-focused)
- **Why**: These are active reference documents for users doing reverse engineering work

### docs/releases/ (NEW)
- **Purpose**: Historical release documentation organized by version
- **Contents**: Release notes, implementation reports, hotfixes
- **Why**: Clear version history, easier navigation, mirrors standard software project structure

### docs/reports/ (NEW)
- **Purpose**: Development session reports, code reviews, enhancement recommendations
- **Contents**: Session evaluations, code review findings, verification reports
- **Why**: Separates development/meta documentation from user-facing docs

### docs/troubleshooting/ (NEW)
- **Purpose**: Troubleshooting guides and common issues
- **Contents**: Plugin loading issues, deployment problems
- **Why**: Easy to find solutions, better user experience

### docs/archive/prompts/ (NEW)
- **Purpose**: Superseded prompt versions for historical reference
- **Contents**: Old prompts replaced by UNIFIED_ANALYSIS_PROMPT.md
- **Why**: Preserves history without cluttering active documentation

---

## File Actions Summary

### CREATE directories:
```bash
mkdir -p docs/prompts
mkdir -p docs/releases/v1.5.1
mkdir -p docs/releases/v1.5.0
mkdir -p docs/releases/v1.4.0
mkdir -p docs/reports
mkdir -p docs/troubleshooting
mkdir -p docs/archive/prompts
```

### MOVE files:
```bash
# Prompts
mv UNIFIED_ANALYSIS_PROMPT.md docs/prompts/
mv ENHANCED_ANALYSIS_PROMPT.md docs/prompts/

# v1.5.1 Release
mv IMPROVEMENTS_IMPLEMENTED.md docs/releases/v1.5.1/

# v1.5.0 Release
mv RELEASE_NOTES_V1.5.0.md docs/releases/v1.5.0/
mv IMPLEMENTATION_V1.5.0.md docs/releases/v1.5.0/
mv HOTFIX_V1.5.0.1.md docs/releases/v1.5.0/

# v1.4.0 Release
mv FIXES_APPLIED_V1.4.0.md docs/releases/v1.4.0/
mv CODE_REVIEW_V1.4.0.md docs/releases/v1.4.0/
mv FIELD_ANALYSIS_IMPLEMENTATION.md docs/releases/v1.4.0/

# Reports
mv SESSION_EVALUATION_REPORT.md docs/reports/
mv MCP_CODE_REVIEW_REPORT.md docs/reports/
mv MCP_ENHANCEMENT_RECOMMENDATIONS.md docs/reports/
mv BUILD_VERIFICATION.md docs/reports/
mv DEPLOYMENT_VERIFICATION.md docs/reports/

# Troubleshooting
mv TROUBLESHOOTING_PLUGIN_LOAD.md docs/troubleshooting/

# Archive
mv GHIDRA_ANALYSIS_PROMPT.md docs/archive/prompts/
mv GHIDRA_DATA_ANALYSIS_PROTOCOL.md docs/archive/prompts/
mv OPTIMIZED_ANALYSIS_PROMPT.md docs/archive/prompts/
mv PROMPT_OPTIMIZATION_ANALYSIS.md docs/archive/
```

### UPDATE README.md links:
- Add link to docs/prompts/UNIFIED_ANALYSIS_PROMPT.md
- Add link to docs/releases/
- Update "Documentation" section

### DELETE (NONE):
- All files are preserved for historical reference

---

## Benefits

1. **Cleaner Root**: Only 3 essential files instead of 22
2. **Better Organization**: Clear separation of prompts, releases, reports
3. **Easier Navigation**: Version-organized releases
4. **Historical Preservation**: All files archived, nothing lost
5. **User-Friendly**: Easy to find current vs historical documentation
6. **Standard Structure**: Follows common open-source project patterns

---

## Post-Cleanup Root Directory

```
ghidra-mcp/
├── README.md
├── CLAUDE.md
├── FINAL_IMPROVEMENTS_V1.5.1.md
├── bridge_mcp_ghidra.py
├── pom.xml
├── requirements.txt
├── requirements-test.txt
├── .env.template
├── copy-ghidra-libs.bat
├── deploy-to-ghidra.ps1
├── clean-install.ps1
├── process_whitelist.json
├── docs/           # Well-organized documentation
├── src/            # Java source code
├── lib/            # Ghidra JARs
├── target/         # Build artifacts
└── tests/          # Test suite
```

**Result**: Professional, clean project structure ready for public release.

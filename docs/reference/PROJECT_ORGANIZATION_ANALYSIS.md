# Project Organization Analysis & Cleanup Plan

**Date**: November 5, 2025  
**Status**: Active Cleanup & Reorganization  
**Last Updated**: Post-Batch-Operations-Fix

## Executive Summary

The ghidra-mcp project has accumulated significant technical debt in the form of:
- **67 markdown files** (many outdated/duplicate)
- **77 ordinal_fix_log_*.txt files** (historical logs from development)
- **Multiple obsolete test/debug scripts** in root directory
- **Binary analysis files** for specific DLLs (D2CLIENT, D2NET, etc.) that duplicate info in main docs

**Goal**: Maintain only current, useful documentation while removing historical artifacts.

---

## 📋 Markdown Files Audit

### KEEP - Core Project Documentation (Essential)

| File | Purpose | Status | Notes |
|------|---------|--------|-------|
| `README.md` | Main project overview, features, quick start | ✅ Current | Update if needed; Primary entry point |
| `CHANGELOG.md` | Version history and changes | ✅ Current | Keep updated |
| `LICENSE` | Apache 2.0 license | ✅ Current | No changes needed |
| `START_HERE.md` | Getting started guide (malformed) | ⚠️ NEEDS FIX | Fix formatting/content duplication |
| `mcp-config.json` | MCP configuration | ✅ Current | Not markdown but important |
| `pytest.ini` | Testing configuration | ✅ Current | Not markdown but important |

### CONSOLIDATE - Diablo II Analysis Files (77 files reference these)

These D2 binary analysis files are project-specific and can be consolidated:

**D2 Binary Analysis Files** (11 total):
- `D2CLIENT_BINARY_ANALYSIS.md`
- `D2CMP_BINARY_ANALYSIS.md`
- `D2COMMON_BINARY_ANALYSIS.md`
- `D2GDI_BINARY_ANALYSIS.md`
- `D2GFX_BINARY_ANALYSIS.md`
- `D2LANG_BINARY_ANALYSIS.md`
- `D2LAUNCH_BINARY_ANALYSIS.md`
- `D2MCPCLIENT_BINARY_ANALYSIS.md`
- `D2MULTI_BINARY_ANALYSIS.md`
- `D2NET_BINARY_ANALYSIS.md`
- `D2SOUND_BINARY_ANALYSIS.md`
- `D2WIN_BINARY_ANALYSIS.md`
- `FOG_BINARY_ANALYSIS.md`
- `GAME_EXE_BINARY_ANALYSIS.md`
- `BNCLIENT_BINARY_ANALYSIS.md`
- `SMACKW32_BINARY_ANALYSIS.md`
- `PD2_EXT_BINARY_ANALYSIS.md`

**Recommendation**: Move to `docs/diablo2_analysis/` directory (can stay for reference)

### CONSOLIDATE - Ordinal/External Location Documentation (5 files)

These document the same workflow with different emphasis:
- `ORDINAL_AUTO_FIX_WORKFLOW.md` - Main workflow
- `ORDINAL_LINKAGE_GUIDE.md` - Linkage details
- `ORDINAL_QUICKSTART.md` - Quick reference
- `ORDINAL_RESTORATION_TOOLKIT.md` - Toolkit reference
- `ORDINAL_INDEX.md` - Index/reference

**Recommendation**: Keep primary file (`ORDINAL_AUTO_FIX_WORKFLOW.md`), consider archiving others or consolidating into single guide

### REMOVE - Outdated/Obsolete Files (BATCH FOR DELETION)

#### Project Status/Process Files (Internal Only):
- `ACTION_PLAN_TESTING.md` - Completed task tracking
- `ACTION_REQUIRED.md` - Old action items
- `AUTOMATED_FIX_STATUS.md` - Historical status
- `IMPLEMENTATION_COMPLETE.md` - Completed milestone marker
- `PROJECT_CLEANUP_COMPLETE.md` - Meta-documentation about cleanup

#### Script/Tool Guides (Superseded by main docs):
- `DETECTION_SCRIPT_USAGE_GUIDE.md` - Specific script guide
- `DETECTION_SCRIPT_V2_COMPLETE.md` - Version-specific docs
- `DETECTION_SCRIPT_V2_SUMMARY.md` - Summary of above
- `DETECTION_VALIDATION_RESULTS.md` - Test results
- `HEADLESS_EXECUTION_GUIDE.md` - Specific execution mode
- `HEADLESS_SCRIPT_SUMMARY.md` - Summary of above
- `SCRIPT_ANALYSIS_RESULTS.md` - Analysis results
- `SCRIPT_IMPROVEMENTS_SUMMARY.md` - Improvement notes

#### Testing/Debugging Documentation:
- `TESTING_CHECKLIST.md` - Old testing checklist
- `QUICK_TEST_GUIDE.md` - Old test guide
- `QUICK_START_FIX.md` - Old quick start
- `EXECUTE_D2NET_FIX.md` - Specific fix documentation
- `EXECUTE_NOW.md` - Urgent action (outdated)
- `PARAMETER_FIXING_ANALYSIS.md` - Analysis from specific phase
- `PARAMETER_FIXING_STATUS.md` - Status from specific phase
- `FUNCTION_DOCUMENTATION_AUDIT.md` - Old audit
- `EXTERNAL_LOCATION_TOOLS.md` - Specific tool documentation
- `EXTERNAL_LOCATION_WORKFLOW.md` - Old workflow

#### Edge Case/Data Improvement Documentation (Historical):
- `EDGE_CASE_DETECTION_README.md` - Old detection guide
- `EDGE_CASE_FINDINGS.md` - Historical findings
- `EDGE_CASE_FIXES_IMPLEMENTATION.md` - Implementation notes
- `EDGE_CASE_INDEX.md` - Index file
- `EDGE_CASE_TEST_RESULTS.md` - Test results
- `SESSION_SUMMARY_EDGE_CASES.md` - Session summary
- `DATA_IMPROVEMENT_EXAMPLES.md` - Example documentation
- `UNIT_MONSTER_STRUCTURES_REPORT.md` - Specific analysis

#### Diablo 2 Analysis Index Files:
- `D2_ANALYSIS_QUICK_START.md` - Old quick start
- `D2_ANALYSIS_SUMMARY.md` - Summary file
- `D2_CUSTOMIZATIONS_README.md` - Old customizations
- `DIABLO2_ANALYSIS_COMPLETE_SUMMARY.md` - Summary
- `DIABLO2_COMPLETE_BINARY_ANALYSIS.md` - Complete analysis
- `DIABLO2_DOCUMENTATION_INDEX.md` - Index file
- `START_DIABLO2_ANALYSIS.md` - Old start guide

#### DLL Exports Documentation:
- `dll_exports_GUIDE.md` - Guide file
- `dll_exports_USAGE.md` - Usage file

**Total to REMOVE: ~45 files**

---

## 📁 Log Files & Artifacts

### Ordinal Fix Logs (77 files)
- Pattern: `ordinal_fix_log_*.txt` and `ordinal_fix_log.txt`
- **Status**: Historical development logs
- **Size**: ~1-2 MB combined
- **Recommendation**: Delete all; not needed for production

### Other Artifacts:
- `nul` - Empty/placeholder file → DELETE
- `STRUCTURE_SUMMARY.txt` - Text summary → Evaluate if needed
- `UNIT_MONSTER_SEARCH_RESULTS.txt` - Search results → DELETE

---

## 🗂️ Directory Structure Issues

### Current Issues:
1. **Root directory**: Too many .md files (67 total)
2. **docs/**: Exists but underutilized
3. **scripts/**: Has useful content, good separation
4. **ghidra_scripts/**: Good separation
5. **No classification**: All docs at root level

### Recommended Structure:
```
ghidra-mcp/
├── README.md (primary entry point)
├── CHANGELOG.md
├── src/
├── tests/
├── ghidra_scripts/
├── docs/
│   ├── QUICK_START.md (new consolidated)
│   ├── API_REFERENCE.md (new consolidated)
│   ├── TROUBLESHOOTING.md (new consolidated)
│   ├── guides/
│   │   ├── function-documentation.md
│   │   ├── binary-analysis.md
│   │   ├── ordinal-linkage.md
│   │   └── external-locations.md
│   ├── diablo2_analysis/
│   │   ├── D2CLIENT_BINARY_ANALYSIS.md
│   │   ├── D2NET_BINARY_ANALYSIS.md
│   │   └── (other D2 files)
│   └── archive/
│       └── (deprecated files)
├── scripts/
├── examples/
├── tools/
└── lib/
```

---

## 🧹 Cleanup Actions

### Phase 1: DELETE (Execute Now)
Files to permanently remove (no value):

```
# Ordinal logs (all 77)
ordinal_fix_log.txt
ordinal_fix_log_*.txt (all variants)

# Single artifacts
nul
UNIT_MONSTER_SEARCH_RESULTS.txt

# Outdated process documentation
ACTION_PLAN_TESTING.md
ACTION_REQUIRED.md
AUTOMATED_FIX_STATUS.md
IMPLEMENTATION_COMPLETE.md
PROJECT_CLEANUP_COMPLETE.md
```

### Phase 2: CONSOLIDATE (Create new structure)
Move to organized docs structure:

```bash
# Create directory structure
mkdir -p docs/guides
mkdir -p docs/diablo2_analysis
mkdir -p docs/archive

# Move D2 analysis files
move D2*_BINARY_ANALYSIS.md docs/diablo2_analysis/
move FOG_BINARY_ANALYSIS.md docs/diablo2_analysis/
move GAME_EXE_BINARY_ANALYSIS.md docs/diablo2_analysis/
move BNCLIENT_BINARY_ANALYSIS.md docs/diablo2_analysis/
move SMACKW32_BINARY_ANALYSIS.md docs/diablo2_analysis/
move PD2_EXT_BINARY_ANALYSIS.md docs/diablo2_analysis/

# Move ordinal files
move ORDINAL_*.md docs/guides/
move *_ORDINAL_*.md docs/guides/

# Archive old documentation
move DETECTION_SCRIPT*.md docs/archive/
move EDGE_CASE*.md docs/archive/
move PARAMETER_FIXING*.md docs/archive/
move (all other outdated files) docs/archive/
```

### Phase 3: CREATE NEW CONSOLIDATED DOCUMENTATION

Create new files to replace the deleted ones:

1. **`docs/QUICK_START.md`** - Replace fragmented quick starts
   - Installation
   - Basic setup
   - First analysis
   - Links to deeper guides

2. **`docs/TROUBLESHOOTING.md`** - Consolidated troubleshooting
   - Common issues
   - MCP connection problems
   - Ghidra plugin issues
   - Performance tuning

3. **`docs/guides/FUNCTION_DOCUMENTATION.md`** - Consolidated guide
   - Function analysis best practices
   - Decompilation workflows
   - Variable naming conventions
   - Comment standards

4. **`docs/guides/BINARY_ANALYSIS.md`** - General binary analysis
   - Structure discovery
   - Import/export analysis
   - Cross-reference analysis
   - Data type inference

5. **`docs/guides/ORDINAL_LINKAGE.md`** - Consolidated ordinal guide
   - When to use ordinal linkage
   - Workflow overview
   - Step-by-step instructions
   - Troubleshooting

6. **Update `START_HERE.md`** - Fix formatting issues
   - Clear table of contents
   - Remove duplicate content
   - Point to organized docs
   - Clearer navigation

---

## 📊 Before & After Stats

### Before Cleanup:
- **67 markdown files** in root
- **77 ordinal_fix_log files**
- **Multiple duplicate docs** (same info, different names)
- **~100+ files** cluttering root directory
- **Hard to find** current documentation

### After Cleanup:
- **~25 markdown files** (main + archive)
- **Organized in docs/** subdirectory
- **No duplicate documentation**
- **Clean root directory** (only essential files)
- **Easy navigation** with clear structure

---

## ✅ Implementation Checklist

- [ ] **Phase 1**: Review and confirm deletion list with stakeholders
- [ ] **Phase 2**: Execute deletions (ordinal logs, obsolete process docs)
- [ ] **Phase 3**: Create directory structure in docs/
- [ ] **Phase 4**: Move D2 analysis files to docs/diablo2_analysis/
- [ ] **Phase 5**: Move guide files to docs/guides/
- [ ] **Phase 6**: Archive deprecated files to docs/archive/
- [ ] **Phase 7**: Fix START_HERE.md formatting and content
- [ ] **Phase 8**: Create new consolidated documentation files
- [ ] **Phase 9**: Update README.md with new doc structure links
- [ ] **Phase 10**: Test all documentation links and references
- [ ] **Phase 11**: Update .gitignore to ignore ordinal_fix_log*.txt
- [ ] **Phase 12**: Create MIGRATION.md explaining the changes

---

## 📝 Notes

1. **D2 Analysis Files**: These contain valuable analysis but are project-specific. Consider if they're useful for future projects.
2. **Ordinal Logs**: These are from development. Consider archiving 1-2 as examples if the methodology is valuable.
3. **Version Control**: Many files reference old versions. Good opportunity to validate current version is v1.8.1.
4. **Documentation Quality**: Several "COMPLETE", "FINAL", "STATUS" files suggest incremental cleanup already happened.

---

## 🎯 Success Criteria

✅ Cleanup is complete when:
- [ ] Root directory has <30 files
- [ ] All markdown documentation is in `docs/` or `docs/*/`
- [ ] No duplicate documentation exists
- [ ] All links in docs are valid
- [ ] Project structure is intuitive and discoverable
- [ ] New developers can navigate docs easily
- [ ] Git repository is smaller and cleaner
- [ ] CI/CD doesn't waste time on obsolete files

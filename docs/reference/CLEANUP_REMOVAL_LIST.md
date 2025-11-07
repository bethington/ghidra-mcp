# Cleanup Removal List - Copy-Paste Ready

Use these commands to remove outdated files. Run from project root.

## DELETE: Ordinal Fix Logs (77 files)

```powershell
# Delete all ordinal fix logs
Remove-Item -Path ordinal_fix_log.txt -ErrorAction SilentlyContinue
Remove-Item -Path ordinal_fix_log_*.txt -ErrorAction SilentlyContinue

# Verify deletion
Get-ChildItem -Path . -Filter "ordinal_fix_log*" | Measure-Object
```

## DELETE: Other Artifacts

```powershell
# Single files
Remove-Item -Path nul -ErrorAction SilentlyContinue
Remove-Item -Path UNIT_MONSTER_SEARCH_RESULTS.txt -ErrorAction SilentlyContinue
Remove-Item -Path STRUCTURE_SUMMARY.txt -ErrorAction SilentlyContinue (optional - check content first)
```

## DELETE: Outdated Process Documentation

```powershell
# Process/Status files - SAFE TO DELETE
$processFiles = @(
    "ACTION_PLAN_TESTING.md",
    "ACTION_REQUIRED.md",
    "AUTOMATED_FIX_STATUS.md",
    "IMPLEMENTATION_COMPLETE.md",
    "PROJECT_CLEANUP_COMPLETE.md"
)

foreach ($file in $processFiles) {
    Remove-Item -Path $file -ErrorAction SilentlyContinue
    Write-Host "Deleted: $file"
}
```

## DELETE: Script/Tool Guides (Superseded)

```powershell
# Detection/Script guides - SAFE TO DELETE
$scriptGuides = @(
    "DETECTION_SCRIPT_USAGE_GUIDE.md",
    "DETECTION_SCRIPT_V2_COMPLETE.md",
    "DETECTION_SCRIPT_V2_SUMMARY.md",
    "DETECTION_VALIDATION_RESULTS.md",
    "HEADLESS_EXECUTION_GUIDE.md",
    "HEADLESS_SCRIPT_SUMMARY.md",
    "SCRIPT_ANALYSIS_RESULTS.md",
    "SCRIPT_IMPROVEMENTS_SUMMARY.md"
)

foreach ($file in $scriptGuides) {
    Remove-Item -Path $file -ErrorAction SilentlyContinue
    Write-Host "Deleted: $file"
}
```

## DELETE: Testing/Debugging Documentation

```powershell
# Old test guides - SAFE TO DELETE
$testDocs = @(
    "TESTING_CHECKLIST.md",
    "QUICK_TEST_GUIDE.md",
    "QUICK_START_FIX.md",
    "EXECUTE_D2NET_FIX.md",
    "EXECUTE_NOW.md",
    "PARAMETER_FIXING_ANALYSIS.md",
    "PARAMETER_FIXING_STATUS.md",
    "FUNCTION_DOCUMENTATION_AUDIT.md",
    "EXTERNAL_LOCATION_TOOLS.md",
    "EXTERNAL_LOCATION_WORKFLOW.md"
)

foreach ($file in $testDocs) {
    Remove-Item -Path $file -ErrorAction SilentlyContinue
    Write-Host "Deleted: $file"
}
```

## DELETE: Edge Case Documentation (Historical)

```powershell
# Edge case files - SAFE TO DELETE
$edgeCaseDocs = @(
    "EDGE_CASE_DETECTION_README.md",
    "EDGE_CASE_FINDINGS.md",
    "EDGE_CASE_FIXES_IMPLEMENTATION.md",
    "EDGE_CASE_INDEX.md",
    "EDGE_CASE_TEST_RESULTS.md",
    "SESSION_SUMMARY_EDGE_CASES.md",
    "DATA_IMPROVEMENT_EXAMPLES.md",
    "UNIT_MONSTER_STRUCTURES_REPORT.md"
)

foreach ($file in $edgeCaseDocs) {
    Remove-Item -Path $file -ErrorAction SilentlyContinue
    Write-Host "Deleted: $file"
}
```

## DELETE: Diablo 2 Analysis Index Files

```powershell
# Old D2 index files - SAFE TO DELETE (analysis files stay for now)
$d2IndexFiles = @(
    "D2_ANALYSIS_QUICK_START.md",
    "D2_ANALYSIS_SUMMARY.md",
    "D2_CUSTOMIZATIONS_README.md",
    "DIABLO2_ANALYSIS_COMPLETE_SUMMARY.md",
    "DIABLO2_COMPLETE_BINARY_ANALYSIS.md",
    "DIABLO2_DOCUMENTATION_INDEX.md",
    "START_DIABLO2_ANALYSIS.md"
)

foreach ($file in $d2IndexFiles) {
    Remove-Item -Path $file -ErrorAction SilentlyContinue
    Write-Host "Deleted: $file"
}
```

## DELETE: DLL Exports Documentation

```powershell
# Old exports docs - SAFE TO DELETE
$exportDocs = @(
    "dll_exports_GUIDE.md",
    "dll_exports_USAGE.md"
)

foreach ($file in $exportDocs) {
    Remove-Item -Path $file -ErrorAction SilentlyContinue
    Write-Host "Deleted: $file"
}
```

## MASTER DELETE SCRIPT (ALL AT ONCE)

```powershell
Write-Host "⚠️  REMOVING OUTDATED FILES - THIS CANNOT BE UNDONE" -ForegroundColor Red
Write-Host "Press Ctrl+C to cancel, or wait 5 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

$allToDelete = @(
    # Ordinal logs
    "ordinal_fix_log.txt",
    # Artifacts
    "nul",
    "UNIT_MONSTER_SEARCH_RESULTS.txt",
    # Process files
    "ACTION_PLAN_TESTING.md",
    "ACTION_REQUIRED.md",
    "AUTOMATED_FIX_STATUS.md",
    "IMPLEMENTATION_COMPLETE.md",
    "PROJECT_CLEANUP_COMPLETE.md",
    # Script guides
    "DETECTION_SCRIPT_USAGE_GUIDE.md",
    "DETECTION_SCRIPT_V2_COMPLETE.md",
    "DETECTION_SCRIPT_V2_SUMMARY.md",
    "DETECTION_VALIDATION_RESULTS.md",
    "HEADLESS_EXECUTION_GUIDE.md",
    "HEADLESS_SCRIPT_SUMMARY.md",
    "SCRIPT_ANALYSIS_RESULTS.md",
    "SCRIPT_IMPROVEMENTS_SUMMARY.md",
    # Test docs
    "TESTING_CHECKLIST.md",
    "QUICK_TEST_GUIDE.md",
    "QUICK_START_FIX.md",
    "EXECUTE_D2NET_FIX.md",
    "EXECUTE_NOW.md",
    "PARAMETER_FIXING_ANALYSIS.md",
    "PARAMETER_FIXING_STATUS.md",
    "FUNCTION_DOCUMENTATION_AUDIT.md",
    "EXTERNAL_LOCATION_TOOLS.md",
    "EXTERNAL_LOCATION_WORKFLOW.md",
    # Edge case docs
    "EDGE_CASE_DETECTION_README.md",
    "EDGE_CASE_FINDINGS.md",
    "EDGE_CASE_FIXES_IMPLEMENTATION.md",
    "EDGE_CASE_INDEX.md",
    "EDGE_CASE_TEST_RESULTS.md",
    "SESSION_SUMMARY_EDGE_CASES.md",
    "DATA_IMPROVEMENT_EXAMPLES.md",
    "UNIT_MONSTER_STRUCTURES_REPORT.md",
    # D2 index files
    "D2_ANALYSIS_QUICK_START.md",
    "D2_ANALYSIS_SUMMARY.md",
    "D2_CUSTOMIZATIONS_README.md",
    "DIABLO2_ANALYSIS_COMPLETE_SUMMARY.md",
    "DIABLO2_COMPLETE_BINARY_ANALYSIS.md",
    "DIABLO2_DOCUMENTATION_INDEX.md",
    "START_DIABLO2_ANALYSIS.md",
    # DLL exports docs
    "dll_exports_GUIDE.md",
    "dll_exports_USAGE.md"
)

$deleted = 0
foreach ($file in $allToDelete) {
    if (Test-Path -Path $file) {
        Remove-Item -Path $file -ErrorAction SilentlyContinue
        Write-Host "✓ Deleted: $file" -ForegroundColor Green
        $deleted++
    }
}

# Delete ordinal logs
$logs = Get-ChildItem -Path ordinal_fix_log_*.txt -ErrorAction SilentlyContinue
foreach ($log in $logs) {
    Remove-Item -Path $log.FullName
    $deleted++
}

Write-Host ""
Write-Host "✅ Cleanup complete! Deleted $deleted files" -ForegroundColor Green
Write-Host ""
Write-Host "Files remaining in root:" -ForegroundColor Cyan
Get-ChildItem -Filter "*.md" | Measure-Object | Select-Object @{Name="Count"; Expression={$_.Count}}
```

## Verification After Cleanup

```powershell
# Count remaining markdown files
Write-Host "Markdown files remaining:" -ForegroundColor Cyan
(Get-ChildItem -Filter "*.md" | Measure-Object).Count

# Count ordinal logs remaining (should be 0)
Write-Host "Ordinal logs remaining:" -ForegroundColor Cyan
(Get-ChildItem -Filter "ordinal_fix_log*" | Measure-Object).Count

# List remaining markdown files
Write-Host ""
Write-Host "Remaining markdown files:" -ForegroundColor Yellow
Get-ChildItem -Filter "*.md" | Sort-Object | ForEach-Object { Write-Host "  $_" }
```

## KEEP THESE FILES

These should NOT be deleted:

```
README.md                    (main documentation)
CHANGELOG.md                 (version history)
LICENSE                      (Apache 2.0)
START_HERE.md                (getting started - will be fixed)
CLAUDE.md                    (Claude-specific notes)

D2*_BINARY_ANALYSIS.md       (project-specific analysis - move to docs/)
FOG_BINARY_ANALYSIS.md       (analysis files)
GAME_EXE_BINARY_ANALYSIS.md  (analysis files)
BNCLIENT_BINARY_ANALYSIS.md  (analysis files)
SMACKW32_BINARY_ANALYSIS.md  (analysis files)
PD2_EXT_BINARY_ANALYSIS.md   (analysis files)

ORDINAL_AUTO_FIX_WORKFLOW.md (primary workflow - move to docs/)
ORDINAL_LINKAGE_GUIDE.md     (move to docs/)
ORDINAL_QUICKSTART.md        (move to docs/)
ORDINAL_RESTORATION_TOOLKIT.md (move to docs/)
ORDINAL_INDEX.md             (move to docs/)
```

---

**Total Files to Delete**: ~45 markdown files + 77 log files + 2 artifacts = **~124 files**

**Result**: Clean project with organized documentation structure!

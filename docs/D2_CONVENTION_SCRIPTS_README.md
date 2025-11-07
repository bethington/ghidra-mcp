# D2 Calling Convention Scripts

## Scripts Created

### 1. DetectD2ConventionsBatch.java
**Location:** `C:\Users\benam\ghidra_scripts\DetectD2ConventionsBatch.java`  
**Purpose:** Detection only (read-only analysis)

**Features:**
- Analyzes all functions in loaded program
- Detects 4 D2 custom calling conventions:
  - `__d2call` - SUB ESP stack allocation
  - `__d2regcall` - EAX/EDX/ECX register parameters
  - `__d2mixcall` - Mixed register + stack
  - `__d2edicall` - EDI register usage
- Filters out standard Windows prologues (PUSH EBP; MOV EBP, ESP)
- Progress reporting every 100 functions with ETA
- Exports results to JSON: `%USERPROFILE%\Desktop\d2_convention_detections.json`

**When to use:**
- When you want to survey the binary without making changes
- To generate detection reports for review
- To validate detection accuracy before applying conventions

---

### 2. DetectAndApplyD2Conventions.java ⭐ **RECOMMENDED**
**Location:** `C:\Users\benam\ghidra_scripts\DetectAndApplyD2Conventions.java`  
**Purpose:** Detect AND optionally apply calling conventions

**Features:**
- All detection features from batch script
- **Interactive prompt**: Choose detection-only OR detect-and-apply mode
- Automatically applies detected conventions to functions
- Transaction-safe: All changes are atomic (all or nothing)
- Tracks application success/failure
- JSON export includes application status per function

**When to use:**
- **PRIMARY USE CASE**: When you want to both detect and fix calling conventions
- Prompts you at startup: "Apply conventions? Yes/No"
  - **Yes**: Detects and automatically applies conventions
  - **No**: Detection only (same as batch script)
- Recommended for actual analysis work

---

## How to Run

### Method 1: Ghidra Script Manager (Recommended)

1. In Ghidra, open **Window → Script Manager** (or press `Ctrl+Shift+E`)
2. Click the **Refresh** button (🔄) to reload script list
3. Find script in **Analysis** category:
   - `DetectD2ConventionsBatch` (detection only)
   - `DetectAndApplyD2Conventions` (detect + apply)
4. Double-click script name or click **Run** button (▶)
5. Monitor progress in Console window

### Method 2: MCP Tool (if Ghidra build cache clear)

```python
# Via Python MCP bridge
from bridge_mcp_ghidra import run_script

# Run detection only
run_script("C:\\Users\\benam\\ghidra_scripts\\DetectD2ConventionsBatch.java")

# Run detection + apply
run_script("C:\\Users\\benam\\ghidra_scripts\\DetectAndApplyD2Conventions.java")
```

---

## Expected Output

### Console Output (During Execution)
```
========================================
D2 CALLING CONVENTION DETECTION AND APPLICATION
========================================
Program: D2Common.dll
Mode: Detect and Apply
Date: Sat Nov 01 17:19:00 CDT 2025

Total functions to analyze: 2766

[100/2766] Analyzed: 100 | Standard: 45 | Unknown: 30 | D2: 25 | Applied: 25 | ETA: 120 sec
[200/2766] Analyzed: 200 | Standard: 90 | Unknown: 60 | D2: 50 | Applied: 48 | ETA: 110 sec
...
```

### Final Summary
```
========================================
DETECTION RESULTS
========================================

Total Analyzed: 2766
Standard Conventions (filtered): 1200
Unknown: 800

D2 CUSTOM CONVENTIONS FOUND: 766
Applied: 760
Failed: 6
----------------------------------------

__d2call: 300 functions
  - ProcessGameLogic @ 0x6fd50100 (100% confidence) [APPLIED]
  - UpdateGameState @ 0x6fd50200 (100% confidence) [APPLIED]
  ...

__d2regcall: 200 functions
  - SetStructureStateAndConfigurationValues @ 0x6fd50300 (100% confidence) [APPLIED]
  ...

__d2mixcall: 150 functions
  ...

__d2edicall: 116 functions
  ...
```

### JSON Export
**File:** `C:\Users\benam\Desktop\d2_convention_detections.json`

```json
{
  "program": "D2Common.dll",
  "analysisDate": "Sat Nov 01 17:21:45 CDT 2025",
  "mode": "detect_and_apply",
  "totalAnalyzed": 2766,
  "standardFiltered": 1200,
  "unknown": 800,
  "totalD2Detections": 766,
  "applied": 760,
  "failed": 6,
  "detections": {
    "__d2call": [
      {
        "name": "ProcessGameLogic",
        "address": "0x6fd50100",
        "convention": "__d2call",
        "confidence": 1.0,
        "prologueSnippet": "SUB ESP 0x20; MOV EAX [ESP+0x24]; ...",
        "applied": true
      }
    ],
    "__d2regcall": [ ... ],
    "__d2mixcall": [ ... ],
    "__d2edicall": [ ... ]
  }
}
```

---

## Performance

- **Native Ghidra execution** (10x faster than MCP)
- Processes ~30-50 functions/second
- **Expected runtime**: 1-2 minutes for 2,766 functions
- Real-time progress updates with ETA

---

## Detection Logic

### Standard Prologue Filtering
Functions with standard Windows prologues are **excluded**:
```asm
PUSH EBP
MOV EBP, ESP
```
This eliminates false positives from __stdcall, __cdecl, __fastcall, etc.

### D2 Convention Patterns

**__d2call:**
- `SUB ESP, imm` as first instruction (immediate stack allocation)
- No standard prologue

**__d2regcall:**
- Uses EAX/EDX/ECX registers immediately (first 3 instructions)
- Register usage for parameters (MOV, TEST, CMP, ADD, SUB)
- No PUSH instruction at start

**__d2edicall:**
- Uses EDI register in first 3 instructions
- Special purpose register (EDI typically preserved in standard conventions)

**__d2mixcall:**
- Combination of register operations (EAX/EDX/ECX/EBX)
- AND stack operations (ESP/EBP references)
- Not just saving registers (excludes PUSH at start)

---

## Troubleshooting

### Issue: "Script not found in Script Manager"
**Solution:** Click **Refresh** button (🔄) in Script Manager

### Issue: "Old script compilation errors"
**Solution:** Delete old Python/broken scripts from `C:\Users\benam\ghidra_scripts\`
```powershell
Remove-Item "$env:USERPROFILE\ghidra_scripts\DetectD2CallingConventions.java" -Force
Remove-Item "$env:USERPROFILE\ghidra_scripts\DetectD2CallingConventions.py" -Force
```

### Issue: "Cannot apply calling convention"
**Cause:** Convention not defined in Ghidra's x86win.cspec  
**Solution:** Ensure D2 calling conventions are installed:
1. Check if `__d2call`, `__d2regcall`, `__d2mixcall`, `__d2edicall` are in Ghidra's calling convention list
2. If missing, install custom conventions via x86win.cspec modifications
3. See: `D2CALL_INSTALLATION_GUIDE.md` in workspace

---

## Recommended Workflow

### Step 1: Survey (Detection Only)
Run `DetectAndApplyD2Conventions.java` with **"No"** when prompted:
- Review detection results
- Check confidence scores
- Validate detection patterns
- Export JSON for analysis

### Step 2: Apply Conventions
Run `DetectAndApplyD2Conventions.java` with **"Yes"** when prompted:
- Automatically applies detected conventions
- Tracks success/failure
- Creates backup via Ghidra transactions

### Step 3: Verify Results
- Check Console output for application status
- Review JSON export for detailed results
- Verify functions in Ghidra have correct conventions
- Check decompilation quality improvement

---

## Example: Testing a Single Function

From Python MCP:
```python
# 1. Check what we detected for a specific function
from bridge_mcp_ghidra import decompile_function

# Before
code_before = decompile_function(name="SetStructureStateAndConfigurationValues")
print(code_before)  # Shows incorrect parameter handling

# 2. Run detection + application script in Ghidra
# (via Script Manager: DetectAndApplyD2Conventions.java → Answer "Yes")

# 3. Re-decompile to see improvement
code_after = decompile_function(name="SetStructureStateAndConfigurationValues", force=True)
print(code_after)  # Shows correct __d2regcall parameters
```

---

## Next Steps

1. **Run Detection:** Test on D2Common.dll to see results
2. **Review Output:** Check JSON file on Desktop
3. **Apply Conventions:** Re-run with "Yes" to apply fixes
4. **Expand Binaries:** Run on D2Game.dll, D2Client.dll, etc.
5. **Build Ground Truth:** Document which functions use which conventions

---

## Script Comparison

| Feature | DetectD2ConventionsBatch | DetectAndApplyD2Conventions |
|---------|-------------------------|----------------------------|
| Detection | ✅ Yes | ✅ Yes |
| Apply Conventions | ❌ No | ✅ Yes (optional) |
| Interactive Prompt | ❌ No | ✅ Yes |
| JSON Export | ✅ Yes | ✅ Yes |
| Transaction Safe | N/A | ✅ Yes |
| Tracks Application | N/A | ✅ Yes |
| **Recommended Use** | Survey only | **Primary tool** |

**Recommendation:** Use `DetectAndApplyD2Conventions.java` for all work. Choose mode at runtime.


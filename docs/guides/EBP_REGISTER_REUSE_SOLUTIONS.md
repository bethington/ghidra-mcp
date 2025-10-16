# Fixing EBP Register Reuse in Ghidra Decompilation

## The Problem

At address `0x6fb6aef0`, the function `ProcessDualManaCostSkillWithAlternateCallbackHandlerAndAdvancedValidation` uses an aggressive compiler optimization where the EBP register is:

1. Saved on the stack at `0x6fb6af47: PUSH EBP`
2. Reused as a local variable at `0x6fb6af4f: MOV EBP,EAX`
3. Used for validation at `0x6fb6af56: TEST EBP,EBP`

This confuses Ghidra's decompiler, which assumes EBP is "unaffected" (`unaff_EBP`) and produces incomplete decompilation that omits the entire mana calculation and callback execution logic.

## Solution Options (Ranked by Effectiveness)

### Option 1: Manual UI-Based Variable Override ⭐ **RECOMMENDED**

**Steps in Ghidra GUI:**

1. Open the function in the Decompiler window
2. Right-click on the decompiled function name → "Edit Function Signature"
3. In the signature editor, look for local variables
4. Find `unaff_EBP` in the local variables list
5. Try to:
   - Rename it to `directionResult`
   - Change its type to `int`
   - Adjust its storage if possible

**Limitations:**
- Ghidra may not allow changing storage for auto-detected variables
- The decompiler may still not correctly track the control flow

### Option 2: Ghidra Script Approach (Provided Scripts)

**Run the Python script:**

```bash
# In Ghidra:
# Window → Script Manager
# Select: FixEBPRegisterReuse.py
# Click: Run
```

The script attempts to:
- Analyze Pcode operations to find EBP reassignments
- Rename `unaff_EBP` to `directionResult`
- Force re-decompilation

**Limitations:**
- Programmatic variable storage modification has limited API support
- May not fully resolve the decompiler's confusion

### Option 3: Ghidra Extension/Plugin Development

Create a custom decompiler extension that:

1. **Detects register reuse patterns** during Pcode analysis
2. **Creates synthetic variables** for reused registers
3. **Modifies the Pcode graph** before decompilation

**Implementation approach:**

```java
// Custom DecompilerCallback to handle register reuse
public class RegisterReuseCallback extends DecompilerCallback {
    @Override
    public void processRegisterTransfer(Varnode dest, Varnode src, PcodeOp op) {
        // Detect: MOV EBP, EAX after PUSH EBP
        if (dest.getAddress().equals(ebpRegister) &&
            isPreviouslyPushed(ebpRegister, op.getSeqnum())) {
            // Create new synthetic variable instead of reusing EBP
            createSyntheticLocal(dest, op.getSeqnum());
        }
    }
}
```

**Pros:**
- Most powerful solution
- Could handle many similar cases automatically

**Cons:**
- Requires deep Ghidra plugin development knowledge
- Significant development effort (100+ hours)
- Needs to be maintained across Ghidra versions

### Option 4: Custom Pcode Injection

**Advanced technique using Ghidra's Sleigh specification:**

1. Create a custom processor specification override
2. Define a "pseudo-instruction" for the EBP reuse pattern
3. Modify the Pcode emission for `MOV EBP,EAX` in this context

**Example Sleigh pattern:**

```sleigh
# Custom pattern for detecting EBP reuse after PUSH
:MOV EBP,EAX is mode=0 & opcode=0x89 & modrm=0xC5 & ebp_pushed=1
{
    # Instead of: EBP = EAX
    # Emit: local_var = EAX
    local_ebp_substitute = EAX;
}
```

**Pros:**
- Lowest-level solution, maximum control
- Would produce correct decompilation

**Cons:**
- Extremely complex
- Requires modifying Ghidra's language definitions
- Hard to maintain

### Option 5: Hybrid Approach - Manual Annotation

**Accept the limitation and document thoroughly:**

1. Add extensive decompiler comments at key addresses
2. Create a separate documentation file with the complete logic
3. Use the disassembly view for accurate analysis

**Implementation:**

```python
# Add detailed comments to guide future analysts
comments = {
    "0x6fb6af4f": "CRITICAL: EBP reused as directionResult = SetMissileDirectionFromParameters()",
    "0x6fb6af56": "Validates directionResult before proceeding to mana calculations",
    "0x6fb6af8f": "Retrieves skill instance for mana cost calculation",
    # ... more comments
}

for addr, comment in comments.items():
    set_decompiler_comment(addr, comment)
```

**Pros:**
- Works immediately
- No complex implementation needed
- Documents your reverse engineering insights

**Cons:**
- Doesn't fix the decompilation
- Requires manual effort for each similar function

### Option 6: Alternative Decompiler Comparison

**Try other decompilers to see if they handle this better:**

1. **IDA Pro's Hex-Rays** - Commercial, often handles register reuse better
2. **Binary Ninja** - Modern decompiler with good optimization handling
3. **RetDec** - Open-source, different analysis approach
4. **Snowman** - Another open-source option

**Test process:**

1. Export the function as binary or import the entire DLL
2. Decompile in alternative tool
3. Compare results

**Expected outcome:**
- Some decompilers may produce better output
- Useful for validation even if not a permanent solution

## Recommended Workflow

**For this specific function:**

1. ✅ **Accept the disassembly as authoritative** (already done)
2. ✅ **Document the complete logic** (already done in previous analysis)
3. ⚠️ **Run the provided Python script** to attempt automatic fix
4. ⚠️ **Add decompiler comments** to document the issue
5. ⏸️ **Consider custom plugin** if you encounter this pattern frequently

**For future similar cases:**

1. Detect the pattern early (PUSH reg, then MOV reg,EAX)
2. Document immediately rather than fighting the decompiler
3. Build a library of known problematic patterns
4. Consider developing a custom Ghidra extension if the pattern is common

## Technical Details: Why This Happens

### Normal Frame Pointer Usage

```asm
PUSH EBP           ; Save old frame pointer
MOV EBP,ESP        ; Set new frame pointer
... function body ...
POP EBP            ; Restore frame pointer
RET
```

### Optimized Register Reuse (Our Case)

```asm
PUSH EBP           ; Save EBP (we need it later)
... some code ...
CALL func          ; Returns value in EAX
MOV EBP,EAX        ; ← Reuse EBP as local variable!
TEST EBP,EBP       ; Use it immediately
... more code ...
POP EBP            ; Restore original EBP
RET
```

**Why compilers do this:**
- Saves a stack slot (no need for separate local variable)
- EBP is available (not being used as frame pointer in __fastcall)
- Common optimization in release builds with /O2 or -O3

**Why Ghidra struggles:**
- Decompiler assumes registers have consistent roles
- "Unaffected" analysis doesn't track mid-function reassignments well
- Control flow tracking loses the dependency on the return value

## References

- **Ghidra Issue Tracker**: Search for "register reuse" and "unaff_" issues
- **Ghidra Plugin Development**: https://ghidra.re/ghidra_docs/api/
- **Pcode Reference**: https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/pcoderef.html
- **Sleigh Documentation**: Ghidra's processor specification language

## Files in This Repository

- `FixEBPRegisterReuse.java` - Java script for Ghidra Script Manager
- `FixEBPRegisterReuse.py` - Python script with Pcode analysis
- `docs/COMPLETE_FUNCTION_ANALYSIS.md` - Full disassembly-based documentation

## Conclusion

**Bottom line:** This is a known limitation of static analysis decompilers. The most practical solution is to:

1. Use the disassembly view for accurate analysis
2. Document your findings thoroughly
3. Add comments in Ghidra for future reference
4. Consider developing a custom plugin only if you encounter this pattern frequently enough to justify the effort

The provided scripts may help in some cases, but for aggressive optimizations like this, **human analysis of the disassembly is often more reliable than fighting the decompiler.**

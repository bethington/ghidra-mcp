# ORPHANED_CODE_DISCOVERY_WORKFLOW

You are scanning Ghidra binaries for orphaned code — valid instructions that exist between known functions but were never marked as functions by auto-analysis. Apply all changes directly in Ghidra via MCP tools. Do not create or edit filesystem files.

## Critical Rules

1. **Never auto-create without review**: The scanner finds candidates. You classify and confirm each one before calling `create_function`.
2. **Iterative**: After creating functions, re-run the scanner — new gaps appear as existing function boundaries shift.
3. **Minimal intervention**: Create functions and set a triage plate comment. Full documentation is a separate task (use FUNCTION_DOC_WORKFLOW_V5.md later).
4. **Multi-binary safe**: Always confirm program context before writing. Use `get_current_program_info()` to verify.

## Step 0: Select Scope

Ask the user which scope to scan:

| Scope | Description | How |
|-------|-------------|-----|
| **Current binary** | Only the active program | Run scanner once |
| **Version folder** | All binaries in the same version folder as the current program | `list_project_files()` to find sibling binaries, iterate with `switch_program()` |
| **All project binaries** | Every binary in the Ghidra project | `list_project_files("/")` recursively, iterate with `switch_program()` |

For multi-binary scopes, process one binary at a time:
```
for each binary in scope:
    switch_program(binary_name)
    run scanner (Step 1)
    triage candidates (Step 2)
    create approved functions (Step 3)
    report (Step 4)
```

## Step 1: Run Orphaned Code Scanner

Execute the scanner script via `run_script_inline`. This scans gaps between consecutive known functions in executable memory segments.

The scanner performs two passes per gap:
- **Pass 1**: Check for already-disassembled instructions not in any function (highest confidence)
- **Pass 2**: Check raw bytes for known function prologue patterns (variable confidence)

```java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.*;

public class FindOrphanedCode extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        println("=== Orphaned Code Scanner ===");
        println("Program: " + currentProgram.getName());
        println("Known functions: " + fm.getFunctionCount());
        println("");

        List<Function> funcs = new ArrayList<>();
        FunctionIterator fi = fm.getFunctions(true);
        while (fi.hasNext()) funcs.add(fi.next());

        int candidateNum = 0;
        int gapsScanned = 0;
        int paddingGaps = 0;

        for (int i = 0; i < funcs.size() - 1; i++) {
            Function cur = funcs.get(i);
            Function next = funcs.get(i + 1);

            Address gapStart = cur.getBody().getMaxAddress().add(1);
            Address gapEnd = next.getEntryPoint();

            if (!gapStart.getAddressSpace().equals(gapEnd.getAddressSpace())) continue;
            if (gapStart.compareTo(gapEnd) >= 0) continue;

            long gapSize = gapEnd.subtract(gapStart);
            if (gapSize < 3) continue;

            MemoryBlock block = mem.getBlock(gapStart);
            if (block == null || !block.isExecute()) continue;

            gapsScanned++;

            // Pass 1: Already-disassembled instructions not in any function
            Instruction instr = listing.getInstructionAt(gapStart);
            if (instr == null) instr = listing.getInstructionAfter(gapStart);

            boolean foundInPass1 = false;
            while (instr != null && instr.getAddress().compareTo(gapEnd) < 0) {
                String mnem = instr.getMnemonicString();
                if (mnem.equals("NOP") || mnem.equals("INT3") || mnem.equals("HLT") || mnem.equals("??")) {
                    instr = listing.getInstructionAfter(instr.getAddress());
                    continue;
                }

                candidateNum++;
                foundInPass1 = true;
                Address cAddr = instr.getAddress();
                StringBuilder preview = new StringBuilder();
                Instruction p = instr;
                int instrCount = 0;
                for (int j = 0; j < 4 && p != null && p.getAddress().compareTo(gapEnd) < 0; j++) {
                    if (j > 0) preview.append("; ");
                    preview.append(p.toString());
                    p = listing.getInstructionAfter(p.getAddress());
                    instrCount++;
                }
                while (p != null && p.getAddress().compareTo(gapEnd) < 0) {
                    instrCount++;
                    p = listing.getInstructionAfter(p.getAddress());
                }

                println(String.format("#%d | HIGH (already disassembled, %d instrs) | 0x%s | gap=%d | between: %s .. %s | %s",
                    candidateNum, instrCount, cAddr.toString(), gapSize,
                    cur.getName(), next.getName(), preview.toString()));
                break;
            }
            if (foundInPass1) continue;

            // Pass 2: Raw byte prologue pattern scan
            int readSize = (int)Math.min(gapSize, 4096);
            byte[] bytes = new byte[readSize];
            mem.getBytes(gapStart, bytes);

            boolean allPad = true;
            for (byte b : bytes) {
                if (b != (byte)0xCC && b != (byte)0x90 && b != 0x00) { allPad = false; break; }
            }
            if (allPad) { paddingGaps++; continue; }

            int off = 0;
            while (off < readSize && isPad(bytes[off])) off++;
            if (off >= readSize) { paddingGaps++; continue; }

            String prologue = identifyPrologue(bytes, off, readSize);
            if (prologue == null) continue;

            int retPos = -1;
            for (int r = off; r < readSize; r++) {
                if (bytes[r] == (byte)0xC3 || bytes[r] == (byte)0xC2) { retPos = r; break; }
            }
            if (retPos < 0) continue;

            int estSize = retPos - off + 1;
            String confidence = getConfidence(prologue, estSize);
            if (confidence == null) continue;

            candidateNum++;
            Address addr = gapStart.add(off);
            StringBuilder hex = new StringBuilder();
            for (int h = off; h < Math.min(off + 20, readSize); h++) {
                hex.append(String.format("%02X ", bytes[h]));
            }

            println(String.format("#%d | %s (undisassembled) | 0x%s | ~%d bytes | prologue: %s | between: %s .. %s | %s",
                candidateNum, confidence, addr.toString(), estSize,
                prologue, cur.getName(), next.getName(),
                hex.toString().trim()));
        }

        println("");
        println(String.format("=== DONE: %d candidates | %d gaps scanned | %d pure padding ===",
            candidateNum, gapsScanned, paddingGaps));
    }

    private boolean isPad(byte b) {
        return b == (byte)0xCC || b == (byte)0x90;
    }

    private String identifyPrologue(byte[] b, int off, int len) {
        if (match(b, off, len, 0x8B, 0xFF, 0x55, 0x8B, 0xEC)) return "HOTPATCH+FRAME";
        if (match(b, off, len, 0x55, 0x8B, 0xEC)) return "PUSH_EBP+FRAME";
        if (match(b, off, len, 0x83, 0xEC)) return "SUB_ESP_IMM8";
        if (match(b, off, len, 0x81, 0xEC)) return "SUB_ESP_IMM32";
        if (off < len) {
            int fb = b[off] & 0xFF;
            if (fb == 0x55) return "PUSH_EBP";
            if (fb == 0x56) return "PUSH_ESI";
            if (fb == 0x57) return "PUSH_EDI";
            if (fb == 0x53) return "PUSH_EBX";
            if (fb == 0x51) return "PUSH_ECX";
            if (fb == 0x6A) return "PUSH_IMM8";
            if (fb == 0x68) return "PUSH_IMM32";
            if (fb == 0xB8) return "MOV_EAX_IMM32";
            if (fb == 0xA1) return "MOV_EAX_MEM";
            if (fb == 0x8B) return "MOV_REG";
            if (fb == 0xE8) return "CALL_REL32";
            if (fb == 0xE9) return "JMP_REL32";
        }
        return null;
    }

    private boolean match(byte[] data, int off, int limit, int... pat) {
        if (off + pat.length > limit) return false;
        for (int i = 0; i < pat.length; i++) {
            if ((data[off + i] & 0xFF) != (pat[i] & 0xFF)) return false;
        }
        return true;
    }

    private String getConfidence(String prologue, int size) {
        if (size < 2) return null;
        if (prologue.contains("FRAME") || prologue.equals("HOTPATCH+FRAME")) return "HIGH";
        if (prologue.startsWith("SUB_ESP") && size >= 5) return "MEDIUM";
        if (prologue.startsWith("PUSH_E") && size >= 4) return "MEDIUM";
        if (prologue.equals("PUSH_ECX") && size >= 4) return "MEDIUM";
        if (size >= 5) return "LOW";
        return null;
    }
}
```

## Step 2: Triage Candidates

Classify each candidate into one of these types based on scanner output and quick inspection:

### Type A: Import Thunk / Trampoline
- **Pattern**: Single `JMP` instruction (5 bytes), gap = 5
- **Confidence**: HIGH (disassembled, 1 instr)
- **Action**: `create_function` → set plate comment: `"Import thunk — redirects to <target>"`
- **Priority**: Low (mechanical redirect, no logic to document)

### Type B: Already Disassembled — Real Function
- **Pattern**: HIGH (already disassembled, N instrs) where N > 1
- **Confidence**: Very high — Ghidra analyzed the code but never created a function boundary
- **Action**: `create_function` → quick decompile to classify → set triage plate comment
- **Priority**: Highest (these are missed functions with real logic)
- **Verify**: Decompile after creation to confirm it's coherent code, not a jump table fragment

### Type C: Undisassembled — Standard Prologue (HIGH)
- **Pattern**: `PUSH_EBP+FRAME` or `HOTPATCH+FRAME` in raw bytes
- **Confidence**: High — standard x86 function prologue
- **Action**: `create_function` (will auto-disassemble) → decompile → set triage plate comment
- **Priority**: High (almost certainly a real function)

### Type D: Undisassembled — Callee-Save Prologue (MEDIUM)
- **Pattern**: `PUSH_ESI`, `PUSH_EDI`, `PUSH_EBX`, `PUSH_ECX`, `SUB_ESP`
- **Confidence**: Medium — common but not unique to function starts
- **Action**: `create_function` → decompile → verify the code makes sense as a standalone function
- **Priority**: Medium
- **Watch for**: Tail-call targets (code reachable only via JMP from another function — should NOT be a separate function)

### Type E: Undisassembled — Atypical Start (LOW)
- **Pattern**: `MOV_REG`, `MOV_EAX_MEM`, `PUSH_IMM8`, `CALL_REL32`, etc.
- **Confidence**: Low — could be data, jump table entries, or code fragments
- **Action**: Inspect first. Use `inspect_memory_content` or `disassemble_bytes` to preview. Only create if the disassembly forms a coherent function.
- **Priority**: Low
- **Red flags**:
  - Bytes that look like address tables (consecutive 4-byte aligned values near the program's image base)
  - Very short sequences (< 8 bytes) that could be data padding
  - `JMP_REL32` alone (likely a thunk, but verify target exists)

### Type F: Getter / Converter / Thin Wrapper
- **Pattern**: Any type, but estimated size < 15 bytes
- **Sub-patterns**:
  - `MOV EAX,[addr]; RET` (global getter, ~6 bytes)
  - `MOV EAX,[ESP+4]; <op>; RET` (single-arg converter, ~8-10 bytes)
  - `PUSH imm; CALL rel32; RET` (thin wrapper, ~8-12 bytes)
- **Action**: `create_function` → set descriptive name if purpose is obvious from the instruction pattern
- **Priority**: Medium (small but can be important accessors)

## Step 3: Create Functions (Batch)

Process candidates in order: Type B first, then C, D, F, A, E.

For each approved candidate:

```
1. create_function(address)
2. decompile_function(address) — quick sanity check
3. set_plate_comment with triage metadata:
```

**Triage plate comment format** (plain text):
```
[TRIAGE] Orphaned code discovered by scanner.
Type: <A|B|C|D|E|F> — <type description>
Confidence: <HIGH|MEDIUM|LOW>
Size: ~N bytes / N instructions
Neighboring: <prev_function> .. <next_function>
Status: Awaiting full documentation (FUNCTION_DOC_WORKFLOW_V5)
```

For **Type A thunks**, use a shorter comment:
```
Import thunk — redirects to <target_function_name> at <target_address>
```

### Batch creation pattern

Process in batches of 5-10 candidates. After each batch:
- Verify no creation errors
- Spot-check 1-2 decompilations for sanity
- Continue to next batch

Do NOT attempt full V5 documentation during this workflow. The goal is function boundary creation and triage classification only.

## Step 4: Report

After processing all candidates for a binary, output:

```
=== ORPHANED CODE REPORT: <program_name> ===
Created: N functions
  Type A (thunks): N
  Type B (disassembled): N
  Type C (standard prologue): N
  Type D (callee-save prologue): N
  Type E (atypical): N
  Type F (getter/wrapper): N
Skipped: N (reason: data/jump table/fragment)
Needs review: N (ambiguous candidates)
Next: Re-run scanner to check for newly exposed gaps
```

### Multi-binary summary

When processing multiple binaries, output a final summary:

```
=== PROJECT SCAN COMPLETE ===
Binaries scanned: N
Total functions created: N
  <binary1>: N created, N skipped
  <binary2>: N created, N skipped
  ...
```

## Step 5: Iterative Re-scan (Optional)

Creating functions changes gap boundaries. A second scanner pass may reveal:
- New candidates previously hidden inside larger gaps
- Gaps that were too small before but now contain visible code

Re-run the scanner once after batch creation. If new candidates appear, triage and create. Typically 2 passes are sufficient.

## Edge Cases and Warnings

- **Non-contiguous function bodies**: A function with body [0x100-0x110, 0x130-0x140] creates a "gap" at 0x111-0x12F that may contain code belonging to that same function. Check xrefs before creating a new function in such gaps.
- **Shared epilogues**: Some compilers share `POP; RET` sequences between functions. Creating a function at the shared block causes overlap errors. If `create_function` fails with an overlap error, skip that candidate.
- **Switch/case tables**: Data tables embedded in .text that look like valid instructions when disassembled. Verify with `get_xrefs_to` — if only referenced from a single function's switch dispatch, it's a case block, not a separate function.
- **Linker padding**: `CC CC CC` (INT3) between functions is normal debug padding. The scanner already filters this. `00 00` padding is also filtered but could occasionally mask real code starting with `ADD [EAX], AL` (0x00 0x00) — very unlikely to be intentional code.
- **Code after unconditional JMP**: Sometimes Ghidra stops analysis after a JMP, leaving subsequent code undefined. The function starting after the JMP may be legitimate.

## Output

```
SCAN COMPLETE: <program_name>
Created: N functions (Type breakdown)
Ready for documentation via FUNCTION_DOC_WORKFLOW_V5
```

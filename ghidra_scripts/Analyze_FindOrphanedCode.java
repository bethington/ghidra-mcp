// Find Orphaned Code
//
// Scans gaps between known functions for valid code that auto-analysis missed. Creates functions automatically, filters data tables, and sets triage plate comments.
//
// Usage: Args: --dry-run, --max-passes=N, --min-size=N, --no-comments, --all-programs, --folder=PATH.
// Output: Creates functions at discovered code locations with triage comments.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Discover orphaned code and create functions automatically
// @menupath Diablo 2.Analysis.Find Orphaned Code

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.model.*;
import java.util.*;

public class Analyze_FindOrphanedCode extends GhidraScript {

    // Configuration
    private boolean dryRun = false;
    private int maxPasses = 5;
    private int minSize = 5;
    private boolean setComments = true;
    private boolean allPrograms = false;
    private String targetFolder = null;

    // Per-program counters (reset before each program)
    private int progCreated;
    private int progSkippedDataTable;
    private int progSkippedTooSmall;
    private int progSkippedCreateFailed;
    private int progSkippedOverlap;
    private int[] progTypeCounters;

    // Grand totals (accumulated across all programs)
    private int grandCreated = 0;
    private int grandSkippedDataTable = 0;
    private int grandSkippedTooSmall = 0;
    private int grandSkippedCreateFailed = 0;
    private int grandSkippedOverlap = 0;
    private int[] grandTypeCounters = new int[8];
    private int grandProgramsScanned = 0;
    private int grandProgramsModified = 0;

    // Per-program summary lines for final report
    private List<String> programSummaries = new ArrayList<>();

    // Program address range for data table detection (set per program)
    private long imageBase;
    private long imageEnd;

    // Active program reference (allows scan methods to work on any program)
    private Program activeProgram;

    @Override
    public void run() throws Exception {
        parseArgs();

        println("=== FindOrphanedCode v5 (Project-Wide) ===");
        println("Mode: " + (dryRun ? "DRY RUN (scan only)" : "CREATE (auto-create functions)"));
        println("Max passes: " + maxPasses + " | Min size: " + minSize + " bytes");

        if (allPrograms || targetFolder != null) {
            // Project-wide mode
            String scope = allPrograms ? "entire project" : ("folder: " + targetFolder);
            println("Scope: " + scope);
            println("");
            runProjectWide();
        } else {
            // Single-program mode (original behavior)
            println("Scope: current program (" + currentProgram.getName() + ")");
            println("");
            activeProgram = currentProgram;
            scanOneProgram(currentProgram, currentProgram.getDomainFile().getPathname());
        }

        // Grand total report
        if (grandProgramsScanned > 1) {
            println("");
            println("==========================================================");
            println("=== GRAND TOTAL (all programs) ===");
            println("==========================================================");
            println("Programs scanned:  " + grandProgramsScanned);
            println("Programs modified: " + grandProgramsModified);
            println("Functions created: " + grandCreated);
            println("  Type B (already disassembled): " + grandTypeCounters[1]);
            println("  Type C (standard prologue):    " + grandTypeCounters[2]);
            println("  Type D (callee-save/operand):  " + grandTypeCounters[3]);
            println("  Type E (atypical start):       " + grandTypeCounters[4]);
            println("  Type F (getter/wrapper):       " + grandTypeCounters[5]);
            println("  Type G (unknown prologue):     " + grandTypeCounters[6]);
            println("  Type A (thunks):               " + grandTypeCounters[0]);
            int grandSkipped = grandSkippedDataTable + grandSkippedTooSmall +
                               grandSkippedCreateFailed + grandSkippedOverlap;
            println("Skipped: " + grandSkipped);
            println("  Data tables:    " + grandSkippedDataTable);
            println("  Too small:      " + grandSkippedTooSmall);
            println("  Create failed:  " + grandSkippedCreateFailed);
            println("  Overlap errors: " + grandSkippedOverlap);
            println("");
            println("--- Per-program breakdown ---");
            for (String summary : programSummaries) {
                println(summary);
            }
        }

        if (dryRun) {
            println("\n*** DRY RUN - no changes were made ***");
        }
    }

    /**
     * Iterate over project files and scan each program.
     */
    private void runProjectWide() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            printerr("ERROR: No project open.");
            return;
        }
        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        // Determine starting folder
        DomainFolder startFolder;
        if (targetFolder != null) {
            startFolder = projectData.getFolder(targetFolder);
            if (startFolder == null) {
                printerr("ERROR: Folder not found: " + targetFolder);
                return;
            }
        } else {
            startFolder = rootFolder;
        }

        // Collect all program files recursively
        List<DomainFile> programFiles = new ArrayList<>();
        collectProgramFiles(startFolder, programFiles);

        println("Found " + programFiles.size() + " program(s) to scan.");
        println("");

        int skippedReadOnly = 0;

        for (int idx = 0; idx < programFiles.size(); idx++) {
            if (monitor.isCancelled()) {
                println("*** Cancelled by user ***");
                break;
            }

            DomainFile df = programFiles.get(idx);
            String path = df.getPathname();
            println(String.format("[%d/%d] Opening: %s", idx + 1, programFiles.size(), path));

            Program program = null;
            boolean weOpened = false;
            boolean hasWriteAccess = false;
            try {
                // Check if this program is already open in the tool
                if (currentProgram != null &&
                    currentProgram.getDomainFile().getPathname().equals(path)) {
                    program = currentProgram;
                    hasWriteAccess = true;
                } else {
                    // Try opening with write access first.
                    // If that fails (version control lock, etc.), fall back to read-only.
                    boolean canWrite = !dryRun; // Only need write if not dry-run
                    DomainObject obj = null;

                    if (canWrite) {
                        try {
                            obj = df.getDomainObject(this, true, false, monitor);
                        } catch (Exception we) {
                            // Write access failed — fall back to read-only
                            println("  Write access failed (" + we.getMessage() + "), opening read-only");
                            canWrite = false;
                        }
                    }

                    if (obj == null) {
                        obj = df.getDomainObject(this, false, false, monitor);
                        canWrite = false;
                    }

                    if (!(obj instanceof Program)) {
                        println("  Skipping (not a program): " + path);
                        obj.release(this);
                        continue;
                    }
                    program = (Program) obj;
                    weOpened = true;
                    hasWriteAccess = canWrite;

                    if (!canWrite && !dryRun) {
                        println("  (read-only — scan only, no functions will be created)");
                        skippedReadOnly++;
                    }
                }

                // If we don't have write access and not dry-run, force scan-only
                boolean savedDryRun = dryRun;
                if (!hasWriteAccess && !dryRun) {
                    dryRun = true;
                }

                activeProgram = program;
                scanOneProgram(program, path);

                dryRun = savedDryRun;

                // Save if we made changes
                if (weOpened && hasWriteAccess && progCreated > 0 && !savedDryRun) {
                    program.save("FindOrphanedCode auto-save", monitor);
                    println("  Saved: " + path);
                }

            } catch (Exception e) {
                printerr("  ERROR processing " + path + ": " + e.getMessage());
            } finally {
                if (weOpened && program != null) {
                    program.release(this);
                }
            }
            println("");
        }

        if (skippedReadOnly > 0) {
            println(String.format("NOTE: %d program(s) were scanned read-only (could not checkout).", skippedReadOnly));
            println("Re-run on individual programs or check out files first.");
        }
    }

    /**
     * Recursively collect all DomainFiles with content type "Program".
     */
    private void collectProgramFiles(DomainFolder folder, List<DomainFile> result) throws Exception {
        for (DomainFile file : folder.getFiles()) {
            // Only include program files
            String contentType = file.getContentType();
            if (contentType != null && contentType.contains("Program")) {
                result.add(file);
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectProgramFiles(sub, result);
        }
    }

    /**
     * Scan a single program for orphaned code. Works on any Program object.
     */
    private void scanOneProgram(Program program, String path) throws Exception {
        // Reset per-program counters
        progCreated = 0;
        progSkippedDataTable = 0;
        progSkippedTooSmall = 0;
        progSkippedCreateFailed = 0;
        progSkippedOverlap = 0;
        progTypeCounters = new int[8];

        FunctionManager fm = program.getFunctionManager();
        Memory mem = program.getMemory();

        // Set image range for data table heuristic
        imageBase = program.getMinAddress().getOffset();
        imageEnd = program.getMaxAddress().getOffset();

        int startCount = fm.getFunctionCount();
        println("  Program: " + program.getName() + " (" + path + ")");
        println("  Starting functions: " + startCount);

        // Iterative scanning loop
        int effectiveMaxPasses = dryRun ? 1 : maxPasses;
        for (int pass = 1; pass <= effectiveMaxPasses; pass++) {
            int created = runScanPass(pass, program);
            println(String.format("  --- Pass %d complete: %d functions %s ---",
                    pass, created, dryRun ? "found" : "created"));
            if (created == 0) {
                break;
            }
        }

        int endCount = fm.getFunctionCount();
        int delta = endCount - startCount;

        // Per-program report
        println(String.format("  Result: %d -> %d (+%d) | data_tables=%d too_small=%d failed=%d overlap=%d",
                startCount, endCount, delta,
                progSkippedDataTable, progSkippedTooSmall,
                progSkippedCreateFailed, progSkippedOverlap));

        // Accumulate grand totals
        grandCreated += progCreated;
        grandSkippedDataTable += progSkippedDataTable;
        grandSkippedTooSmall += progSkippedTooSmall;
        grandSkippedCreateFailed += progSkippedCreateFailed;
        grandSkippedOverlap += progSkippedOverlap;
        for (int t = 0; t < progTypeCounters.length; t++) {
            grandTypeCounters[t] += progTypeCounters[t];
        }
        grandProgramsScanned++;
        if (progCreated > 0) grandProgramsModified++;

        // Save summary line
        programSummaries.add(String.format("  %-40s  %d -> %d (+%d)", path, startCount, endCount, delta));
    }

    /**
     * Run one scan pass over a program, returning the number of functions created.
     */
    private int runScanPass(int passNum, Program program) throws Exception {
        Listing listing = program.getListing();
        FunctionManager fm = program.getFunctionManager();
        Memory mem = program.getMemory();

        List<Function> funcs = new ArrayList<>();
        FunctionIterator fi = fm.getFunctions(true);
        while (fi.hasNext()) funcs.add(fi.next());

        int createdThisPass = 0;
        int gapsScanned = 0;
        int paddingGaps = 0;

        for (int i = 0; i < funcs.size() - 1; i++) {
            if (monitor.isCancelled()) {
                println("  *** Cancelled by user ***");
                return createdThisPass;
            }

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

            // Read raw bytes upfront for all passes (data table check, Pass 2, Pass 3)
            int readSize = (int) Math.min(gapSize, 4096);
            byte[] bytes = new byte[readSize];
            mem.getBytes(gapStart, bytes);

            // Check if all padding (CC, 90, or 00)
            boolean allPad = true;
            for (byte b : bytes) {
                if (b != (byte) 0xCC && b != (byte) 0x90 && b != 0x00) {
                    allPad = false;
                    break;
                }
            }
            if (allPad) { paddingGaps++; continue; }

            // Skip leading padding (CC, 90, and 00)
            int off = 0;
            while (off < readSize && isPad(bytes[off])) off++;
            if (off >= readSize) { paddingGaps++; continue; }

            // Data table detection BEFORE any pass -- applies to all candidates
            if (isLikelyDataTable(bytes, off, readSize)) {
                progSkippedDataTable++;
                continue;
            }

            // Pass 1: Already-disassembled instructions not in any function
            Instruction instr = listing.getInstructionAt(gapStart);
            if (instr == null) instr = listing.getInstructionAfter(gapStart);

            if (instr != null && instr.getAddress().compareTo(gapEnd) < 0) {
                // Skip padding instructions
                while (instr != null && instr.getAddress().compareTo(gapEnd) < 0) {
                    String mnem = instr.getMnemonicString();
                    if (!mnem.equals("NOP") && !mnem.equals("INT3") &&
                        !mnem.equals("HLT") && !mnem.equals("??")) {
                        break;
                    }
                    instr = listing.getInstructionAfter(instr.getAddress());
                }

                if (instr != null && instr.getAddress().compareTo(gapEnd) < 0) {
                    Address cAddr = instr.getAddress();
                    int instrCount = countInstructions(listing, cAddr, gapEnd);
                    boolean isThunk = (instrCount == 1 && instr.getMnemonicString().equals("JMP"));

                    String type = isThunk ? "A" : "B";
                    int typeIdx = isThunk ? 0 : 1;

                    if (tryCreateFunction(program, cAddr, cur.getName(), next.getName(),
                            type, typeIdx, "HIGH",
                            instrCount + " instrs (already disassembled)", (int) gapSize)) {
                        createdThisPass++;
                    }
                    continue;
                }
            }

            // Find first RET
            int retPos = -1;
            for (int r = off; r < readSize; r++) {
                if (bytes[r] == (byte) 0xC3 || bytes[r] == (byte) 0xC2) {
                    retPos = r;
                    break;
                }
            }
            if (retPos < 0) continue;

            int estSize = retPos - off + 1;

            // Pass 2: Known prologue patterns
            String prologue = identifyPrologue(bytes, off, readSize);
            if (prologue != null) {
                String confidence = getConfidence(prologue, estSize);
                if (confidence == null) {
                    progSkippedTooSmall++;
                    continue;
                }

                Address addr = gapStart.add(off);
                String type = mapPrologueToType(prologue, confidence);
                int typeIdx = typeCharToIndex(type);

                if (tryCreateFunction(program, addr, cur.getName(), next.getName(),
                        type, typeIdx, confidence,
                        "~" + estSize + " bytes, prologue: " + prologue, (int) gapSize)) {
                    createdThisPass++;
                }
                continue;
            }

            // Pass 3: Unknown prologue fallback
            if (estSize >= minSize) {
                Address addr = gapStart.add(off);

                int retCount = 0;
                for (int r = off; r < readSize; r++) {
                    if (bytes[r] == (byte) 0xC3 || bytes[r] == (byte) 0xC2) retCount++;
                }
                String extra = retCount > 1 ? " MULTI-RET(" + retCount + ")" : "";

                if (tryCreateFunction(program, addr, cur.getName(), next.getName(),
                        "G", 6, "REVIEW",
                        "~" + estSize + " bytes, first=0x" + String.format("%02X", bytes[off] & 0xFF) + extra,
                        (int) gapSize)) {
                    createdThisPass++;
                }
            }
        }

        println(String.format("    Pass %d: scanned %d gaps, %d padding, %d created",
                passNum, gapsScanned, paddingGaps, createdThisPass));
        return createdThisPass;
    }

    /**
     * Attempt to create a function at the given address in the specified program.
     */
    private boolean tryCreateFunction(Program program, Address addr,
                                       String prevFunc, String nextFunc,
                                       String type, int typeIdx, String confidence,
                                       String sizeInfo, int gapSize) {
        if (dryRun) {
            println(String.format("    [DRY RUN] Would create Type %s at 0x%s | %s | %s | between: %s .. %s",
                    type, addr.toString(), confidence, sizeInfo, prevFunc, nextFunc));
            progCreated++;
            progTypeCounters[typeIdx]++;
            return true;
        }

        FunctionManager fm = program.getFunctionManager();
        if (fm.getFunctionAt(addr) != null) {
            return false;
        }

        // Wrap all modifications in a single transaction.
        // Programs opened via getDomainObject() (not currentProgram) require
        // explicit transactions for any write operations.
        int txId = program.startTransaction("FindOrphanedCode: create function");
        boolean txSuccess = false;
        try {
            Listing listing = program.getListing();

            // Disassemble first if needed
            if (listing.getInstructionAt(addr) == null) {
                ghidra.app.cmd.disassemble.DisassembleCommand cmd =
                    new ghidra.app.cmd.disassemble.DisassembleCommand(addr, null, true);
                cmd.applyTo(program, monitor);
            }

            if (listing.getInstructionAt(addr) == null) {
                progSkippedCreateFailed++;
                return false;
            }

            // Create the function
            CreateFunctionCmd createCmd = new CreateFunctionCmd(addr);
            boolean success = createCmd.applyTo(program, monitor);

            if (!success) {
                String err = createCmd.getStatusMsg();
                if (err != null && err.contains("overlap")) {
                    progSkippedOverlap++;
                } else {
                    progSkippedCreateFailed++;
                }
                return false;
            }

            Function newFunc = fm.getFunctionAt(addr);
            if (newFunc == null) {
                progSkippedCreateFailed++;
                return false;
            }

            // Determine if it's actually a thunk (single JMP)
            if (type.equals("B")) {
                Instruction firstInstr = listing.getInstructionAt(addr);
                if (firstInstr != null && firstInstr.getMnemonicString().equals("JMP")) {
                    int instrCount = countInstructions(listing, addr,
                            newFunc.getBody().getMaxAddress().add(1));
                    if (instrCount == 1) {
                        type = "A";
                        typeIdx = 0;
                    }
                }
            }

            // Check if it's a small getter/wrapper (Type F override)
            long bodySize = newFunc.getBody().getNumAddresses();
            if (bodySize <= 15 && !type.equals("A") && !type.equals("B")) {
                type = "F";
                typeIdx = 5;
                sizeInfo = bodySize + " bytes (getter/wrapper)";
            }

            // Set plate comment
            if (setComments) {
                String typeDesc = getTypeDescription(type);
                String comment;
                if (type.equals("A")) {
                    Instruction jmpInstr = listing.getInstructionAt(addr);
                    String target = jmpInstr != null ? jmpInstr.getDefaultOperandRepresentation(0) : "unknown";
                    comment = "Import thunk -- redirects to " + target;
                } else {
                    comment = String.format(
                            "[TRIAGE] Orphaned code discovered by FindOrphanedCode script.\n" +
                            "Type: %s -- %s\n" +
                            "Confidence: %s\n" +
                            "Size: %s\n" +
                            "Neighboring: %s .. %s\n" +
                            "Status: Awaiting full documentation (FUNCTION_DOC_WORKFLOW_V5)",
                            type, typeDesc, confidence, sizeInfo, prevFunc, nextFunc);
                }
                newFunc.setComment(comment);
            }

            txSuccess = true;
            progCreated++;
            progTypeCounters[typeIdx]++;
            println(String.format("    Created Type %s: %s at 0x%s (%d bytes) | %s | %s .. %s",
                    type, newFunc.getName(), addr.toString(), bodySize, confidence, prevFunc, nextFunc));
            return true;

        } catch (Exception e) {
            progSkippedCreateFailed++;
            println(String.format("    ERROR creating at 0x%s: %s", addr.toString(), e.getMessage()));
            return false;
        } finally {
            program.endTransaction(txId, txSuccess);
        }
    }

    // -----------------------------------------------------------------------
    // Data table detection
    // -----------------------------------------------------------------------

    /**
     * Detect if a byte range looks like an address/jump table rather than code.
     * Scans multiple windows within the gap to catch tables that don't start at `off`.
     */
    private boolean isLikelyDataTable(byte[] bytes, int off, int len) {
        Set<Integer> startPositions = new LinkedHashSet<>();
        startPositions.add(off);

        for (int pos = (off + 15) & ~15; pos + 8 < len; pos += 16) {
            startPositions.add(pos);
        }

        for (int startOff : startPositions) {
            if (checkDataTableWindow(bytes, startOff, len)) {
                return true;
            }
        }
        return false;
    }

    private boolean checkDataTableWindow(byte[] bytes, int off, int len) {
        int checkLen = Math.min(len - off, 64);
        if (checkLen < 8) return false;

        int alignedOff = (off + 3) & ~3;
        if (alignedOff >= len) return false;

        int dwordCount = 0;
        int addrCount = 0;

        for (int pos = alignedOff; pos + 3 < len && pos < alignedOff + 64; pos += 4) {
            long val = ((bytes[pos] & 0xFFL)) |
                       ((bytes[pos + 1] & 0xFFL) << 8) |
                       ((bytes[pos + 2] & 0xFFL) << 16) |
                       ((bytes[pos + 3] & 0xFFL) << 24);
            dwordCount++;
            if (val >= imageBase && val <= imageEnd) {
                addrCount++;
            }
        }

        return dwordCount >= 2 && (addrCount * 100 / dwordCount) > 50;
    }

    // -----------------------------------------------------------------------
    // Utility methods
    // -----------------------------------------------------------------------

    private int countInstructions(Listing listing, Address start, Address end) {
        int count = 0;
        Instruction instr = listing.getInstructionAt(start);
        while (instr != null && instr.getAddress().compareTo(end) < 0) {
            count++;
            instr = listing.getInstructionAfter(instr.getAddress());
        }
        return count;
    }

    private boolean isPad(byte b) {
        return b == (byte) 0xCC || b == (byte) 0x90 || b == 0x00;
    }

    private String identifyPrologue(byte[] b, int off, int len) {
        // Multi-byte patterns (check first)
        if (match(b, off, len, 0x8B, 0xFF, 0x55, 0x8B, 0xEC)) return "HOTPATCH+FRAME";
        if (match(b, off, len, 0x55, 0x8B, 0xEC)) return "PUSH_EBP+FRAME";
        if (match(b, off, len, 0x83, 0xEC)) return "SUB_ESP_IMM8";
        if (match(b, off, len, 0x81, 0xEC)) return "SUB_ESP_IMM32";

        // Two-byte 0x0F prefix instructions (MOVSX, MOVZX)
        if (match(b, off, len, 0x0F, 0xBE)) return "MOVSX_R32_R8";
        if (match(b, off, len, 0x0F, 0xBF)) return "MOVSX_R32_R16";
        if (match(b, off, len, 0x0F, 0xB6)) return "MOVZX_R32_R8";
        if (match(b, off, len, 0x0F, 0xB7)) return "MOVZX_R32_R16";

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
            if (fb == 0x8B) return "MOV_R32_RM32";
            if (fb == 0x8A) return "MOV_R8_RM8";
            if (fb == 0x89) return "MOV_RM32_R32";
            if (fb == 0x88) return "MOV_RM8_R8";
            if (fb == 0x33) return "XOR_R32_RM32";
            if (fb == 0x31) return "XOR_RM32_R32";
            if (fb == 0x3B) return "CMP_R32_RM32";
            if (fb == 0x85) return "TEST_R32_R32";
            if (fb == 0xF6) return "TEST_RM8_IMM8";
            if (fb == 0x80) return "ALU_RM8_IMM8";
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
        if (prologue.startsWith("MOVSX") || prologue.startsWith("MOVZX")) return "MEDIUM";
        if (prologue.equals("MOV_R8_RM8") && size >= 5) return "MEDIUM";
        if (prologue.equals("XOR_R32_RM32") && size >= 4) return "MEDIUM";
        if (prologue.equals("TEST_R32_R32") && size >= 4) return "MEDIUM";
        if (size >= 5) return "LOW";
        return null;
    }

    private String mapPrologueToType(String prologue, String confidence) {
        if (confidence.equals("HIGH")) return "C";
        if (confidence.equals("MEDIUM")) return "D";
        return "E";
    }

    private int typeCharToIndex(String type) {
        switch (type) {
            case "A": return 0;
            case "B": return 1;
            case "C": return 2;
            case "D": return 3;
            case "E": return 4;
            case "F": return 5;
            case "G": return 6;
            default: return 6;
        }
    }

    private String getTypeDescription(String type) {
        switch (type) {
            case "A": return "Import thunk / trampoline";
            case "B": return "Already disassembled, real function";
            case "C": return "Standard prologue (PUSH EBP; MOV EBP,ESP)";
            case "D": return "Callee-save / operand prologue";
            case "E": return "Atypical start";
            case "F": return "Getter / converter / thin wrapper";
            case "G": return "Unknown prologue (pass 3 fallback)";
            default: return "Unknown";
        }
    }

    private void parseArgs() {
        String[] args = getScriptArgs();
        for (String arg : args) {
            if (arg.equals("--dry-run")) {
                dryRun = true;
            } else if (arg.startsWith("--max-passes=")) {
                maxPasses = Integer.parseInt(arg.substring("--max-passes=".length()));
            } else if (arg.startsWith("--min-size=")) {
                minSize = Integer.parseInt(arg.substring("--min-size=".length()));
            } else if (arg.equals("--no-comments")) {
                setComments = false;
            } else if (arg.equals("--all-programs")) {
                allPrograms = true;
            } else if (arg.startsWith("--folder=")) {
                targetFolder = arg.substring("--folder=".length());
            }
        }
    }
}

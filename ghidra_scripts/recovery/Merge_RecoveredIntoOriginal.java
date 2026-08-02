// Merge_RecoveredIntoOriginal.java
// Copies all RE documentation from a "<name>_recovered" Program to the
// matching "<name>.dll" original at the same address. Use after the orphan
// rescue (Recover_OrphanedProgramSaveAs.java + Recover_AllOrphans.java).
//
// What gets merged (in this order, all best-effort):
//   1. Function signatures (full prototype: return + params with names + types)
//   2. Function names (when source name is not the default FUN_<addr>)
//   3. Plate comments on functions
//   4. EOL / PRE / POST comments on every instruction
//   5. Labels at every address that has one in source but not in target
//   6. Global variable symbols (data labels in the global namespace)
//
// What this does NOT do (yet):
//   - Apply data type DEFINITIONS (struct layouts, enums, typedefs).
//     Function signatures pull in any types they reference, but standalone
//     types from source's DataTypeManager that aren't reachable via signatures
//     are not copied. If you need them, run the existing DataTypeService
//     import on the target separately.
//   - Bookmarks
//
// Usage:
//   1. Open the ORIGINAL (e.g. Bnclient.dll) in a CodeBrowser. The script
//      uses currentProgram as the merge TARGET.
//   2. The recovered sibling MUST exist in the same project folder with the
//      name "<originalStem>_recovered" (e.g. Bnclient_recovered).
//   3. First run with PERFORM_WRITES = false. Script counts what would be
//      merged without writing anything.
//   4. Inspect counts. Set PERFORM_WRITES = true and re-run.
//   5. After success, save the target program (Ctrl+S) and checkin.
//
//@author benam
//@category Recovery
//@menupath Tools.Recovery.Merge Recovered Docs Into Original

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramMerge;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class Merge_RecoveredIntoOriginal extends GhidraScript {

    // === Configuration ===
    private static final boolean PERFORM_WRITES   = false;  // <-- flip to true to actually merge
    private static final String  RECOVERED_SUFFIX = "_recovered";

    // FUN_xxxxxxxx, LAB_xxxxxxxx, DAT_xxxxxxxx — Ghidra default symbol patterns
    private static final Pattern DEFAULT_NAME = Pattern.compile(
        "^(FUN|LAB|DAT|UNK|SUB|EXT|OFF|switchD)_[0-9a-fA-F]+$");

    @Override
    public void run() throws Exception {
        Program target = currentProgram;
        if (target == null) {
            println("ERROR: open the ORIGINAL program in CodeBrowser first.");
            return;
        }

        // Resolve the recovered sibling
        String origName = target.getName();
        String stem = origName;
        int dot = stem.lastIndexOf('.');
        if (dot > 0) stem = stem.substring(0, dot);
        String recoveredName = stem + RECOVERED_SUFFIX;

        DomainFile origDf = target.getDomainFile();
        if (origDf == null) {
            println("ERROR: target program has no DomainFile (orphaned?). Aborting.");
            return;
        }
        DomainFolder folder = origDf.getParent();
        DomainFile recoveredDf = folder.getFile(recoveredName);
        if (recoveredDf == null) {
            println("ERROR: no sibling found at " + folder.getPathname() + "/" + recoveredName);
            return;
        }

        println("Target:    " + origDf.getPathname()
            + " (fns=" + target.getFunctionManager().getFunctionCount()
            + ", syms=" + target.getSymbolTable().getNumSymbols() + ")");
        println("Source:    " + recoveredDf.getPathname()
            + " (loading...)");

        // Open recovered as a sibling DomainObject (read-only consumer)
        Program source = (Program) recoveredDf.getDomainObject(this, false, false, monitor);
        try {
            println("Source:    " + recoveredDf.getPathname()
                + " (fns=" + source.getFunctionManager().getFunctionCount()
                + ", syms=" + source.getSymbolTable().getNumSymbols() + ")");

            if (PERFORM_WRITES) {
                int txId = target.startTransaction("Merge from " + recoveredName);
                try {
                    runMerge(source, target);
                    target.endTransaction(txId, true);
                } catch (Throwable t) {
                    target.endTransaction(txId, false);
                    throw t;
                }
            } else {
                runMerge(source, target);
            }
        } finally {
            source.release(this);
        }
    }

    private int totalFnSig = 0, wroteFnSig = 0;
    private int totalFnName = 0, wroteFnName = 0;
    private int totalPlate = 0, wrotePlate = 0;
    private int totalInstrComments = 0, wroteInstrComments = 0;
    private int totalLabels = 0, wroteLabels = 0;
    private int totalGlobals = 0, wroteGlobals = 0;
    private int errors = 0;

    private void runMerge(Program source, Program target) {
        FunctionManager srcFm = source.getFunctionManager();
        FunctionManager tgtFm = target.getFunctionManager();
        Listing srcListing = source.getListing();
        Listing tgtListing = target.getListing();
        SymbolTable srcSt = source.getSymbolTable();
        SymbolTable tgtSt = target.getSymbolTable();

        // --- Functions: name + signature + plate comment ---
        FunctionIterator srcFns = srcFm.getFunctions(true);
        for (Function srcFn : srcFns) {
            if (monitor.isCancelled()) break;
            Address addr = srcFn.getEntryPoint();
            Function tgtFn = tgtFm.getFunctionAt(addr);
            if (tgtFn == null) continue;  // function exists in source but not target

            // Function name
            String srcName = srcFn.getName();
            if (!isDefaultName(srcName)) {
                totalFnName++;
                if (!srcName.equals(tgtFn.getName())) {
                    if (PERFORM_WRITES) {
                        try {
                            tgtFn.setName(srcName, SourceType.USER_DEFINED);
                            wroteFnName++;
                        } catch (Exception e) {
                            errors++;
                            println("  rename @" + addr + " " + tgtFn.getName() + " -> " + srcName + " : " + e.getMessage());
                        }
                    } else {
                        wroteFnName++;
                    }
                }
            }

            // Function signature (return type + params with names + types)
            // We compare by stringified prototype to avoid no-op writes.
            try {
                String srcProto = srcFn.getPrototypeString(true, false);
                String tgtProto = tgtFn.getPrototypeString(true, false);
                if (!srcProto.equals(tgtProto)) {
                    totalFnSig++;
                    if (PERFORM_WRITES) {
                        // Use ghidra.program.model.listing.FunctionUtility's copySignature
                        try {
                            ghidra.program.util.FunctionUtility.updateFunction(tgtFn, srcFn);
                            wroteFnSig++;
                        } catch (Exception e) {
                            errors++;
                            println("  signature @" + addr + " : " + e.getMessage());
                        }
                    } else {
                        wroteFnSig++;
                    }
                }
            } catch (Exception e) {
                // prototype string failed — skip signature for this function
            }

            // Plate comment
            String srcPlate = srcFn.getComment();
            if (srcPlate != null && !srcPlate.isEmpty()) {
                totalPlate++;
                String tgtPlate = tgtFn.getComment();
                if (tgtPlate == null || tgtPlate.isEmpty() || !tgtPlate.equals(srcPlate)) {
                    if (PERFORM_WRITES) {
                        try {
                            tgtFn.setComment(srcPlate);
                            wrotePlate++;
                        } catch (Exception e) {
                            errors++;
                        }
                    } else {
                        wrotePlate++;
                    }
                }
            }
        }

        // --- Instruction comments (EOL / PRE / POST) ---
        // Use the new int constants since the CodeUnit.* constants are deprecated.
        // Ghidra 12 still accepts the same int values for backwards compat.
        final int EOL_COMMENT = CodeUnit.EOL_COMMENT;
        final int PRE_COMMENT = CodeUnit.PRE_COMMENT;
        final int POST_COMMENT = CodeUnit.POST_COMMENT;
        final int[] commentTypes = { EOL_COMMENT, PRE_COMMENT, POST_COMMENT };

        InstructionIterator srcInstrs = srcListing.getInstructions(true);
        for (Instruction srcInstr : srcInstrs) {
            if (monitor.isCancelled()) break;
            Address addr = srcInstr.getAddress();
            for (int ct : commentTypes) {
                String srcCmt = srcInstr.getComment(ct);
                if (srcCmt == null || srcCmt.isEmpty()) continue;
                totalInstrComments++;
                String tgtCmt = tgtListing.getComment(ct, addr);
                if (tgtCmt != null && tgtCmt.equals(srcCmt)) continue;
                if (PERFORM_WRITES) {
                    try {
                        tgtListing.setComment(addr, ct, srcCmt);
                        wroteInstrComments++;
                    } catch (Exception e) {
                        errors++;
                    }
                } else {
                    wroteInstrComments++;
                }
            }
        }

        // --- Labels & global variables ---
        // Walk all source symbols. Copy any non-default user-named symbol that
        // doesn't already exist at the same address in the target.
        SymbolIterator allSrc = srcSt.getAllSymbols(false);
        while (allSrc.hasNext()) {
            if (monitor.isCancelled()) break;
            Symbol srcSym = allSrc.next();
            String name = srcSym.getName();
            if (isDefaultName(name)) continue;
            if (srcSym.getSource() == SourceType.DEFAULT) continue;

            Address addr = srcSym.getAddress();
            if (addr == null || !addr.isMemoryAddress()) continue;

            // Skip if it's a function entry point — already handled above
            if (srcSym.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) continue;

            // Check target already has this name at this address
            Symbol[] tgtSyms = tgtSt.getSymbols(addr);
            boolean exists = false;
            for (Symbol s : tgtSyms) {
                if (s.getName().equals(name)) { exists = true; break; }
            }
            if (exists) continue;

            // Classify as label vs global based on namespace
            boolean isGlobal = srcSym.getParentNamespace().isGlobal();
            if (isGlobal) totalGlobals++; else totalLabels++;

            if (PERFORM_WRITES) {
                try {
                    tgtSt.createLabel(addr, name, SourceType.USER_DEFINED);
                    if (isGlobal) wroteGlobals++; else wroteLabels++;
                } catch (Exception e) {
                    errors++;
                }
            } else {
                if (isGlobal) wroteGlobals++; else wroteLabels++;
            }
        }

        // --- Summary ---
        println("\n=== Merge summary (mode: " + (PERFORM_WRITES ? "WROTE" : "DRY RUN") + ") ===");
        println(String.format("  function names (changed):   %d / %d", wroteFnName, totalFnName));
        println(String.format("  function signatures:        %d / %d", wroteFnSig, totalFnSig));
        println(String.format("  plate comments:             %d / %d", wrotePlate, totalPlate));
        println(String.format("  instruction comments:       %d / %d", wroteInstrComments, totalInstrComments));
        println(String.format("  labels (non-global):        %d / %d", wroteLabels, totalLabels));
        println(String.format("  global symbols:             %d / %d", wroteGlobals, totalGlobals));
        println(String.format("  errors:                     %d", errors));
        if (!PERFORM_WRITES) {
            println("\n>>> DRY RUN — set PERFORM_WRITES=true at top of script and re-run to apply. <<<");
        } else {
            println("\nNext: Ctrl+S to save the target program, then checkin via Project Manager.");
        }
    }

    private boolean isDefaultName(String name) {
        if (name == null) return true;
        return DEFAULT_NAME.matcher(name).matches();
    }
}

// Clear incorrect CALL_RETURN flow overrides in Ghidra
// This script scans all functions for CALL instructions with CALL_RETURN overrides
// and clears them, allowing Ghidra to re-analyze the control flow correctly.
// It also fixes noreturn function signatures that cause these overrides,
// disassembles previously hidden code regions, and removes stale flow override comments.
// Use when decompilation shows incomplete code after CALL instructions.
//
// @author Ben Ethington
// @category Analysis
// @keybinding
// @menupath Tools.Clear CALL_RETURN Overrides
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.options.Options;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ClearCallReturnOverrides extends GhidraScript {

    /**
     * Statistics holder for cleanup results
     */
    private static class CleanupStats {
        int totalCallsChecked = 0;
        int overridesFound = 0;
        int overridesCleared = 0;
        int staleCommentsRemoved = 0;
        int noreturnFunctionsFixed = 0;
        int addressesDisassembled = 0;
        List<ClearedOverride> clearedAddresses = new ArrayList<>();
        Set<Function> affectedFunctions = new HashSet<>();
        Set<Function> noreturnFunctionsToFix = new HashSet<>();
        Set<Address> addressesToDisassemble = new HashSet<>();

        static class ClearedOverride {
            Address address;
            String calledFunction;
            Function containingFunction;

            ClearedOverride(Address address, String calledFunction, Function containingFunction) {
                this.address = address;
                this.calledFunction = calledFunction;
                this.containingFunction = containingFunction;
            }
        }
    }

    @Override
    protected void run() throws Exception {
        println("CALL_RETURN Override Cleanup Script");
        println("============================================================");
        println("\nPreparing to clear overrides with restricted disassembly...");
        println("Note: This script will disassemble code but prevent flow analysis re-creating overrides.\n");
        println("Scanning all functions for CALL_RETURN flow overrides...");
        println("These overrides can cause incomplete decompilation.\n");

        // Automatically clear all CALL_RETURN overrides (also detects noreturn functions)
        CleanupStats stats = clearAllCallReturnOverrides();
        printCleanupSummary(stats);

        // Fix noreturn function signatures that are causing the overrides
        if (stats.noreturnFunctionsToFix.size() > 0) {
            println("\n" + "=".repeat(60));
            println("Fixing noreturn function signatures...");
            println("=".repeat(60));
            fixNoreturnFunctionSignatures(stats);
        }

        // Note: Disassembly already done in Step 1 (same transaction as clearing overrides)
        println("\n" + "=".repeat(60));
        println("Disassembly Summary");
        println("=".repeat(60));
        println("Disassembled " + stats.addressesDisassembled + " code region(s) immediately after clearing overrides");

        // Clean up stale flow override comments
        println("\n" + "=".repeat(60));
        println("Cleaning up stale flow override comments...");
        println("=".repeat(60));
        removeStaleFlowOverrideComments(stats);

        println("\nDone! CALL_RETURN overrides cleared, noreturn fixed, code disassembled, and stale comments removed.");
        println("Disassembly was done in restricted mode to prevent re-creating overrides.");
        println("Refresh the Decompiler window (F5) to see changes.");

        // COMMENTED OUT FOR TESTING - These steps may be undoing the good changes
        /*
        // Automatically re-decompile affected functions
        if (stats.affectedFunctions.size() > 0) {
            println("\n" + "=".repeat(60));
            println("Re-decompiling affected functions...");
            println("=".repeat(60));
            redecompileAffectedFunctions(stats.affectedFunctions);
        }

        println("\nDone! All affected functions have been re-decompiled.");
        println("Stale comments have been removed.");
        if (stats.noreturnFunctionsFixed > 0) {
            println("Fixed " + stats.noreturnFunctionsFixed + " incorrectly marked noreturn function(s).");
        }
        if (stats.addressesDisassembled > 0) {
            println("Disassembled " + stats.addressesDisassembled + " previously hidden code region(s).");
        }
        println("Changes should now be visible in the Decompiler window.");
        */
    }

    /**
     * Clears all CALL_RETURN overrides in the entire program.
     * IMPORTANT: Clears override AND immediately disassembles hidden code in same transaction
     * to prevent Ghidra from re-creating the override.
     *
     * @return CleanupStats containing statistics about the cleanup operation
     * @throws CancelledException if the user cancels the operation
     */
    private CleanupStats clearAllCallReturnOverrides() throws CancelledException {
        CleanupStats stats = new CleanupStats();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);

        int transactionId = currentProgram.startTransaction("Clear CALL_RETURN Overrides and Disassemble");
        boolean success = false;

        try {
            while (instructions.hasNext() && !monitor.isCancelled()) {
                monitor.checkCanceled();
                Instruction instruction = instructions.next();

                // Check if this is a CALL instruction
                if (instruction.getFlowType().isCall()) {
                    stats.totalCallsChecked++;

                    // Get the flow override at this instruction
                    FlowOverride flowOverride = instruction.getFlowOverride();

                    // Check if it's a CALL_RETURN override
                    if (flowOverride == FlowOverride.CALL_RETURN) {
                        stats.overridesFound++;

                        // Get the function being called (if available)
                        String calledFunctionName = "unknown";
                        Function calledFunction = null;
                        Reference[] references = instruction.getReferencesFrom();
                        for (Reference ref : references) {
                            if (ref.getReferenceType().isCall()) {
                                Address calledAddr = ref.getToAddress();
                                calledFunction = getFunctionAt(calledAddr);
                                if (calledFunction != null) {
                                    calledFunctionName = calledFunction.getName();

                                    // Check if called function is marked noreturn
                                    if (calledFunction.hasNoReturn()) {
                                        stats.noreturnFunctionsToFix.add(calledFunction);
                                    }
                                }
                                break;
                            }
                        }

                        // Get the function containing this instruction
                        Function containingFunction = currentProgram.getFunctionManager()
                            .getFunctionContaining(instruction.getAddress());

                        // Clear the override FIRST
                        instruction.setFlowOverride(FlowOverride.NONE);
                        stats.overridesCleared++;

                        // IMMEDIATELY disassemble hidden code in the SAME transaction
                        // Use restricted mode to prevent following control flow
                        Address nextAddr = instruction.getAddress().add(instruction.getLength());
                        if (nextAddr != null) {
                            CodeUnit codeUnit = currentProgram.getListing().getCodeUnitAt(nextAddr);
                            if (codeUnit == null || codeUnit instanceof Data) {
                                // Disassemble with restrictedFlow=true to prevent following control flow
                                AddressSet addressSet = new AddressSet(nextAddr);
                                DisassembleCommand cmd = new DisassembleCommand(addressSet, null, true);
                                if (cmd.applyTo(currentProgram, monitor)) {
                                    stats.addressesDisassembled++;
                                    println("  Disassembled hidden code at " + nextAddr + " (restricted mode)");
                                }
                            }
                            stats.addressesToDisassemble.add(nextAddr);
                        }

                        stats.clearedAddresses.add(
                            new CleanupStats.ClearedOverride(
                                instruction.getAddress(),
                                calledFunctionName,
                                containingFunction
                            )
                        );

                        // Track affected function for re-decompilation
                        if (containingFunction != null) {
                            stats.affectedFunctions.add(containingFunction);
                        }

                        String funcName = (containingFunction != null) ?
                            containingFunction.getName() : "unknown";
                        println("Cleared CALL_RETURN at " + instruction.getAddress() +
                               " in " + funcName + " (calling " + calledFunctionName + ")");
                    }
                }
            }

            success = true;

        } finally {
            currentProgram.endTransaction(transactionId, success);
        }

        return stats;
    }

    /**
     * Fixes noreturn function signatures that are incorrectly causing CALL_RETURN overrides.
     *
     * @param stats CleanupStats containing functions to fix
     * @throws CancelledException if the user cancels the operation
     */
    private void fixNoreturnFunctionSignatures(CleanupStats stats) throws CancelledException {
        int transactionId = currentProgram.startTransaction("Fix Noreturn Function Signatures");
        boolean success = false;

        try {
            for (Function function : stats.noreturnFunctionsToFix) {
                if (monitor.isCancelled()) {
                    break;
                }
                monitor.checkCanceled();

                // Remove noreturn attribute
                function.setNoReturn(false);
                stats.noreturnFunctionsFixed++;

                println("Fixed noreturn attribute for: " + function.getName() +
                       " at " + function.getEntryPoint());
            }

            success = true;

        } finally {
            currentProgram.endTransaction(transactionId, success);
        }

        println("Fixed " + stats.noreturnFunctionsFixed + " noreturn function signature(s)");
    }

    /**
     * Disassembles code that was previously hidden by CALL_RETURN overrides.
     * This ensures that code after cleared CALL instructions gets properly analyzed.
     *
     * @param stats CleanupStats containing addresses to disassemble
     * @throws CancelledException if the user cancels the operation
     */
    private void disassembleUndiscoveredCode(CleanupStats stats) throws CancelledException {
        int transactionId = currentProgram.startTransaction("Disassemble Hidden Code");
        boolean success = false;

        try {
            for (Address addr : stats.addressesToDisassemble) {
                if (monitor.isCancelled()) {
                    break;
                }
                monitor.checkCanceled();

                // Check if address needs disassembly
                CodeUnit codeUnit = currentProgram.getListing().getCodeUnitAt(addr);
                if (codeUnit == null || codeUnit instanceof Data) {
                    // Try to disassemble starting at this address
                    AddressSet addressSet = new AddressSet(addr);
                    DisassembleCommand cmd = new DisassembleCommand(addressSet, null);

                    if (cmd.applyTo(currentProgram, monitor)) {
                        stats.addressesDisassembled++;
                        println("  Disassembled code at " + addr);
                    } else {
                        // Address may already be disassembled or invalid
                        // This is not an error - just means no work needed
                    }
                }
            }

            success = true;

        } finally {
            currentProgram.endTransaction(transactionId, success);
        }

        println("Disassembled " + stats.addressesDisassembled + " code region(s)");
    }

    /**
     * Removes stale flow override comments from all instructions.
     * These are POST comments that say "Flow Override: CALL_RETURN" but the
     * actual override has already been cleared.
     *
     * @param stats CleanupStats to update with number of comments removed
     * @throws CancelledException if the user cancels the operation
     */
    @SuppressWarnings("deprecation")
    private void removeStaleFlowOverrideComments(CleanupStats stats) throws CancelledException {
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);

        int transactionId = currentProgram.startTransaction("Remove Stale Flow Override Comments");
        boolean success = false;

        try {
            while (instructions.hasNext() && !monitor.isCancelled()) {
                monitor.checkCanceled();
                Instruction instruction = instructions.next();

                // Get the current flow override state
                FlowOverride override = instruction.getFlowOverride();

                // Only remove comments if override is actually cleared
                if (override == FlowOverride.NONE) {
                    // Check all comment types for flow override references
                    int[] commentTypes = {
                        CodeUnit.POST_COMMENT,
                        CodeUnit.EOL_COMMENT,
                        CodeUnit.PRE_COMMENT,
                        CodeUnit.PLATE_COMMENT
                    };

                    for (int commentType : commentTypes) {
                        String comment = instruction.getComment(commentType);
                        if (comment != null &&
                            (comment.contains("Flow Override") ||
                             comment.contains("CALL_RETURN") ||
                             comment.contains("CALL_TERMINATOR"))) {

                            instruction.setComment(commentType, null);
                            stats.staleCommentsRemoved++;

                            String typeStr = getCommentTypeName(commentType);
                            println("  Removed stale " + typeStr + " comment at " + instruction.getAddress());
                        }
                    }
                }
            }

            success = true;

        } finally {
            currentProgram.endTransaction(transactionId, success);
        }

        println("Removed " + stats.staleCommentsRemoved + " stale flow override comment(s)");
    }

    /**
     * Helper to get human-readable comment type name.
     */
    private String getCommentTypeName(int commentType) {
        switch (commentType) {
            case CodeUnit.POST_COMMENT: return "POST";
            case CodeUnit.EOL_COMMENT: return "EOL";
            case CodeUnit.PRE_COMMENT: return "PRE";
            case CodeUnit.PLATE_COMMENT: return "PLATE";
            default: return "UNKNOWN";
        }
    }

    /**
     * Re-decompiles all affected functions to reflect the cleared overrides.
     *
     * @param affectedFunctions Set of functions that had overrides cleared
     * @throws Exception if decompilation fails
     */
    private void redecompileAffectedFunctions(Set<Function> affectedFunctions) throws Exception {
        DecompInterface decompiler = new DecompInterface();

        try {
            decompiler.openProgram(currentProgram);
            decompiler.setSimplificationStyle("normalize");

            int count = 0;
            int total = affectedFunctions.size();

            for (Function function : affectedFunctions) {
                if (monitor.isCancelled()) {
                    break;
                }

                count++;
                monitor.setMessage("Re-decompiling " + function.getName() +
                                 " (" + count + "/" + total + ")");

                // Force re-decompilation by clearing cache and decompiling again
                DecompileResults results = decompiler.decompileFunction(
                    function,
                    30,  // 30 second timeout
                    monitor
                );

                if (results != null && results.decompileCompleted()) {
                    println("  Re-decompiled: " + function.getName() + " @ " +
                           function.getEntryPoint());
                } else {
                    printerr("  Failed to re-decompile: " + function.getName());
                }
            }

            println("\nSuccessfully re-decompiled " + count + " function(s)");

        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Prints a summary of the cleanup operation.
     *
     * @param stats CleanupStats containing the results
     */
    private void printCleanupSummary(CleanupStats stats) {
        println("\n" + "=".repeat(60));
        println("CALL_RETURN Override Cleanup Summary");
        println("=".repeat(60));
        println("Total CALL instructions checked: " + stats.totalCallsChecked);
        println("CALL_RETURN overrides found: " + stats.overridesFound);
        println("Overrides cleared: " + stats.overridesCleared);
        println("Noreturn functions detected: " + stats.noreturnFunctionsToFix.size());
        println("Functions affected: " + stats.affectedFunctions.size());
        println("Code regions to disassemble: " + stats.addressesToDisassemble.size());
        println("=".repeat(60));

        if (!stats.clearedAddresses.isEmpty()) {
            println("\nCleared overrides at the following addresses:");
            for (CleanupStats.ClearedOverride entry : stats.clearedAddresses) {
                String funcName = (entry.containingFunction != null) ?
                    entry.containingFunction.getName() : "unknown";
                println("  " + entry.address + " in " + funcName + " -> " + entry.calledFunction);
            }
        }
    }
}

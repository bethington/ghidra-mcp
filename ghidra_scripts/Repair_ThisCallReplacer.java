// This Call Replacer
//
// Finds all functions using __thiscall calling convention and changes them to 'unknown'. Useful when __thiscall is incorrectly applied to non-member functions in D2 binaries.
//
// Usage: Run from Script Manager on any program.
// Output: Changes calling convention on all __thiscall functions.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Replace __thiscall convention with unknown
// @menupath Diablo 2.Repair.This Call Replacer

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;

public class Repair_ThisCallReplacer extends GhidraScript {

    @Override
    public void run() throws Exception {
        int count = 0;

        try {
            FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext()) {
                monitor.checkCanceled();
                Function func = funcIter.next();
                if ("__thiscall".equals(func.getCallingConventionName())) {
                    count++;
                    func.setCallingConvention("unknown");
                }
            }
        } catch (CancelledException e) {
            // cancelled
        }

        println("Found " + count + " functions with __thiscall calling convention");
    }
}

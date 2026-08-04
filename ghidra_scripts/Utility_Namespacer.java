// Namespacer
//
// Assigns all functions after the current address to the same namespace as the selected function. Stops at two consecutive functions already in the target namespace.
//
// Usage: Place cursor on a namespaced function, then run from Script Manager.
// Output: Moves subsequent functions into the selected namespace.
//
// @author Ben Ethington
// @category Diablo 2.Utility
// @description Bulk assign functions to the current namespace
// @menupath Diablo 2.Utility.Namespacer

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;

public class Utility_Namespacer extends GhidraScript {

    @Override
    public void run() throws Exception {
        Function startFunc = currentProgram.getFunctionManager().getFunctionAt(currentAddress);
        if (startFunc == null) {
            println("No function at current address.");
            return;
        }

        Namespace targetNamespace = startFunc.getParentNamespace();
        int consecutiveMatches = 0;

        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(currentAddress, true);
        while (funcIter.hasNext()) {
            monitor.checkCanceled();
            Function f = funcIter.next();
            Namespace cn = f.getParentNamespace();
            if (cn.equals(targetNamespace)) {
                consecutiveMatches++;
                println(f.getName());
                if (consecutiveMatches == 2) break;
            } else {
                consecutiveMatches = 0;
                f.setParentNamespace(targetNamespace);
            }
        }
    }
}

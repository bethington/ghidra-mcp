// Categorize Remaining
//
// Classifies remaining Ordinal_ functions as either JMP thunks to other DLLs or direct exports. Reports the target DLL and label for each thunk.
//
// Usage: Run from Script Manager on any program with Ordinal_ functions.
// Output: Console categorization of Ordinal_ functions.
//
// @author Ben Ethington
// @category Diablo 2.Documentation
// @description Categorize remaining Ordinal_ functions by type
// @menupath Diablo 2.Documentation.Categorize Remaining

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.util.*;

public class Document_CategorizeRemaining extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        ExternalManager extMgr = currentProgram.getExternalManager();
        SymbolTable st = currentProgram.getSymbolTable();

        int thunks = 0, exports = 0;
        FunctionIterator fi = fm.getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            if (!f.getName().startsWith("Ordinal_")) continue;

            Instruction instr = getInstructionAt(f.getEntryPoint());
            boolean isJmpThunk = (instr != null && instr.getMnemonicString().equals("JMP") && f.getBody().getNumAddresses() <= 6);

            if (isJmpThunk) {
                // Find target DLL
                String targetDll = "unknown";
                String targetLabel = "unknown";
                Reference[] refs = rm.getReferencesFrom(f.getEntryPoint());
                for (Reference ref : refs) {
                    Symbol[] syms = st.getSymbols(ref.getToAddress());
                    for (Symbol sym : syms) {
                        Namespace ns = sym.getParentNamespace();
                        if (ns != null && !ns.isGlobal()) {
                            targetDll = ns.getName();
                            targetLabel = sym.getName();
                        }
                    }
                    // Also check IAT pointer
                    Reference[] iatRefs = rm.getReferencesFrom(ref.getToAddress());
                    for (Reference iatRef : iatRefs) {
                        Symbol[] syms2 = st.getSymbols(iatRef.getToAddress());
                        for (Symbol sym : syms2) {
                            Namespace ns = sym.getParentNamespace();
                            if (ns != null && !ns.isGlobal()) {
                                targetDll = ns.getName();
                                targetLabel = sym.getName();
                            }
                        }
                    }
                }
                println("THUNK: " + f.getName() + " @ " + f.getEntryPoint() + " -> " + targetDll + "::" + targetLabel + " (xrefs=" + rm.getReferenceCountTo(f.getEntryPoint()) + ")");
                thunks++;
            } else {
                println("EXPORT: " + f.getName() + " @ " + f.getEntryPoint() + " (body=" + f.getBody().getNumAddresses() + " bytes, xrefs=" + rm.getReferenceCountTo(f.getEntryPoint()) + ")");
                exports++;
            }
        }
        println("Summary: " + thunks + " thunks (unresolved imports), " + exports + " exports (own functions)");
    }
}

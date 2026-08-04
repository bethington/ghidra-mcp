// Custom Registers
//
// Identifies functions using non-standard registers (in_*, unaff_*) as parameters and promotes them to explicit function arguments with custom variable storage.
//
// Usage: Run from Script Manager on any program.
// Output: Adds register parameters to function signatures.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Promote non-standard registers to function arguments
// @menupath Diablo 2.Repair.Custom Registers

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;

public class Repair_CustomRegisters extends GhidraScript {

    private int stepFindCustomRegisters(String msg) throws Exception {
        int c = 0;
        monitor.setMessage(msg);
        println(msg);
        monitor.initialize(currentProgram.getFunctionManager().getFunctionCount());

        DecompileOptions options = new DecompileOptions();
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(options);
        ifc.openProgram(currentProgram);

        try {
            FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext()) {
                monitor.checkCanceled();
                Function func = funcIter.next();
                monitor.incrementProgress(1);
                monitor.setShowProgressValue(true);

                if (func.getEntryPoint().toString().equals("00681a48")) break;

                monitor.setMessage("Analyzing 0x" + func.getEntryPoint());
                DecompileResults res = ifc.decompileFunction(func, 60, monitor);
                HighFunction highFunc = res.getHighFunction();
                if (highFunc != null) {
                    LocalSymbolMap lsm = highFunc.getLocalSymbolMap();

                    HighFunctionDBUtil.commitParamsToDatabase(highFunc, true, SourceType.USER_DEFINED);
                    HighFunctionDBUtil.commitReturnToDatabase(highFunc, SourceType.USER_DEFINED);
                    HighFunctionDBUtil.commitLocalNamesToDatabase(highFunc, SourceType.USER_DEFINED);

                    Iterator<HighSymbol> symbols = lsm.getSymbols();
                    boolean update = false;
                    while (symbols.hasNext()) {
                        HighSymbol symbol = symbols.next();
                        String symName = symbol.getName();
                        String storageStr = symbol.getStorage().toString();

                        boolean isCustomReg = (symName.startsWith("in_") || symName.startsWith("unaff_"))
                            && !symName.startsWith("in_register")
                            && !symName.startsWith("in_FS")
                            && !symbol.isParameter()
                            && !storageStr.startsWith("unique")
                            && !storageStr.startsWith("Stack")
                            && !storageStr.startsWith("HASH");

                        if (isCustomReg) {
                            func.setCustomVariableStorage(true);
                            ParameterImpl p = new ParameterImpl(null, symbol.getDataType(),
                                symbol.getStorage(), currentProgram);
                            println("Adding " + symbol.getStorage() + " as param for 0x" + func.getEntryPoint());
                            func.addParameter(p, SourceType.USER_DEFINED);
                            update = true;
                        } else if (symName.startsWith("in_stack_000000")) {
                            println("0x" + func.getEntryPoint() + " require stack param " + symbol);
                        }
                    }

                    if (update) {
                        func.setCallingConvention("unknown");
                        c++;
                    }
                }
            }
        } catch (CancelledException e) {
            // cancelled
        } finally {
            ifc.dispose();
        }

        println("Found " + c + " functions using custom registers!");
        return c;
    }

    @Override
    public void run() throws Exception {
        long start = System.currentTimeMillis();
        stepFindCustomRegisters("Find functions what uses custom registers as arguments and fix them");
        long end = System.currentTimeMillis();
        println("Time: " + (end - start) / 1000.0 + " seconds");
    }
}

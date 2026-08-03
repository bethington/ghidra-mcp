// Stack Arguments Searcher
//
// Identifies functions with incorrect stack parameter counts by analyzing RET instructions. Compares stack cleanup size with declared parameters and adds missing undefined4 parameters.
//
// Usage: Run from Script Manager on any program.
// Output: Fixes function parameter counts based on RET analysis.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Fix stack parameter counts using RET analysis
// @menupath Diablo 2.Repair.Stack Arguments Searcher

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import java.util.*;

public class Repair_StackArgumentsSearcher extends GhidraScript {

    private DataTypeManager getDataTypeManagerByName(String name) {
        ghidra.framework.plugintool.PluginTool tool = state.getTool();
        if (tool == null) return null;
        DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
        if (service == null) return null;
        DataTypeManager[] managers = service.getDataTypeManagers();
        for (DataTypeManager manager : managers) {
            if (manager.getName().contains(name)) {
                return manager;
            }
        }
        return null;
    }

    private DataType findDataTypeByNameInDataManager(String nameDT, String nameDTM) {
        DataTypeManager manager = getDataTypeManagerByName(nameDTM);
        if (manager == null) return null;
        Iterator<DataType> allDataTypes = manager.getAllDataTypes();
        while (allDataTypes.hasNext()) {
            DataType dataType = allDataTypes.next();
            if (dataType.getName().startsWith(nameDT)) {
                return dataType;
            }
        }
        return null;
    }

    private DataType findDataTypeByName(String name) {
        DataType dt = findDataTypeByNameInDataManager(name, currentProgram.getName());
        if (dt == null) dt = findDataTypeByNameInDataManager(name, "BuiltInTypes");
        if (dt == null) dt = findDataTypeByNameInDataManager(name, "windows_vs12_32");
        return dt;
    }

    @Override
    public void run() throws Exception {
        long start = System.currentTimeMillis();
        monitor.initialize(currentProgram.getFunctionManager().getFunctionCount());
        int c = 0;

        try {
            FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext()) {
                monitor.checkCanceled();
                Function func = funcIter.next();

                if (func.getEntryPoint().toString().equals("00681a48")) break;

                if (func.hasCustomVariableStorage()) {
                    func.setCallingConvention("unknown");
                }

                monitor.incrementProgress(1);
                monitor.setShowProgressValue(true);

                boolean found = false;

                // Get stack parameters only
                Parameter[] args = func.getParameters();
                List<Parameter> stackArgs = new ArrayList<>();
                for (Parameter arg : args) {
                    if (arg.isStackVariable()) {
                        stackArgs.add(arg);
                    }
                }

                int argsSize = 0;
                for (Parameter arg : stackArgs) {
                    int a = arg.getLength();
                    if (a < 4) a = 4;
                    argsSize += a;
                }

                int argcount = stackArgs.size();
                int retSize = 0;
                int retcount = 0;

                for (Instruction inst : currentProgram.getListing().getInstructions(func.getBody(), true)) {
                    int opByte = inst.getUnsignedByte(0) & 0xFF;
                    if (opByte == 0xC2) {
                        retSize = inst.getUnsignedShort(1) & 0xFFFF;
                        retcount = retSize / 4;
                        found = true;
                        break;
                    }
                }

                if (found) {
                    if (argsSize != retSize) {
                        if (argsSize < retSize) {
                            if (!func.hasCustomVariableStorage()) {
                                DataType undefined4 = findDataTypeByName("undefined4");
                                if (undefined4 != null) {
                                    for (int i = 0; i < retcount - argcount; i++) {
                                        ParameterImpl p = new ParameterImpl(null, undefined4, currentProgram);
                                        func.addParameter(p, SourceType.USER_DEFINED);
                                    }
                                }
                            }
                        }
                        c++;
                        println("Function 0x" + func.getEntryPoint() +
                            " has defined " + argcount + "/" + retcount + " stack arguments");
                    }
                }
            }
        } catch (CancelledException e) {
            // cancelled
        }

        println("Found " + c + " functions with wrong stack arguments count");
        long end = System.currentTimeMillis();
        println("Time: " + (end - start) / 1000.0 + " seconds");
    }
}

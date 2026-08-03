// Arguments Unifier
//
// Converts variable-sized types to explicit fixed-width equivalents (int->int32_t, uint->uint32_t, short->int16_t, etc.) across all function parameters and return types.
//
// Usage: Run from Script Manager on any program.
// Output: Converts all parameter types to fixed-width equivalents.
//
// @author Ben Ethington
// @category Diablo 2.Utility
// @description Standardize parameters to fixed-width types
// @menupath Diablo 2.Utility.Arguments Unifier

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import java.util.*;

public class Utility_ArgumentsUnifier extends GhidraScript {

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

    private int retypeArgs(Variable[] args) throws Exception {
        int c = 0;
        for (Variable arg : args) {
            String typeName = arg.getDataType().toString();
            DataType newType = null;
            if (typeName.equals("int")) {
                newType = findDataTypeByName("int32_t");
            } else if (typeName.equals("uint")) {
                newType = findDataTypeByName("uint32_t");
            } else if (typeName.equals("short")) {
                newType = findDataTypeByName("int16_t");
            } else if (typeName.equals("ushort")) {
                newType = findDataTypeByName("uint16_t");
            } else if (typeName.equals("BYTE")) {
                newType = findDataTypeByName("int8_t");
            }
            if (newType != null) {
                arg.setDataType(newType, SourceType.USER_DEFINED);
                c++;
            }
        }
        return c;
    }

    @Override
    public void run() throws Exception {
        monitor.initialize(currentProgram.getFunctionManager().getFunctionCount());
        int c = 0;

        try {
            FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext()) {
                monitor.checkCanceled();
                Function func = funcIter.next();

                if (func.getEntryPoint().toString().equals("00681a48")) break;

                monitor.incrementProgress(1);
                monitor.setShowProgressValue(true);

                // retype function arguments
                Parameter[] args = func.getParameters();
                c += retypeArgs(args);

                // retype function return
                Parameter ret = func.getReturn();
                if (ret != null) {
                    c += retypeArgs(new Variable[]{ret});
                }
            }
        } catch (CancelledException e) {
            // cancelled
        }

        println("Fixed " + c + " argument types");
    }
}

// Bulk Type Fix
//
// Scans all functions and fixes variable types based on Hungarian naming prefixes. Resolves undefined types to int, uint, short, ushort, byte, or bool as appropriate.
//
// Usage: Run from Script Manager on any documented program.
// Output: Fixes variable types across all functions.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Bulk fix variable types based on Hungarian naming
// @menupath Diablo 2.Repair.Bulk Type Fix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.address.*;
import java.util.*;

public class Repair_BulkTypeFix extends GhidraScript {

    @Override
    public void run() throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        // Built-in types
        DataType intType = dtm.getDataType("/int");
        DataType uintType = dtm.getDataType("/uint");
        DataType shortType = dtm.getDataType("/short");
        DataType ushortType = dtm.getDataType("/ushort");
        DataType byteType = dtm.getDataType("/byte");
        DataType boolType = dtm.getDataType("/bool");
        DataType intPtrType = new PointerDataType(intType);
        DataType voidPtrType = new PointerDataType();

        int totalFixed = 0;
        int totalFunctions = 0;
        int totalSkipped = 0;

        FunctionIterator funcs = fm.getFunctions(true);
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            String name = func.getName();

            // Skip default-named functions
            if (name.startsWith("FUN_") || name.startsWith("thunk_") || name.startsWith("Ordinal_")) {
                continue;
            }

            totalFunctions++;
            Variable[] allVars = func.getAllVariables();

            for (Variable var : allVars) {
                DataType dt = var.getDataType();
                String dtName = dt.getName();
                String varName = var.getName();

                // Only fix undefined types
                if (!dtName.startsWith("undefined")) {
                    continue;
                }

                // Skip unaff_ and in_ and extraout_ variables
                if (varName.startsWith("unaff_") || varName.startsWith("in_") || varName.startsWith("extraout_")) {
                    totalSkipped++;
                    continue;
                }

                DataType newType = null;

                if (dtName.equals("undefined4")) {
                    // Use Hungarian prefix to determine type
                    if (varName.startsWith("p") && varName.length() > 1 && Character.isUpperCase(varName.charAt(1))) {
                        newType = intPtrType; // pointer
                    } else if (varName.startsWith("dw") || varName.startsWith("u")) {
                        newType = uintType;
                    } else if (varName.startsWith("n") || varName.startsWith("i")) {
                        newType = intType;
                    } else if (varName.startsWith("f") && varName.length() > 1 && Character.isUpperCase(varName.charAt(1))) {
                        newType = boolType;
                    } else {
                        newType = intType; // default undefined4 -> int
                    }
                } else if (dtName.equals("undefined2")) {
                    if (varName.startsWith("w")) {
                        newType = ushortType;
                    } else if (varName.startsWith("n")) {
                        newType = shortType;
                    } else {
                        newType = shortType; // default undefined2 -> short
                    }
                } else if (dtName.equals("undefined1")) {
                    newType = byteType;
                } else if (dtName.equals("undefined")) {
                    newType = byteType;
                }
                // Skip undefined8 — could be double or longlong, too ambiguous

                if (newType != null) {
                    try {
                        var.setDataType(newType, SourceType.USER_DEFINED);
                        totalFixed++;
                    } catch (Exception e) {
                        // Skip variables that can't be retyped (register-only, etc.)
                        totalSkipped++;
                    }
                }
            }
        }

        println("BulkTypeFix complete: " + totalFunctions + " functions scanned, " +
                totalFixed + " variables retyped, " + totalSkipped + " skipped");
    }
}

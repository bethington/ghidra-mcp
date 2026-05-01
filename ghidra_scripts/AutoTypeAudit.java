//Automatically apply types to function variables based on Hungarian notation prefixes
//@category RELoop
//@menupath Tools.RE Loop.Auto Type Audit
//@description For a given function, finds all variables with undefined/generic types and applies correct types based on Hungarian naming prefixes. Eliminates the need for AI to perform the mechanical type audit step.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;
import java.util.*;

public class AutoTypeAudit extends GhidraScript {

    // Hungarian prefix -> Ghidra type mapping
    private static final Map<String, String> PREFIX_TO_TYPE = new LinkedHashMap<>();
    static {
        PREFIX_TO_TYPE.put("b", "byte");
        PREFIX_TO_TYPE.put("c", "char");
        PREFIX_TO_TYPE.put("f", "bool");          // also BOOL (int used as boolean)
        PREFIX_TO_TYPE.put("n", "int");
        PREFIX_TO_TYPE.put("dw", "uint");          // DWORD
        PREFIX_TO_TYPE.put("w", "ushort");          // WORD
        PREFIX_TO_TYPE.put("fl", "float");
        PREFIX_TO_TYPE.put("d", "double");
        PREFIX_TO_TYPE.put("ll", "longlong");
        PREFIX_TO_TYPE.put("qw", "ulonglong");      // QWORD
        PREFIX_TO_TYPE.put("h", "uint");            // HANDLE (platform-dependent, uint on 32-bit)
        PREFIX_TO_TYPE.put("pp", "void **");        // pointer-to-pointer
        PREFIX_TO_TYPE.put("pb", "byte *");
        PREFIX_TO_TYPE.put("pw", "ushort *");
        PREFIX_TO_TYPE.put("pdw", "uint *");
        PREFIX_TO_TYPE.put("pn", "int *");
        PREFIX_TO_TYPE.put("pfn", "void *");        // function pointer
        PREFIX_TO_TYPE.put("p", "void *");          // generic pointer
        PREFIX_TO_TYPE.put("lpsz", "char *");       // LP string (param)
        PREFIX_TO_TYPE.put("sz", "char *");         // string (local)
        PREFIX_TO_TYPE.put("wsz", "wchar_t *");     // wide string
        PREFIX_TO_TYPE.put("g_", null);             // global prefix, skip
    }

    // Types considered "undefined" that need fixing
    private static final Set<String> UNDEFINED_TYPES = new HashSet<>(Arrays.asList(
        "undefined", "undefined1", "undefined2", "undefined4", "undefined8"
    ));

    @Override
    public void run() throws Exception {
        // Get function address from script arguments or ask user
        String addrStr = null;
        String[] args = getScriptArgs();
        if (args.length > 0) {
            addrStr = args[0];
        } else {
            addrStr = askString("Auto Type Audit", "Enter function address (hex):");
        }

        if (addrStr == null || addrStr.trim().isEmpty()) {
            println("Error: No address provided");
            return;
        }

        // Parse address
        addrStr = addrStr.trim();
        if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
            addrStr = addrStr.substring(2);
        }
        Address funcAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrStr);
        Function func = currentProgram.getFunctionManager().getFunctionAt(funcAddr);

        if (func == null) {
            println("Error: No function at address 0x" + addrStr);
            return;
        }

        println("=== Auto Type Audit: " + func.getName() + " @ 0x" + addrStr + " ===");

        // Decompile to get high-level variables
        List<String[]> changes = new ArrayList<>(); // [varName, currentType, newType]
        List<String> skipped = new ArrayList<>();
        DecompInterface decomp = new DecompInterface();

        try {
            decomp.openProgram(currentProgram);
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);

            if (results == null || !results.decompileCompleted()) {
                println("Error: Decompilation failed");
                return;
            }

            HighFunction hf = results.getHighFunction();
            if (hf == null) {
                println("Error: No high function");
                return;
            }

            Iterator<HighSymbol> symbols = hf.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol sym = symbols.next();
                String varName = sym.getName();
                DataType currentType = sym.getDataType();
                String currentTypeName = currentType != null ? currentType.getName() : "undefined";

                // Skip phantoms
                if (varName.startsWith("extraout_") || varName.startsWith("in_") ||
                    varName.startsWith("CONCAT") || varName.startsWith("Multiequal")) {
                    skipped.add(varName + " (phantom)");
                    continue;
                }

                // Skip SSA-only variables (can't be retyped)
                if (varName.matches("[a-z]+Var\\d+")) {
                    skipped.add(varName + " (register-only SSA)");
                    continue;
                }

                // Only process if current type is undefined or generic
                if (!isUndefinedType(currentTypeName)) {
                    continue;
                }

                // Determine target type from Hungarian prefix
                String targetType = resolveTypeFromPrefix(varName);
                if (targetType != null && !targetType.equals(currentTypeName)) {
                    changes.add(new String[]{varName, currentTypeName, targetType});
                }
            }
        } finally {
            decomp.dispose();
        }

        // Apply type changes
        int successCount = 0;
        int failCount = 0;
        List<String> errors = new ArrayList<>();

        if (!changes.isEmpty()) {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int txId = currentProgram.startTransaction("Auto Type Audit");
            boolean success = false;

            try {
                // Re-decompile for each change (type changes trigger re-decompilation)
                DecompInterface decomp2 = new DecompInterface();
                try {
                    decomp2.openProgram(currentProgram);

                    for (String[] change : changes) {
                        String varName = change[0];
                        String newTypeName = change[2];

                        try {
                            DataType newType = resolveDataType(dtm, newTypeName);
                            if (newType == null) {
                                errors.add(varName + ": cannot resolve type '" + newTypeName + "'");
                                failCount++;
                                continue;
                            }

                            // Re-decompile to get fresh variable references
                            DecompileResults freshResults = decomp2.decompileFunction(func, 15, monitor);
                            if (freshResults == null || !freshResults.decompileCompleted()) {
                                errors.add(varName + ": re-decompilation failed");
                                failCount++;
                                continue;
                            }

                            HighFunction freshHf = freshResults.getHighFunction();
                            HighSymbol freshSym = findSymbol(freshHf, varName);
                            if (freshSym == null) {
                                errors.add(varName + ": symbol not found after re-decompile");
                                failCount++;
                                continue;
                            }

                            // Apply the type change
                            HighFunctionDBUtil.updateDBVariable(freshSym, varName, newType, SourceType.USER_DEFINED);
                            successCount++;
                            println("  Set " + varName + ": " + change[1] + " -> " + newTypeName);
                        } catch (Exception e) {
                            errors.add(varName + ": " + e.getMessage());
                            failCount++;
                        }
                    }
                } finally {
                    decomp2.dispose();
                }

                success = true;
            } finally {
                currentProgram.endTransaction(txId, success);
            }
        }

        // Build JSON result
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"function\": \"").append(escJson(func.getName())).append("\"");
        json.append(", \"address\": \"0x").append(addrStr).append("\"");
        json.append(", \"types_set\": ").append(successCount);
        json.append(", \"types_failed\": ").append(failCount);
        json.append(", \"types_skipped\": ").append(skipped.size());
        json.append(", \"changes\": [");
        for (int i = 0; i < changes.size(); i++) {
            if (i > 0) json.append(", ");
            json.append("{\"var\": \"").append(escJson(changes.get(i)[0])).append("\"");
            json.append(", \"from\": \"").append(escJson(changes.get(i)[1])).append("\"");
            json.append(", \"to\": \"").append(escJson(changes.get(i)[2])).append("\"}");
        }
        json.append("]");
        if (!errors.isEmpty()) {
            json.append(", \"errors\": [");
            for (int i = 0; i < errors.size(); i++) {
                if (i > 0) json.append(", ");
                json.append("\"").append(escJson(errors.get(i))).append("\"");
            }
            json.append("]");
        }
        json.append("}");

        println("\n=== Result ===");
        println(json.toString());
        println("\nSet: " + successCount + ", Failed: " + failCount + ", Skipped: " + skipped.size());
    }

    private boolean isUndefinedType(String typeName) {
        return UNDEFINED_TYPES.contains(typeName) ||
               typeName.equals("int") ||  // generic int that might need refinement
               typeName.equals("uint");    // generic uint
    }

    private String resolveTypeFromPrefix(String varName) {
        // Strip global prefix
        String name = varName;
        if (name.startsWith("g_")) {
            name = name.substring(2);
        }

        // Try longest prefix first (lpsz before l, pdw before p, etc.)
        for (Map.Entry<String, String> entry : PREFIX_TO_TYPE.entrySet()) {
            String prefix = entry.getKey();
            String type = entry.getValue();
            if (type == null) continue; // skip markers like g_

            if (name.length() > prefix.length() &&
                name.startsWith(prefix) &&
                Character.isUpperCase(name.charAt(prefix.length()))) {
                return type;
            }
        }
        return null;
    }

    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // Handle pointer types
        if (typeName.endsWith(" *")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 2).trim();
            if (baseTypeName.equals("void")) {
                return dtm.getPointer(DataType.VOID);
            }
            DataType baseType = resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(baseType);
            }
            return null;
        }
        if (typeName.endsWith(" **")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 3).trim();
            DataType baseType = resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(dtm.getPointer(baseType));
            }
            return null;
        }

        // Built-in types
        switch (typeName) {
            case "byte": return ghidra.program.model.data.ByteDataType.dataType;
            case "char": return ghidra.program.model.data.CharDataType.dataType;
            case "bool": return ghidra.program.model.data.BooleanDataType.dataType;
            case "int": return ghidra.program.model.data.IntegerDataType.dataType;
            case "uint": return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "short": return ghidra.program.model.data.ShortDataType.dataType;
            case "ushort": return ghidra.program.model.data.UnsignedShortDataType.dataType;
            case "long": return ghidra.program.model.data.LongDataType.dataType;
            case "ulong": return ghidra.program.model.data.UnsignedLongDataType.dataType;
            case "longlong": return ghidra.program.model.data.LongLongDataType.dataType;
            case "ulonglong": return ghidra.program.model.data.UnsignedLongLongDataType.dataType;
            case "float": return ghidra.program.model.data.FloatDataType.dataType;
            case "double": return ghidra.program.model.data.DoubleDataType.dataType;
            case "void": return DataType.VOID;
            case "wchar_t": return ghidra.program.model.data.WideChar16DataType.dataType;
            default:
                // Try to find in data type manager
                for (DataType dt : dtm.getAllDataTypes()) {
                    if (dt.getName().equals(typeName)) return dt;
                }
                return null;
        }
    }

    private HighSymbol findSymbol(HighFunction hf, String name) {
        Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
        while (it.hasNext()) {
            HighSymbol sym = it.next();
            if (sym.getName().equals(name)) return sym;
        }
        return null;
    }

    private String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}

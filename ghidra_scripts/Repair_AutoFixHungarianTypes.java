// Auto Fix Hungarian Types
//
// Scans all functions for variables with Hungarian names but wrong types and auto-sets them: dw->uint, n->int, w->ushort, b->byte, f->BOOL, sz->char*, p->struct lookup.
//
// Usage: Run from Script Manager on any documented program.
// Output: JSON report at workflows/ with type changes applied.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Auto-fix variable types from Hungarian prefixes
// @menupath Diablo 2.Repair.Auto Fix Hungarian Types

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.*;
import ghidra.framework.model.*;
import java.io.*;
import java.util.*;

public class Repair_AutoFixHungarianTypes extends GhidraScript {

    // Hungarian prefix -> canonical type name
    private static final LinkedHashMap<String, String> PREFIX_TO_TYPE = new LinkedHashMap<>();
    static {
        // Order matters: longer prefixes first
        PREFIX_TO_TYPE.put("lpsz", "char *");
        PREFIX_TO_TYPE.put("wsz",  "wchar_t *");
        PREFIX_TO_TYPE.put("pfn",  null);       // function pointer — skip, too complex
        PREFIX_TO_TYPE.put("pp",   null);        // pointer to pointer — skip
        PREFIX_TO_TYPE.put("pb",   "byte *");
        PREFIX_TO_TYPE.put("pw",   "ushort *");
        PREFIX_TO_TYPE.put("pdw",  "uint *");
        PREFIX_TO_TYPE.put("pn",   "int *");
        PREFIX_TO_TYPE.put("dw",   "uint");
        PREFIX_TO_TYPE.put("fl",   "float");
        PREFIX_TO_TYPE.put("ll",   "longlong");
        PREFIX_TO_TYPE.put("qw",   "ulonglong");
        PREFIX_TO_TYPE.put("sz",   "char *");
        PREFIX_TO_TYPE.put("p",    null);        // struct pointer — handled specially
        PREFIX_TO_TYPE.put("b",    "byte");
        PREFIX_TO_TYPE.put("c",    "char");
        PREFIX_TO_TYPE.put("f",    "BOOL");
        PREFIX_TO_TYPE.put("n",    "int");
        PREFIX_TO_TYPE.put("w",    "ushort");
        PREFIX_TO_TYPE.put("h",    "uint");      // HANDLE — typically uint/void* in D2
        PREFIX_TO_TYPE.put("d",    "double");
    }

    // Types that are already correct and don't need fixing
    private static final Map<String, Set<String>> PREFIX_VALID_TYPES = new LinkedHashMap<>();
    static {
        PREFIX_VALID_TYPES.put("dw",  setOf("uint", "DWORD", "ulong", "int", "dword"));
        PREFIX_VALID_TYPES.put("n",   setOf("int", "short", "long", "INT", "LONG"));
        PREFIX_VALID_TYPES.put("w",   setOf("ushort", "WORD", "short", "word"));
        PREFIX_VALID_TYPES.put("b",   setOf("byte", "uchar", "BYTE", "char", "bool", "undefined1"));
        PREFIX_VALID_TYPES.put("c",   setOf("char", "byte", "uchar"));
        PREFIX_VALID_TYPES.put("f",   setOf("bool", "BOOL", "int", "uint", "byte"));
        PREFIX_VALID_TYPES.put("fl",  setOf("float", "double"));
        PREFIX_VALID_TYPES.put("d",   setOf("double", "float"));
        PREFIX_VALID_TYPES.put("ll",  setOf("longlong", "ulonglong", "int64", "uint64"));
        PREFIX_VALID_TYPES.put("qw",  setOf("ulonglong", "longlong", "QWORD", "uint64"));
        PREFIX_VALID_TYPES.put("h",   setOf("HANDLE", "void *", "int", "uint"));
        PREFIX_VALID_TYPES.put("sz",  setOf("char *"));
        PREFIX_VALID_TYPES.put("lpsz", setOf("char *", "LPCSTR", "LPSTR"));
        PREFIX_VALID_TYPES.put("wsz", setOf("wchar_t *", "LPCWSTR", "LPWSTR"));
        PREFIX_VALID_TYPES.put("pb",  setOf("byte *", "uchar *", "BYTE *"));
        PREFIX_VALID_TYPES.put("pw",  setOf("ushort *", "WORD *", "short *"));
        PREFIX_VALID_TYPES.put("pdw", setOf("uint *", "DWORD *", "ulong *"));
        PREFIX_VALID_TYPES.put("pn",  setOf("int *", "long *"));
    }

    private static Set<String> setOf(String... values) {
        return new HashSet<>(Arrays.asList(values));
    }

    // Types considered "wrong" — need fixing
    private static final Set<String> FIXABLE_TYPES = new HashSet<>(Arrays.asList(
        "undefined", "undefined1", "undefined2", "undefined3", "undefined4",
        "undefined8", "undefined16",
        "undefined *", "undefined1 *", "undefined4 *"
    ));

    @Override
    public void run() throws Exception {
        boolean dryRun = true;
        String programPath = null;
        String[] args = getScriptArgs();
        for (String arg : args) {
            if (arg.equalsIgnoreCase("apply")) {
                dryRun = false;
            } else if (arg.startsWith("/")) {
                programPath = arg;
            }
        }

        // Resolve target program: use path arg if provided, else currentProgram
        Program targetProgram = currentProgram;
        boolean weOpened = false;
        if (programPath != null) {
            DomainFolder root = state.getProject().getProjectData().getRootFolder();
            DomainFile df = findDomainFile(root, programPath);
            if (df != null) {
                targetProgram = (Program) df.getDomainObject(this, true, false, monitor);
                weOpened = true;
                println("Opened program from path: " + programPath);
            } else {
                printerr("Program not found: " + programPath);
                return;
            }
        }

        try {
            runOnProgram(targetProgram, dryRun);
        } finally {
            if (weOpened && targetProgram != null) {
                targetProgram.release(this);
            }
        }
    }

    private DomainFile findDomainFile(DomainFolder folder, String path) throws Exception {
        // path like /Vanilla/1.13c/D2Game.dll
        String[] parts = path.split("/");
        DomainFolder current = folder;
        for (int i = 1; i < parts.length - 1; i++) {
            current = current.getFolder(parts[i]);
            if (current == null) return null;
        }
        return current.getFile(parts[parts.length - 1]);
    }

    private void runOnProgram(Program program, boolean dryRun) throws Exception {
        String programName = program.getName();
        FunctionManager fm = program.getFunctionManager();
        DataTypeManager dtm = program.getDataTypeManager();

        println("=== Auto-Fix Hungarian Types ===");
        println("Program: " + programName);
        if (dryRun) {
            println("Mode: DRY RUN (showing what would change)");
        } else {
            println("Mode: APPLY - making changes");
        }

        // Build struct name lookup cache
        Map<String, DataType> structCache = buildStructCache(dtm);
        println("Struct cache: " + structCache.size() + " structs available for pointer resolution");

        int totalFunctions = 0;
        int functionsWithFixes = 0;
        int totalFixes = 0;
        int structResolved = 0;
        int structFallbackVoid = 0;
        int skippedAlreadyCorrect = 0;

        List<String> changeLog = new ArrayList<>();

        int txId = -1;
        if (!dryRun) {
            txId = program.startTransaction("Auto-Fix Hungarian Types");
        }

        try {
            for (Function func : fm.getFunctions(true)) {
                if (monitor.isCancelled()) break;
                totalFunctions++;

                boolean functionModified = false;
                List<String> funcChanges = new ArrayList<>();

                // Check parameters
                for (Parameter param : func.getParameters()) {
                    String varName = param.getName();
                    String currentType = param.getDataType().getDisplayName();
                    String currentTypeBase = param.getDataType().getName();

                    FixResult fix = determineTypeFix(varName, currentType, currentTypeBase, structCache, dtm);
                    if (fix == null) continue;

                    if (fix.alreadyCorrect) {
                        skippedAlreadyCorrect++;
                        continue;
                    }

                    totalFixes++;
                    if (fix.structResolved) structResolved++;
                    if (fix.structFallback) structFallbackVoid++;

                    String desc = "  PARAM " + varName + ": " + currentType + " -> " + fix.newTypeName;
                    if (fix.structResolved) desc += " (struct match)";
                    funcChanges.add(desc);

                    if (!dryRun && fix.newDataType != null) {
                        try {
                            param.setDataType(fix.newDataType, SourceType.USER_DEFINED);
                        } catch (Exception e) {
                            funcChanges.add("    FAILED: " + e.getMessage());
                        }
                    }
                    functionModified = true;
                }

                // Check local variables
                for (Variable local : func.getLocalVariables()) {
                    String varName = local.getName();
                    String currentType = local.getDataType().getDisplayName();
                    String currentTypeBase = local.getDataType().getName();

                    FixResult fix = determineTypeFix(varName, currentType, currentTypeBase, structCache, dtm);
                    if (fix == null) continue;

                    if (fix.alreadyCorrect) {
                        skippedAlreadyCorrect++;
                        continue;
                    }

                    totalFixes++;
                    if (fix.structResolved) structResolved++;
                    if (fix.structFallback) structFallbackVoid++;

                    String desc = "  LOCAL " + varName + ": " + currentType + " -> " + fix.newTypeName;
                    if (fix.structResolved) desc += " (struct match)";
                    funcChanges.add(desc);

                    if (!dryRun && fix.newDataType != null) {
                        try {
                            local.setDataType(fix.newDataType, SourceType.USER_DEFINED);
                        } catch (Exception e) {
                            funcChanges.add("    FAILED: " + e.getMessage());
                        }
                    }
                    functionModified = true;
                }

                if (functionModified) {
                    functionsWithFixes++;
                    changeLog.add(func.getName() + " @ " + func.getEntryPoint());
                    changeLog.addAll(funcChanges);
                }

                if (totalFunctions % 500 == 0) {
                    println("  Scanned " + totalFunctions + " functions, " + totalFixes + " fixes so far...");
                }
            }
        } finally {
            if (!dryRun && txId != -1) {
                program.endTransaction(txId, true);
            }
        }

        // Write report
        String safeProgName = programName.replaceAll("[^a-zA-Z0-9._-]", "_");
        File outputDir = findWorkflowsDir();
        String suffix = dryRun ? "_dryrun" : "_applied";
        File reportFile = new File(outputDir, "hungarian_fix_" + safeProgName + suffix + ".json");

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"program\": \"").append(escJson(programName)).append("\",\n");
        json.append("  \"mode\": \"").append(dryRun ? "dry_run" : "applied").append("\",\n");
        json.append("  \"total_functions_scanned\": ").append(totalFunctions).append(",\n");
        json.append("  \"functions_with_fixes\": ").append(functionsWithFixes).append(",\n");
        json.append("  \"total_type_fixes\": ").append(totalFixes).append(",\n");
        json.append("  \"struct_resolved\": ").append(structResolved).append(",\n");
        json.append("  \"struct_fallback_void\": ").append(structFallbackVoid).append(",\n");
        json.append("  \"skipped_already_correct\": ").append(skippedAlreadyCorrect).append(",\n");
        json.append("  \"changes\": [\n");
        for (int i = 0; i < changeLog.size(); i++) {
            if (i > 0) json.append(",\n");
            json.append("    \"").append(escJson(changeLog.get(i))).append("\"");
        }
        json.append("\n  ]\n");
        json.append("}\n");

        try (FileWriter fw = new FileWriter(reportFile)) {
            fw.write(json.toString());
        }

        println("\n=== " + (dryRun ? "Dry Run" : "Apply") + " Complete ===");
        println("Functions scanned:     " + totalFunctions);
        println("Functions with fixes:  " + functionsWithFixes);
        println("Total type fixes:      " + totalFixes);
        println("  Struct resolved:     " + structResolved);
        println("  Struct fallback:     " + structFallbackVoid);
        println("Skipped (correct):     " + skippedAlreadyCorrect);
        println("Report: " + reportFile.getAbsolutePath());
        if (dryRun) {
            println("\nTo apply changes, run with argument: apply");
        } else if (totalFixes > 0) {
            program.save(programName + " - Hungarian type fixes", monitor);
            println("Program saved.");
        }
    }

    private static class FixResult {
        String newTypeName;
        DataType newDataType;
        boolean alreadyCorrect;
        boolean structResolved;
        boolean structFallback;
    }

    /**
     * Determine if a variable needs a type fix based on its Hungarian name.
     * Returns null if no Hungarian prefix detected or type can't be determined.
     */
    private FixResult determineTypeFix(String varName, String currentType, String currentTypeBase,
                                        Map<String, DataType> structCache, DataTypeManager dtm) {
        // Strip g_ global prefix
        String name = varName;
        if (name.startsWith("g_")) name = name.substring(2);

        // Try prefixes longest first
        for (Map.Entry<String, String> entry : PREFIX_TO_TYPE.entrySet()) {
            String prefix = entry.getKey();
            String targetType = entry.getValue();

            if (!name.startsWith(prefix) || name.length() <= prefix.length()) continue;
            char afterPrefix = name.charAt(prefix.length());
            if (!Character.isUpperCase(afterPrefix)) continue;

            // Found a Hungarian prefix match
            FixResult result = new FixResult();

            // Check if already correct
            Set<String> validTypes = PREFIX_VALID_TYPES.get(prefix);
            if (validTypes != null) {
                for (String valid : validTypes) {
                    if (currentType.contains(valid)) {
                        result.alreadyCorrect = true;
                        return result;
                    }
                }
            }

            // Only fix if current type is clearly wrong (undefined or generic)
            boolean needsFix = FIXABLE_TYPES.contains(currentTypeBase) ||
                               FIXABLE_TYPES.contains(currentType);

            // For p-prefix, also fix void*/int*/uint* to struct pointers
            if (prefix.equals("p")) {
                needsFix = needsFix || currentType.equals("void *") ||
                           currentType.equals("int *") || currentType.equals("uint *");
            }

            if (!needsFix) {
                result.alreadyCorrect = true;
                return result;
            }

            // Handle p-prefix: struct pointer lookup
            if (prefix.equals("p")) {
                String structName = name.substring(1); // pUnit -> Unit
                return resolveStructPointer(structName, structCache, dtm);
            }

            // Handle null target (pfn, pp) — skip
            if (targetType == null) return null;

            // Resolve the target type
            DataType dt = resolveType(targetType, dtm);
            if (dt == null) return null;

            result.newTypeName = targetType;
            result.newDataType = dt;
            return result;
        }

        return null; // No Hungarian prefix recognized
    }

    /**
     * Try to resolve a struct pointer: pUnit -> UnitAny *, pGame -> Game *
     */
    private FixResult resolveStructPointer(String structName, Map<String, DataType> structCache, DataTypeManager dtm) {
        FixResult result = new FixResult();

        // Direct lookup
        DataType structDt = structCache.get(structName);

        // Try common variations: UnitAny for Unit, GameResourceManager for Game
        if (structDt == null) {
            // Search for structs containing the name
            for (Map.Entry<String, DataType> entry : structCache.entrySet()) {
                if (entry.getKey().toLowerCase().startsWith(structName.toLowerCase())) {
                    structDt = entry.getValue();
                    break;
                }
            }
        }

        if (structDt != null) {
            // Found a struct — make a pointer to it
            PointerDataType ptrType = new PointerDataType(structDt);
            result.newTypeName = structDt.getName() + " *";
            result.newDataType = ptrType;
            result.structResolved = true;
            return result;
        }

        // No struct found — fall back to void *
        DataType voidPtr = resolveType("void *", dtm);
        if (voidPtr != null && !result.alreadyCorrect) {
            result.newTypeName = "void *";
            result.newDataType = voidPtr;
            result.structFallback = true;
            return result;
        }

        return null;
    }

    /**
     * Build a cache of all struct/class names -> DataType for pointer resolution.
     */
    private Map<String, DataType> buildStructCache(DataTypeManager dtm) {
        Map<String, DataType> cache = new LinkedHashMap<>();
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt instanceof Structure || dt instanceof ghidra.program.model.data.TypeDef) {
                cache.put(dt.getName(), dt);
            }
        }
        return cache;
    }

    /**
     * Resolve a type name to a DataType from the program's data type manager.
     */
    private DataType resolveType(String typeName, DataTypeManager dtm) {
        // Try program's data type manager first (dtm param is already program's DTM)
        DataTypeManager builtIn = dtm;

        // Search all data types for a match
        Iterator<DataType> iter1 = builtIn.getAllDataTypes();
        while (iter1.hasNext()) {
            DataType dt = iter1.next();
            if (dt.getDisplayName().equals(typeName) || dt.getName().equals(typeName)) {
                return dt;
            }
        }

        // Try the BuiltInDataTypeManager
        DataTypeManager builtInMgr = ghidra.program.model.data.BuiltInDataTypeManager.getDataTypeManager();
        Iterator<DataType> iter2 = builtInMgr.getAllDataTypes();
        while (iter2.hasNext()) {
            DataType dt = iter2.next();
            if (dt.getDisplayName().equals(typeName) || dt.getName().equals(typeName)) {
                return dt;
            }
        }

        return null;
    }

    private File findWorkflowsDir() {
        String[] candidates = {
            "C:/Users/benam/source/mcp/ghidra-mcp/workflows",
            System.getProperty("user.dir") + "/workflows"
        };
        for (String path : candidates) {
            File dir = new File(path);
            if (dir.exists() && dir.isDirectory()) return dir;
        }
        File dir = new File(System.getProperty("user.dir"), "workflows");
        dir.mkdirs();
        return dir;
    }

    private String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}

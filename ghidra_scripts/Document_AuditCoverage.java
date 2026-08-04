// Audit Coverage
//
// Audits all functions against a minimum documentation standard. Checks custom name, plate comment, EOL comments, Hungarian variables, resolved types, struct pointers, and function prototypes.
//
// Usage: Run from Script Manager on any documented program.
// Output: JSON report at workflows/audit_<program>.json with per-function scores.
//
// @author Ben Ethington
// @category Diablo 2.Documentation
// @description Audit documentation coverage with quality scoring
// @menupath Diablo 2.Documentation.Audit Coverage

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class Document_AuditCoverage extends GhidraScript {

    private static final String[] REQUIRED_PLATE_SECTIONS = {
        "Parameter", "Return", "Algorithm"
    };

    private static final Pattern UNRESOLVED_VAR_PATTERN = Pattern.compile(
        "^(param_\\d+|local_[0-9a-fA-F]+|iVar\\d+|uVar\\d+|bVar\\d+|" +
        "pcVar\\d+|puVar\\d+|piVar\\d+|ppvVar\\d+|pvVar\\d+|plVar\\d+|" +
        "sVar\\d+|cVar\\d+|fVar\\d+|dVar\\d+|lVar\\d+|auVar\\d+)$"
    );

    private static final Set<String> UNRESOLVED_TYPES = new HashSet<>(Arrays.asList(
        "undefined", "undefined1", "undefined2", "undefined3", "undefined4",
        "undefined8", "undefined16"
    ));

    // Generic pointer types that should be struct pointers when p-prefixed
    private static final Set<String> GENERIC_PTR_TYPES = new HashSet<>(Arrays.asList(
        "void *", "int *", "uint *", "undefined4 *", "undefined *"
    ));

    // Hungarian prefix -> expected type families
    private static final Map<String, Set<String>> HUNGARIAN_PREFIX_TYPES = new LinkedHashMap<>();
    static {
        HUNGARIAN_PREFIX_TYPES.put("b",   setOf("byte", "uchar", "BYTE", "bool", "undefined1"));
        HUNGARIAN_PREFIX_TYPES.put("c",   setOf("char", "byte", "uchar"));
        HUNGARIAN_PREFIX_TYPES.put("f",   setOf("bool", "BOOL", "int", "uint", "byte", "undefined4"));
        HUNGARIAN_PREFIX_TYPES.put("n",   setOf("int", "short", "long", "INT", "LONG"));
        HUNGARIAN_PREFIX_TYPES.put("dw",  setOf("uint", "DWORD", "ulong", "int", "undefined4"));
        HUNGARIAN_PREFIX_TYPES.put("w",   setOf("ushort", "WORD", "short", "undefined2"));
        HUNGARIAN_PREFIX_TYPES.put("fl",  setOf("float", "double"));
        HUNGARIAN_PREFIX_TYPES.put("d",   setOf("double", "float"));
        HUNGARIAN_PREFIX_TYPES.put("ll",  setOf("longlong", "ulonglong", "int64", "uint64"));
        HUNGARIAN_PREFIX_TYPES.put("qw",  setOf("ulonglong", "longlong", "QWORD", "uint64"));
        HUNGARIAN_PREFIX_TYPES.put("h",   setOf("HANDLE", "void *", "int", "uint"));
        HUNGARIAN_PREFIX_TYPES.put("sz",  setOf("char *", "char["));
        HUNGARIAN_PREFIX_TYPES.put("lpsz", setOf("char *", "LPCSTR", "LPSTR"));
        HUNGARIAN_PREFIX_TYPES.put("wsz", setOf("wchar_t *", "LPCWSTR", "LPWSTR"));
        HUNGARIAN_PREFIX_TYPES.put("pfn", setOf("code *", "func *")); // function pointers
    }

    private static Set<String> setOf(String... values) {
        return new HashSet<>(Arrays.asList(values));
    }

    @Override
    public void run() throws Exception {
        String programName = currentProgram.getName();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        println("=== Audit Documentation Coverage ===");
        println("Program: " + programName);

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        decomp.setSimplificationStyle("decompile");

        int totalFunctions = 0;
        int passCount = 0;

        // Failure counters
        int missingName = 0;
        int missingPlate = 0;
        int incompletePlate = 0;
        int missingDisasmComments = 0;
        int unresolvedVarNames = 0;
        int unresolvedVarTypes = 0;
        int hungarianMismatch = 0;
        int genericPtrCount = 0;
        int prototypeIssues = 0;

        StringBuilder failedJson = new StringBuilder();
        int failedCount = 0;
        int passedCount = 0;

        for (Function func : fm.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            totalFunctions++;

            String addr = func.getEntryPoint().toString();
            String name = func.getName();
            boolean isThunk = func.isThunk() || isSimpleThunk(func);

            List<String> failures = new ArrayList<>();

            // --- Check 1: Custom name ---
            if (isUndocumented(name)) {
                failures.add("no_custom_name");
                missingName++;
            }

            // --- Check 2: Plate comment (full format) ---
            String plateComment = listing.getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint());
            if (plateComment == null || plateComment.trim().isEmpty()) {
                failures.add("no_plate_comment");
                missingPlate++;
            } else {
                List<String> missingSections = new ArrayList<>();
                for (String section : REQUIRED_PLATE_SECTIONS) {
                    if (!plateComment.toLowerCase().contains(section.toLowerCase())) {
                        missingSections.add(section);
                    }
                }
                if (!missingSections.isEmpty()) {
                    failures.add("incomplete_plate:" + String.join(",", missingSections));
                    incompletePlate++;
                }
            }

            // --- Check 3: Disassembly EOL comments ---
            int instructionCount = 0;
            int eolCommentCount = 0;
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                instructionCount++;
                String eol = instr.getComment(CodeUnit.EOL_COMMENT);
                if (eol != null && !eol.trim().isEmpty()) {
                    eolCommentCount++;
                }
            }
            if (eolCommentCount == 0) {
                failures.add("no_disasm_comments");
                missingDisasmComments++;
            }

            // --- Check 7: Function prototype/signature ---
            List<String> protoIssues = checkPrototype(func);
            if (!protoIssues.isEmpty()) {
                failures.add("prototype_issues:" + String.join(",", protoIssues));
                prototypeIssues++;
            }

            // --- Checks 4-6: Variables via decompiler ---
            int unresolvedNameCount = 0;
            int unresolvedTypeCount = 0;
            int hungarianMismatchCount = 0;
            int genericPtrVarCount = 0;
            int totalVars = 0;
            List<String> sampleIssues = new ArrayList<>();

            try {
                DecompileResults results = decomp.decompileFunction(func, 5, monitor);
                if (results != null && results.decompileCompleted()) {
                    HighFunction hf = results.getHighFunction();
                    if (hf != null) {
                        Iterator<HighSymbol> symbols = hf.getLocalSymbolMap().getSymbols();
                        while (symbols.hasNext()) {
                            HighSymbol sym = symbols.next();
                            String varName = sym.getName();
                            String varType = sym.getDataType().getDisplayName();
                            String varTypeBase = sym.getDataType().getName();

                            // Skip phantoms
                            if (varName.startsWith("in_") || varName.startsWith("extraout_") ||
                                varName.startsWith("CONCAT") || varName.startsWith("unaff_")) {
                                continue;
                            }

                            totalVars++;

                            // Check 4: Unresolved variable name
                            if (UNRESOLVED_VAR_PATTERN.matcher(varName).matches()) {
                                unresolvedNameCount++;
                                if (sampleIssues.size() < 8)
                                    sampleIssues.add("name:" + varName + "=" + varType);
                            }

                            // Check 5: Unresolved variable type
                            if (UNRESOLVED_TYPES.contains(varTypeBase)) {
                                unresolvedTypeCount++;
                                if (sampleIssues.size() < 8)
                                    sampleIssues.add("type:" + varName + "=" + varType);
                            }

                            // Check 6a: Hungarian prefix-to-type validation
                            if (!UNRESOLVED_VAR_PATTERN.matcher(varName).matches()) {
                                String mismatch = checkHungarianPrefix(varName, varType);
                                if (mismatch != null) {
                                    hungarianMismatchCount++;
                                    if (sampleIssues.size() < 8)
                                        sampleIssues.add("hungarian:" + mismatch);
                                }
                            }

                            // Check 6b: Generic pointer on p-prefixed variable
                            if (varName.length() > 1 && varName.startsWith("p") &&
                                Character.isUpperCase(varName.charAt(1)) &&
                                GENERIC_PTR_TYPES.contains(varType)) {
                                genericPtrVarCount++;
                                if (sampleIssues.size() < 8)
                                    sampleIssues.add("generic_ptr:" + varName + "=" + varType);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                failures.add("decompile_failed");
            }

            if (unresolvedNameCount > 0) {
                failures.add("unresolved_var_names:" + unresolvedNameCount);
                unresolvedVarNames++;
            }
            if (unresolvedTypeCount > 0) {
                failures.add("unresolved_var_types:" + unresolvedTypeCount);
                unresolvedVarTypes++;
            }
            if (hungarianMismatchCount > 0) {
                failures.add("hungarian_mismatch:" + hungarianMismatchCount);
                hungarianMismatch++;
            }
            if (genericPtrVarCount > 0) {
                failures.add("generic_ptr_should_be_struct:" + genericPtrVarCount);
                genericPtrCount++;
            }

            // --- Classify result ---
            boolean passed = failures.isEmpty();
            if (passed) {
                passCount++;
                passedCount++;
            } else {
                if (failedCount > 0) failedJson.append(",\n");
                failedJson.append("    {\"address\": \"0x").append(addr).append("\"");
                failedJson.append(", \"name\": \"").append(escJson(name)).append("\"");
                failedJson.append(", \"is_thunk\": ").append(isThunk);
                failedJson.append(", \"instructions\": ").append(instructionCount);
                failedJson.append(", \"eol_comments\": ").append(eolCommentCount);
                failedJson.append(", \"total_vars\": ").append(totalVars);
                failedJson.append(", \"failures\": [");
                for (int i = 0; i < failures.size(); i++) {
                    if (i > 0) failedJson.append(", ");
                    failedJson.append("\"").append(escJson(failures.get(i))).append("\"");
                }
                failedJson.append("]");
                if (!sampleIssues.isEmpty()) {
                    failedJson.append(", \"samples\": [");
                    for (int i = 0; i < sampleIssues.size(); i++) {
                        if (i > 0) failedJson.append(", ");
                        failedJson.append("\"").append(escJson(sampleIssues.get(i))).append("\"");
                    }
                    failedJson.append("]");
                }
                failedJson.append("}");
                failedCount++;
            }

            if (totalFunctions % 200 == 0) {
                println("  Processed " + totalFunctions + " functions...");
            }
        }

        decomp.dispose();

        // Build JSON report
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"program\": \"").append(escJson(programName)).append("\",\n");
        json.append("  \"total_functions\": ").append(totalFunctions).append(",\n");
        json.append("  \"passed\": ").append(passCount).append(",\n");
        json.append("  \"failed\": ").append(failedCount).append(",\n");
        json.append("  \"pass_rate\": \"").append(totalFunctions > 0 ?
            String.format("%.1f%%", 100.0 * passCount / totalFunctions) : "0%").append("\",\n");
        json.append("  \"failure_breakdown\": {\n");
        json.append("    \"no_custom_name\": ").append(missingName).append(",\n");
        json.append("    \"no_plate_comment\": ").append(missingPlate).append(",\n");
        json.append("    \"incomplete_plate_comment\": ").append(incompletePlate).append(",\n");
        json.append("    \"no_disasm_comments\": ").append(missingDisasmComments).append(",\n");
        json.append("    \"unresolved_var_names\": ").append(unresolvedVarNames).append(",\n");
        json.append("    \"unresolved_var_types\": ").append(unresolvedVarTypes).append(",\n");
        json.append("    \"hungarian_prefix_mismatch\": ").append(hungarianMismatch).append(",\n");
        json.append("    \"generic_ptr_should_be_struct\": ").append(genericPtrCount).append(",\n");
        json.append("    \"prototype_issues\": ").append(prototypeIssues).append("\n");
        json.append("  },\n");
        json.append("  \"minimum_standard\": {\n");
        json.append("    \"requires\": [\"custom_name\", \"full_plate_comment\", \"disasm_eol_comments\",\n");
        json.append("      \"hungarian_var_names\", \"hungarian_prefix_type_match\", \"resolved_var_types\",\n");
        json.append("      \"struct_ptr_not_generic\", \"calling_convention\", \"resolved_param_types\", \"resolved_return_type\"],\n");
        json.append("    \"plate_sections\": [\"").append(String.join("\", \"", REQUIRED_PLATE_SECTIONS)).append("\"]\n");
        json.append("  },\n");
        json.append("  \"failed_functions\": [\n");
        json.append(failedJson);
        json.append("\n  ]\n");
        json.append("}\n");

        // Write report
        String safeProgName = programName.replaceAll("[^a-zA-Z0-9._-]", "_");
        File outputDir = findWorkflowsDir();
        File outputFile = new File(outputDir, "audit_" + safeProgName + ".json");

        try (FileWriter fw = new FileWriter(outputFile)) {
            fw.write(json.toString());
        }

        println("\n=== Audit Complete ===");
        println("Total: " + totalFunctions + " functions");
        println("Passed: " + passCount + " (" + (totalFunctions > 0 ?
            String.format("%.1f%%", 100.0 * passCount / totalFunctions) : "0%") + ")");
        println("Failed: " + failedCount);
        println("");
        println("Failure Breakdown:");
        println("  No custom name:            " + missingName);
        println("  No plate comment:          " + missingPlate);
        println("  Incomplete plate comment:  " + incompletePlate);
        println("  No disasm comments:        " + missingDisasmComments);
        println("  Unresolved var names:      " + unresolvedVarNames);
        println("  Unresolved var types:      " + unresolvedVarTypes);
        println("  Hungarian prefix mismatch: " + hungarianMismatch);
        println("  Generic ptr (need struct): " + genericPtrCount);
        println("  Prototype issues:          " + prototypeIssues);
        println("");
        println("Report: " + outputFile.getAbsolutePath());
    }

    /**
     * Check function prototype for: calling convention, param types, return type.
     */
    private List<String> checkPrototype(Function func) {
        List<String> issues = new ArrayList<>();

        // Check calling convention
        String cc = func.getCallingConventionName();
        if (cc == null || cc.equals("unknown") || cc.equals("default")) {
            issues.add("no_calling_convention");
        }

        // Check return type
        String returnType = func.getReturnType().getName();
        if (returnType.startsWith("undefined")) {
            issues.add("undefined_return:" + returnType);
        }

        // Check parameter types
        int undefinedParams = 0;
        for (Parameter param : func.getParameters()) {
            String paramType = param.getDataType().getName();
            if (paramType.startsWith("undefined")) {
                undefinedParams++;
            }
        }
        if (undefinedParams > 0) {
            issues.add("undefined_params:" + undefinedParams);
        }

        return issues;
    }

    /**
     * Validate Hungarian prefix matches the actual data type.
     * Returns a description of the mismatch, or null if valid.
     */
    private String checkHungarianPrefix(String varName, String varType) {
        // Strip global prefix
        String name = varName;
        if (name.startsWith("g_")) name = name.substring(2);

        // Try to match longest prefix first (e.g., "lpsz" before "l")
        String[] orderedPrefixes = {"lpsz", "wsz", "pfn", "pp", "pb", "pw", "pdw", "pn",
                                     "dw", "fl", "ll", "qw", "sz", "p", "b", "c", "f",
                                     "n", "w", "h", "d"};

        for (String prefix : orderedPrefixes) {
            if (name.startsWith(prefix) && name.length() > prefix.length()) {
                char afterPrefix = name.charAt(prefix.length());
                // Prefix must be followed by uppercase (Hungarian convention)
                if (!Character.isUpperCase(afterPrefix)) continue;

                Set<String> expectedTypes = HUNGARIAN_PREFIX_TYPES.get(prefix);
                if (expectedTypes == null) continue;

                // For pointer prefixes (p, pb, pw, etc.), the type should contain *
                if (prefix.equals("p") || prefix.equals("pb") || prefix.equals("pw") ||
                    prefix.equals("pdw") || prefix.equals("pn") || prefix.equals("pp")) {
                    if (!varType.contains("*")) {
                        return varName + " (prefix '" + prefix + "' expects pointer, got " + varType + ")";
                    }
                    return null; // Pointer type present, detailed struct check is in generic_ptr check
                }

                // For non-pointer prefixes, check type family
                boolean matched = false;
                for (String expected : expectedTypes) {
                    if (varType.contains(expected)) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    return varName + " (prefix '" + prefix + "' expects " + expectedTypes + ", got " + varType + ")";
                }
                return null; // Matched
            }
        }

        return null; // No recognized Hungarian prefix — not a failure
    }

    private boolean isUndocumented(String name) {
        return name.startsWith("FUN_") ||
               name.startsWith("Ordinal_") ||
               name.startsWith("thunk_FUN_") ||
               name.startsWith("thunk_Ordinal_");
    }

    private boolean isSimpleThunk(Function func) {
        InstructionIterator iter = currentProgram.getListing().getInstructions(func.getBody(), true);
        int instrCount = 0;
        boolean hasJump = false;
        while (iter.hasNext() && instrCount < 5) {
            Instruction instr = iter.next();
            String mnemonic = instr.getMnemonicString().toUpperCase();
            if (mnemonic.equals("JMP")) hasJump = true;
            instrCount++;
        }
        return instrCount <= 2 && hasJump;
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

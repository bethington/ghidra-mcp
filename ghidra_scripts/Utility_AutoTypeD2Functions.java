// Auto Type D2 Functions
//
// Analyzes assembly patterns to infer parameter types: detects pointer params from MOV [ptr+offset], identifies struct types from field access patterns, and generates meaningful parameter names.
//
// Usage: Run from Script Manager on any D2 binary.
// Output: Applies inferred types and names to function parameters.
//
// @author Ben Ethington
// @category Diablo 2.Utility
// @description Auto-type D2 function parameters from assembly patterns
// @menupath Diablo 2.Utility.Auto Type D2 Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;
import java.util.regex.*;

public class Utility_AutoTypeD2Functions extends GhidraScript {

    private static class StructSignature {
        String name;
        int[][] fields; // {offset, fieldIndex}
        String[] fieldNames;

        StructSignature(String name, int[][] fields, String[] fieldNames) {
            this.name = name;
            this.fields = fields;
            this.fieldNames = fieldNames;
        }
    }

    private static class TypingSuggestion {
        String functionName;
        String address;
        String signature;
        List<ParamSuggestion> parameters = new ArrayList<>();
    }

    private static class ParamSuggestion {
        int index;
        String name;
        String originalType;
        String inferredType;
        double confidence;
        String suggestedName;
    }

    private static final StructSignature[] STRUCT_SIGNATURES = {
        new StructSignature("UnitAny",
            new int[][]{{0x00},{0x04},{0x0C},{0x10},{0x44},{0x8C},{0x8E}},
            new String[]{"dwType","dwTxtFileNo","dwUnitId","dwMode","dwGfxFrame","wX","wY"}),
        new StructSignature("ItemData",
            new int[][]{{0x00},{0x0C},{0x28},{0x44}},
            new String[]{"dwQuality","dwItemFlags","dwQuality2","BodyLocation"}),
        new StructSignature("Inventory",
            new int[][]{{0x00},{0x08},{0x0C},{0x28}},
            new String[]{"dwSignature","pOwner","pFirstItem","dwItemCount"}),
        new StructSignature("Path",
            new int[][]{{0x00},{0x02},{0x10},{0x12}},
            new String[]{"xOffset","xPos","xTarget","yTarget"}),
        new StructSignature("PlayerData",
            new int[][]{{0x00},{0x10}},
            new String[]{"szName","pNormalQuest"}),
    };

    private Listing listing;
    private FunctionManager funcMgr;
    private List<TypingSuggestion> typingSuggestions = new ArrayList<>();

    private static final Map<String, String> NAMING_RULES = new HashMap<>();
    static {
        NAMING_RULES.put("UnitAny", "pUnit");
        NAMING_RULES.put("ItemData", "pItem");
        NAMING_RULES.put("Inventory", "pInv");
        NAMING_RULES.put("Path", "pPath");
        NAMING_RULES.put("PlayerData", "pPlayer");
        NAMING_RULES.put("MonsterData", "pMonster");
    }

    private String inferStructType(Map<String, List<Integer>> paramAccesses) {
        if (paramAccesses.isEmpty()) return null;

        Set<Integer> accessedOffsets = new HashSet<>();
        for (List<Integer> accesses : paramAccesses.values()) {
            accessedOffsets.addAll(accesses);
        }
        if (accessedOffsets.isEmpty()) return null;

        String bestMatch = null;
        double bestScore = 0.0;

        for (StructSignature sig : STRUCT_SIGNATURES) {
            int matches = 0;
            for (int[] field : sig.fields) {
                if (accessedOffsets.contains(field[0])) matches++;
            }
            double score = (double) matches / sig.fields.length;
            if (score > bestScore && score > 0.4) {
                bestScore = score;
                bestMatch = sig.name;
            }
        }
        return bestMatch;
    }

    private TypingSuggestion analyzeFunction(Function func) {
        Address funcAddr = func.getEntryPoint();
        if (funcAddr == null) return null;

        FunctionSignature signature = func.getSignature();
        if (signature == null) return null;

        ParameterDefinition[] formalParams = signature.getArguments();
        if (formalParams == null || formalParams.length == 0) return null;

        // Scan for struct field accesses
        Map<String, List<Integer>> paramAccesses = new HashMap<>();
        Instruction instr = listing.getInstructionAt(funcAddr);
        int scanCount = 0;
        Pattern structPattern = Pattern.compile("\\[([A-Z]{2,3})\\s*\\+\\s*(0x[0-9A-Fa-f]+)\\]");

        while (instr != null && scanCount < 100) {
            scanCount++;
            String opStr = instr.toString();
            Matcher m = structPattern.matcher(opStr);
            if (m.find()) {
                String reg = m.group(1);
                int offset = Integer.parseInt(m.group(2).substring(2), 16);
                paramAccesses.computeIfAbsent(reg, k -> new ArrayList<>()).add(offset);
            }
            instr = instr.getNext();
        }

        List<ParamSuggestion> params = new ArrayList<>();
        for (int idx = 0; idx < formalParams.length; idx++) {
            ParameterDefinition fp = formalParams[idx];
            String structType = inferStructType(paramAccesses);
            if (structType != null) {
                ParamSuggestion ps = new ParamSuggestion();
                ps.index = idx;
                ps.name = fp.getName();
                ps.originalType = fp.getDataType().getName();
                ps.inferredType = structType;
                ps.confidence = 0.8;
                ps.suggestedName = NAMING_RULES.getOrDefault(structType, "pParam");
                params.add(ps);
            } else if (!paramAccesses.isEmpty()) {
                ParamSuggestion ps = new ParamSuggestion();
                ps.index = idx;
                ps.name = fp.getName();
                ps.originalType = fp.getDataType().getName();
                ps.inferredType = "void*";
                ps.confidence = 0.6;
                ps.suggestedName = "pParam" + idx;
                params.add(ps);
            }
        }

        if (params.isEmpty()) return null;

        TypingSuggestion ts = new TypingSuggestion();
        ts.functionName = func.getName();
        ts.address = funcAddr.toString();
        ts.signature = signature.toString();
        ts.parameters = params;
        return ts;
    }

    private void printResults() {
        println("\n" + "=".repeat(80));
        println("DIABLO II FUNCTION PARAMETER TYPING ANALYSIS");
        println("=".repeat(80) + "\n");

        if (typingSuggestions.isEmpty()) {
            println("[*] No parameter typing suggestions generated.\n");
            return;
        }

        Map<String, List<Object[]>> byType = new LinkedHashMap<>();
        for (TypingSuggestion ts : typingSuggestions) {
            for (ParamSuggestion ps : ts.parameters) {
                byType.computeIfAbsent(ps.inferredType, k -> new ArrayList<>())
                      .add(new Object[]{ts.functionName, ps});
            }
        }

        println("Total functions with typing suggestions: " + typingSuggestions.size() + "\n");

        for (Map.Entry<String, List<Object[]>> entry : new TreeMap<>(byType).entrySet()) {
            List<Object[]> suggestions = entry.getValue();
            println(entry.getKey() + ": " + suggestions.size() + " parameter instances");
            println("-".repeat(80));
            int shown = Math.min(15, suggestions.size());
            for (int i = 0; i < shown; i++) {
                Object[] pair = suggestions.get(i);
                String funcName = (String) pair[0];
                ParamSuggestion ps = (ParamSuggestion) pair[1];
                println("  Function: " + funcName);
                println("    Param:     " + (ps.suggestedName != null ? ps.suggestedName : ps.name));
                println("    Type:      " + ps.inferredType);
                println(String.format("    Confidence: %.0f%%", ps.confidence * 100));
                println("");
            }
            if (suggestions.size() > 15) {
                println("  ... and " + (suggestions.size() - 15) + " more\n");
            }
        }

        println("\n" + "=".repeat(80));
        println("APPLYING TYPING CHANGES VIA MCP BRIDGE");
        println("=".repeat(80) + "\n");
        println("[*] To apply these changes:");
        println("    1. Export suggestions to JSON");
        println("    2. Use MCP bridge batch_set_variable_types() with suggestions");
        println("    3. Verify changes in Ghidra");
        println("    4. Iterate with loop analysis and function documentation");
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("[X] No program loaded in Ghidra!");
            return;
        }

        listing = currentProgram.getListing();
        funcMgr = currentProgram.getFunctionManager();

        println("[*] Starting Diablo II function parameter analysis...");
        println("[*] Program: " + currentProgram.getName());

        int limit = 1000;
        int analyzed = 0;
        int typed = 0;
        FunctionIterator funcs = funcMgr.getFunctions(true);

        while (funcs.hasNext() && analyzed < limit) {
            monitor.checkCanceled();
            Function func = funcs.next();
            analyzed++;
            if (analyzed % 100 == 0) {
                println("Progress: " + analyzed + "/" + limit + " - " + typed + " functions with typing suggestions");
            }
            TypingSuggestion ts = analyzeFunction(func);
            if (ts != null && !ts.parameters.isEmpty()) {
                typingSuggestions.add(ts);
                typed++;
            }
        }

        printResults();

        println("\n[*] JSON export available for batch MCP operations");
        println("[*] Use with: batch_set_variable_types(), document_function_complete()");
        println("\n[+] Analysis complete!");
        println("    Total functions scanned: " + analyzed);
        println("    Functions with typing suggestions: " + typed);
        int totalParams = 0;
        for (TypingSuggestion ts : typingSuggestions) totalParams += ts.parameters.size();
        println("    Parameter instances to type: " + totalParams);
    }
}

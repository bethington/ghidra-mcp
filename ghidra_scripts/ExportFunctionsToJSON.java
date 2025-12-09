//Export all functions to JSON for anchor-based matching
//@category D2VersionChanger
//@menupath Tools.Export Functions to JSON

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.util.*;

public class ExportFunctionsToJSON extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get program info
        String programName = currentProgram.getName();
        String baseName = programName.replace(".dll", "").replace(".exe", "");

        // Output file path - save next to the program or in a known location
        File outputDir = new File("F:/D2VersionChanger/data/anchor");
        outputDir.mkdirs();
        File outputFile = new File(outputDir, programName + ".json");

        println("Exporting functions from: " + programName);
        println("Output file: " + outputFile.getAbsolutePath());

        FunctionManager funcManager = currentProgram.getFunctionManager();
        long imageBase = currentProgram.getImageBase().getOffset();

        // Collect all functions
        List<String> functionEntries = new ArrayList<>();
        int totalFuncs = 0;
        int namedFuncs = 0;

        FunctionIterator funcIter = funcManager.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            totalFuncs++;

            String name = func.getName();
            long address = func.getEntryPoint().getOffset();
            long rva = address - imageBase;

            // Check if it has a custom name (not FUN_ or default)
            boolean hasCustomName = !name.startsWith("FUN_") &&
                                   !name.startsWith("thunk_FUN_") &&
                                   !name.equals("entry");

            if (hasCustomName) {
                namedFuncs++;
            }

            // Get signature
            String signature = func.getSignature().getPrototypeString();
            String callingConvention = func.getCallingConventionName();

            // Get function size
            long size = 0;
            AddressSetView body = func.getBody();
            if (body != null) {
                size = body.getNumAddresses();
            }

            // Build JSON entry (manual to avoid dependencies)
            StringBuilder entry = new StringBuilder();
            entry.append("    {\n");
            entry.append("      \"address\": \"").append(String.format("0x%08X", address)).append("\",\n");
            entry.append("      \"rva\": \"").append(String.format("0x%X", rva)).append("\",\n");
            entry.append("      \"name\": \"").append(escapeJson(name)).append("\",\n");
            entry.append("      \"has_custom_name\": ").append(hasCustomName).append(",\n");
            entry.append("      \"signature\": \"").append(escapeJson(signature)).append("\",\n");
            entry.append("      \"calling_convention\": \"").append(escapeJson(callingConvention)).append("\",\n");
            entry.append("      \"size\": ").append(size).append("\n");
            entry.append("    }");

            functionEntries.add(entry.toString());
        }

        // Write JSON file
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            writer.println("{");
            writer.println("  \"program_name\": \"" + escapeJson(programName) + "\",");
            writer.println("  \"image_base\": \"" + String.format("0x%08X", imageBase) + "\",");
            writer.println("  \"total_functions\": " + totalFuncs + ",");
            writer.println("  \"named_functions\": " + namedFuncs + ",");
            writer.println("  \"functions\": [");

            for (int i = 0; i < functionEntries.size(); i++) {
                writer.print(functionEntries.get(i));
                if (i < functionEntries.size() - 1) {
                    writer.println(",");
                } else {
                    writer.println();
                }
            }

            writer.println("  ]");
            writer.println("}");
        }

        println("Export complete!");
        println("Total functions: " + totalFuncs);
        println("Named functions: " + namedFuncs);
        println("Output: " + outputFile.getAbsolutePath());
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}

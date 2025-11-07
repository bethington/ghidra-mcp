// Export DLL Function Mappings to Text File (Automated)
// @description Exports all function addresses and names for the currently loaded program (non-interactive)
// @category Diablo 2.Ordinal Linkage
// @author Ben Ethington
// @menupath Diablo II.Ordinal Linkage.Export DLL Function Mappings (Auto)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.nio.file.*;

public class ExportDLLFunctionMappingsAuto extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("[ERROR] No program is currently open!");
            return;
        }

        // Get program name
        String programName = currentProgram.getName();
        String programNameUpper = programName.toUpperCase();

        println("======================================================================");
        println("EXPORT DLL FUNCTION MAPPINGS (AUTOMATED)");
        println("======================================================================");
        println("Program: " + programName);
        println("");

        // Use hardcoded output directory (relative to project)
        String outputDirPath = "C:\\Users\\benam\\source\\mcp\\ghidra-mcp\\dll_exports";
        File outputDir = new File(outputDirPath);

        if (!outputDir.exists()) {
            println("[ERROR] Output directory does not exist: " + outputDirPath);
            return;
        }

        // Create output filename (e.g., D2Common.txt)
        String outputFileName = programName.replace(".dll", ".txt").replace(".DLL", ".txt");
        File outputFile = new File(outputDir, outputFileName);

        println("Output file: " + outputFile.getAbsolutePath());
        println("");

        // Read existing file if it exists to get the export names
        java.util.Map<String, String> addressToExportName = new java.util.LinkedHashMap<>();

        if (outputFile.exists()) {
            println("Reading existing export data from: " + outputFileName);
            try (BufferedReader reader = new BufferedReader(new FileReader(outputFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    // Parse format: DLLNAME::ExportName@address or DLLNAME::ExportName@address->GhidraName
                    if (line.contains("@")) {
                        String[] parts = line.split("@");
                        if (parts.length >= 2) {
                            String exportPart = parts[0]; // DLLNAME::ExportName
                            // Get the LAST part (address), handle optional ->GhidraName mapping
                            String addressPart = parts[parts.length - 1].split("->")[0]; // address (before any existing mapping)

                            // Extract export name
                            if (exportPart.contains("::")) {
                                String exportName = exportPart.split("::")[1];
                                addressToExportName.put(addressPart.toLowerCase(), exportName);
                            }
                        }
                    }
                }
            }
            println("Loaded " + addressToExportName.size() + " export addresses");
            println("");
        } else {
            println("[ERROR] Export file not found: " + outputFile.getAbsolutePath());
            println("Please run Phase 1 first: python export_dll_functions.py F:\\PD2_RE --output dll_exports");
            return;
        }

        // Build mapping: for each address, find the Ghidra function name
        println("Mapping Ghidra function names...");
        println("");

        int successCount = 0;
        int failCount = 0;
        java.util.List<String> outputLines = new java.util.ArrayList<>();

        FunctionManager functionManager = currentProgram.getFunctionManager();

        for (java.util.Map.Entry<String, String> entry : addressToExportName.entrySet()) {
            String addressStr = entry.getKey();
            String exportName = entry.getValue();

            try {
                // Parse address (remove 0x prefix if present)
                addressStr = addressStr.replace("0x", "");
                long addressValue = Long.parseLong(addressStr, 16);
                Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addressValue);

                // Get function at this address
                Function function = functionManager.getFunctionAt(address);

                String outputLine;
                if (function != null) {
                    String ghidraFuncName = function.getName();
                    outputLine = programNameUpper + "::" + exportName + "@" + addressStr + "->" + ghidraFuncName;
                    successCount++;
                } else {
                    // No function at this address
                    outputLine = programNameUpper + "::" + exportName + "@" + addressStr;
                    failCount++;
                }

                outputLines.add(outputLine);

                // Progress indicator
                if ((successCount + failCount) % 100 == 0) {
                    println("  Processed " + (successCount + failCount) + " addresses (" + successCount + " mapped, " + failCount + " unmapped)");
                }

            } catch (Exception e) {
                println("  [ERROR] Processing address " + addressStr + ": " + e.getMessage());
                failCount++;
                outputLines.add(programNameUpper + "::" + exportName + "@" + addressStr);
            }
        }

        // Write output file
        println("");
        println("Writing output file...");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            for (String line : outputLines) {
                writer.write(line);
                writer.newLine();
            }
        }

        println("");
        println("======================================================================");
        println("EXPORT COMPLETE");
        println("======================================================================");
        println("Output file: " + outputFile.getAbsolutePath());
        println("Total addresses: " + outputLines.size());
        println("Successfully mapped: " + successCount);
        println("Unmapped: " + failCount);
        println("");
        println("Format: DLLNAME::ExportName@address->GhidraFunctionName");
        println("======================================================================");
    }
}

// Export DLL Function Mappings to Text File
// @description Exports all function addresses and names for the currently loaded program
// @category Diablo 2.Ordinal Linkage
// @author Ben Ethington
// @menupath Diablo II.Ordinal Linkage.Export DLL Function Mappings

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.nio.file.*;

public class ExportDLLFunctionMappings extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            popup("No program is currently open!");
            return;
        }

        // Get program name
        String programName = currentProgram.getName();
        String programNameUpper = programName.toUpperCase();

        println("======================================================================");
        println("EXPORT DLL FUNCTION MAPPINGS");
        println("======================================================================");
        println("Program: " + programName);
        println("");

        // Ask user for output directory
        File outputDir = askDirectory("Select Output Directory", "Choose where to save the mapping file");
        if (outputDir == null) {
            println("Export cancelled by user");
            return;
        }

        // Create output filename (e.g., D2Common.txt)
        String outputFileName = programName.replace(".dll", ".txt").replace(".DLL", ".txt");
        File outputFile = new File(outputDir, outputFileName);

        println("Output file: " + outputFile.getAbsolutePath());
        println("");

        // Read existing file if it exists to get the export names
        java.util.Map<String, String> addressToExportName = new java.util.HashMap<>();

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
                            String addressPart = parts[1].split("->")[0]; // address (before any existing mapping)

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
            popup("Error: Export file not found!\n\nPlease run Phase 1 first:\npython export_dll_functions.py F:\\PD2_RE --output " + outputDir.getName());
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
                if ((successCount + failCount) % 50 == 0) {
                    println("  Processed " + (successCount + failCount) + " addresses (" + successCount + " mapped, " + failCount + " unmapped)");
                }

            } catch (Exception e) {
                println("  Error processing address " + addressStr + ": " + e.getMessage());
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

        popup("Export complete!\n\nFile: " + outputFileName + "\nMapped: " + successCount + " / " + outputLines.size() + " functions");
    }
}

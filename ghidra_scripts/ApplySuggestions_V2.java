//Apply reviewed suggestions from propagation_suggestions file
//@author GhidraMCP
//@category D2
//@keybinding
//@menupath D2.1c - Apply Reviewed Suggestions
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class ApplySuggestions_V2 extends GhidraScript {

    @Override
    public void run() throws Exception {
        String homeDir = System.getProperty("user.home");
        String programName = currentProgram.getName();
        File suggestFile = new File(homeDir, "propagation_suggestions_" + programName + ".txt");

        if (!suggestFile.exists()) {
            printerr("Suggestions file not found: " + suggestFile.getAbsolutePath());
            printerr("Run 'Propagate From Index V2' first to generate suggestions.");
            return;
        }

        // Ask for reviewed file (user edits and keeps only approved lines)
        File reviewedFile = askFile("Select Reviewed Suggestions File", "Open");
        if (reviewedFile == null) {
            println("Cancelled.");
            return;
        }

        println("Loading suggestions from: " + reviewedFile.getAbsolutePath());

        List<String> lines = Files.readAllLines(reviewedFile.toPath());
        int applied = 0;
        int skipped = 0;
        int errors = 0;

        for (String line : lines) {
            // Skip comments and empty lines
            if (line.trim().isEmpty() || line.startsWith("#")) {
                continue;
            }

            try {
                // Parse: Address | CurrentName | SuggestedName | Confidence | MatchType | Evidence
                String[] parts = line.split("\\|");
                if (parts.length < 3) {
                    println("Skipping malformed line: " + line);
                    skipped++;
                    continue;
                }

                String addressStr = parts[0].trim();
                String currentName = parts[1].trim();
                String suggestedName = parts[2].trim();

                // Find function at address
                Address addr = toAddr(addressStr);
                if (addr == null) {
                    printerr("Invalid address: " + addressStr);
                    errors++;
                    continue;
                }

                Function func = getFunctionAt(addr);
                if (func == null) {
                    printerr("No function at: " + addressStr);
                    errors++;
                    continue;
                }

                // Verify current name matches (safety check)
                if (!func.getName().equals(currentName)) {
                    println("Warning: Function at " + addressStr + " is now '" + func.getName() +
                            "', expected '" + currentName + "'. Applying anyway...");
                }

                // Apply the rename
                func.setName(suggestedName, SourceType.USER_DEFINED);
                println("Applied: " + currentName + " -> " + suggestedName);
                applied++;

            } catch (Exception e) {
                printerr("Error processing line: " + line);
                printerr("  " + e.getMessage());
                errors++;
            }
        }

        println("\n========== RESULTS ==========");
        println("Applied: " + applied);
        println("Skipped: " + skipped);
        println("Errors: " + errors);
    }
}

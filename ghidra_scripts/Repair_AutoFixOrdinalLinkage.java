// Auto Fix Ordinal Linkage
//
// Automatically fixes external function pointers by looking up ordinal names in DLL export mappings and renaming symbols to their real function names across all imported DLLs.
//
// Usage: Run from Script Manager on any program with ordinal imports.
// Output: Renames ordinal symbols to real function names.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Auto-fix external ordinal pointers to real names
// @menupath Diablo 2.Repair.Auto Fix Ordinal Linkage

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.*;

public class Repair_AutoFixOrdinalLinkage extends GhidraScript {

    private static class OrdinalMapping {
        String name;
        String address;

        OrdinalMapping(String name, String address) {
            this.name = name;
            this.address = address;
        }
    }

    private Map<String, Map<String, OrdinalMapping>> loadDllMappings(String dllExportsDir) {
        Map<String, Map<String, OrdinalMapping>> mappings = new HashMap<>();

        File dir = new File(dllExportsDir);
        if (!dir.exists()) {
            println("[ERROR] DLL exports directory not found: " + dllExportsDir);
            return mappings;
        }

        File[] txtFiles = dir.listFiles((d, name) -> name.endsWith(".txt"));
        if (txtFiles == null) txtFiles = new File[0];

        println("Found " + txtFiles.length + " DLL export mapping files");
        println("");

        for (File txtFile : txtFiles) {
            String dllName = txtFile.getName().replace(".txt", ".dll").toUpperCase();
            mappings.putIfAbsent(dllName, new HashMap<>());

            println("Loading mappings from: " + txtFile.getName());

            try (BufferedReader reader = new BufferedReader(new FileReader(txtFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || !line.contains("->")) continue;

                    try {
                        String[] parts = line.split("->", 2);
                        if (parts.length != 2) continue;

                        String exportPart = parts[0];
                        String ghidraName = parts[1];

                        if (!exportPart.contains("::")) continue;

                        String[] dllAndRest = exportPart.split("::", 2);
                        String rest = dllAndRest[1];

                        String[] atParts = rest.split("@");
                        if (atParts.length < 2) continue;

                        String exportName = atParts[0];
                        String address = atParts[atParts.length - 1];

                        if (exportName.startsWith("Ordinal_")) {
                            mappings.get(dllName).put(exportName,
                                new OrdinalMapping(ghidraName.trim(), address.trim()));
                        }
                    } catch (Exception e) {
                        println("  [WARN] Error parsing line: " + line + " - " + e.getMessage());
                    }
                }
            } catch (IOException e) {
                println("  [ERROR] Reading file: " + e.getMessage());
            }

            int ordinalCount = mappings.get(dllName).size();
            println("  Loaded " + ordinalCount + " ordinal mappings");
        }

        println("");
        return mappings;
    }

    private List<Map<String, Object>> findAllExternalOrdinalPointers() {
        List<Map<String, Object>> pointers = new ArrayList<>();

        ExternalManager externalManager = currentProgram.getExternalManager();
        Collection<String> externalNames = externalManager.getExternalLibraryNames();

        println("Scanning external libraries for ordinal pointers...");
        println("");

        for (String libName : externalNames) {
            println("Processing library: " + libName);

            Iterator<ExternalLocation> externalLocations = externalManager.getExternalLocations(libName);
            int ordinalCount = 0;

            while (externalLocations.hasNext()) {
                ExternalLocation extLoc = externalLocations.next();
                String label = extLoc.getLabel();

                if (label != null && label.startsWith("Ordinal_")) {
                    Map<String, Object> pointer = new HashMap<>();
                    pointer.put("dll", libName.toUpperCase());
                    pointer.put("ordinal_name", label);
                    pointer.put("external_location", extLoc);
                    pointers.add(pointer);
                    ordinalCount++;
                }
            }

            println("  Found " + ordinalCount + " ordinal pointers");
        }

        println("");
        println("Total ordinal pointers found: " + pointers.size());
        println("");
        return pointers;
    }

    private boolean fixOrdinalPointer(Map<String, Object> pointerInfo, OrdinalMapping mapping) {
        String ordinalName = (String) pointerInfo.get("ordinal_name");
        ExternalLocation extLoc = (ExternalLocation) pointerInfo.get("external_location");

        try {
            Symbol symbol = extLoc.getSymbol();
            if (symbol != null) {
                symbol.setName(mapping.name, SourceType.USER_DEFINED);
                return true;
            } else {
                println("    [WARN] No symbol found for " + ordinalName);
                return false;
            }
        } catch (Exception e) {
            println("    [ERROR] Failed to fix " + ordinalName + ": " + e.getMessage());
            return false;
        }
    }

    private void logAndPrint(PrintWriter logWriter, String message) {
        println(message);
        if (logWriter != null) {
            logWriter.println(message);
        }
    }

    @Override
    public void run() throws Exception {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String logFilePath = "C:\\Users\\benam\\source\\mcp\\ghidra-mcp\\ordinal_fix_log_" + timestamp + ".txt";

        PrintWriter logWriter = null;
        try {
            logWriter = new PrintWriter(new FileWriter(logFilePath, true));
        } catch (Exception e) {
            println("[WARN] Could not create log file: " + e.getMessage());
        }

        logAndPrint(logWriter, "=".repeat(80));
        logAndPrint(logWriter, "AUTO-FIX ORDINAL LINKAGE");
        logAndPrint(logWriter, "=".repeat(80));
        logAndPrint(logWriter, "");
        logAndPrint(logWriter, "Program: " + currentProgram.getName());
        logAndPrint(logWriter, "Log file: " + logFilePath);
        logAndPrint(logWriter, "");

        String dllExportsDir = "C:\\Users\\benam\\source\\mcp\\ghidra-mcp\\dll_exports";

        logAndPrint(logWriter, "[1/4] Loading DLL export mappings...");
        logAndPrint(logWriter, "");
        Map<String, Map<String, OrdinalMapping>> mappings = loadDllMappings(dllExportsDir);

        if (mappings.isEmpty()) {
            logAndPrint(logWriter, "[ERROR] No DLL mappings loaded. Aborting.");
            if (logWriter != null) logWriter.close();
            return;
        }

        int totalMappings = 0;
        for (Map<String, OrdinalMapping> m : mappings.values()) totalMappings += m.size();
        logAndPrint(logWriter, "Loaded " + totalMappings + " total ordinal mappings from " + mappings.size() + " DLLs");
        logAndPrint(logWriter, "");

        logAndPrint(logWriter, "[2/4] Finding all external ordinal pointers...");
        logAndPrint(logWriter, "");
        List<Map<String, Object>> pointers = findAllExternalOrdinalPointers();

        if (pointers.isEmpty()) {
            logAndPrint(logWriter, "[INFO] No ordinal pointers found. Nothing to fix.");
            if (logWriter != null) logWriter.close();
            return;
        }

        logAndPrint(logWriter, "[3/4] Fixing ordinal pointers...");
        logAndPrint(logWriter, "");

        int successCount = 0;
        int failCount = 0;
        int missingCount = 0;
        Map<String, List<String>> fixesByDll = new LinkedHashMap<>();

        for (Map<String, Object> pointer : pointers) {
            monitor.checkCanceled();
            String dll = (String) pointer.get("dll");
            String ordinalName = (String) pointer.get("ordinal_name");

            if (!mappings.containsKey(dll)) {
                logAndPrint(logWriter, "  [SKIP] " + ordinalName + " - No mappings available for " + dll);
                missingCount++;
                continue;
            }

            if (!mappings.get(dll).containsKey(ordinalName)) {
                logAndPrint(logWriter, "  [SKIP] " + ordinalName + " - No mapping found in " + dll);
                missingCount++;
                continue;
            }

            OrdinalMapping mapping = mappings.get(dll).get(ordinalName);
            fixesByDll.computeIfAbsent(dll, k -> new ArrayList<>());

            logAndPrint(logWriter, "  Fixing: " + ordinalName + " -> " + mapping.name + " @ " + mapping.address);

            if (fixOrdinalPointer(pointer, mapping)) {
                successCount++;
                fixesByDll.get(dll).add(ordinalName + " -> " + mapping.name);
            } else {
                failCount++;
            }
        }

        logAndPrint(logWriter, "");
        logAndPrint(logWriter, "=".repeat(80));
        logAndPrint(logWriter, "[4/4] SUMMARY");
        logAndPrint(logWriter, "=".repeat(80));
        logAndPrint(logWriter, "Total ordinal pointers found: " + pointers.size());
        logAndPrint(logWriter, "Successfully fixed: " + successCount);
        logAndPrint(logWriter, "Failed to fix: " + failCount);
        logAndPrint(logWriter, "No mapping available: " + missingCount);
        logAndPrint(logWriter, "");

        if (!fixesByDll.isEmpty()) {
            logAndPrint(logWriter, "FIXES BY DLL:");
            logAndPrint(logWriter, "");
            for (Map.Entry<String, List<String>> entry : fixesByDll.entrySet()) {
                List<String> fixes = entry.getValue();
                logAndPrint(logWriter, "  " + entry.getKey() + " (" + fixes.size() + " fixed):");
                int shown = Math.min(10, fixes.size());
                for (int i = 0; i < shown; i++) {
                    logAndPrint(logWriter, "    - " + fixes.get(i));
                }
                if (fixes.size() > 10) {
                    logAndPrint(logWriter, "    ... and " + (fixes.size() - 10) + " more");
                }
                logAndPrint(logWriter, "");
            }
        }

        if (successCount > 0) {
            logAndPrint(logWriter, "[SUCCESS] Fixed " + successCount + " ordinal pointers!");
        }

        logAndPrint(logWriter, "=".repeat(80));
        logAndPrint(logWriter, "");
        logAndPrint(logWriter, "Log file saved to: " + logFilePath);
        logAndPrint(logWriter, "");

        if (logWriter != null) logWriter.close();
    }
}

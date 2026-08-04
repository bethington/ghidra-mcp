// Ultimate Ordinal Fixer
//
// Updates all ordinal symbol references throughout the program using batch rename operations. Processes symbols, labels, pointers, and external locations against DLL export mappings.
//
// Usage: Run from Script Manager. Uses hardcoded ordinal-to-name map.
// Output: Renames all ordinal references to real function names.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Batch rename all ordinal symbols to real names
// @menupath Diablo 2.Repair.Ultimate Ordinal Fixer

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class Repair_UltimateOrdinalFixer extends GhidraScript {

    private static final Map<Integer, String> ORDINAL_NAMES = new LinkedHashMap<>();
    static {
        ORDINAL_NAMES.put(10084, "ProcessUnitCoordinatesAndPath");
        ORDINAL_NAMES.put(10092, "ProcessUnitMovement");
        ORDINAL_NAMES.put(10123, "GetUnitPosition");
        ORDINAL_NAMES.put(10259, "CreateUnitStruct");
        ORDINAL_NAMES.put(10338, "ProcessUnitAI");
        ORDINAL_NAMES.put(10527, "UpdateUnitAnimation");
        ORDINAL_NAMES.put(10770, "ProcessUnitCollision");
        ORDINAL_NAMES.put(10817, "GetUnitStats");
    }

    private int updateAllOrdinalReferences() throws Exception {
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        int totalUpdated = 0;

        for (Map.Entry<Integer, String> entry : ORDINAL_NAMES.entrySet()) {
            int ordinalNum = entry.getKey();
            String functionName = entry.getValue();

            println("\nProcessing Ordinal_" + ordinalNum + " -> " + functionName + ":");
            String ordinalPattern = "Ordinal_" + ordinalNum;

            SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
            int updatedCount = 0;

            while (allSymbols.hasNext()) {
                monitor.checkCanceled();
                Symbol symbol = allSymbols.next();
                String symbolName = symbol.getName();

                if (!symbolName.contains(ordinalPattern)) continue;

                String oldName = symbolName;
                String newName;

                if (symbolName.startsWith("PTR_")) {
                    String addrSuffix = "";
                    String[] parts = symbolName.split("_");
                    if (parts.length >= 3) {
                        addrSuffix = "_" + parts[parts.length - 1];
                    }
                    newName = "PTR_" + functionName + addrSuffix;
                } else if (symbolName.startsWith("LAB_")) {
                    newName = "LAB_" + functionName;
                } else if (symbolName.equals(ordinalPattern)) {
                    newName = functionName;
                } else {
                    newName = symbolName.replace(ordinalPattern, functionName);
                }

                try {
                    println("  Renaming: " + oldName + " -> " + newName);
                    symbol.setName(newName, SourceType.USER_DEFINED);
                    updatedCount++;
                    println("    SUCCESS!");
                } catch (Exception e) {
                    println("    FAILED: " + e.getMessage());

                    try {
                        Address symbolAddr = symbol.getAddress();
                        Namespace symbolNamespace = symbol.getParentNamespace();

                        symbolTable.removeSymbolSpecial(symbol);
                        Symbol newSymbol = symbolTable.createLabel(
                            symbolAddr, newName, symbolNamespace, SourceType.USER_DEFINED);

                        if (newSymbol != null) {
                            updatedCount++;
                            println("    SUCCESS (recreated)!");
                        } else {
                            println("    FAILED (recreation failed)");
                        }
                    } catch (Exception e2) {
                        println("    FAILED (recreation): " + e2.getMessage());
                    }
                }
            }

            println("  Updated " + updatedCount + " symbols for Ordinal_" + ordinalNum);
            totalUpdated += updatedCount;
        }

        return totalUpdated;
    }

    private int updateExternalLocationNames() throws Exception {
        ExternalManager extManager = currentProgram.getExternalManager();
        int updatedExternal = 0;

        println("\nUpdating external location names...");

        for (String libName : extManager.getExternalLibraryNames()) {
            if (libName.toUpperCase().contains("D2COMMON")) {
                Iterator<ExternalLocation> locations = extManager.getExternalLocations(libName);

                while (locations.hasNext()) {
                    monitor.checkCanceled();
                    ExternalLocation extLocation = locations.next();
                    String currentName = extLocation.getLabel();

                    for (Map.Entry<Integer, String> entry : ORDINAL_NAMES.entrySet()) {
                        if (("Ordinal_" + entry.getKey()).equals(currentName)) {
                            try {
                                println("  External: " + currentName + " -> " + entry.getValue());
                                extLocation.setName(entry.getValue(), SourceType.USER_DEFINED);
                                updatedExternal++;
                                println("    SUCCESS!");
                            } catch (Exception e) {
                                println("    FAILED: " + e.getMessage());
                            }
                            break;
                        }
                    }
                }
                break;
            }
        }

        return updatedExternal;
    }

    @Override
    public void run() throws Exception {
        println("=".repeat(80));
        println("ULTIMATE ORDINAL NAME FIXER");
        println("Updating ALL symbols, labels, and references to use proper function names");
        println("=".repeat(80));

        println("1. Updating symbol table references...");
        int symbolUpdates = updateAllOrdinalReferences();

        println("\n2. Updating external location names...");
        int externalUpdates = updateExternalLocationNames();

        println("\n" + "=".repeat(80));
        println("ULTIMATE ORDINAL FIXING COMPLETE!");
        println("Updated " + symbolUpdates + " symbols in symbol table");
        println("Updated " + externalUpdates + " external locations");
        println("Total updates: " + (symbolUpdates + externalUpdates));
        println("");
        println("Check your function pointer at 0x6fb7e220 - it should now show:");
        println("PTR_ProcessUnitCoordinatesAndPath_6fb7e220");
        println("=".repeat(80));
    }
}

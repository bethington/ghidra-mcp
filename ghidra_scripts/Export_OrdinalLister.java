// Ordinal Lister
//
// Parses the PE export table to extract ordinal numbers and maps them to current Ghidra function names. Useful for tracking which ordinals have been renamed.
//
// Usage: Run from Script Manager on any DLL with exports.
// Output: Console CSV listing: Ordinal, Address, Function Name.
//
// @author Ben Ethington
// @category Diablo 2.Export
// @description List exported functions with ordinal numbers as CSV
// @menupath Diablo 2.Export.Ordinal Lister

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import java.util.*;

public class Export_OrdinalLister extends GhidraScript {

    private static class ExportResult {
        int ordinal;
        String address;
        String currentName;
        String exportedName;

        ExportResult(int ordinal, String address, String currentName, String exportedName) {
            this.ordinal = ordinal;
            this.address = address;
            this.currentName = currentName;
            this.exportedName = exportedName;
        }
    }

    private void getExportsWithOrdinals() throws Exception {
        Address base = currentProgram.getImageBase();

        // Parse PE header
        int peHeaderOffset = currentProgram.getMemory().getInt(base.add(0x3c));
        Address peHeader = base.add(peHeaderOffset);

        // Export table RVA
        int exportTableRVA = currentProgram.getMemory().getInt(peHeader.add(0x18 + 0x60));
        Address exportTable = base.add(exportTableRVA);

        int baseOrdinal = currentProgram.getMemory().getInt(exportTable.add(0x10));
        int numFunctions = currentProgram.getMemory().getInt(exportTable.add(0x14));
        int numNames = currentProgram.getMemory().getInt(exportTable.add(0x18));

        int functionsArrayRVA = currentProgram.getMemory().getInt(exportTable.add(0x1C));
        int namesArrayRVA = currentProgram.getMemory().getInt(exportTable.add(0x20));
        int nameOrdinalsArrayRVA = currentProgram.getMemory().getInt(exportTable.add(0x24));

        Address functionsArray = base.add(functionsArrayRVA);
        Address namesArray = base.add(namesArrayRVA);
        Address nameOrdinalsArray = base.add(nameOrdinalsArrayRVA);

        println("Export Table Analysis");
        println("=".repeat(80));
        println("Base Ordinal: " + baseOrdinal);
        println("Number of Functions: " + numFunctions);
        println("Number of Named Exports: " + numNames);
        println("=".repeat(80));
        println("");
        println("Ordinal,Address,CurrentName,ExportedName");
        println("-".repeat(80));

        // Build map of ordinal index -> exported name
        Map<Integer, String> exportedNames = new HashMap<>();
        for (int i = 0; i < numNames; i++) {
            int ordinalIndex = currentProgram.getMemory().getShort(nameOrdinalsArray.add(i * 2)) & 0xFFFF;
            int nameRVA = currentProgram.getMemory().getInt(namesArray.add(i * 4));
            Address nameAddr = base.add(nameRVA);

            StringBuilder exportedName = new StringBuilder();
            int offset = 0;
            while (true) {
                byte b = currentProgram.getMemory().getByte(nameAddr.add(offset));
                if (b == 0) break;
                exportedName.append((char)(b & 0xFF));
                offset++;
            }
            exportedNames.put(ordinalIndex, exportedName.toString());
        }

        List<ExportResult> results = new ArrayList<>();
        for (int i = 0; i < numFunctions; i++) {
            monitor.checkCanceled();
            int functionRVA = currentProgram.getMemory().getInt(functionsArray.add(i * 4));
            if (functionRVA == 0) continue;

            Address functionAddr = base.add(functionRVA);
            int ordinalNumber = baseOrdinal + i;

            Function func = currentProgram.getFunctionManager().getFunctionAt(functionAddr);
            String currentName = func != null ? func.getName() : "<no function>";
            String exportedName = exportedNames.getOrDefault(i, "<ordinal only>");

            ExportResult result = new ExportResult(ordinalNumber,
                "0x" + functionAddr, currentName, exportedName);
            results.add(result);

            println(ordinalNumber + "," + result.address + "," + currentName + "," + exportedName);
        }

        println("");
        println("=".repeat(80));
        println("Total exported functions: " + results.size());
        println("Functions with names: " + numNames);
        println("Functions with ordinal only: " + (results.size() - numNames));

        List<ExportResult> defaultNames = new ArrayList<>();
        for (ExportResult r : results) {
            if (r.currentName.startsWith("FUN_") || r.currentName.startsWith("Ordinal_")) {
                defaultNames.add(r);
            }
        }
        if (!defaultNames.isEmpty()) {
            println("");
            println("Functions still using default names: " + defaultNames.size());
            println("-".repeat(80));
            for (ExportResult r : defaultNames) {
                println("  Ordinal " + r.ordinal + " @ " + r.address + " : " + r.currentName);
            }
        }
    }

    @Override
    public void run() throws Exception {
        try {
            getExportsWithOrdinals();
        } catch (CancelledException e) {
            // cancelled
        }
    }
}

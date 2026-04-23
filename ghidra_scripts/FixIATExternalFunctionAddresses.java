// FixIATExternalFunctionAddresses.java
//
// Fixes "<<not bound>>" external function references across all imported DLLs.
//
// PROBLEM:
//   The IAT (Import Address Table) is read from the PE on disk. Before the
//   Windows loader runs, IAT slots contain pre-binding values:
//     - Import by ordinal: 0x80000000 | ordinal_number
//     - Import by name:    RVA to hint/name table entry
//   Ghidra sees these raw values and cannot resolve them to actual DLL addresses,
//   so all external functions show "<<not bound>>".
//
// FIX:
//   For each external function in the program, look up its correct runtime address
//   in the dll_exports/*.txt files and:
//     1. Patch the IAT pointer bytes with the correct resolved address
//     2. Set the ExternalLocation address so Ghidra shows it as "bound"
//
// EXPORT FILE FORMAT (dll_exports/*.txt):
//   D2COMMON.DLL::Ordinal_10000@6fd9f450->Ordinal_10000
//   D2COMMON.DLL::ITEMSReadInfoFromStreamVersioned@6fd72000->ITEMSReadInfoFromStreamVersioned
//
// USAGE:
//   Run from Ghidra Script Manager on the binary being analyzed.
//   The dll_exports/ folder is expected at:
//     <GHIDRA_PROJECT_DIR>/../dll_exports/   (relative to the project)
//   OR set DLL_EXPORTS_DIR below to an absolute path.
//
// @author d2re
// @category Diablo 2
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class FixIATExternalFunctionAddresses extends GhidraScript {

    // -----------------------------------------------------------------------
    // Config: override if dll_exports is not auto-detected
    // -----------------------------------------------------------------------
    private static final String DLL_EXPORTS_DIR = "";  // leave empty for auto-detect

    @Override
    public void run() throws Exception {
        // 1. Locate export tables
        File exportsDir = findExportsDir();
        if (exportsDir == null || !exportsDir.isDirectory()) {
            printerr("ERROR: Cannot find dll_exports directory. Set DLL_EXPORTS_DIR in script.");
            return;
        }
        println("Loading export tables from: " + exportsDir.getAbsolutePath());

        // 2. Parse all *.txt files → { "D2COMMON.DLL" -> { "Ordinal_10000" -> 0x6fd9f450L } }
        Map<String, Map<String, Long>> allExports = loadAllExports(exportsDir);
        int totalExportEntries = allExports.values().stream().mapToInt(Map::size).sum();
        println(String.format("Loaded %d DLLs, %d total exports.", allExports.size(), totalExportEntries));

        // 3. Iterate external functions and patch
        ExternalManager extMgr = currentProgram.getExternalManager();
        Memory mem = currentProgram.getMemory();
        int fixed = 0, notFound = 0, alreadyBound = 0, noRef = 0;

        List<String> libNames = new ArrayList<>();
        for (String lib : extMgr.getExternalLibraryNames()) {
            libNames.add(lib);
        }
        Collections.sort(libNames);

        println("\n--- Per-DLL summary ---");
        for (String libName : libNames) {
            if (monitor.isCancelled()) break;

            String libKey = libName.toUpperCase();
            Map<String, Long> exportMap = allExports.get(libKey);

            Iterator<ExternalLocation> iter = extMgr.getExternalLocations(libName);
            int libFixed = 0, libNotFound = 0, libAlready = 0, libNoRef = 0;

            while (iter.hasNext()) {
                if (monitor.isCancelled()) break;
                ExternalLocation extLoc = iter.next();

                String funcName = extLoc.getLabel();

                // Check if already bound (address is set to a real location)
                Address currentExtAddr = extLoc.getAddress();
                if (currentExtAddr != null && !isPreBindingValue(currentExtAddr.getOffset())) {
                    // Already looks like a real address (not an ordinal-encoded stub)
                    alreadyBound++;
                    libAlready++;
                    continue;
                }

                // Look up correct address in export table
                Long correctAddrLong = null;
                if (exportMap != null) {
                    correctAddrLong = exportMap.get(funcName);
                }

                if (correctAddrLong == null) {
                    notFound++;
                    libNotFound++;
                    continue;
                }

                Address correctAddr = toAddr(correctAddrLong);

                // Set the bound address on the ExternalLocation
                try {
                    int txId = currentProgram.startTransaction("Fix external: " + funcName);
                    try {
                        extLoc.setAddress(correctAddr);
                        currentProgram.endTransaction(txId, true);
                    } catch (Exception e) {
                        currentProgram.endTransaction(txId, false);
                        printerr("  Failed to set address for " + funcName + ": " + e.getMessage());
                        notFound++;
                        libNotFound++;
                        continue;
                    }
                } catch (Exception e) {
                    printerr("  Transaction error for " + funcName + ": " + e.getMessage());
                    continue;
                }

                // Patch IAT pointer bytes for each PTR_xxx reference in the program
                // References: data refs from the IAT slot to this external function
                boolean patchedAny = false;
                for (Reference ref : getReferencesTo(extLoc.getExternalSpaceAddress())) {
                    if (monitor.isCancelled()) break;
                    Address fromAddr = ref.getFromAddress();
                    if (!fromAddr.isExternalAddress()) {
                        // This is an IAT pointer in real memory — patch the stored address
                        try {
                            int txId = currentProgram.startTransaction("Patch IAT: " + funcName);
                            try {
                                // 32-bit PE: write 4 bytes
                                mem.setInt(fromAddr, (int) correctAddrLong.longValue());
                                currentProgram.endTransaction(txId, true);
                                patchedAny = true;
                            } catch (MemoryAccessException mae) {
                                currentProgram.endTransaction(txId, false);
                                // Read-only segment? Try clearing and re-initializing
                                // (non-fatal, ExternalLocation binding is the important part)
                            } catch (Exception e) {
                                currentProgram.endTransaction(txId, false);
                            }
                        } catch (Exception e) {
                            // skip
                        }
                    }
                }

                if (!patchedAny) {
                    libNoRef++;
                    noRef++;
                }

                fixed++;
                libFixed++;
            }

            if (libFixed + libNotFound + libAlready + libNoRef > 0) {
                println(String.format("  %-30s fixed=%-4d notFound=%-4d alreadyBound=%-4d noIATRef=%d",
                    libName, libFixed, libNotFound, libAlready, libNoRef));
            }
        }

        println("\n=== Summary ===");
        println(String.format("  Fixed (address set + IAT patched): %d", fixed));
        println(String.format("  Already bound (skipped):            %d", alreadyBound));
        println(String.format("  Not in export tables:               %d", notFound));
        println(String.format("  Fixed but no IAT ref found:         %d", noRef));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Returns true if the value looks like a pre-binding IAT stub rather than a
     * real runtime address:
     *   - 0x80xxxxxx = ordinal-encoded (high bit set, low 16 bits = ordinal)
     *   - < 0x00200000 = suspiciously small (likely an RVA from hint/name table)
     */
    private boolean isPreBindingValue(long v) {
        if ((v & 0x80000000L) != 0) return true;   // ordinal-encoded
        if (v > 0 && v < 0x00200000L) return true; // small RVA
        return false;
    }

    /**
     * Parse all dll_exports/*.txt files into a nested map.
     * Line format: D2COMMON.DLL::FuncName@hexaddr->FuncName
     */
    private Map<String, Map<String, Long>> loadAllExports(File dir) throws IOException {
        Map<String, Map<String, Long>> result = new HashMap<>();
        File[] files = dir.listFiles((d, name) -> name.endsWith(".txt"));
        if (files == null) return result;

        for (File f : files) {
            try (BufferedReader br = new BufferedReader(new FileReader(f))) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    // D2COMMON.DLL::Ordinal_10000@6fd9f450->Ordinal_10000
                    int dcIdx = line.indexOf("::");
                    int atIdx = line.indexOf('@', dcIdx);
                    int arrowIdx = line.indexOf("->", atIdx);
                    if (dcIdx < 0 || atIdx < 0 || arrowIdx < 0) continue;

                    String dllName = line.substring(0, dcIdx).toUpperCase();
                    String funcName = line.substring(dcIdx + 2, atIdx);
                    String hexAddr = line.substring(atIdx + 1, arrowIdx);

                    long addr;
                    try {
                        addr = Long.parseUnsignedLong(hexAddr, 16);
                    } catch (NumberFormatException e) {
                        continue;
                    }

                    result.computeIfAbsent(dllName, k -> new HashMap<>()).put(funcName, addr);
                }
            }
        }
        return result;
    }

    /**
     * Attempt to locate the dll_exports/ directory automatically.
     * Priority:
     *  1. DLL_EXPORTS_DIR constant if set
     *  2. Sibling of the Ghidra project directory
     *  3. Sibling of the script file directory
     */
    private File findExportsDir() {
        if (!DLL_EXPORTS_DIR.isEmpty()) {
            return new File(DLL_EXPORTS_DIR);
        }

        // Try relative to project directory
        if (state != null && state.getProject() != null) {
            File projDir = new File(state.getProject().getProjectLocator().getProjectDirPath());
            File candidate = new File(projDir.getParentFile(), "dll_exports");
            if (candidate.isDirectory()) return candidate;
            // One level up
            candidate = new File(projDir.getParentFile().getParentFile(), "dll_exports");
            if (candidate.isDirectory()) return candidate;
        }

        // Try relative to script file
        if (sourceFile != null) {
            File scriptDir = sourceFile.getParentFile();
            File candidate = new File(scriptDir.getParentFile(), "dll_exports");
            if (candidate.isDirectory()) return candidate;
        }

        return null;
    }
}

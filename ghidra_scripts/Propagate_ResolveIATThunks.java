// Resolve IAT Thunks
//
// Builds ordinal maps from imported DLLs in the same folder and resolves IAT (Import Address Table) thunk functions that jump to ordinal imports. Renames them to their real function names.
//
// Usage: Run from Script Manager. Automatically finds sibling DLLs.
// Output: Renames IAT thunk functions to their resolved names.
//
// @author Ben Ethington
// @category Diablo 2.Propagation
// @description Resolve IAT thunk functions from DLL ordinal maps
// @menupath Diablo 2.Propagation.Resolve IAT Thunks

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.framework.model.*;
import java.util.*;

public class Propagate_ResolveIATThunks extends GhidraScript {

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        SymbolTable st = currentProgram.getSymbolTable();
        ExternalManager extMgr = currentProgram.getExternalManager();

        println("Building ordinal maps from imported DLLs...");

        Map<String, Map<Integer, String>> dllOrdinalMaps = new HashMap<>();
        Set<String> neededDlls = new HashSet<>();

        for (String libName : extMgr.getExternalLibraryNames()) {
            if (libName.equals("<EXTERNAL>")) continue;
            ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
            while (iter.hasNext()) {
                ExternalLocation ext = iter.next();
                if (ext.getLabel() != null && ext.getLabel().startsWith("Ordinal_")) {
                    neededDlls.add(libName.toUpperCase());
                    break;
                }
            }
        }

        println("DLLs with unresolved ordinals: " + neededDlls);

        DomainFolder versionFolder = currentProgram.getDomainFile().getParent();
        if (versionFolder == null) {
            println("ERROR: Could not find parent folder");
            return;
        }
        println("Source folder: " + versionFolder.getPathname());

        for (String dllName : neededDlls) {
            String cleanName = dllName;
            if (!cleanName.toLowerCase().endsWith(".dll")) cleanName += ".dll";

            DomainFile df = null;
            for (DomainFile f : versionFolder.getFiles()) {
                if (f.getName().equalsIgnoreCase(cleanName)) {
                    df = f;
                    break;
                }
            }

            if (df == null) {
                println("  " + dllName + ": not found in project");
                continue;
            }

            Program srcProg = null;
            try {
                srcProg = (Program) df.getImmutableDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
                Map<Integer, String> ordMap = buildOrdinalMap(srcProg);
                dllOrdinalMaps.put(dllName.toUpperCase(), ordMap);
                println("  " + dllName + ": " + ordMap.size() + " ordinals mapped");
            } catch (Exception e) {
                println("  " + dllName + ": error opening - " + e.getMessage());
            } finally {
                if (srcProg != null) srcProg.release(this);
            }
        }

        println("Resolving thunks...");
        int renamed = 0, extRenamed = 0, skipped = 0, failed = 0;

        int txId = currentProgram.startTransaction("Resolve IAT thunks");
        try {
            for (String libName : extMgr.getExternalLibraryNames()) {
                if (libName.equals("<EXTERNAL>")) continue;
                Map<Integer, String> ordMap = dllOrdinalMaps.get(libName.toUpperCase());
                if (ordMap == null) continue;

                ExternalLocationIterator extIter = extMgr.getExternalLocations(libName);
                while (extIter.hasNext()) {
                    ExternalLocation ext = extIter.next();
                    String label = ext.getLabel();
                    if (label == null || !label.startsWith("Ordinal_")) continue;

                    int ordNum;
                    try {
                        ordNum = Integer.parseInt(label.substring(8));
                    } catch (Exception e) { continue; }

                    String realName = ordMap.get(ordNum);
                    if (realName == null || realName.startsWith("FUN_") || realName.startsWith("Ordinal_")) continue;

                    try {
                        Symbol sym = ext.getSymbol();
                        sym.setName(realName, SourceType.USER_DEFINED);
                        extRenamed++;
                    } catch (Exception e) {
                        println("  ext rename fail: " + label + " -> " + realName + ": " + e.getMessage());
                    }
                }
            }

            FunctionIterator fi = fm.getFunctions(true);
            while (fi.hasNext()) {
                Function f = fi.next();
                String name = f.getName();
                if (!name.startsWith("Ordinal_")) continue;

                Instruction instr = getInstructionAt(f.getEntryPoint());
                if (instr == null || !instr.getMnemonicString().equals("JMP")) { skipped++; continue; }

                Reference[] refs = rm.getReferencesFrom(f.getEntryPoint());
                String targetName = null;
                String targetDll = null;

                for (Reference ref : refs) {
                    Symbol[] syms = st.getSymbols(ref.getToAddress());
                    for (Symbol sym : syms) {
                        try {
                            ExternalLocation ext = extMgr.getExternalLocation(sym);
                            if (ext != null) {
                                targetName = ext.getLabel();
                                targetDll = ext.getLibraryName();
                            }
                        } catch (Exception e) {}
                    }
                }

                if (targetName == null) {
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isData()) {
                            Reference[] iatRefs = rm.getReferencesFrom(ref.getToAddress());
                            for (Reference iatRef : iatRefs) {
                                Symbol[] syms2 = st.getSymbols(iatRef.getToAddress());
                                for (Symbol sym : syms2) {
                                    try {
                                        ExternalLocation ext = extMgr.getExternalLocation(sym);
                                        if (ext != null) {
                                            targetName = ext.getLabel();
                                            targetDll = ext.getLibraryName();
                                        }
                                    } catch (Exception e) {}
                                }
                            }
                        }
                    }
                }

                if (targetName != null && !targetName.startsWith("Ordinal_") && !targetName.startsWith("FUN_")) {
                    try {
                        f.setName(targetName, SourceType.USER_DEFINED);
                        renamed++;
                    } catch (Exception e) {
                        try {
                            String prefix = targetDll != null ? targetDll.replace(".DLL","").replace(".dll","") + "_" : "";
                            f.setName(prefix + targetName, SourceType.USER_DEFINED);
                            renamed++;
                        } catch (Exception e2) {
                            println("FAILED: " + name + " -> " + targetName + ": " + e2.getMessage());
                            failed++;
                        }
                    }
                } else {
                    skipped++;
                }
            }

            currentProgram.endTransaction(txId, true);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            println("TRANSACTION ERROR: " + e.getMessage());
            throw e;
        }

        println("Done: " + renamed + " thunks renamed, " + extRenamed + " externals renamed, " + skipped + " skipped, " + failed + " failed");
    }

    private Map<Integer, String> buildOrdinalMap(Program prog) {
        Map<Integer, String> map = new HashMap<>();
        try {
            Memory mem = prog.getMemory();
            Address imageBase = prog.getImageBase();

            int peOffset = mem.getInt(imageBase.add(0x3C));
            Address peHeader = imageBase.add(peOffset);

            int exportDirRVA = mem.getInt(peHeader.add(0x78));
            if (exportDirRVA == 0) return map;

            Address exportDir = imageBase.add(exportDirRVA);
            int numFunctions = mem.getInt(exportDir.add(0x14));
            int numNames = mem.getInt(exportDir.add(0x18));
            int addrOfFunctions = mem.getInt(exportDir.add(0x1C));
            int addrOfNames = mem.getInt(exportDir.add(0x20));
            int addrOfNameOrdinals = mem.getInt(exportDir.add(0x24));
            int ordinalBase = mem.getInt(exportDir.add(0x10));

            Map<Integer, String> indexToName = new HashMap<>();
            for (int i = 0; i < numNames; i++) {
                int nameRVA = mem.getInt(imageBase.add(addrOfNames + i * 4));
                short nameOrdIdx = mem.getShort(imageBase.add(addrOfNameOrdinals + i * 2));
                StringBuilder sb = new StringBuilder();
                Address nameAddr = imageBase.add(nameRVA);
                byte b;
                while ((b = mem.getByte(nameAddr)) != 0) {
                    sb.append((char) b);
                    nameAddr = nameAddr.add(1);
                }
                indexToName.put((int)(nameOrdIdx & 0xFFFF), sb.toString());
            }

            FunctionManager srcFm = prog.getFunctionManager();
            for (int i = 0; i < numFunctions; i++) {
                int funcRVA = mem.getInt(imageBase.add(addrOfFunctions + i * 4));
                if (funcRVA == 0) continue;
                int ordinal = i + ordinalBase;
                Address funcAddr = imageBase.add(funcRVA);

                Function func = srcFm.getFunctionAt(funcAddr);
                if (func != null) {
                    String fname = func.getName();
                    if (!fname.startsWith("FUN_") && !fname.startsWith("Ordinal_")) {
                        map.put(ordinal, fname);
                        continue;
                    }
                }

                String peName = indexToName.get(i);
                if (peName != null) {
                    map.put(ordinal, peName);
                }
            }
        } catch (Exception e) {
            println("  Error building ordinal map: " + e.getMessage());
        }
        return map;
    }
}

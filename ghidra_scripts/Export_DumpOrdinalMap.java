// Dump Ordinal Map
//
// Parses the PE export table of a sibling DLL to extract ordinal-to-address mappings. Opens the target DLL from the same project folder as the current program.
//
// Usage: Args: [0]=target DLL name (default: D2Win.dll).
// Output: Console listing of ordinal numbers mapped to addresses.
//
// @author Ben Ethington
// @category Diablo 2.Export
// @description Dump PE export table ordinal-to-address mappings
// @menupath Diablo 2.Export.Dump Ordinal Map

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.framework.model.*;
import java.util.*;

public class Export_DumpOrdinalMap extends GhidraScript {
    @Override
    public void run() throws Exception {
        String targetDll = "D2Win.dll";
        String[] args = getScriptArgs();
        if (args.length > 0) targetDll = args[0];

        DomainFolder folder = currentProgram.getDomainFile().getParent();
        DomainFile df = null;
        for (DomainFile f : folder.getFiles()) {
            if (f.getName().equalsIgnoreCase(targetDll)) { df = f; break; }
        }
        if (df == null) { println("Not found: " + targetDll); return; }

        Program prog = (Program) df.getImmutableDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
        try {
            Memory mem = prog.getMemory();
            Address imageBase = prog.getImageBase();
            int peOffset = mem.getInt(imageBase.add(0x3C));
            Address peHeader = imageBase.add(peOffset);
            int exportDirRVA = mem.getInt(peHeader.add(0x78));
            Address exportDir = imageBase.add(exportDirRVA);
            int numFunctions = mem.getInt(exportDir.add(0x14));
            int numNames = mem.getInt(exportDir.add(0x18));
            int addrOfFunctions = mem.getInt(exportDir.add(0x1C));
            int addrOfNames = mem.getInt(exportDir.add(0x20));
            int addrOfNameOrdinals = mem.getInt(exportDir.add(0x24));
            int ordinalBase = mem.getInt(exportDir.add(0x10));

            println("ordinalBase=" + ordinalBase + " numFunctions=" + numFunctions + " numNames=" + numNames);

            // Build name index -> PE name
            Map<Integer, String> indexToName = new HashMap<>();
            for (int i = 0; i < numNames; i++) {
                int nameRVA = mem.getInt(imageBase.add(addrOfNames + i * 4));
                short nameOrdIdx = mem.getShort(imageBase.add(addrOfNameOrdinals + i * 2));
                StringBuilder sb = new StringBuilder();
                Address nameAddr = imageBase.add(nameRVA);
                byte b;
                while ((b = mem.getByte(nameAddr)) != 0) { sb.append((char) b); nameAddr = nameAddr.add(1); }
                indexToName.put((int)(nameOrdIdx & 0xFFFF), sb.toString());
            }

            FunctionManager srcFm = prog.getFunctionManager();
            for (int i = 0; i < numFunctions; i++) {
                int funcRVA = mem.getInt(imageBase.add(addrOfFunctions + i * 4));
                if (funcRVA == 0) continue;
                int ordinal = i + ordinalBase;
                Address funcAddr = imageBase.add(funcRVA);
                Function func = srcFm.getFunctionAt(funcAddr);
                String funcName = func != null ? func.getName() : "<no func>";
                String peName = indexToName.get(i);
                println("ORD|" + ordinal + "|" + funcName + "|" + (peName != null ? peName : ""));
            }
        } finally {
            prog.release(this);
        }
    }
}

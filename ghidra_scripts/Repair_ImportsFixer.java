// Imports Fixer
//
// Analyzes Diablo 2 DLL imports by parsing PE headers, counts imported functions from key DLLs, and creates functions at all exported addresses. Ensures all ordinals have function definitions.
//
// Usage: Run from Script Manager on any D2 DLL.
// Output: Creates functions at exported addresses in the program.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Fix D2 DLL imports and create export functions
// @menupath Diablo 2.Repair.Imports Fixer

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;

public class Repair_ImportsFixer extends GhidraScript {

    private void getExports() throws Exception {
        Address base = currentProgram.getImageBase();
        Address a = base.add(0x3c);
        int b = currentProgram.getMemory().getInt(a);
        Address pe = base.add(b);
        Address c = pe.add(0x18 + 0x60);
        int d = currentProgram.getMemory().getInt(c);
        Address export = base.add(d);
        println("Export header " + export);
        Address e = export.add(0x10);
        int f = currentProgram.getMemory().getInt(e);
        Address g = export.add(0x14);
        int h = currentProgram.getMemory().getInt(g);
        Address i = export.add(0x14 + 4 + 4);
        int j = currentProgram.getMemory().getInt(i);
        Address k = base.add(j);
        println("Number of exported functions is equal to " + h + " and first ordinal number is " + f);
        println("Ordinal table is located at address " + k);
        for (int u = 0; u < h; u++) {
            Address x = k.add((long)u * 4);
            int y = currentProgram.getMemory().getInt(x);
            if (y != 0) {
                Address z = base.add(y);
                Function p = currentProgram.getFunctionManager().getFunctionAt(z);
                if (p == null) {
                    CreateFunctionCmd cmd = new CreateFunctionCmd(z);
                    cmd.applyTo(currentProgram);
                    DisassembleCommand disCmd = new DisassembleCommand(z, null, false);
                    disCmd.applyTo(currentProgram, monitor);
                }
            }
        }
    }

    private void findImports(String name) {
        int count = 0;
        monitor.setMessage("Finding imported functions");
        for (Function func : currentProgram.getFunctionManager().getExternalFunctions()) {
            if (func.getExternalLocation().getParentName().contains(name)) {
                count++;
            }
        }
        println("Found " + count + " imported functions from " + name);
    }

    @Override
    public void run() throws Exception {
        try {
            findImports("D2COMMON.DLL");
            findImports("D2CMP.DLL");
            findImports("D2LANG.DLL");
            findImports("D2NET.DLL");
            findImports("FOG.DLL");
            findImports("STORM.DLL");
            getExports();
        } catch (CancelledException e) {
            // cancelled
        }
    }
}

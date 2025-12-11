//@category Analysis
//@menupath Analysis.Recreate Function 6fc84db0

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class RecreateFunction6fc84db0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc84db0L);

        // Remove existing function if present
        Function existingFunc = getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function at " + addr);
            removeFunction(existingFunc);
        }

        // Disassemble and create function
        println("Disassembling at " + addr);
        disassemble(addr);

        println("Creating function at " + addr);
        createFunction(addr, null);

        Function newFunc = getFunctionAt(addr);
        if (newFunc != null) {
            println("SUCCESS: Created function: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("ERROR: Function creation failed");
        }
    }
}

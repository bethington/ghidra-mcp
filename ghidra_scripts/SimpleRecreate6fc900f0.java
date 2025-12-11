//Simple recreate function
//@author GhidraMCP
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;

public class SimpleRecreate6fc900f0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc900f0L);
        
        // Just disassemble and let Ghidra figure out the rest
        println("Starting disassembly at " + addr);
        
        // Disassemble starting from this address
        int result = currentProgram.getListing().getNumInstructions();
        println("Instructions before: " + result);
        
        disassemble(addr);
        
        result = currentProgram.getListing().getNumInstructions();
        println("Instructions after: " + result);
        
        // Now create the function
        createFunction(addr, "FUN_6fc900f0");
        
        println("Done");
    }
}

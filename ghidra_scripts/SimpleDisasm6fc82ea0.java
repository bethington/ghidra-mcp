// Simple disassembly at 0x6fc82ea0
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;

public class SimpleDisasm6fc82ea0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc82ea1);
        
        // Just disassemble starting from next byte
        for (int i = 0; i < 300; i++) {
            Address current = addr.add(i);
            if (getInstructionAt(current) == null) {
                disassemble(current);
            }
        }
        
        println("Disassembly complete");
        
        // Check function
        Address funcAddr = toAddr(0x6fc82ea0);
        var func = getFunctionAt(funcAddr);
        if (func != null) {
            println("Function body: " + func.getBody().getNumAddresses() + " bytes");
        }
    }
}

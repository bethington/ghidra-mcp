//Recreate function at 0x6fc83a20
//@category D2Game
//@author GhidraMCP

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class Recreate_6fc83a20 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc83a20);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            println("Removing existing function at " + addr);
            fm.removeFunction(addr);
        }
        
        // Disassemble the area first
        disassemble(addr);
        
        // Create new function
        func = createFunction(addr, "FUN_6fc83a20");
        if (func != null) {
            println("Created function: " + func.getName() + " at " + func.getEntryPoint());
            println("Body: " + func.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

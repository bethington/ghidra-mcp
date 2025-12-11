//Recreate function at 0x6fc98210
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class RecreateFunc6fc98210 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc98210);
        
        // Remove existing function
        Function func = getFunctionAt(addr);
        if (func != null) {
            println("Removing existing function: " + func.getName());
            removeFunction(func);
        }
        
        // Disassemble from address
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create function
        println("Creating function at " + addr);
        func = createFunction(addr, null);
        
        if (func != null) {
            println("Function created: " + func.getName());
            println("Entry: " + func.getEntryPoint());
            println("Body: " + func.getBody());
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

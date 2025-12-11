//Recreate function at 0x6fc8fa00
//@author GhidraMCP
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction6fc8fa00 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8fa00);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            println("Removing existing function: " + existing.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble at address
        println("Disassembling at " + addr);
        disassemble(addr);
        
        // Create new function
        println("Creating function at " + addr);
        Function newFunc = createFunction(addr, "FUN_6fc8fa00");
        
        if (newFunc != null) {
            println("Success! Function created: " + newFunc.getName());
            println("Body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

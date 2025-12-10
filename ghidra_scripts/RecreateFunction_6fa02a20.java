// RecreateFunction_6fa02a20.java
//@author Claude
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class RecreateFunction_6fa02a20 extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fa02a20L);
        
        int txId = currentProgram.startTransaction("Recreate Function");
        try {
            FunctionManager funcMgr = currentProgram.getFunctionManager();
            Function existingFunc = funcMgr.getFunctionAt(startAddr);
            
            if (existingFunc != null) {
                println("Removing: " + existingFunc.getName());
                funcMgr.removeFunction(startAddr);
            }
            
            // Clear a reasonable range
            Address endAddr = startAddr.add(0x1A0);
            clearListing(startAddr, endAddr);
            
            // Disassemble
            disassemble(startAddr);
            
            // Create function
            Function newFunc = createFunction(startAddr, null);
            if (newFunc != null) {
                println("Created: " + newFunc.getName() + " body=" + newFunc.getBody());
            } else {
                println("Failed to create function");
            }
            
            currentProgram.endTransaction(txId, true);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            throw e;
        }
    }
}

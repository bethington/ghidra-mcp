//Recreates a function at the specified address by clearing and re-analyzing
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class RecreateFunction6fc8f670 extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Target address for FUN_6fc8f670
        String addrString = "6fc8f670";
        
        Address addr = currentProgram.getAddressFactory().getAddress(addrString);
        if (addr == null) {
            println("ERROR: Invalid address: " + addrString);
            return;
        }
        
        println("Working on program: " + currentProgram.getName());
        println("Target address: " + addr);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function existingFunc = funcMgr.getFunctionAt(addr);
        
        if (existingFunc != null) {
            println("Existing function: " + existingFunc.getName());
            println("Current body: " + existingFunc.getBody().getNumAddresses() + " bytes");
            
            // Remove the existing broken function
            println("Removing broken function...");
            funcMgr.removeFunction(existingFunc.getEntryPoint());
        }
        
        // Clear and disassemble fresh
        println("Disassembling at " + addrString + "...");
        clearListing(addr);
        disassemble(addr);
        
        // Create function
        println("Creating function at " + addrString + "...");
        Function newFunc = createFunction(addr, null);
        
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName() + " at " + addr);
            println("Entry point: " + newFunc.getEntryPoint());
            println("Body size: " + newFunc.getBody().getNumAddresses() + " bytes");
        } else {
            println("ERROR: Failed to create function at " + addrString);
        }
    }
}

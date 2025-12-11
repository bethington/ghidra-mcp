//Creates a function at 0x6fc82750
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class CreateFunctionAt6fc82750 extends GhidraScript {
    @Override
    public void run() throws Exception {
        String addrString = "6fc82750";
        
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
            println("Function already exists at " + addrString + ": " + existingFunc.getName());
            println("Removing truncated function...");
            funcMgr.removeFunction(addr);
        }
        
        // Check if there's code at the address
        if (currentProgram.getListing().getInstructionAt(addr) == null) {
            println("Disassembling at " + addrString + "...");
            disassemble(addr);
        }
        
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

//Fix the broken function at 0x6fc80b20 by re-creating it
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class FixFunction6fc80b20 extends GhidraScript {
    @Override
    public void run() throws Exception {
        String addrString = "6fc80b20";
        
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
            println("Current body size: " + existingFunc.getBody().getNumAddresses() + " bytes");
            
            // Remove the broken function
            println("Removing broken function...");
            funcMgr.removeFunction(addr);
        }
        
        // Disassemble the full range
        Address endAddr = currentProgram.getAddressFactory().getAddress("6fc80b93");
        println("Disassembling range " + addr + " to " + endAddr + "...");
        
        Address current = addr;
        while (current.compareTo(endAddr) <= 0) {
            if (currentProgram.getListing().getInstructionAt(current) == null) {
                disassemble(current);
            }
            current = current.add(1);
        }
        
        // Re-create the function
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

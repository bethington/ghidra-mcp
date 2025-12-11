//Recreate function at 0x6fc8f620
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class RecreateFunction6fc8f620 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc8f620);
        
        // Remove existing function if present
        Function existingFunc = getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            removeFunction(existingFunc);
        }
        
        // Clear and disassemble
        clearListing(addr, addr.add(0x50));
        DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
        disCmd.applyTo(currentProgram, monitor);
        println("Disassembled from " + addr);
        
        // Create function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        cmd.applyTo(currentProgram, monitor);
        
        Function newFunc = getFunctionAt(addr);
        if (newFunc != null) {
            println("Created function: " + newFunc.getName() + " body: " + newFunc.getBody());
        } else {
            println("Failed to create function");
        }
    }
}

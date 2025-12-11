//Fix function at 0x6fc986a0 by clearing and redisassembling
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFunc6fc986a0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc986a0L);
        Address endAddr = toAddr(0x6fc987d0L);  // Next function
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        
        // Step 1: Remove existing function
        Function existing = fm.getFunctionAt(startAddr);
        if (existing != null) {
            println("Removing function: " + existing.getName());
            fm.removeFunction(startAddr);
        }
        
        // Step 2: Clear all code in the range
        AddressSet range = new AddressSet(startAddr, endAddr.subtract(1));
        println("Clearing range: " + range);
        listing.clearCodeUnits(startAddr, endAddr.subtract(1), false);
        
        // Step 3: Disassemble the range
        println("Disassembling from " + startAddr + " to " + endAddr);
        DisassembleCommand disCmd = new DisassembleCommand(range, null, true);
        disCmd.applyTo(currentProgram, monitor);
        
        // Step 4: Create the function
        println("Creating function at " + startAddr);
        CreateFunctionCmd createCmd = new CreateFunctionCmd(startAddr);
        boolean success = createCmd.applyTo(currentProgram, monitor);
        
        if (success) {
            Function newFunc = fm.getFunctionAt(startAddr);
            if (newFunc != null) {
                println("SUCCESS: " + newFunc.getName());
                println("Body range: " + newFunc.getBody());
                println("Size: " + newFunc.getBody().getNumAddresses() + " bytes");
            }
        } else {
            println("FAILED to create function");
        }
    }
}

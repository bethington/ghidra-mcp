// Fix function at 0x6fa110d0 - remove and recreate with proper analysis
// @category Repair
// @author Claude

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFunction_6fa110d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fa110d0L);
        
        println("=== Fixing function at 0x6fa110d0 ===");
        
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing function
        Function existingFunc = fm.getFunctionAt(startAddr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            println("  Body was: " + existingFunc.getBody());
            fm.removeFunction(startAddr);
        }
        
        // Clear listing at start to force re-analysis
        Listing listing = currentProgram.getListing();
        
        // Disassemble from start address
        println("Disassembling from 0x6fa110d0...");
        AddressSet disasmSet = new AddressSet(startAddr, toAddr(0x6fa11127L));
        disassemble(disasmSet);
        
        // Create function using Ghidra's auto-analysis
        println("Creating function...");
        CreateFunctionCmd cmd = new CreateFunctionCmd(startAddr);
        boolean success = cmd.applyTo(currentProgram);
        
        if (success) {
            Function newFunc = fm.getFunctionAt(startAddr);
            if (newFunc != null) {
                println("SUCCESS: Function created");
                println("  Name: " + newFunc.getName());
                println("  Body: " + newFunc.getBody());
                println("  Signature: " + newFunc.getSignature());
            }
        } else {
            println("ERROR: CreateFunctionCmd failed");
            println("  Status: " + cmd.getStatusMsg());
        }
    }
}

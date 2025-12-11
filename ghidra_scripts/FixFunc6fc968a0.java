//Fix function at 0x6fc968a0 
//@category Fix
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFunc6fc968a0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc968a0L);
        Address endAddr = toAddr(0x6fc96960L);  // Estimated end based on code pattern
        FunctionManager fm = currentProgram.getFunctionManager();
        
        int txId = currentProgram.startTransaction("Fix function 6fc968a0");
        try {
            // Remove existing function
            Function existing = fm.getFunctionAt(startAddr);
            if (existing != null) {
                println("Removing existing function: " + existing.getName());
                fm.removeFunction(startAddr);
            }
            
            // Clear any code units in the range
            AddressSet range = new AddressSet(startAddr, endAddr);
            println("Clearing code in range: " + range);
            clearListing(range);
            
            // Disassemble the range
            println("Disassembling from " + startAddr + " to " + endAddr);
            DisassembleCommand disCmd = new DisassembleCommand(startAddr, range, true);
            disCmd.applyTo(currentProgram, monitor);
            
            // Create function
            println("Creating function at " + startAddr);
            CreateFunctionCmd createCmd = new CreateFunctionCmd(startAddr);
            boolean success = createCmd.applyTo(currentProgram, monitor);
            
            if (success) {
                Function newFunc = fm.getFunctionAt(startAddr);
                if (newFunc != null) {
                    println("SUCCESS: Function created: " + newFunc.getName());
                    println("Body range: " + newFunc.getBody());
                }
            } else {
                println("FAILED: " + createCmd.getStatusMsg());
            }
            
            currentProgram.endTransaction(txId, true);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            throw e;
        }
    }
}

//Recreate function at 0x6fa103e0 with correct boundaries
//@category Repair
//@description Recreate function FUN_6fa103e0 to include all code up to RET

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;

public class RecreateFunction_6fa103e0_v2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fa103e0);
        Address endAddr = toAddr(0x6fa10427);  // RET 4 at 0x6fa10425 + 3 bytes = 0x6fa10428
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove existing function if present
        Function existingFunc = funcMgr.getFunctionAt(startAddr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            funcMgr.removeFunction(startAddr);
        }
        
        // Ensure bytes are disassembled
        AddressSet disasmSet = new AddressSet(startAddr, endAddr);
        DisassembleCommand disCmd = new DisassembleCommand(disasmSet, null, true);
        disCmd.applyTo(currentProgram, monitor);
        println("Disassembled range: " + startAddr + " - " + endAddr);
        
        // Create function with correct body
        Function newFunc = funcMgr.createFunction(
            "FUN_6fa103e0",
            startAddr,
            new AddressSet(startAddr, endAddr),
            SourceType.USER_DEFINED
        );
        
        if (newFunc != null) {
            println("Created function: " + newFunc.getName() + " from " + 
                    newFunc.getEntryPoint() + " to " + newFunc.getBody().getMaxAddress());
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

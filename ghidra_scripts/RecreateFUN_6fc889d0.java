//Recreate function at 0x6fc889d0
//@author Claude
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;

public class RecreateFUN_6fc889d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc889d0);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Remove existing function if any
        Function existingFunc = funcMgr.getFunctionAt(addr);
        if (existingFunc != null) {
            println("Removing existing function at " + addr);
            funcMgr.removeFunction(addr);
        }
        
        // Disassemble starting at address (256 bytes should cover most functions)
        AddressSet addrSet = new AddressSet(addr, addr.add(512));
        DisassembleCommand disCmd = new DisassembleCommand(addrSet, null, true);
        disCmd.applyTo(currentProgram, monitor);
        println("Disassembled bytes at " + addr);
        
        // Create function
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        boolean success = cmd.applyTo(currentProgram, monitor);
        
        if (success) {
            Function newFunc = funcMgr.getFunctionAt(addr);
            if (newFunc != null) {
                println("SUCCESS: Created function at " + addr);
                println("Function body: " + newFunc.getBody().getMinAddress() + " - " + newFunc.getBody().getMaxAddress());
            }
        } else {
            println("FAILED to create function at " + addr);
        }
    }
}

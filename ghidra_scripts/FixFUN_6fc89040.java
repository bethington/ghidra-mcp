//Fix truncated function at 0x6fc89040
//@category Repair
//@author Claude

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class FixFUN_6fc89040 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc89040);
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Remove existing broken function
        Function oldFunc = fm.getFunctionAt(addr);
        if (oldFunc != null) {
            println("Removing broken function: " + oldFunc.getName());
            fm.removeFunction(addr);
        }
        
        // Disassemble the full range
        Address endAddr = toAddr(0x6fc89069); // End after the RET
        DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
        disCmd.applyTo(currentProgram);
        println("Disassembled from " + addr + " to " + endAddr);
        
        // Create new function
        CreateFunctionCmd createCmd = new CreateFunctionCmd(addr);
        boolean success = createCmd.applyTo(currentProgram);
        if (success) {
            Function newFunc = fm.getFunctionAt(addr);
            println("Created function: " + newFunc.getName() + " at " + addr);
            println("Function body: " + newFunc.getBody());
        } else {
            println("Failed to create function at " + addr);
        }
    }
}

//Recreate function at 0x6fc88fe0
//@author GhidraMCP
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class Fix6fc88fe0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc88fe0L);
        println("Starting fix at: " + addr);

        FunctionManager fm = currentProgram.getFunctionManager();
        Function existingFunc = fm.getFunctionAt(addr);

        // Remove existing function if present
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            fm.removeFunction(addr);
        }

        // Disassemble 96 bytes
        Address endAddr = addr.add(96);
        println("Disassembling from " + addr + " to " + endAddr);
        DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
        cmd.applyTo(currentProgram, monitor);

        // Create new function
        println("Creating function at " + addr);
        Function newFunc = fm.createFunction(null, addr,
            new ghidra.program.model.address.AddressSet(addr, addr),
            ghidra.program.model.symbol.SourceType.USER_DEFINED);

        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName() + " at " + addr);
            println("Body: " + newFunc.getBody());
        } else {
            println("FAILED: Could not create function");
        }
    }
}

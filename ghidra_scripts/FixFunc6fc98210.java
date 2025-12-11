//Fix and recreate function at 0x6fc98210
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class FixFunc6fc98210 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc98210);
        Address endAddr = toAddr(0x6fc98350);  // Scan up to 0x140 bytes
        
        // Remove existing function if any
        Function func = getFunctionAt(startAddr);
        if (func != null) {
            println("Removing truncated function: " + func.getName());
            println("Old body: " + func.getBody());
            removeFunction(func);
        }
        
        // Clear any undefined bytes and disassemble
        AddressSet range = new AddressSet(startAddr, endAddr);
        DisassembleCommand cmd = new DisassembleCommand(startAddr, range, true);
        cmd.applyTo(currentProgram, monitor);
        println("Disassembled range: " + startAddr + " to " + endAddr);
        
        // Create function using CreateFunctionCmd
        CreateFunctionCmd createCmd = new CreateFunctionCmd(startAddr);
        createCmd.applyTo(currentProgram, monitor);
        
        // Check result
        func = getFunctionAt(startAddr);
        if (func != null) {
            println("SUCCESS: Function recreated: " + func.getName());
            println("Entry: " + func.getEntryPoint());
            println("Body: " + func.getBody());
            
            // List first few instructions
            Listing listing = currentProgram.getListing();
            InstructionIterator iter = listing.getInstructions(func.getBody(), true);
            int count = 0;
            while (iter.hasNext() && count < 20) {
                Instruction instr = iter.next();
                println(instr.getAddress() + ": " + instr.toString());
                count++;
            }
        } else {
            println("ERROR: Failed to create function");
        }
    }
}

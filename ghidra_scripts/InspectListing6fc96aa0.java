//Inspect what's at addresses following 0x6fc96aa0
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class InspectListing6fc96aa0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc96aa0L);
        
        println("=== Inspecting 0x6fc96aa0 ===");
        
        // Check if there's an instruction
        Instruction instr = getInstructionAt(addr);
        if (instr != null) {
            println("Instruction at " + addr + ": " + instr.toString());
            println("  Length: " + instr.getLength());
            println("  Fall-through: " + instr.getFallThrough());
        } else {
            println("No instruction at " + addr);
        }
        
        // Check if there's data
        Data data = getDataAt(addr);
        if (data != null) {
            println("Data at " + addr + ": " + data.toString());
        }
        
        // Check next few addresses
        for (int i = 0; i < 20; i++) {
            Address checkAddr = addr.add(i);
            Instruction inst = getInstructionAt(checkAddr);
            Data dat = getDataAt(checkAddr);
            
            if (inst != null) {
                println(checkAddr + ": INSTR " + inst.getMnemonicString() + " (len=" + inst.getLength() + ")");
            } else if (dat != null) {
                println(checkAddr + ": DATA " + dat.getDataType().getName());
            } else {
                // Check raw byte
                byte b = getByte(checkAddr);
                println(checkAddr + ": UNDEFINED byte=0x" + String.format("%02X", b & 0xFF));
            }
        }
        
        // Check function
        Function func = getFunctionAt(addr);
        if (func != null) {
            println("\nFunction: " + func.getName());
            println("Body: " + func.getBody());
            println("Body size: " + func.getBody().getNumAddresses());
        }
    }
}

//Check instructions after 6fc8ea30
//@category Fix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class CheckInstr6fc8ea34 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        Address start = toAddr(0x6fc8ea30);
        
        // Check first 10 addresses
        for (int i = 0; i < 96; i++) {
            Address addr = start.add(i);
            Instruction inst = listing.getInstructionAt(addr);
            if (inst != null) {
                println(addr + ": " + inst.toString());
            }
        }
    }
}

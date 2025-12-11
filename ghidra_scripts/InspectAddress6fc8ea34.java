//Inspect what's at 6fc8ea34
//@category Fix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;

public class InspectAddress6fc8ea34 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        
        for (int i = 0; i < 20; i++) {
            Address addr = toAddr(0x6fc8ea30 + i);
            Instruction inst = listing.getInstructionAt(addr);
            Data data = listing.getDataAt(addr);
            CodeUnit cu = listing.getCodeUnitAt(addr);
            
            String instStr = inst != null ? inst.toString() : "null";
            String dataStr = data != null ? data.toString() : "null";
            String cuStr = cu != null ? cu.getClass().getSimpleName() : "null";
            
            println(addr.toString() + ": inst=" + instStr + ", data=" + dataStr + ", cu=" + cuStr);
        }
    }
}

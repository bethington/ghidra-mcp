//Fix function at 0x6fc889d0
//@author Claude
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class Fix6fc889d0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc889d0);
        
        // Clear and disassemble
        clearListing(addr, addr.add(512));
        disassemble(addr);
        
        // Create function
        createFunction(addr, null);
        
        println("Done - check function at 0x6fc889d0");
    }
}

//Debug6fc95e20.java
//@category Repair
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class Debug6fc95e20 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc95e20);
        Listing listing = currentProgram.getListing();
        
        // Check what's at the address
        CodeUnit cu = listing.getCodeUnitAt(addr);
        println("CodeUnit at " + addr + ": " + (cu != null ? cu.getClass().getSimpleName() + " - " + cu : "null"));
        
        // Check next few addresses
        for (int i = 0; i < 10; i++) {
            Address a = addr.add(i * 3);
            cu = listing.getCodeUnitAt(a);
            if (cu != null) {
                println(a + ": " + cu.getClass().getSimpleName() + " len=" + cu.getLength());
            } else {
                println(a + ": null");
            }
        }
        
        // Check function
        FunctionManager fm = currentProgram.getFunctionManager();
        Function f = fm.getFunctionAt(addr);
        if (f != null) {
            println("Function: " + f.getName());
            println("Body ranges: " + f.getBody().getNumAddressRanges());
            for (AddressRange r : f.getBody()) {
                println("  Range: " + r);
            }
        }
    }
}

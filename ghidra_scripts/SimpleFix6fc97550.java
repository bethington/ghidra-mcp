//Simple fix for function at 0x6fc97550
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SimpleFix6fc97550 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x6fc97550);
        println("Clearing listing at: " + addr);
        clearListing(addr, toAddr(0x6fc97700));
        println("Done clearing");
    }
}

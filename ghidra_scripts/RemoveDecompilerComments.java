//Removes all decompiler/auto-generated comments from current function
//@author Claude
//@category Documentation
//@keybinding
//@menupath Tools.Remove Decompiler Comments

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;

public class RemoveDecompilerComments extends GhidraScript {

    @Override
    protected void run() throws Exception {
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Address currentAddr = currentLocation.getAddress();
        Function func = funcMgr.getFunctionContaining(currentAddr);

        if (func == null) {
            println("No function at current location");
            return;
        }

        println("Processing function: " + func.getName() + " at " + func.getEntryPoint());
        
        Listing listing = currentProgram.getListing();
        int removedCount = 0;
        int totalCount = 0;

        // Iterate through all addresses in the function
        Address minAddr = func.getBody().getMinAddress();
        Address maxAddr = func.getBody().getMaxAddress();

        for (Address addr = minAddr; addr <= maxAddr && !monitor.isCancelled(); addr = addr.add(1)) {
            CodeUnit cu = listing.getCodeUnitAt(addr);
            if (cu != null) {
                totalCount++;
                
                // Check and remove PRE_COMMENT
                String preComment = cu.getComment(CodeUnit.PRE_COMMENT);
                if (preComment != null && !preComment.isEmpty()) {
                    cu.setComment(CodeUnit.PRE_COMMENT, null);
                    removedCount++;
                    println("Removed PRE comment at " + addr + ": " + preComment.substring(0, Math.min(50, preComment.length())));
                }
                
                // Check and remove POST_COMMENT
                String postComment = cu.getComment(CodeUnit.POST_COMMENT);
                if (postComment != null && !postComment.isEmpty()) {
                    cu.setComment(CodeUnit.POST_COMMENT, null);
                    removedCount++;
                    println("Removed POST comment at " + addr);
                }
            }
        }

        println("=== Results ===");
        println("Function: " + func.getName());
        println("Total code units checked: " + totalCount);
        println("Comments removed: " + removedCount);
    }
}

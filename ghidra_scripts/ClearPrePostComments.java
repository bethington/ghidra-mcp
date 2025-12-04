//Clears PRE and POST comments from the current program or selection (preserves EOL and PLATE)
//@author Claude
//@category Documentation
//@keybinding
//@menupath Tools.Clear Pre Post Comments
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;

public class ClearPrePostComments extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Listing listing = currentProgram.getListing();
        AddressSet addressSet;

        // Use current selection if available, otherwise use entire program
        if (currentSelection != null && !currentSelection.isEmpty()) {
            addressSet = new AddressSet(currentSelection);
            println("Clearing PRE/POST comments in selection: " + currentSelection.getMinAddress() + " to " + currentSelection.getMaxAddress());
        } else {
            addressSet = new AddressSet(currentProgram.getMemory());
            println("Clearing PRE/POST comments in entire program");
        }

        int preCount = 0;
        int postCount = 0;

        // Iterate through all code units in the address set
        AddressIterator addrIter = addressSet.getAddresses(true);

        long totalAddresses = addressSet.getNumAddresses();
        long processed = 0;
        long lastReport = 0;

        while (addrIter.hasNext() && !monitor.isCancelled()) {
            Address addr = addrIter.next();
            CodeUnit cu = listing.getCodeUnitAt(addr);

            if (cu != null) {
                // Clear PRE comment
                String preComment = cu.getComment(CodeUnit.PRE_COMMENT);
                if (preComment != null) {
                    cu.setComment(CodeUnit.PRE_COMMENT, null);
                    preCount++;
                }

                // Clear POST comment
                String postComment = cu.getComment(CodeUnit.POST_COMMENT);
                if (postComment != null) {
                    cu.setComment(CodeUnit.POST_COMMENT, null);
                    postCount++;
                }
            }

            processed++;

            // Report progress every 10000 addresses
            if (processed - lastReport >= 10000) {
                monitor.setMessage("Processing: " + processed + " / " + totalAddresses);
                lastReport = processed;
            }
        }

        if (monitor.isCancelled()) {
            println("Operation cancelled by user");
        }

        println("=== Comments Cleared ===");
        println("PRE comments:  " + preCount);
        println("POST comments: " + postCount);
        println("Total:         " + (preCount + postCount));
        println("(EOL and PLATE comments preserved)");
    }
}

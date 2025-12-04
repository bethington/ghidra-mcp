//Clears PRE, POST, and EOL comments from the current program or selection
//@author Claude
//@category Documentation
//@keybinding
//@menupath Tools.Clear All Comments
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;

public class ClearAllComments extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Listing listing = currentProgram.getListing();
        AddressSet addressSet;

        // Use current selection if available, otherwise use entire program
        if (currentSelection != null && !currentSelection.isEmpty()) {
            addressSet = new AddressSet(currentSelection);
            println("Clearing comments in selection: " + currentSelection.getMinAddress() + " to " + currentSelection.getMaxAddress());
        } else {
            addressSet = new AddressSet(currentProgram.getMemory());
            println("Clearing comments in entire program");
        }

        int preCount = 0;
        int postCount = 0;
        int eolCount = 0;
        int plateCount = 0;

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

                // Clear EOL comment
                String eolComment = cu.getComment(CodeUnit.EOL_COMMENT);
                if (eolComment != null) {
                    cu.setComment(CodeUnit.EOL_COMMENT, null);
                    eolCount++;
                }

                // Clear PLATE comment
                String plateComment = cu.getComment(CodeUnit.PLATE_COMMENT);
                if (plateComment != null) {
                    cu.setComment(CodeUnit.PLATE_COMMENT, null);
                    plateCount++;
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
        println("PRE comments:   " + preCount);
        println("POST comments:  " + postCount);
        println("EOL comments:   " + eolCount);
        println("PLATE comments: " + plateCount);
        println("Total:          " + (preCount + postCount + eolCount + plateCount));
    }
}
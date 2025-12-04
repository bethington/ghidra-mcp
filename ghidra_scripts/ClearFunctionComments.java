//Clears all comments (plate, pre, post, EOL, repeatable) for the currently selected function
//@category Documentation
//@keybinding
//@menupath Tools.Clear Function Comments
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class ClearFunctionComments extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program open");
            return;
        }

        Function func = getFunctionContaining(currentAddress);
        if (func == null) {
            printerr("No function at current address: " + currentAddress);
            return;
        }

        Listing listing = currentProgram.getListing();
        AddressSetView body = func.getBody();
        
        int plateCleared = 0;
        int preCleared = 0;
        int postCleared = 0;
        int eolCleared = 0;
        int repeatableCleared = 0;

        // Clear plate comment at function entry
        Address entryPoint = func.getEntryPoint();
        String plateComment = listing.getComment(CodeUnit.PLATE_COMMENT, entryPoint);
        if (plateComment != null) {
            listing.setComment(entryPoint, CodeUnit.PLATE_COMMENT, null);
            plateCleared++;
        }

        // Iterate through all code units in the function
        CodeUnitIterator codeUnits = listing.getCodeUnits(body, true);
        while (codeUnits.hasNext()) {
            CodeUnit cu = codeUnits.next();
            
            // Clear PRE_COMMENT
            if (cu.getComment(CodeUnit.PRE_COMMENT) != null) {
                cu.setComment(CodeUnit.PRE_COMMENT, null);
                preCleared++;
            }
            
            // Clear POST_COMMENT
            if (cu.getComment(CodeUnit.POST_COMMENT) != null) {
                cu.setComment(CodeUnit.POST_COMMENT, null);
                postCleared++;
            }
            
            // Clear EOL_COMMENT
            if (cu.getComment(CodeUnit.EOL_COMMENT) != null) {
                cu.setComment(CodeUnit.EOL_COMMENT, null);
                eolCleared++;
            }
            
            // Clear REPEATABLE_COMMENT
            if (cu.getComment(CodeUnit.REPEATABLE_COMMENT) != null) {
                cu.setComment(CodeUnit.REPEATABLE_COMMENT, null);
                repeatableCleared++;
            }
        }

        int total = plateCleared + preCleared + postCleared + eolCleared + repeatableCleared;
        println("Cleared " + total + " comments from function: " + func.getName());
        println("  Plate: " + plateCleared);
        println("  Pre: " + preCleared);
        println("  Post: " + postCleared);
        println("  EOL: " + eolCleared);
        println("  Repeatable: " + repeatableCleared);
    }
}

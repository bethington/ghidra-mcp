// Sign Function
//
// Adds a standardized function header comment with date, author (from Ghidra username), function name, address, and existing description. Notes custom register parameters if present.
//
// Usage: Place cursor on a function, run via F6 or Script Manager.
// Output: Prepends a signed header to the function's plate comment.
//
// @author Ben Ethington
// @category Diablo 2.Documentation
// @description Add standardized function header with author signature
// @menupath Diablo 2.Documentation.Sign Function

import ghidra.app.script.GhidraScript;
import ghidra.framework.client.ClientUtil;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class Document_SignFunction extends GhidraScript {

    @Override
    public void run() throws Exception {
        try {
            Function func = currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
            if (func == null) {
                println("No function at current address.");
                return;
            }

            String nick = ClientUtil.getUserName();
            LocalDate today = LocalDate.now();
            String dateStr = today.format(DateTimeFormatter.ofPattern("yyyy.MM.dd"));

            // Extract existing description from comment if present
            String comment = func.getComment();
            String description = "";
            if (comment != null) {
                for (String line : comment.split("\n")) {
                    if (line.contains("@description: ")) {
                        description = line.split("@description: ", 2)[1];
                        break;
                    }
                }
            }

            String programBase = currentProgram.getName();
            int lastDot = programBase.lastIndexOf('.');
            if (lastDot >= 0) programBase = programBase.substring(0, lastDot);

            String newComment = "Diablo 2 1.14d reverse team\n" +
                "https://blizzhackers.dev\n" +
                "        \n" +
                "@Date: " + dateStr + "\n" +
                "@Author: " + nick + "\n" +
                "@Function: " + func.getName() + "\n" +
                "@Address: " + programBase + ".0x" + func.getEntryPoint() + "\n" +
                "@description: " + description;

            func.setComment(newComment);

            if (func.hasCustomVariableStorage()) {
                StringBuilder s = new StringBuilder();
                for (Parameter arg : func.getParameters()) {
                    s.append("\n").append(arg.toString());
                }
                func.setComment(func.getComment() +
                    "\n\nFunction uses custom registers for function arguments!" + s);
            }
        } catch (CancelledException e) {
            // cancelled
        }
    }
}
